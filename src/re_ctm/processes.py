from __future__ import annotations

import os
import queue
import secrets
import signal
import subprocess
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable

from .errors import ReCTMError, invalid_argument


COMMAND_BUFFER_BYTES = 524_288
COMMAND_HEAD_BUFFER_DIVISOR = 8
MAX_ACTIVE_COMMANDS = 16
MAX_RETAINED_COMMANDS = 32
COMPLETED_COMMAND_TTL_SECONDS = 300
DEFAULT_COMMAND_TIMEOUT_MS = 300_000
MAX_COMMAND_TIMEOUT_MS = 600_000
HARD_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)


def terminate_process_group(
    process: subprocess.Popen[bytes],
    signum: signal.Signals,
    *,
    force: bool = False,
) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signum)
        elif force:
            process.kill()
        else:
            process.terminate()
    except ProcessLookupError:
        return
    except OSError:
        try:
            process.kill() if force else process.terminate()
        except OSError:
            return


def spawn_process(
    command: list[str],
    *,
    env: dict[str, str],
    tty: bool,
) -> tuple[subprocess.Popen[bytes], int | None]:
    # Linux parent-death signals follow the creating thread, not just its
    # process. HTTP request threads may exit as soon as "running" is returned,
    # so the owner of a --die-with-parent child must live until that child exits.
    outcomes: queue.Queue[
        tuple[subprocess.Popen[bytes], int | None] | BaseException
    ] = queue.Queue(maxsize=1)

    def supervise() -> None:
        try:
            spawned = _spawn_process_owned(command, env=env, tty=tty)
        except BaseException as exc:
            outcomes.put(exc)
            return
        outcomes.put(spawned)
        process, _ = spawned
        while True:
            try:
                if process.poll() is not None or process.wait() is not None:
                    return
            except Exception:
                # Observation failure must not itself kill a still-live child
                # by ending its parent thread. Other lifecycle waiters retain
                # their existing timeout/kill authority and provenance.
                time.sleep(0.05)

    owner = threading.Thread(
        target=supervise, name="re-ctm-command-owner", daemon=True,
    )
    owner.start()  # A failure propagates before waiting for the handshake.
    outcome = outcomes.get()
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome


def _spawn_process_owned(
    command: list[str],
    *,
    env: dict[str, str],
    tty: bool,
) -> tuple[subprocess.Popen[bytes], int | None]:
    popen_kwargs: dict[str, Any] = {"start_new_session": True}
    if not tty:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            **popen_kwargs,
        )
        return process, None
    if os.name == "nt":
        raise ReCTMError(
            "TTY_UNSUPPORTED",
            "tty=true is not supported on this platform.",
            category="runtime",
        )
    try:
        import pty

        master_fd, slave_fd = pty.openpty()
    except (ImportError, OSError) as exc:
        raise ReCTMError(
            "TTY_UNSUPPORTED",
            "A POSIX pseudo-terminal could not be created.",
            category="runtime",
        ) from exc
    try:
        process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            **popen_kwargs,
        )
    except Exception:
        os.close(master_fd)
        raise
    finally:
        os.close(slave_fd)
    return process, master_fd


@dataclass
class CommandRun:
    command_id: str
    process: subprocess.Popen[bytes]
    timeout_at: float | None = None
    requested_timeout_ms: int | None = None
    warnings: list[str] = field(default_factory=list)
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    stdout_head: bytearray = field(default_factory=bytearray)
    stderr_head: bytearray = field(default_factory=bytearray)
    stdout_start_offset: int = 0
    stderr_start_offset: int = 0
    stdout_cursor: int = 0
    stderr_cursor: int = 0
    stdout_total_bytes: int = 0
    stderr_total_bytes: int = 0
    stdout_dropped_bytes: int = 0
    stderr_dropped_bytes: int = 0
    buffer_limit: int = COMMAND_BUFFER_BYTES
    lock: threading.Lock = field(default_factory=threading.Lock)
    reader_threads: list[threading.Thread] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    exit_code: int | None = None
    signal_name: str | None = None
    timed_out: bool = False
    terminating: bool = False
    termination_source: str | None = None
    term_sent_by_re_ctm: bool = False
    kill_sent_by_re_ctm: bool = False
    pty_master_fd: int | None = None
    _stdin_closed: bool = False
    _status_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _terminal_observed: bool = field(default=False, repr=False)
    on_terminal: Callable[[dict[str, Any]], None] | None = field(default=None, repr=False)

    @property
    def head_buffer_limit(self) -> int:
        return self.buffer_limit // COMMAND_HEAD_BUFFER_DIVISOR

    def append_stdout(self, chunk: bytes) -> None:
        with self.lock:
            capacity = self.head_buffer_limit - len(self.stdout_head)
            if capacity > 0:
                self.stdout_head.extend(chunk[:capacity])
            self.stdout.extend(chunk)
            self.stdout_total_bytes += len(chunk)
            self.stdout_dropped_bytes += self._trim(self.stdout, "stdout_start_offset", self.stdout_total_bytes)

    def append_stderr(self, chunk: bytes) -> None:
        with self.lock:
            capacity = self.head_buffer_limit - len(self.stderr_head)
            if capacity > 0:
                self.stderr_head.extend(chunk[:capacity])
            self.stderr.extend(chunk)
            self.stderr_total_bytes += len(chunk)
            self.stderr_dropped_bytes += self._trim(self.stderr, "stderr_start_offset", self.stderr_total_bytes)

    def _trim(self, buffer: bytearray, start_attr: str, total: int) -> int:
        tail_limit = self.buffer_limit - self.head_buffer_limit
        overflow = len(buffer) - tail_limit
        if overflow <= 0:
            return 0
        del buffer[:overflow]
        setattr(self, start_attr, total - len(buffer))
        return overflow

    def write_input(self, data: bytes) -> None:
        if self._stdin_closed:
            raise ReCTMError("COMMAND_CLOSED", "Command stdin is closed.", category="runtime")
        try:
            if self.pty_master_fd is not None:
                os.write(self.pty_master_fd, data)
                return
            if self.process.stdin is None or self.process.stdin.closed:
                raise ReCTMError("COMMAND_CLOSED", "Command stdin is closed.", category="runtime")
            self.process.stdin.write(data)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise ReCTMError("COMMAND_CLOSED", "Command stdin is closed.", category="runtime") from exc

    def close_stdin(self) -> None:
        if self.pty_master_fd is not None or self._stdin_closed:
            return
        self._stdin_closed = True
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass

    def request_termination(
        self,
        signum: signal.Signals,
        *,
        source: str,
        force: bool = False,
    ) -> bool:
        # Keep timeout provenance and explicit signal bookkeeping coherent with
        # the single status snapshot used by all four observation tools.
        with self._status_lock:
            if self.process.poll() is not None:
                return False
            self.terminating = True
            self.termination_source = self.termination_source or source
            if source == "command_timeout":
                self.timed_out = True
            if signum == signal.SIGTERM:
                self.term_sent_by_re_ctm = True
            if force:
                self.kill_sent_by_re_ctm = True
            terminate_process_group(self.process, signum, force=force)
            return True

    def refresh_status(self) -> None:
        with self._status_lock:
            if self.completed_at is not None:
                return
            expired = (
                self.timeout_at is not None
                and not self.timed_out
                and time.time() >= self.timeout_at
            )
        if expired:
            self.request_termination(signal.SIGTERM, source="command_timeout")
        code = self.process.poll()
        if code is None:
            return
        # Reader threads acquire the output lock, so never join them while
        # holding that lock or the lifecycle snapshot lock.
        self.drain_readers()
        with self._status_lock:
            if self.completed_at is not None:
                return
            self.exit_code = code
            self.terminating = False
            if code < 0:
                try:
                    self.signal_name = signal.Signals(-code).name
                except ValueError:
                    self.signal_name = str(-code)
                if self.termination_source is None:
                    self.termination_source = "external_or_unknown"
            self.completed_at = time.time()

    def observe_status(self) -> dict[str, Any]:
        """Return one coherent observation and report its first terminal state.

        Maintenance/watchdog status refreshes do not consume the observation.
        The callback receives public lifecycle facts, never output or a private
        once flag; read_output can observe without advancing polling cursors.
        """
        self.refresh_status()
        with self._status_lock:
            terminal = self.completed_at is not None
            if not terminal:
                outcome, status = "running", "running"
            elif self.timed_out:
                outcome, status = "timeout", "timeout"
            elif self.signal_name is not None:
                outcome, status = "signal", "terminated"
            elif self.exit_code == 0:
                outcome, status = "exited_0", "exited"
            else:
                outcome, status = "exited_nonzero", "exited"
            first_terminal = terminal and not self._terminal_observed
            if terminal:
                self._terminal_observed = True
            elapsed_ms = int(((self.completed_at or time.time()) - self.started_at) * 1000)
            payload: dict[str, Any] = {
                "command_id": self.command_id,
                "operation_outcome": outcome,
                "status": status,
                "exit_code": self.exit_code,
                "signal": self.signal_name,
                "timed_out": self.timed_out,
                "elapsed_ms": elapsed_ms,
                "termination": {
                    "source": self.termination_source,
                    "requested_timeout_ms": self.requested_timeout_ms,
                    "elapsed_ms": elapsed_ms,
                    "observed_signal": self.signal_name,
                    "term_sent_by_re_ctm": self.term_sent_by_re_ctm,
                    "kill_sent_by_re_ctm": self.kill_sent_by_re_ctm,
                },
            }
        if first_terminal and self.on_terminal is not None:
            self.on_terminal({**payload, "termination": dict(payload["termination"])})
        return payload

    def drain_readers(self, timeout: float = 0.25) -> None:
        deadline = time.time() + timeout
        for thread in list(self.reader_threads):
            remaining = max(0.0, deadline - time.time())
            if remaining <= 0:
                break
            thread.join(timeout=remaining)

    def snapshot_since_cursor(self, max_output_bytes: int) -> dict[str, Any]:
        self.refresh_status()
        with self.lock:
            stdout_omitted = max(0, self.stdout_start_offset - self.stdout_cursor)
            stderr_omitted = max(0, self.stderr_start_offset - self.stderr_cursor)
            stdout_start = max(0, self.stdout_cursor - self.stdout_start_offset)
            stderr_start = max(0, self.stderr_cursor - self.stderr_start_offset)
            stdout = bytes(self.stdout[stdout_start:])
            stderr = bytes(self.stderr[stderr_start:])
            self.stdout_cursor = self.stdout_total_bytes
            self.stderr_cursor = self.stderr_total_bytes
        stdout_text, stdout_truncated = _tail_text(stdout, max_output_bytes)
        stderr_text, stderr_truncated = _tail_text(stderr, max_output_bytes)
        payload: dict[str, Any] = {
            "ok": True,
            **self.observe_status(),
            "stdout": stdout_text,
            "stderr": stderr_text,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "stdout_dropped_bytes": self.stdout_dropped_bytes,
            "stderr_dropped_bytes": self.stderr_dropped_bytes,
            "stdout_omitted_bytes": stdout_omitted,
            "stderr_omitted_bytes": stderr_omitted,
            "truncated": stdout_truncated or stderr_truncated or stdout_omitted > 0 or stderr_omitted > 0,
        }
        if self.warnings:
            payload["warnings"] = list(self.warnings)
        return payload

    def retained_stream_segments(self, stream: str) -> tuple[bytes, bytes, int, int, int]:
        with self.lock:
            if stream == "stdout":
                return (
                    bytes(self.stdout_head),
                    bytes(self.stdout),
                    self.stdout_start_offset,
                    self.stdout_total_bytes,
                    self.stdout_dropped_bytes,
                )
            if stream == "stderr":
                return (
                    bytes(self.stderr_head),
                    bytes(self.stderr),
                    self.stderr_start_offset,
                    self.stderr_total_bytes,
                    self.stderr_dropped_bytes,
                )
        raise invalid_argument("stream must be stdout or stderr")


def start_reader_threads(command: CommandRun) -> None:
    def reader(stream: BinaryIO, append: Any) -> None:
        try:
            while True:
                chunk = os.read(stream.fileno(), 4096)
                if not chunk:
                    break
                append(chunk)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def pty_reader(fd: int) -> None:
        try:
            while True:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                command.append_stdout(chunk)
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            if command.pty_master_fd == fd:
                command.pty_master_fd = None

    if command.pty_master_fd is not None:
        thread = threading.Thread(target=pty_reader, args=(command.pty_master_fd,), daemon=True)
        command.reader_threads.append(thread)
        thread.start()
        return
    if command.process.stdout is not None:
        thread = threading.Thread(target=reader, args=(command.process.stdout, command.append_stdout), daemon=True)
        command.reader_threads.append(thread)
        thread.start()
    if command.process.stderr is not None:
        thread = threading.Thread(target=reader, args=(command.process.stderr, command.append_stderr), daemon=True)
        command.reader_threads.append(thread)
        thread.start()


class CommandManager:
    def __init__(
        self, *, on_terminal: Callable[[dict[str, Any]], None] | None = None
    ) -> None:
        self.on_terminal = on_terminal
        self.active: dict[str, CommandRun] = {}
        self.retained: OrderedDict[str, CommandRun] = OrderedDict()
        self.lock = threading.Lock()
        self.closed = False

    def start(
        self,
        command_argv: list[str],
        *,
        env: dict[str, str],
        timeout_ms: int = DEFAULT_COMMAND_TIMEOUT_MS,
        yield_time_ms: int,
        max_output_bytes: int,
        stdin_text: str,
        tty: bool,
        verbosity: str | None,
        preview_bytes: int,
    ) -> dict[str, Any]:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_COMMAND_TIMEOUT_MS:
            raise invalid_argument("timeout_ms must be between 1 and 600000")
        if verbosity is not None and verbosity not in {"summary", "preview", "full"}:
            raise invalid_argument("verbosity must be summary, preview, or full")
        self._prune()
        with self.lock:
            if self.closed:
                raise ReCTMError("COMMAND_CLOSED", "Command manager is closed.", category="runtime")
            if len(self.active) >= MAX_ACTIVE_COMMANDS:
                raise ReCTMError(
                    "COMMAND_LIMIT_REACHED",
                    "Too many commands are already running.",
                    category="runtime",
                    retryable=True,
                    details={"max_active_commands": MAX_ACTIVE_COMMANDS},
                )
            # Keep admission, the spawn handshake and registration atomic with
            # close() and other starts. The owner thread never takes this lock.
            command_id = secrets.token_urlsafe(18)
            process, pty_master_fd = spawn_process(command_argv, env=env, tty=tty)
            command = CommandRun(
                command_id=command_id,
                process=process,
                timeout_at=time.time() + timeout_ms / 1000.0,
                requested_timeout_ms=timeout_ms,
                pty_master_fd=pty_master_fd,
                on_terminal=self.on_terminal,
            )
            self.active[command.command_id] = command
        start_reader_threads(command)
        self._start_watchdog(command)
        if stdin_text:
            command.write_input(stdin_text.encode("utf-8"))
        if not tty:
            command.close_stdin()
        deadline = time.time() + max(0, min(yield_time_ms, 30_000)) / 1000.0
        while time.time() < deadline and process.poll() is None:
            time.sleep(0.02)
        command.refresh_status()
        payload = command.snapshot_since_cursor(max_output_bytes)
        return self._format(command, payload, verbosity=verbosity, preview_bytes=preview_bytes)

    def poll(
        self,
        command_id: str,
        *,
        chars: str,
        yield_time_ms: int,
        max_output_bytes: int,
        verbosity: str | None,
        preview_bytes: int,
    ) -> dict[str, Any]:
        command = self._get(command_id, stdin=True)
        command.refresh_status()
        if command.process.poll() is not None and chars:
            raise ReCTMError("COMMAND_CLOSED", "Command is closed; stdin write blocked.", category="runtime")
        if chars and command.process.poll() is None:
            command.write_input(chars.encode("utf-8"))
        deadline = time.time() + max(0, min(yield_time_ms, 30_000)) / 1000.0
        while time.time() < deadline and command.process.poll() is None:
            with command.lock:
                has_output = (
                    len(command.stdout) > max(0, command.stdout_cursor - command.stdout_start_offset)
                    or len(command.stderr) > max(0, command.stderr_cursor - command.stderr_start_offset)
                )
            if has_output:
                break
            time.sleep(0.02)
        payload = command.snapshot_since_cursor(max_output_bytes)
        return self._format(command, payload, verbosity=verbosity, preview_bytes=preview_bytes)

    def kill(
        self,
        command_id: str,
        *,
        signal_name: str,
        wait_ms: int,
        kill_wait_ms: int,
        max_output_bytes: int,
        verbosity: str | None,
        preview_bytes: int,
    ) -> dict[str, Any]:
        command = self._get(command_id, stdin=False)
        signum = {
            "TERM": signal.SIGTERM,
            "KILL": HARD_KILL_SIGNAL,
            "INT": signal.SIGINT,
        }.get(signal_name)
        if signum is None:
            raise invalid_argument("signal must be TERM, KILL, or INT")
        force = signal_name == "KILL"
        killed = False
        evicted = True
        original_running = command.request_termination(
            signum, source="explicit_kill", force=force
        )
        if original_running:
            try:
                command.process.wait(timeout=max(0, wait_ms) / 1000.0)
            except subprocess.TimeoutExpired:
                if not force:
                    force = True
                    command.request_termination(
                        HARD_KILL_SIGNAL, source="explicit_kill", force=True
                    )
                    try:
                        command.process.wait(timeout=max(0, kill_wait_ms) / 1000.0)
                    except subprocess.TimeoutExpired:
                        pass
        payload = command.snapshot_since_cursor(max_output_bytes)
        killed = original_running and payload["operation_outcome"] != "running"
        if original_running and not killed:
            status = "terminating"
            evicted = False
        elif original_running:
            status = "killed" if force else "terminated"
        else:
            status = "exited"
        payload.update(
            {
                "killed": killed,
                "status": status,
                "evicted": evicted,
                "signal_sent": "SIGKILL" if force else signal.Signals(signum).name,
            }
        )
        formatted = self._format(command, payload, verbosity=verbosity, preview_bytes=preview_bytes)
        if status == "terminating":
            warnings = list(formatted.get("warnings", []))
            warnings.append(
                "Process did not exit after TERM/SIGKILL; command retained for retry or watchdog cleanup."
            )
            formatted["warnings"] = warnings
            formatted["next_action"] = "retry kill_command or wait for watchdog cleanup"
        if evicted:
            with self.lock:
                self.active.pop(command_id, None)
                self.retained.pop(command_id, None)
        return formatted

    def read_output(self, output_ref: str, *, stream: str | None, offset: int, limit: int) -> dict[str, Any]:
        import re

        match = re.fullmatch(r"command:([^:]+):(stdout|stderr)", output_ref)
        if not match:
            raise invalid_argument("output_ref must look like command:<id>:stdout or command:<id>:stderr")
        command = self._get(match.group(1), stdin=False)
        selected = match.group(2)
        if stream and stream != selected:
            raise invalid_argument("stream does not match output_ref")
        lifecycle = command.observe_status()
        head, tail, tail_start, total, dropped = command.retained_stream_segments(selected)
        requested = max(0, offset)
        limit = max(1, min(limit, COMMAND_BUFFER_BYTES))
        head_len = len(head)
        gap = max(0, tail_start - head_len)
        if requested >= tail_start:
            actual = requested
            chunk = tail[actual - tail_start : actual - tail_start + limit]
        elif requested < head_len:
            actual = requested
            chunk = head[actual : min(head_len, actual + limit)]
        else:
            actual = tail_start
            chunk = tail[:limit]
        next_offset = actual + len(chunk) if actual + len(chunk) < total else None
        omitted_bytes = actual - requested
        warnings: list[str] = []
        if omitted_bytes:
            warnings.append(f"{selected} offset skipped dropped bytes")
        if gap:
            warnings.append(
                f"{selected} output between the retained head and the rolling tail was evicted; "
                "redirect large output to a file (cmd > out.log 2>&1) to keep everything"
            )
        result: dict[str, Any] = {
            "ok": True,
            **lifecycle,
            "output_ref": output_ref,
            "stream_output_ref": f"command:{command.command_id}:{selected}",
            "stream": selected,
            "offset": actual,
            "requested_offset": requested,
            "limit": limit,
            "content": chunk.decode("utf-8", errors="replace"),
            "next_offset": next_offset,
            "total_retained_bytes": len(tail) + min(head_len, tail_start),
            "head_retained_bytes": head_len,
            "evicted_gap_bytes": gap,
            "retained_start_offset": tail_start,
            "total_stream_bytes": total,
            "stdout_dropped_bytes": command.stdout_dropped_bytes,
            "stderr_dropped_bytes": command.stderr_dropped_bytes,
            "stream_dropped_bytes": dropped,
            "omitted_bytes": omitted_bytes,
            "truncated": next_offset is not None,
            "warnings": warnings,
        }
        if next_offset is not None:
            result["next_action"] = {
                "tool": "read_output",
                "arguments": {"output_ref": output_ref, "offset": next_offset, "limit": limit},
            }
        return result

    def close(self) -> None:
        with self.lock:
            self.closed = True
            active = list(self.active.values())
        for command in active:
            command.request_termination(signal.SIGTERM, source="parent_shutdown")

    def _get(self, command_id: str, *, stdin: bool) -> CommandRun:
        self._prune()
        with self.lock:
            command = self.active.get(command_id) or self.retained.get(command_id)
        if command is None:
            raise ReCTMError(
                "COMMAND_NOT_FOUND",
                "Command not found; stdin access denied." if stdin else "Output command not found.",
                category="not_found",
            )
        return command

    def _prune(self) -> None:
        with self.lock:
            active = list(self.active.values())
        for command in active:
            command.refresh_status()
            if command.process.poll() is not None:
                with self.lock:
                    self.active.pop(command.command_id, None)
                    self.retained[command.command_id] = command
        cutoff = time.time() - COMPLETED_COMMAND_TTL_SECONDS
        with self.lock:
            expired = [
                command_id
                for command_id, command in self.retained.items()
                if command.completed_at is not None and command.completed_at < cutoff
            ]
            for command_id in expired:
                self.retained.pop(command_id, None)
            while len(self.retained) > MAX_RETAINED_COMMANDS:
                self.retained.popitem(last=False)

    def _format(
        self,
        command: CommandRun,
        payload: dict[str, Any],
        *,
        verbosity: str | None,
        preview_bytes: int,
    ) -> dict[str, Any]:
        terminal = payload.get("operation_outcome") != "running"
        if terminal:
            with self.lock:
                self.active.pop(command.command_id, None)
                self.retained[command.command_id] = command
        else:
            payload["next_action"] = {
                "tool": "write_stdin",
                "arguments": {"command_id": command.command_id, "chars": "", "yield_time_ms": 10000},
            }
        refs = {
            "stdout": f"command:{command.command_id}:stdout",
            "stderr": f"command:{command.command_id}:stderr",
        }
        payload["output_refs"] = refs
        payload["output_ref"] = refs["stderr"] if not payload.get("stdout") and payload.get("stderr") else refs["stdout"]
        selected = (verbosity or "").strip().lower()
        if selected and selected not in {"summary", "preview", "full"}:
            raise invalid_argument("verbosity must be summary, preview, or full")
        if selected in {"summary", "preview"}:
            compact = {
                key: value
                for key, value in payload.items()
                if key not in {"stdout", "stderr"}
            }
            compact["summary"] = _summary(command, payload)
            if selected == "preview":
                combined = _combined_output(command)
                preview, truncated = _tail_text(combined, max(1, preview_bytes))
                compact["preview"] = preview
                compact["preview_truncated"] = truncated
            return compact
        return payload

    def _start_watchdog(self, command: CommandRun) -> None:
        if command.timeout_at is None:
            return

        def watchdog() -> None:
            delay = max(0.0, command.timeout_at - time.time())
            try:
                command.process.wait(timeout=delay)
            except subprocess.TimeoutExpired:
                command.request_termination(signal.SIGTERM, source="command_timeout")
            command.refresh_status()

        threading.Thread(target=watchdog, daemon=True).start()


def _combined_output(command: CommandRun) -> bytes:
    with command.lock:
        stdout = bytes(command.stdout)
        stderr = bytes(command.stderr)
    pieces: list[bytes] = []
    if stdout:
        pieces += [b"--- stdout ---\n", stdout]
    if stderr:
        if pieces:
            pieces.append(b"\n")
        pieces += [b"--- stderr ---\n", stderr]
    return b"".join(pieces)


def _summary(command: CommandRun, payload: dict[str, Any]) -> str:
    text = _combined_output(command).decode("utf-8", errors="replace")
    lines = text.splitlines()
    tail = next((line.strip() for line in reversed(lines) if line.strip()), "")[:120]
    elapsed = float(payload.get("elapsed_ms") or 0) / 1000.0
    status = (
        f"exit {payload.get('exit_code')}"
        if payload.get("exit_code") is not None
        else str(payload.get("status", "running"))
    )
    return " | ".join(part for part in (status, f"{elapsed:.1f}s", f"{len(lines)} lines", f"tail: {tail!r}" if tail else "") if part)


def _tail_text(data: bytes, max_bytes: int) -> tuple[str, bool]:
    if len(data) <= max_bytes:
        return data.decode("utf-8", errors="replace"), False
    return data[-max_bytes:].decode("utf-8", errors="replace"), True
