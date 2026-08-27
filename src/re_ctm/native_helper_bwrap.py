from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Mapping


PROTOCOL = "re-ctm-native-helper-v1"
MAX_REQUEST_BYTES = 1_048_576
MAX_ARG_COUNT = 512
MAX_ARG_BYTES = 256 * 1024
MAX_CAPTURE_BYTES = 1_048_576
CAPTURE_HEAD_BYTES = 65_536
SUPPORTED_MODES = {"safe", "trusted", "dangerous"}
SYSTEM_READ_ROOTS = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/var/lib/texmf",
    "/var/cache/fontconfig",
    "/var/cache/fonts",
)


class HelperError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        category: str = "validation",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.category = category
        self.details = dict(details or {})
        super().__init__(message)


@dataclass
class BoundedCapture:
    limit: int = MAX_CAPTURE_BYTES
    head_limit: int = CAPTURE_HEAD_BYTES
    head: bytearray = field(default_factory=bytearray)
    tail: bytearray = field(default_factory=bytearray)
    total_bytes: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def append(self, chunk: bytes) -> None:
        with self._lock:
            self.total_bytes += len(chunk)
            remaining_head = max(0, self.head_limit - len(self.head))
            if remaining_head:
                self.head.extend(chunk[:remaining_head])
                chunk = chunk[remaining_head:]
            if not chunk:
                return
            tail_limit = max(0, self.limit - self.head_limit)
            if tail_limit == 0:
                return
            self.tail.extend(chunk)
            if len(self.tail) > tail_limit:
                del self.tail[: len(self.tail) - tail_limit]

    def payload(self) -> dict[str, Any]:
        retained = bytes(self.head + self.tail)
        retained_bytes = len(retained)
        return {
            "text": retained.decode("utf-8", errors="replace"),
            "total_bytes": self.total_bytes,
            "retained_bytes": retained_bytes,
            "dropped_bytes": max(0, self.total_bytes - retained_bytes),
            "truncated": self.total_bytes > retained_bytes,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="re-ctm-native-helper",
        description="Bubblewrap hard-isolation helper for Re-CTM native argv execution.",
    )
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print(json.dumps({"protocol": PROTOCOL, "backend": "bubblewrap", "version": "1"}))
        return 0

    request_id: str | None = None
    operation: str | None = None
    try:
        request = _read_request()
        request_id = _required_text(request, "request_id", maximum=256)
        operation = _required_text(request, "operation", maximum=32)
        if operation == "attest":
            response = _attest(request)
        elif operation == "execute":
            response = _execute(request)
        else:
            raise HelperError(
                "NATIVE_HELPER_OPERATION_UNSUPPORTED",
                "operation must be attest or execute",
            )
        _write_response(response)
        return 0
    except HelperError as exc:
        _write_response(
            {
                "protocol": PROTOCOL,
                "operation": operation,
                "request_id": request_id,
                "ok": False,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "category": exc.category,
                    "details": exc.details,
                },
            }
        )
        return 1
    except Exception as exc:  # noqa: BLE001 - helper boundary must stay structured
        _write_response(
            {
                "protocol": PROTOCOL,
                "operation": operation,
                "request_id": request_id,
                "ok": False,
                "error": {
                    "code": "NATIVE_HELPER_INTERNAL_ERROR",
                    "message": str(exc),
                    "category": "internal",
                    "details": {"exception_type": type(exc).__name__},
                },
            }
        )
        return 1


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise HelperError(
            "NATIVE_HELPER_REQUEST_TOO_LARGE",
            "helper request exceeded the maximum size",
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HelperError(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "helper request must be one UTF-8 JSON object",
        ) from exc
    if not isinstance(payload, dict) or payload.get("protocol") != PROTOCOL:
        raise HelperError(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            "unsupported helper protocol",
        )
    return payload


def _write_response(payload: Mapping[str, Any]) -> None:
    sys.stdout.write(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")
    sys.stdout.flush()


def _attest(request: Mapping[str, Any]) -> dict[str, Any]:
    request_id = _required_text(request, "request_id", maximum=256)
    workspace = _workspace(request)
    mode = _mode(request)
    raw_forbidden = request.get("forbidden_paths") or []
    if not isinstance(raw_forbidden, list) or not all(
        isinstance(item, str) for item in raw_forbidden
    ):
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "forbidden_paths must be an array of absolute paths",
        )
    forbidden_paths: list[str] = []
    for raw_path in raw_forbidden:
        path = Path(raw_path).expanduser().resolve(strict=False)
        if not path.is_absolute():
            raise HelperError(
                "NATIVE_HELPER_INVALID_ARGUMENT",
                "forbidden_paths entries must be absolute",
            )
        if path.is_relative_to(workspace) or workspace.is_relative_to(path):
            raise HelperError(
                "NATIVE_HELPER_TRUST_DOMAIN_OVERLAP",
                "workspace and forbidden path must not overlap",
                category="security",
            )
        forbidden_paths.append(str(path))

    probe_name = f".re-ctm-attest-{request_id[:12]}"
    probe_script = (
        "import json,os,sys;"
        "paths=json.loads(sys.argv[1]);"
        "probe=sys.argv[2];"
        "result={'workspace_mounted':os.path.isdir('/workspace'),"
        "'forbidden_visible':[p for p in paths if os.path.lexists(p)],"
        "'parent_secret_visible':bool(os.environ.get('RE_CTM_ATTEST_PARENT_SECRET')),"
        "'no_new_privs':None,'workspace_writable':False};"
        "status=open('/proc/self/status',encoding='utf-8').read();"
        "result['no_new_privs']=('NoNewPrivs:\\t1' in status);"
        "target='/workspace/'+probe;"
        "open(target,'w',encoding='utf-8').write('ok');"
        "result['workspace_writable']=os.path.isfile(target);"
        "os.unlink(target);"
        "print(json.dumps(result,sort_keys=True))"
    )
    parent_env = _helper_child_env()
    parent_env["RE_CTM_ATTEST_PARENT_SECRET"] = "must-not-enter-sandbox"
    result = _run_in_sandbox(
        workspace=workspace,
        argv=["/usr/bin/python3", "-c", probe_script, json.dumps(forbidden_paths), probe_name],
        workdir=".",
        timeout_ms=15_000,
        mode=mode,
        parent_env=parent_env,
    )
    if result["exit_code"] != 0:
        raise HelperError(
            "NATIVE_HELPER_ATTESTATION_FAILED",
            "bubblewrap attestation probe did not exit successfully",
            category="security",
            details={"exit_code": result["exit_code"], "stderr": result["stderr"]["text"][-2000:]},
        )
    try:
        probe = json.loads(result["stdout"]["text"].strip())
    except json.JSONDecodeError as exc:
        raise HelperError(
            "NATIVE_HELPER_ATTESTATION_FAILED",
            "bubblewrap attestation probe returned invalid JSON",
            category="security",
        ) from exc
    if not isinstance(probe, Mapping):
        raise HelperError(
            "NATIVE_HELPER_ATTESTATION_FAILED",
            "bubblewrap attestation probe returned an invalid object",
            category="security",
        )
    forbidden_visible = probe.get("forbidden_visible")
    forbidden_hidden = isinstance(forbidden_visible, list) and not forbidden_visible
    if (
        probe.get("workspace_mounted") is not True
        or probe.get("workspace_writable") is not True
        or probe.get("parent_secret_visible") is not False
        or probe.get("no_new_privs") is not True
        or not forbidden_hidden
    ):
        raise HelperError(
            "NATIVE_HELPER_ATTESTATION_FAILED",
            "bubblewrap probe did not prove the required isolation properties",
            category="security",
            details={
                "workspace_mounted": probe.get("workspace_mounted"),
                "workspace_writable": probe.get("workspace_writable"),
                "parent_secret_visible": probe.get("parent_secret_visible"),
                "no_new_privs": probe.get("no_new_privs"),
                "forbidden_visible_count": len(forbidden_visible)
                if isinstance(forbidden_visible, list)
                else None,
            },
        )
    attestation = _attestation(mode=mode, forbidden_paths_hidden=True)
    return {
        "protocol": PROTOCOL,
        "operation": "attest",
        "request_id": request_id,
        "ok": True,
        "attestation": attestation,
        "probe": {
            "workspace_writable": True,
            "parent_environment_cleared": True,
            "forbidden_path_count": len(forbidden_paths),
        },
    }


def _execute(request: Mapping[str, Any]) -> dict[str, Any]:
    request_id = _required_text(request, "request_id", maximum=256)
    workspace = _workspace(request)
    mode = _mode(request)
    argv = request.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "argv must be a non-empty array of strings",
        )
    if len(argv) > MAX_ARG_COUNT or sum(len(item.encode("utf-8")) for item in argv) > MAX_ARG_BYTES:
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "argv exceeded the helper size limit",
        )
    if any("\x00" in item for item in argv):
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "argv must not contain NUL bytes",
        )
    workdir = _relative_workdir(str(request.get("workdir") or "."), workspace)
    try:
        timeout_ms = int(request.get("timeout_ms", 30_000))
    except (TypeError, ValueError) as exc:
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "timeout_ms must be an integer",
        ) from exc
    if not 1 <= timeout_ms <= 600_000:
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "timeout_ms must be between 1 and 600000",
        )
    result = _run_in_sandbox(
        workspace=workspace,
        argv=list(argv),
        workdir=workdir,
        timeout_ms=timeout_ms,
        mode=mode,
        parent_env=_helper_child_env(),
    )
    return {
        "protocol": PROTOCOL,
        "operation": "execute",
        "request_id": request_id,
        "ok": True,
        "status": result["status"],
        "exit_code": result["exit_code"],
        "signal": result["signal"],
        "timed_out": result["timed_out"],
        "elapsed_ms": result["elapsed_ms"],
        "stdout": result["stdout"]["text"],
        "stderr": result["stderr"]["text"],
        "stdout_meta": {key: value for key, value in result["stdout"].items() if key != "text"},
        "stderr_meta": {key: value for key, value in result["stderr"].items() if key != "text"},
        "attestation": _attestation(mode=mode, forbidden_paths_hidden=True),
    }


def _run_in_sandbox(
    *,
    workspace: Path,
    argv: list[str],
    workdir: str,
    timeout_ms: int,
    mode: str,
    parent_env: Mapping[str, str],
) -> dict[str, Any]:
    command = _bubblewrap_command(
        workspace=workspace,
        workdir=workdir,
        mode=mode,
        argv=argv,
    )
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(parent_env),
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_capture = BoundedCapture()
    stderr_capture = BoundedCapture()
    threads = [
        threading.Thread(
            target=_drain,
            args=(process.stdout, stdout_capture),
            daemon=True,
        ),
        threading.Thread(
            target=_drain,
            args=(process.stderr, stderr_capture),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        return_code = process.wait(timeout=timeout_ms / 1000)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            return_code = process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return_code = process.wait(timeout=5.0)
    finally:
        for thread in threads:
            thread.join(timeout=2.0)
    signal_name = None
    if return_code < 0:
        try:
            signal_name = signal.Signals(-return_code).name
        except ValueError:
            signal_name = str(-return_code)
    return {
        "status": "timeout" if timed_out else "exited",
        "exit_code": return_code if return_code >= 0 else None,
        "signal": signal_name,
        "timed_out": timed_out,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "stdout": stdout_capture.payload(),
        "stderr": stderr_capture.payload(),
    }


def _drain(stream: BinaryIO, capture: BoundedCapture) -> None:
    try:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            capture.append(chunk)
    finally:
        stream.close()


def _bubblewrap_command(
    *,
    workspace: Path,
    workdir: str,
    mode: str,
    argv: list[str],
) -> list[str]:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise HelperError(
            "NATIVE_BWRAP_NOT_FOUND",
            "bubblewrap is required for the built-in native isolation backend",
            category="security",
        )
    command = [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--uid",
        "0",
        "--gid",
        "0",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--disable-userns",
        "--hostname",
        "re-ctm-native",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "--setenv",
        "HOME",
        "/home/re-ctm",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--cap-drop",
        "ALL",
    ]
    if mode == "safe":
        command.append("--unshare-net")
    for root in SYSTEM_READ_ROOTS:
        if Path(root).exists():
            command.extend(["--ro-bind", root, root])
    command.extend(
        [
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/home",
            "--dir",
            "/home/re-ctm",
            "--bind",
            str(workspace),
            "/workspace",
            "--chdir",
            "/workspace" if workdir == "." else f"/workspace/{workdir}",
            "--",
            *argv,
        ]
    )
    return command


def _attestation(*, mode: str, forbidden_paths_hidden: bool) -> dict[str, Any]:
    bwrap = shutil.which("bwrap")
    version = "unknown"
    if bwrap is not None:
        try:
            completed = subprocess.run(
                [bwrap, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
                check=False,
            )
            version = completed.stdout.strip()[:200] or "unknown"
        except (OSError, subprocess.SubprocessError):
            pass
    return {
        "backend": "bubblewrap",
        "backend_version": version,
        "hard_isolation": True,
        "workspace_mounted": True,
        "workspace_mount": "/workspace",
        "forbidden_paths_hidden": forbidden_paths_hidden,
        "private_vault_mounted": False,
        "network_isolated": mode == "safe",
        "no_privilege_escalation": True,
        "mount_namespace": True,
        "user_namespace": True,
        "pid_namespace": True,
        "ipc_namespace": True,
        "uts_namespace": True,
        "nested_user_namespaces_disabled": True,
        "parent_environment_cleared": True,
        "capabilities_dropped": True,
    }


def _workspace(request: Mapping[str, Any]) -> Path:
    raw = _required_text(request, "workspace", maximum=4096)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workspace must be absolute",
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workspace does not exist",
        ) from exc
    if not resolved.is_dir() or resolved in {Path("/").resolve(), Path.home().resolve()}:
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workspace must be a safe directory",
        )
    return resolved


def _mode(request: Mapping[str, Any]) -> str:
    mode = _required_text(request, "mode", maximum=32)
    if mode not in SUPPORTED_MODES:
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "mode must be safe, trusted, or dangerous",
        )
    return mode


def _relative_workdir(raw: str, workspace: Path) -> str:
    if not raw or "\x00" in raw or raw.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", raw):
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workdir must be a workspace-relative path",
        )
    pure = PurePosixPath(raw)
    if any(part == ".." for part in pure.parts):
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workdir must not escape the workspace",
        )
    relative = pure.as_posix()
    target = workspace.joinpath(*pure.parts).resolve(strict=True)
    if not target.is_relative_to(workspace) or not target.is_dir():
        raise HelperError(
            "NATIVE_HELPER_INVALID_ARGUMENT",
            "workdir must resolve to a directory inside the workspace",
        )
    return relative


def _required_text(
    payload: Mapping[str, Any],
    key: str,
    *,
    maximum: int,
) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise HelperError(
            "NATIVE_HELPER_PROTOCOL_ERROR",
            f"{key} must be a non-empty string of at most {maximum} characters",
        )
    return value


def _helper_child_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in ("PATH", "LANG", "LC_ALL", "LC_CTYPE"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


if __name__ == "__main__":
    raise SystemExit(main())
