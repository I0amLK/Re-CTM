from __future__ import annotations

import queue
import sys
import threading
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from .debug import DebugEvent


_VISIBLE_EVENTS = frozenset(
    {
        "tool.call_started",
        "tool.call_finished",
        "tool.call_failed",
        "oauth.authorization_code_issued",
        "oauth.access_token_issued",
        "oauth.access_token_accepted",
        "oauth.external_origin_resolved",
    }
)
_STOP = object()


class TerminalSession:
    """Append-only, non-blocking terminal observer for an interactive server."""

    def __init__(self, *, stream: TextIO | None = None, queue_size: int = 256) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be positive")
        self.stream = stream or sys.stderr
        self._queue: queue.Queue[DebugEvent | object] = queue.Queue(maxsize=queue_size)
        self._thread: threading.Thread | None = None
        self._started = threading.Event()
        self._stopping = threading.Event()
        self._output_failed = threading.Event()
        self._write_lock = threading.Lock()
        self._drop_lock = threading.Lock()
        self._dropped = 0
        self._oauth_state = ""
        self._resolved_origin = ""

    def observe(self, event: DebugEvent) -> None:
        """Accept one already-redacted event without blocking the producer."""

        if (
            event.event_type not in _VISIBLE_EVENTS
            or not self._started.is_set()
            or self._stopping.is_set()
            or self._output_failed.is_set()
        ):
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._drop_lock:
                self._dropped += 1

    def start(
        self,
        *,
        version: str,
        workspace: Path,
        mcp_url: str,
        generated_oauth_key: str | None,
    ) -> None:
        if self._started.is_set() or self._stopping.is_set():
            return
        key_display = generated_oauth_key or "configured externally"
        self._safe_write(
            "\n".join(
                (
                    f"Re-CTM { _terminal_text(version) }",
                    "-" * 60,
                    f"Workspace      {_terminal_text(str(workspace))}",
                    f"MCP URL        {_terminal_text(mcp_url)}",
                    f"OAuth key      {_terminal_text(key_display)}",
                    "OAuth status   waiting for authorization",
                    "-" * 60,
                )
            )
            + "\n"
        )
        if self._output_failed.is_set():
            return
        self._oauth_state = "waiting for authorization"
        self._resolved_origin = mcp_url[:-4] if mcp_url.endswith("/mcp") else ""
        self._started.set()
        self._thread = threading.Thread(
            target=self._run,
            name="re-ctm-terminal-ui",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        if not self._started.is_set() or self._stopping.is_set():
            return
        self._stopping.set()
        try:
            self._queue.put_nowait(_STOP)
        except queue.Full:
            pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout=0.2)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                break
            assert isinstance(item, DebugEvent)
            self._report_dropped()
            self._render_event(item)
            if self._stopping.is_set() and self._queue.empty():
                break

    def _render_event(self, event: DebugEvent) -> None:
        event_type = event.event_type
        if event_type.startswith("tool.call_"):
            self._render_tool_event(event)
            return
        if event_type == "oauth.authorization_code_issued":
            self._set_oauth_state("authorization accepted")
            return
        if event_type == "oauth.access_token_issued":
            self._set_oauth_state("token issued")
            return
        if event_type == "oauth.access_token_accepted":
            self._set_oauth_state("connected")
            return
        if event_type == "oauth.external_origin_resolved":
            base_url = event.details.get("base_url")
            if isinstance(base_url, str) and base_url and base_url != self._resolved_origin:
                self._resolved_origin = base_url
                self._safe_write(
                    f"{_time_label(event)}  MCP URL        "
                    f"{_terminal_text(base_url.rstrip('/') + '/mcp')}\n"
                )

    def _render_tool_event(self, event: DebugEvent) -> None:
        tool = event.details.get("tool")
        if not isinstance(tool, str) or not tool:
            return
        trace = _trace_label(event.trace_id)
        if event.event_type == "tool.call_started":
            marker = ">"
            suffix = ""
        elif event.event_type == "tool.call_finished":
            marker = "OK"
            suffix = ""
        else:
            marker = "ERR"
            code = _error_code(event.details.get("error"))
            suffix = f"  {code}" if code else ""
        self._safe_write(
            f"{_time_label(event)}  {marker:<3} [{trace}] "
            f"{_terminal_text(tool)}{_terminal_text(suffix)}\n"
        )

    def _set_oauth_state(self, state: str) -> None:
        if state == self._oauth_state:
            return
        self._oauth_state = state
        self._safe_write(f"OAuth status   {_terminal_text(state)}\n")

    def _report_dropped(self) -> None:
        with self._drop_lock:
            dropped = self._dropped
            self._dropped = 0
        if dropped:
            self._safe_write(f"[{dropped} terminal display event(s) dropped]\n")

    def _safe_write(self, text: str) -> None:
        if self._output_failed.is_set():
            return
        try:
            with self._write_lock:
                self.stream.write(text)
                self.stream.flush()
        except Exception:
            self._output_failed.set()


def _error_code(value: object) -> str:
    if not isinstance(value, Mapping):
        return ""
    code = value.get("code")
    return code if isinstance(code, str) else ""


def _time_label(event: DebugEvent) -> str:
    timestamp = event.timestamp
    return timestamp[11:19] if len(timestamp) >= 19 and timestamp[10:11] == "T" else "--:--:--"


def _trace_label(trace_id: str) -> str:
    return _terminal_text(trace_id[-6:] if len(trace_id) > 6 else trace_id)


def _terminal_text(value: str) -> str:
    return "".join(
        character if unicodedata.category(character)[0] != "C" else "?"
        for character in value
    )
