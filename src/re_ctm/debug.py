from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


_SENSITIVE_KEY = re.compile(
    r"(token|secret|password|authorization|credential|api[_-]?key|code_verifier|code_challenge)",
    re.I,
)
_SENSITIVE_VALUE = re.compile(
    r"(Bearer\s+[A-Za-z0-9._~+/=-]+|sk-[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.I,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00",
        "Z",
    )


def new_trace_id() -> str:
    return "tr_" + secrets.token_urlsafe(12)


def token_fingerprint(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()[:12]


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            result[text_key] = "<redacted>" if _SENSITIVE_KEY.search(text_key) else redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}:{token_fingerprint(value)}>"
    if isinstance(value, str):
        return _SENSITIVE_VALUE.sub("<redacted>", value)
    return value


@dataclass(frozen=True)
class DebugEvent:
    timestamp: str
    trace_id: str
    event_type: str
    component: str
    run_id: str | None = None
    actor_role: str | None = None
    domain_id: str | None = None
    before_state: str | None = None
    after_state: str | None = None
    decision: str | None = None
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class DebugEventBus:
    """Thread-safe, redacted JSONL event sink with per-run mirrors."""

    def __init__(
        self,
        global_path: Path,
        private_root: Path,
        *,
        enabled: bool = True,
        trace_payloads: bool = False,
    ) -> None:
        self.global_path = global_path
        self.private_root = private_root
        self.enabled = enabled
        self.trace_payloads = trace_payloads
        self._lock = threading.Lock()

    def emit(
        self,
        event_type: str,
        component: str,
        *,
        trace_id: str | None = None,
        run_id: str | None = None,
        actor_role: str | None = None,
        domain_id: str | None = None,
        before_state: str | None = None,
        after_state: str | None = None,
        decision: str | None = None,
        reason: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> str:
        resolved_trace = trace_id or new_trace_id()
        if not self.enabled:
            return resolved_trace
        safe_details = redact(dict(details or {}))
        if not self.trace_payloads and "payload" in safe_details:
            payload = safe_details.pop("payload")
            safe_details["payload_summary"] = _payload_summary(payload)
        event = DebugEvent(
            timestamp=utc_now(),
            trace_id=resolved_trace,
            event_type=event_type,
            component=component,
            run_id=run_id,
            actor_role=actor_role,
            domain_id=domain_id,
            before_state=before_state,
            after_state=after_state,
            decision=decision,
            reason=reason,
            details=safe_details,
        )
        line = json.dumps(asdict(event), ensure_ascii=False, sort_keys=True) + "\n"
        with self._lock:
            _append_line(self.global_path, line)
            if run_id:
                _append_line(
                    self.private_root / "runs" / run_id / "debug" / "events.jsonl",
                    line,
                )
        return resolved_trace

    def write_state_snapshot(
        self,
        run_id: str,
        sequence: int,
        payload: Mapping[str, Any],
    ) -> Path:
        target = (
            self.private_root
            / "runs"
            / run_id
            / "debug"
            / "state"
            / f"{sequence:08d}.json"
        )
        _atomic_json(target, redact(dict(payload)))
        return target

    def write_last_error(
        self,
        run_id: str,
        payload: Mapping[str, Any],
    ) -> Path:
        target = self.private_root / "runs" / run_id / "debug" / "last_error.json"
        _atomic_json(target, redact(dict(payload)))
        return target


def _append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    temp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temp, path)


def _payload_summary(payload: Any) -> dict[str, Any]:
    if isinstance(payload, Mapping):
        return {"type": "object", "keys": sorted(str(key) for key in payload)[:50]}
    if isinstance(payload, (list, tuple)):
        return {"type": "array", "length": len(payload)}
    if isinstance(payload, str):
        return {"type": "string", "length": len(payload)}
    return {"type": type(payload).__name__}
