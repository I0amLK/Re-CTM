"""Bounded, caller-scoped Native write replay, never workflow authority.

Receipts are historical evidence within one runtime instance, not a crash journal.
Pending and uncertain writes cannot be evicted into permission to run again.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .errors import ReCTMError, invalid_argument

CAPACITY = 64
MAX_RESULT_BYTES = 1_048_576


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise invalid_argument("Native arguments must contain valid JSON values") from exc


def validate_key(key: Any) -> str:
    if not isinstance(key, str) or not key or "\0" in key:
        raise invalid_argument("idempotency_key must contain 1..128 UTF-8 bytes without NUL")
    try:
        size = len(key.encode("utf-8"))
    except UnicodeError as exc:
        raise invalid_argument("idempotency_key must be valid UTF-8") from exc
    if size > 128:
        raise invalid_argument("idempotency_key must contain 1..128 UTF-8 bytes without NUL")
    return key


@dataclass
class _Entry:
    fingerprint: str
    state: str = "pending"
    result: dict[str, Any] | None = None


class NativeReplay:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, _Entry] = OrderedDict()

    def execute(
        self, principal_scope: Mapping[str, Any] | None, tool: str,
        arguments: Mapping[str, Any], operation: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        if tool not in {"apply_patch", "apply_changes"} or "idempotency_key" not in arguments:
            return operation()
        key = validate_key(arguments["idempotency_key"])
        if not isinstance(principal_scope, Mapping) or any(
            not isinstance(principal_scope.get(name), str) or not principal_scope[name]
            for name in ("subject", "client_id", "scope")
        ):
            raise ReCTMError(
                "NATIVE_REPLAY_SCOPE_REQUIRED", "Keyed writes require an authenticated caller scope.",
                category="security",
            )
        scope = {name: principal_scope[name] for name in ("subject", "client_id", "scope")}
        slot = hashlib.sha256(canonical_bytes([scope, tool, key])).hexdigest()
        work = {name: value for name, value in arguments.items() if name != "idempotency_key"}
        fingerprint = hashlib.sha256(canonical_bytes(work)).hexdigest()
        dry_run = arguments.get("dry_run") is True
        with self._lock:
            entry = self._entries.get(slot)
            if entry is not None:
                if entry.fingerprint != fingerprint:
                    raise ReCTMError(
                        "IDEMPOTENCY_KEY_REUSED", "Key is bound to different arguments.",
                        category="conflict",
                    )
                if entry.state == "pending":
                    raise ReCTMError(
                        "NATIVE_WRITE_IN_PROGRESS", "The original keyed write is still in progress.",
                        category="conflict", retryable=True,
                    )
                if entry.state == "unknown":
                    raise ReCTMError(
                        "NATIVE_WRITE_RESULT_UNKNOWN",
                        "Write outcome is uncertain. Inspect and reconcile files; a fresh key or restart does not make retry safe.",
                        category="conflict",
                    )
                self._entries.move_to_end(slot)
                return {**copy.deepcopy(entry.result), "idempotent_replay": True}
            if not dry_run:
                if len(self._entries) >= CAPACITY:
                    removable = next((name for name, value in self._entries.items()
                                      if value.state == "complete"), None)
                    if removable is None:
                        raise ReCTMError(
                            "NATIVE_REPLAY_LIMIT", "Replay capacity is occupied by active or unresolved writes.",
                            category="conflict", retryable=True,
                        )
                    del self._entries[removable]
                self._entries[slot] = _Entry(fingerprint)
        if dry_run:
            return operation()
        # Never hold this lock across filesystem work or the transaction lock.
        try:
            result = operation()
        except BaseException as exc:
            with self._lock:
                if isinstance(exc, ReCTMError) and exc.category not in {"runtime", "internal"}:
                    del self._entries[slot]
                else:
                    self._entries[slot].state = "unknown"
            raise
        with self._lock:
            entry = self._entries[slot]
            try:
                cacheable = (isinstance(result, dict) and result.get("ok") is not False
                             and len(canonical_bytes(result)) <= MAX_RESULT_BYTES)
            except ReCTMError:
                cacheable = False
            if cacheable:
                entry.result = copy.deepcopy(result)
                entry.state = "complete"
            else:
                entry.state = "unknown"
        return result
