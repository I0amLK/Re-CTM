"""Prepare action facts before effects, then certify them atomically.

Action sidecars contain binding digests and file hashes, never caller bodies.
Recovery may retire interrupted actions; it never runs them. A later authorized
correction may reuse only byte-identical effects under the same input binding.
"""
from __future__ import annotations
import contextvars
import hashlib
import json
from typing import Any, Mapping
from .debug import utc_now
from .errors import ReCTMError
from .storage_receipts import ATOMIC_ACTION_STATES, RESTARTABLE_ACTION_STATES, canonical
from .vault_effects import PreparedFiles, image, lock_run, publish, read_regular

_current: contextvars.ContextVar["PreparedAction | None"] = contextvars.ContextVar("workflow_action", default=None)


def active(engine: Any) -> "PreparedAction | None":
    value = _current.get()
    return value if value is not None and value.engine is engine else None


class PreparedAction:
    def __init__(self, engine: Any, run: Mapping[str, Any], claims: Any, action: str, payload: Mapping[str, Any], trace: str) -> None:
        self.engine, self.run, self.claims, self.action, self.trace = engine, run, claims, action, trace
        self.updates: dict[str, Any] = {}
        self.project_mode = None
        self.branch = None
        self.transition = None
        self.files = PreparedFiles(engine.vault.run_root(claims.run_id))
        binding = {"version": "re-ctm-action-effect-v1", "run_id": claims.run_id, "domain_id": claims.domain_id,
                   "role": claims.role.value, "epoch": claims.epoch, "state": claims.issued_state.value,
                   "action": action, "payload": dict(payload)}
        self.key = hashlib.sha256(canonical(binding).encode()).hexdigest()
        scope = {key: value for key, value in binding.items() if key != "payload"}
        self.scope = hashlib.sha256(canonical(scope).encode()).hexdigest()
        self.sidecar = self.files.root / "debug" / "state" / ("action-" + self.scope[:32] + "-" + self.key[:32] + ".json")
        candidates = list(self.sidecar.parent.glob("action-" + self.scope[:32] + "-*.json"))
        if len(candidates) > 4096:
            raise ReCTMError("ACTION_EFFECT_LIMIT", "Action evidence scope exceeds its bound.", category="conflict", retryable=False)
        for candidate in candidates:
            raw_candidate = read_regular(candidate)
            if raw_candidate is None or len(raw_candidate) > 65536:
                raise ReCTMError("ACTION_EFFECT_CONFLICT", "Action evidence cannot be read safely.", category="conflict", retryable=False)
            previous = json.loads(raw_candidate)
            if previous.get("scope") != self.scope:
                raise ReCTMError("ACTION_EFFECT_CONFLICT", "Action scope evidence disagrees.", category="conflict", retryable=False)
            if previous.get("binding") != self.key:
                receipt = engine.store.submission_for_execution(previous["execution_id"])
                if (receipt is None and (previous.get("receipted", True) or bool(previous.get("effects")))) or (receipt is not None and (receipt["result"] is None or receipt["result"]["disposition"] != "applied")):
                    raise ReCTMError("ACTION_EFFECT_CONFLICT", "Interrupted action effects may only be reused with their exact original input.", category="conflict", retryable=False)
        raw = read_regular(self.sidecar)
        self.prior = json.loads(raw) if raw is not None else None
        if self.prior is not None and (not isinstance(self.prior, dict) or self.prior.get("binding") != self.key):
            raise ReCTMError("ACTION_EFFECT_CONFLICT", "Action evidence is inconsistent.", category="conflict", retryable=False)
        self.created_at = self.prior["created_at"] if self.prior else utc_now()
        self.stamp_index = 0

    def stamp(self) -> tuple[str, str]:
        self.stamp_index += 1
        return "research-" + hashlib.sha256(f"{self.key}:{self.stamp_index}".encode()).hexdigest()[:24], self.created_at

    def apply_files(self) -> None:
        prior = {entry["relative_path"]: entry for entry in self.prior["effects"]} if self.prior else {}
        effects = []
        for path, (before, after) in list(self.files.effects.items()):
            relative = path.relative_to(self.files.root).as_posix()
            expected = prior.get(relative)
            if expected is not None and image(before) == expected["after"]:
                # Re-preparing append actions sees the already-installed bytes.
                # Only the exact suffix and proven original prefix may be reused.
                if after.startswith(before or b"") and after != before:
                    suffix = after[len(before or b""):]
                    original = before[:-len(suffix)] if before is not None and suffix and before.endswith(suffix) else None
                    if original == b"" and expected["before"] is None:
                        original = None
                    if image(original) == expected["before"]:
                        self.files.effects[path] = original, before
                elif image(after) == expected["after"]:
                    # Replacement output is already exactly installed.
                    self.files.effects[path] = before, after
                candidate = self.files.evidence(path)
                if candidate["after"] != expected["after"]:
                    raise ReCTMError("ACTION_EFFECT_CONFLICT", "Retained action bytes differ from this submission.", category="conflict", retryable=False)
                effects.append(expected)
            else:
                candidate = self.files.evidence(path)
                if expected is not None and candidate != expected:
                    raise ReCTMError("ACTION_EFFECT_CONFLICT", "Retained action evidence conflicts.", category="conflict", retryable=False)
                effects.append(candidate)
        evidence = {"version": 1, "binding": self.key, "scope": self.scope,
                    "execution_id": self.prior["execution_id"] if self.prior else self.trace,
                    "receipted": self.prior.get("receipted", True) if self.prior else self.engine.store.submission_for_execution(self.trace) is not None,
                    "created_at": self.created_at, "effects": effects}
        if self.prior is not None and set(prior) != {entry["relative_path"] for entry in effects}:
            raise ReCTMError("ACTION_EFFECT_CONFLICT", "Retained action effect set differs.", category="conflict", retryable=False)
        encoded = canonical(evidence).encode()
        if len(encoded) > 65536:
            raise ReCTMError("ACTION_EFFECT_LIMIT", "Action evidence exceeds its bound.", category="conflict", retryable=False)
        # Enrollment precedes any action sidecar/file effect.
        self.engine.store.enroll_restartable_action(self.claims, self.trace, self.action)
        publish(self.sidecar, encoded, exact=True)
        for path, (_, after) in self.files.effects.items():
            expected = next(entry for entry in effects if entry["relative_path"] == path.relative_to(self.files.root).as_posix())
            observed = image(read_regular(path))
            if observed == expected["after"]:
                continue
            if observed != expected["before"]:
                raise ReCTMError("ACTION_EFFECT_CONFLICT", "Private action file no longer matches its evidence.", category="conflict", retryable=False)
            publish(path, after)


def commit_action(engine: Any, run: Mapping[str, Any], claims: Any, action: str, payload: dict[str, Any], trace_id: str) -> dict[str, Any]:
    with lock_run(engine.vault.private_root, claims.run_id):
        prepared = PreparedAction(engine, run, claims, action, payload, trace_id)
        token = _current.set(prepared)
        try:
            with prepared.files.capture():
                result = engine._prepare_commit_action(run, claims, action, payload, trace_id)
        finally:
            _current.reset(token)
        restartable = action if action in RESTARTABLE_ACTION_STATES else None
        if restartable:
            prepared.apply_files()
        elif action in ATOMIC_ACTION_STATES:
            if prepared.files.effects:
                raise ReCTMError("ATOMIC_ACTION_FILE_EFFECT", "Atomic action unexpectedly produced a private file effect.", category="internal")
            engine.store.enroll_atomic_action(claims, trace_id, action)
        else:
            raise ReCTMError("INVALID_COMMIT_ACTION", "Unsupported commit action.", category="validation")
        if prepared.transition is None:
            if action != "direct_proving_complete" or result.get("complete") is not False:
                raise ReCTMError("ACTION_TRANSITION_MISSING", "Prepared action has no certified transition.", category="internal")
            count = engine.store.submission_accepted_writes(trace_id) or 0
            engine.store.complete_partial_task(claims, trace_id=trace_id, expected_metadata=run["metadata"], metadata_updates=prepared.updates,
                result={"disposition": "applied", "state": run["state"], "writes_applied": count, "complete": False, "error_code": None})
        else:
            changed = engine.store.transition_task(claims, transition=prepared.transition, expected_metadata=run["metadata"],
                metadata_updates=prepared.updates, project_mode=prepared.project_mode, branch=prepared.branch, restartable_action=restartable)
            engine._emit_transition(changed, prepared.transition)
        return result
