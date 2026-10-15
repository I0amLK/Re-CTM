"""Reconcile stored evidence only: never execute missing caller writes/actions."""
from __future__ import annotations

import json
import re
from typing import Any, Mapping, TYPE_CHECKING

from .debug import utc_now
from .storage_receipts import (
    ATOMIC_ACTION_STATES, RESTARTABLE_ACTION_STATES, canonical, check_task,
    checkpoint_on, current_receipt, execution_on, finish_on, recheck_authority,
    receipt_error, require_digest, unknown,
)

if TYPE_CHECKING:
    from .capabilities import CapabilityClaims

NO_OBSERVATION = object()


def validate_image(image: Mapping[str, Any] | None) -> None:
    if image is None:
        return
    if not isinstance(image, Mapping) or set(image) != {"bytes", "sha256"}:
        raise receipt_error()
    if type(image["bytes"]) is not int or not 0 <= image["bytes"] <= 64 * 1024 * 1024:
        raise receipt_error()
    require_digest(image["sha256"])


def validate_file_evidence(evidence: Mapping[str, Any]) -> str:
    if not isinstance(evidence, Mapping) or set(evidence) != {"relative_path", "before", "after"}:
        raise receipt_error()
    path = evidence["relative_path"]
    if not isinstance(path, str):
        raise receipt_error()
    parts = path.split("/")
    if any(not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", part) or part in {".", ".."} for part in parts):
        raise receipt_error()
    supported = path in {"draft/proof.tex", "join/result.json", "verification/verification.json"}
    supported |= len(parts) == 3 and parts[0] == "memory" and parts[1] in {"generation", "verifier"} and parts[2].endswith(".jsonl")
    supported |= len(parts) == 4 and parts[0] == "branches" and parts[2] == "memory" and parts[3].endswith(".jsonl")
    supported |= len(parts) == 3 and parts[0] == "branches" and parts[2] == "result.json"
    if not supported or evidence["after"] is None:
        raise receipt_error()
    validate_image(evidence["before"])
    validate_image(evidence["after"])
    return path


def decode_marker(raw: str | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    if len(raw.encode()) > 4096:
        raise receipt_error()
    try:
        marker = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise receipt_error() from exc
    if not isinstance(marker, dict):
        raise receipt_error()
    kind = marker.get("kind")
    if kind in {"between", "opaque"} and set(marker) == {"kind"}:
        return marker
    if kind == "file" and set(marker) == {"kind", "evidence"}:
        validate_file_evidence(marker["evidence"])
        return marker
    if kind == "restartable_action" and set(marker) == {"kind", "action"} and marker["action"] in RESTARTABLE_ACTION_STATES:
        return marker
    raise receipt_error()


def recovery_diagnostic(checkpoint: Mapping[str, Any] | None) -> dict[str, Any]:
    phase = checkpoint["phase"] if checkpoint else "legacy_unknown"
    marker = decode_marker(checkpoint["marker_json"]) if checkpoint else None
    kind = marker["kind"] if marker else None
    return {
        "kind": {None: "legacy_unknown", "between": "between_writes", "file": "file_effect",
                 "opaque": "opaque_effect", "restartable_action": "restartable_action"}[kind],
        "recover_only_may_reconcile": phase == "prepared" or (phase == "running" and kind in {"between", "file"})
            or (phase == "commit_ready" and (kind == "restartable_action" or (kind == "between" and checkpoint["atomic_action"] in ATOMIC_ACTION_STATES))),
        "automatic_retry": False, "grants_authority": False,
    }


class RecoveryStore:
    def begin_submission_write(self, execution: Mapping[str, Any], index: int, evidence: Mapping[str, Any] | None = None) -> None:
        if type(index) is not int or not 0 <= index < 65536:
            raise receipt_error()
        marker = {"kind": "opaque"} if evidence is None else {"kind": "file", "evidence": dict(evidence)}
        encoded = canonical(marker)
        prepared_marker = decode_marker(encoded)
        evidence = prepared_marker.get("evidence")
        with self.transaction() as connection:
            receipt, checkpoint = execution_on(connection, execution)
            claims = execution["claims"]
            recheck_authority(connection, claims)
            if evidence is not None:
                parts = evidence["relative_path"].split("/")
                if parts[0] == "branches":
                    domain = connection.execute("SELECT metadata_json FROM domains WHERE domain_id=?", (claims.domain_id,)).fetchone()
                    if json.loads(domain[0]).get("branch_id") != parts[1]:
                        raise receipt_error("CROSS_BRANCH_ACCESS_DENIED", "Evidence belongs to another branch.")
                if parts[:1] == ["memory"]:
                    resource = f"memory:{parts[1]}:{parts[2][:-6]}"
                elif len(parts) == 4:
                    resource = f"memory:branch:{parts[3][:-6]}"
                else:
                    resource = {"draft": "proof", "join": "join_result", "verification": "verification_report"}.get(parts[0])
                if resource is None:
                    raise receipt_error()
                recheck_authority(connection, claims, resource, "write")
            if (checkpoint["phase"] != "running" or checkpoint["accepted_writes"] != index
                or checkpoint["expected_writes"] <= index or checkpoint["marker_json"] != canonical({"kind": "between"})):
                raise receipt_error()
            connection.execute("UPDATE step_write_journals SET marker_json=? WHERE capability_sha256=?", (encoded, receipt["capability_sha256"]))

    def enroll_restartable_action(self, claims: CapabilityClaims, trace_id: str, action: str) -> None:
        if RESTARTABLE_ACTION_STATES.get(action) != claims.issued_state.value:
            raise receipt_error()
        encoded = canonical({"kind": "restartable_action", "action": action})
        with self.transaction() as connection:
            recheck_authority(connection, claims)
            receipt = check_task(connection, claims, trace_id)
            if receipt is None:
                return
            connection.execute("UPDATE step_write_journals SET marker_json=? WHERE capability_sha256=?", (encoded, receipt["capability_sha256"]))

    def submission_recovery(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            actual = current_receipt(self._connection, receipt)
            checkpoint = checkpoint_on(self._connection, actual["capability_sha256"])
            marker = decode_marker(checkpoint["marker_json"]) if checkpoint else None
            return {"receipt": actual, "checkpoint": checkpoint, "marker": marker,
                    "file_evidence": marker["evidence"] if marker and marker["kind"] == "file" else None}

    def reconcile_unstarted_submission(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        recovery = self.submission_recovery(receipt)
        if recovery["receipt"]["result"] is not None:
            return recovery["receipt"]
        if recovery["checkpoint"] is None or recovery["checkpoint"]["phase"] != "prepared":
            raise unknown()
        return self.reconcile_caller_writes(recovery)

    def reconcile_caller_writes(self, recovery: Mapping[str, Any], observed: Any = NO_OBSERVATION) -> dict[str, Any]:
        """Caller holds the private OS lock when supplying a file observation.

        Omitted observation means no file was inspected; None proves absence.
        This method can only retire an interrupted submission with a correction.
        """
        if observed is not NO_OBSERVATION:
            validate_image(observed)
        now = utc_now()
        with self.transaction() as connection:
            receipt = current_receipt(connection, recovery["receipt"])
            if receipt["result"] is not None:
                return receipt
            checkpoint = checkpoint_on(connection, receipt["capability_sha256"])
            if checkpoint is None or checkpoint != recovery["checkpoint"]:
                raise unknown()
            marker = decode_marker(checkpoint["marker_json"])
            if marker != recovery["marker"]:
                raise unknown()
            phase, accepted = checkpoint["phase"], checkpoint["accepted_writes"]
            if phase == "prepared":
                if observed is not NO_OBSERVATION:
                    raise unknown()
                code, accepted = "SUBMISSION_NOT_STARTED", 0
            else:
                kind = marker["kind"] if marker else None
                atomic = (phase == "commit_ready" and ATOMIC_ACTION_STATES.get(checkpoint["atomic_action"]) == receipt["issued_state"]
                          and kind == "between" and checkpoint["expected_writes"] == accepted and observed is NO_OBSERVATION)
                restartable = (phase == "commit_ready" and checkpoint["atomic_action"] is None and kind == "restartable_action"
                               and RESTARTABLE_ACTION_STATES.get(marker["action"]) == receipt["issued_state"]
                               and checkpoint["expected_writes"] == accepted and observed is NO_OBSERVATION)
                if (checkpoint["atomic_action"] is not None and not atomic) or (phase != "running" and not atomic and not restartable):
                    raise unknown()
                if kind in {"between", "restartable_action"} and observed is NO_OBSERVATION:
                    extra = 0
                elif kind == "file" and observed is not NO_OBSERVATION:
                    evidence = marker["evidence"]
                    if evidence["before"] == evidence["after"]:
                        raise unknown()
                    if observed == evidence["after"]:
                        extra = 1
                    elif observed == evidence["before"]:
                        extra = 0
                    else:
                        raise unknown()
                else:
                    raise unknown()
                accepted += extra
                if checkpoint["expected_writes"] is None or accepted > checkpoint["expected_writes"]:
                    raise receipt_error()
                code = "SUBMISSION_INTERRUPTED"
            return finish_on(connection, receipt, {"disposition": "correction_required", "state": receipt["issued_state"],
                             "writes_applied": accepted, "complete": False, "error_code": code}, now)

    def pending_submission_status(self, owner_id: str, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute("SELECT capability_sha256 FROM step_receipts WHERE owner_id=? AND run_id=? AND status='pending'", (owner_id, run_id)).fetchone()
            if row is None:
                return None
            checkpoint = checkpoint_on(self._connection, row[0])
            phase = checkpoint["phase"] if checkpoint else "legacy_unknown"
            return {"status": "pending", "phase": phase,
                    "atomic_action": checkpoint["atomic_action"] if checkpoint else None,
                    "recover_atomic_action_available": bool(checkpoint and phase == "commit_ready" and checkpoint["atomic_action"] in ATOMIC_ACTION_STATES),
                    "caller_write_recovery": recovery_diagnostic(checkpoint),
                    "accepted_caller_writes_lower_bound": checkpoint["accepted_writes"] if checkpoint else None,
                    "recover_unstarted_available": phase == "prepared", "automatic_retry": False, "grants_authority": False}
