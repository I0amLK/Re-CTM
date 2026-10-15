"""Durable, authority-bound submission evidence on StateStore's sole connection.

Receipts are summaries, never capabilities. No filesystem/network operation or
caller callback runs within a transaction in this module.
"""
from __future__ import annotations

import fnmatch
import json
import re
import secrets
import sqlite3
import time
from typing import Any, Mapping, TYPE_CHECKING

from .debug import utc_now
from .errors import ReCTMError

if TYPE_CHECKING:
    from .capabilities import CapabilityClaims

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ATOMIC_ACTION_STATES = {
    "assessment_complete": "assess", "exploration_complete": "explore",
    "proof_submitted": "assemble", "repair_submitted": "repair",
}
RESTARTABLE_ACTION_STATES = {
    "plans_proposed": "propose_plans", "direct_proving_complete": "direct_proving",
    "branch_complete": "branch_run", "join_complete": "branch_join",
    "failures_identified": "identify_failures", "replan_complete": "replan",
    "verification_submitted": "verify",
}


def receipt_error(code: str = "SUBMISSION_RECEIPT_INVALID", message: str = "Submission evidence is missing or inconsistent.") -> ReCTMError:
    return ReCTMError(code, message, category="conflict", retryable=False,
                      details={"automatic_retry": False, "receipt_grants_authority": False})


def unknown() -> ReCTMError:
    return receipt_error("RESULT_UNKNOWN", "No safe checkpoint proves the result. Do not replay partial work or replace its capability.")


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def require_digest(value: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise receipt_error()


def validate_result(result: Mapping[str, Any]) -> dict[str, Any]:
    from .enums import WorkflowState
    fields = {"disposition", "state", "writes_applied", "complete", "error_code"}
    if set(result) != fields or result["state"] not in {item.value for item in WorkflowState}:
        raise receipt_error()
    count = result["writes_applied"]
    code = result["error_code"]
    if (type(count) is not int or not 0 <= count <= 65536 or type(result["complete"]) is not bool
        or result["disposition"] not in {"applied", "correction_required"}):
        raise receipt_error()
    if result["disposition"] == "applied":
        if code is not None:
            raise receipt_error()
    elif result["complete"] or not isinstance(code, str) or not re.fullmatch(r"[A-Z0-9_]{1,80}", code):
        raise receipt_error()
    encoded = canonical(dict(result))
    if len(encoded.encode()) > 2048:
        raise receipt_error()
    return json.loads(encoded)


def decode_receipt(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    for key in ("capability_sha256", "workspace_sha256", "request_sha256"):
        require_digest(data[key])
    try:
        result = json.loads(data.pop("result_json")) if data["result_json"] is not None else None
    except (ValueError, TypeError) as exc:
        raise receipt_error() from exc
    if "result_json" in data:
        data.pop("result_json")
    if data["status"] == "completed":
        if not isinstance(result, dict) or not data["completed_at"]:
            raise receipt_error()
        validate_result(result)
    elif data["status"] != "pending" or result is not None or data["completed_at"] is not None:
        raise receipt_error()
    if not data["created_at"]:
        raise receipt_error()
    data["result"] = result
    data["grants_authority"] = False
    return data


def read_receipt(connection: sqlite3.Connection, fingerprint: str, owner: str, run: str) -> dict[str, Any] | None:
    return decode_receipt(connection.execute(
        "SELECT * FROM step_receipts WHERE capability_sha256=? AND owner_id=? AND run_id=?",
        (fingerprint, owner, run),
    ).fetchone())


def check_binding(receipt: Mapping[str, Any], workspace: str, request: str) -> None:
    if receipt["workspace_sha256"] != workspace:
        raise receipt_error("SUBMISSION_WORKSPACE_MISMATCH", "Submission belongs to a different workspace.")
    if receipt["request_sha256"] != request:
        raise receipt_error("IDEMPOTENCY_CONFLICT", "This capability identifies different input; do not replay changed writes.")


def current_receipt(connection: sqlite3.Connection, expected: Mapping[str, Any]) -> dict[str, Any]:
    actual = read_receipt(connection, expected["capability_sha256"], expected["owner_id"], expected["run_id"])
    if actual is None:
        raise receipt_error()
    check_binding(actual, expected["workspace_sha256"], expected["request_sha256"])
    for key in ("domain_id", "role", "epoch", "issued_state"):
        if actual[key] != expected[key]:
            raise receipt_error()
    return actual


def matches_claims(receipt: Mapping[str, Any], claims: CapabilityClaims) -> bool:
    return all(receipt[key] == value for key, value in {
        "owner_id": claims.owner_id, "run_id": claims.run_id, "domain_id": claims.domain_id,
        "role": claims.role.value, "epoch": claims.epoch, "issued_state": claims.issued_state.value,
    }.items())


def recheck_authority(connection: sqlite3.Connection, claims: CapabilityClaims, resource: str = "workflow", action: str = "commit") -> None:
    from .capabilities import _record_matches_claims, authorize_role_resource
    run = connection.execute("SELECT * FROM runs WHERE run_id=?", (claims.run_id,)).fetchone()
    domain = connection.execute("SELECT * FROM domains WHERE domain_id=?", (claims.domain_id,)).fetchone()
    cap = connection.execute("SELECT * FROM capabilities WHERE nonce=?", (claims.nonce,)).fetchone()
    record = dict(cap) if cap is not None else {}
    record["permissions"] = json.loads(record.pop("permissions_json", "[]"))
    if (run is None or domain is None or cap is None or not _record_matches_claims(record, claims)
        or cap["revoked"] or claims.expires_at < int(time.time()) or run["owner_id"] != claims.owner_id
        or run["epoch"] != claims.epoch or run["state"] != claims.issued_state.value
        or domain["status"] != "open" or domain["run_id"] != claims.run_id or domain["role"] != claims.role.value):
        raise receipt_error("SUBMISSION_AUTHORITY_CHANGED", "Submission authority changed; no write was attempted.")
    if not any(fnmatch.fnmatchcase(f"{action}:{resource}", p) for p in claims.permissions):
        raise ReCTMError("ROLE_ACCESS_DENIED", "Reserved task lacks the required permission.", category="permission")
    payload = dict(domain)
    payload["metadata"] = json.loads(payload.pop("metadata_json"))
    authorize_role_resource(role=claims.role, state=claims.issued_state, action=action, resource=resource, domain=payload)


def finish_on(connection: sqlite3.Connection, receipt: Mapping[str, Any], result: Mapping[str, Any], now: str) -> dict[str, Any]:
    encoded = canonical(validate_result(result))
    changed = connection.execute(
        "UPDATE step_receipts SET status='completed',result_json=?,completed_at=? "
        "WHERE capability_sha256=? AND owner_id=? AND run_id=? AND status='pending'",
        (encoded, now, receipt["capability_sha256"], receipt["owner_id"], receipt["run_id"]),
    ).rowcount
    if changed != 1:
        raise receipt_error()
    return current_receipt(connection, receipt)


def checkpoint_on(connection: sqlite3.Connection, fingerprint: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT c.*,j.marker_json FROM step_checkpoints c LEFT JOIN step_write_journals j USING(capability_sha256) "
        "WHERE c.capability_sha256=?", (fingerprint,),
    ).fetchone()
    return dict(row) if row is not None else None


def require_between(connection: sqlite3.Connection, fingerprint: str) -> None:
    row = connection.execute("SELECT marker_json FROM step_write_journals WHERE capability_sha256=?", (fingerprint,)).fetchone()
    if row is None or row[0] != canonical({"kind": "between"}):
        raise receipt_error()


def execution_on(connection: sqlite3.Connection, execution: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt = current_receipt(connection, execution["receipt"])
    checkpoint = checkpoint_on(connection, receipt["capability_sha256"])
    if (receipt["result"] is not None or checkpoint is None or checkpoint["execution_id"] != execution["execution_id"]
        or not matches_claims(receipt, execution["claims"])):
        raise receipt_error()
    return receipt, checkpoint


class SubmissionStore:
    """Mixin using StateStore.transaction; it never owns or reopens a database."""

    def find_submission_receipt(self, capability_sha256: str, owner_id: str, run_id: str) -> dict[str, Any] | None:
        require_digest(capability_sha256)
        with self._lock:
            return read_receipt(self._connection, capability_sha256, owner_id, run_id)

    def submission_for_execution(self, trace_id: str) -> dict[str, Any] | None:
        with self._lock:
            return decode_receipt(self._connection.execute(
                "SELECT r.* FROM step_receipts r JOIN step_checkpoints c USING(capability_sha256) WHERE c.execution_id=?",
                (trace_id,),
            ).fetchone())

    def submission_accepted_writes(self, trace_id: str) -> int | None:
        with self._lock:
            row = self._connection.execute("SELECT accepted_writes FROM step_checkpoints WHERE execution_id=?", (trace_id,)).fetchone()
            return row[0] if row is not None else None

    def reserve_submission(self, claims: CapabilityClaims, *, capability_sha256: str, workspace_sha256: str, request_sha256: str) -> dict[str, Any]:
        for digest in (capability_sha256, workspace_sha256, request_sha256):
            require_digest(digest)
        execution_id, now = secrets.token_hex(16), utc_now()
        with self.transaction() as connection:
            receipt = read_receipt(connection, capability_sha256, claims.owner_id, claims.run_id)
            if receipt is not None:
                if not matches_claims(receipt, claims):
                    raise receipt_error()
                check_binding(receipt, workspace_sha256, request_sha256)
                return {**receipt, "reserved": False}
            if connection.execute("SELECT 1 FROM step_receipts WHERE run_id=? AND status='pending'", (claims.run_id,)).fetchone():
                raise unknown()
            recheck_authority(connection, claims)
            total = connection.execute("SELECT COUNT(*) FROM step_receipts").fetchone()[0]
            count = connection.execute("SELECT COUNT(*) FROM step_receipts WHERE run_id=?", (claims.run_id,)).fetchone()[0]
            if total >= 100000 or count >= 4096:
                raise receipt_error("SUBMISSION_RECEIPT_CAPACITY", "Safety receipt capacity reached; no records were removed.")
            connection.execute(
                "INSERT INTO step_receipts(capability_sha256,owner_id,workspace_sha256,request_sha256,run_id,domain_id,role,epoch,issued_state,status,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,'pending',?)",
                (capability_sha256, claims.owner_id, workspace_sha256, request_sha256, claims.run_id, claims.domain_id,
                 claims.role.value, claims.epoch, claims.issued_state.value, now),
            )
            connection.execute("INSERT INTO step_checkpoints(capability_sha256,execution_id,phase) VALUES(?,?,'prepared')", (capability_sha256, execution_id))
            return {**read_receipt(connection, capability_sha256, claims.owner_id, claims.run_id), "reserved": True}

    def activate_submission(self, receipt: Mapping[str, Any], claims: CapabilityClaims, writes: int) -> dict[str, Any]:
        if type(writes) is not int or not 0 <= writes <= 65536 or not matches_claims(receipt, claims):
            raise receipt_error()
        with self.transaction() as connection:
            actual = current_receipt(connection, receipt)
            if actual["result"] is not None:
                raise receipt_error("SUBMISSION_NOT_STARTED", "This unstarted reservation was already resolved.")
            recheck_authority(connection, claims)
            checkpoint = checkpoint_on(connection, actual["capability_sha256"])
            if checkpoint is None or checkpoint["phase"] != "prepared":
                raise unknown()
            connection.execute("UPDATE step_checkpoints SET phase='running',expected_writes=? WHERE capability_sha256=?", (writes, actual["capability_sha256"]))
            connection.execute("INSERT INTO step_write_journals VALUES(?,?)", (actual["capability_sha256"], canonical({"kind": "between"})))
            return {"receipt": actual, "claims": claims, "execution_id": checkpoint["execution_id"], "trace_id": checkpoint["execution_id"]}

    def observed_submission(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            return current_receipt(self._connection, receipt)

    observe_submission = observed_submission

    def checkpoint_submission_write(self, execution: Mapping[str, Any], accepted: int) -> None:
        if type(accepted) is not int or not 1 <= accepted <= 65536:
            raise receipt_error()
        with self.transaction() as connection:
            receipt, checkpoint = execution_on(connection, execution)
            if checkpoint["phase"] != "running" or checkpoint["accepted_writes"] != accepted - 1 or checkpoint["expected_writes"] < accepted:
                raise receipt_error()
            from .storage_recovery import decode_marker
            marker = decode_marker(checkpoint["marker_json"])
            if marker is None or marker["kind"] not in {"file", "opaque"}:
                raise receipt_error()
            connection.execute("UPDATE step_checkpoints SET accepted_writes=? WHERE capability_sha256=?", (accepted, receipt["capability_sha256"]))
            connection.execute("UPDATE step_write_journals SET marker_json=? WHERE capability_sha256=?", (canonical({"kind": "between"}), receipt["capability_sha256"]))

    def arm_submission_commit(self, execution: Mapping[str, Any]) -> None:
        with self.transaction() as connection:
            receipt, checkpoint = execution_on(connection, execution)
            require_between(connection, receipt["capability_sha256"])
            if checkpoint["phase"] != "running" or checkpoint["expected_writes"] != checkpoint["accepted_writes"]:
                raise receipt_error()
            connection.execute("UPDATE step_checkpoints SET phase='commit_ready' WHERE capability_sha256=?", (receipt["capability_sha256"],))

    def record_submission_outcome(self, receipt: Mapping[str, Any], result: Mapping[str, Any]) -> dict[str, Any]:
        result = validate_result(result)
        now = utc_now()
        with self.transaction() as connection:
            actual = current_receipt(connection, receipt)
            recorded = actual["result"]
            if recorded is not None:
                if recorded == result or (recorded["disposition"] == result["disposition"] == "applied"
                    and recorded["writes_applied"] == result["writes_applied"] and recorded["complete"] == result["complete"]):
                    return actual
                raise receipt_error()
            checkpoint = checkpoint_on(connection, actual["capability_sha256"])
            if checkpoint is None:
                raise unknown()
            if checkpoint["phase"] == "prepared":
                if result["disposition"] != "correction_required" or result["writes_applied"] != 0:
                    raise receipt_error()
            else:
                require_between(connection, actual["capability_sha256"])
                if checkpoint["accepted_writes"] != result["writes_applied"]:
                    raise receipt_error()
                if result["disposition"] == "applied" and checkpoint["phase"] != "commit_ready":
                    raise receipt_error()
            return finish_on(connection, actual, result, now)

    complete_submission = record_submission_outcome

    def enroll_atomic_action(self, claims: CapabilityClaims, trace_id: str, action: str) -> None:
        if ATOMIC_ACTION_STATES.get(action) != claims.issued_state.value:
            raise receipt_error()
        with self.transaction() as connection:
            recheck_authority(connection, claims)
            receipt = check_task(connection, claims, trace_id)
            if receipt is None:
                return
            changed = connection.execute(
                "UPDATE step_checkpoints SET atomic_action=? WHERE execution_id=? AND atomic_action IS NULL",
                (action, trace_id),
            ).rowcount
            if changed != 1:
                raise receipt_error()


def check_task(connection: sqlite3.Connection, claims: CapabilityClaims, trace_id: str, restartable_action: str | None = None) -> dict[str, Any] | None:
    row = connection.execute("SELECT r.* FROM step_receipts r JOIN step_checkpoints c USING(capability_sha256) WHERE c.execution_id=?", (trace_id,)).fetchone()
    receipt = decode_receipt(row)
    if receipt is None:
        if connection.execute("SELECT 1 FROM step_receipts WHERE run_id=? AND status='pending'", (claims.run_id,)).fetchone():
            raise receipt_error()
        return None
    checkpoint = checkpoint_on(connection, receipt["capability_sha256"])
    if (not matches_claims(receipt, claims) or receipt["result"] is not None or checkpoint is None
        or checkpoint["phase"] != "commit_ready" or checkpoint["expected_writes"] != checkpoint["accepted_writes"]):
        raise receipt_error()
    if restartable_action is None:
        require_between(connection, receipt["capability_sha256"])
    else:
        from .storage_recovery import decode_marker
        expected = {"kind": "restartable_action", "action": restartable_action}
        if decode_marker(checkpoint["marker_json"]) != expected:
            raise receipt_error()
    return receipt


def record_transition(connection: sqlite3.Connection, *, before: Mapping[str, Any], run_id: str, expected_state: str,
                      after_state: str, actor: str, trace_id: str, now: str) -> None:
    row = connection.execute("SELECT r.* FROM step_receipts r JOIN step_checkpoints c USING(capability_sha256) WHERE c.execution_id=?", (trace_id,)).fetchone()
    receipt = decode_receipt(row)
    if receipt is None:
        # A legacy transition cannot silently settle or advance an enrolled task.
        if connection.execute("SELECT 1 FROM step_receipts WHERE run_id=? AND status='pending'", (run_id,)).fetchone():
            raise receipt_error()
        return
    checkpoint = checkpoint_on(connection, receipt["capability_sha256"])
    if (receipt["result"] is not None or checkpoint["phase"] != "commit_ready"
        or checkpoint["accepted_writes"] != checkpoint["expected_writes"] or receipt["run_id"] != run_id
        or receipt["role"] != actor or receipt["issued_state"] != expected_state
        or receipt["epoch"] != before["epoch"] or receipt["owner_id"] != before["owner_id"]):
        raise receipt_error()
    require_between(connection, receipt["capability_sha256"])
    finish_on(connection, receipt, {"disposition": "applied", "state": after_state,
              "writes_applied": checkpoint["accepted_writes"], "complete": True, "error_code": None}, now)
