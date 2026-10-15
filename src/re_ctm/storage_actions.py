"""Prepared workflow facts committed together with transition certificates."""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Mapping, Sequence, TYPE_CHECKING

from .debug import utc_now
from .errors import ReCTMError
from .storage_receipts import (
    RESTARTABLE_ACTION_STATES, canonical, check_task, execution_on,
    recheck_authority, receipt_error, require_between, finish_on, checkpoint_on, validate_result,
)

if TYPE_CHECKING:
    from .capabilities import CapabilityClaims


def conflict(code: str = "TASK_TRANSITION_CONFLICT") -> ReCTMError:
    return ReCTMError(code, "Prepared task bindings or database facts changed; no effects were committed.", category="conflict", retryable=False)


def manifest_on(connection: sqlite3.Connection, run_id: str, canonical_manifest: str, sha256: str, now: str) -> None:
    connection.execute(
        "INSERT INTO proof_manifests(run_id,manifest_json,sha256,created_at,updated_at) VALUES(?,?,?,?,?) "
        "ON CONFLICT(run_id) DO UPDATE SET manifest_json=excluded.manifest_json,sha256=excluded.sha256,updated_at=excluded.updated_at",
        (run_id, canonical_manifest, sha256, now, now),
    )


AUDIT_FIELDS = (
    "reference_id", "disposition", "evidence_basis", "evidence_locator", "verifier_domain_id",
    "proof_sha256", "proof_manifest_sha256", "material", "assumptions_checked", "notation_checked",
    "source_checked", "independently_rederived", "notes",
)


def audit_on(connection: sqlite3.Connection, run_id: str, audit: Mapping[str, Any], now: str) -> dict[str, Any]:
    if set(audit) != set(AUDIT_FIELDS):
        raise receipt_error()
    reference = connection.execute("SELECT run_id FROM references_registry WHERE reference_id=?", (audit["reference_id"],)).fetchone()
    if reference is None:
        raise ReCTMError("REFERENCE_NOT_FOUND", "Unknown reference.", category="not_found")
    if reference["run_id"] != run_id:
        raise ReCTMError("REFERENCE_RUN_MISMATCH", "Reference does not belong to this run.", category="permission")
    if audit["disposition"] not in {"SOURCE_VERIFIED", "INDEPENDENTLY_REDERIVED", "UNRESOLVED", "NOT_MATERIAL"}:
        raise ReCTMError("INVALID_REFERENCE_DISPOSITION", "Unsupported reference audit disposition.", category="validation")
    values = [audit[key] for key in AUDIT_FIELDS]
    for index, key in enumerate(AUDIT_FIELDS):
        if key in {"material", "assumptions_checked", "notation_checked", "source_checked", "independently_rederived"}:
            if type(values[index]) is not bool:
                raise receipt_error()
            values[index] = int(values[index])
        elif not isinstance(values[index], str):
            raise receipt_error()
    connection.execute(
        "INSERT INTO reference_audits(run_id," + ",".join(AUDIT_FIELDS) + ",created_at,updated_at) "
        "VALUES(" + ",".join("?" for _ in range(16)) + ") ON CONFLICT(run_id,reference_id) DO UPDATE SET "
        + ",".join(f"{field}=excluded.{field}" for field in AUDIT_FIELDS[1:]) + ",updated_at=excluded.updated_at",
        (run_id, *values, now, now),
    )
    return dict(connection.execute("SELECT * FROM reference_audits WHERE run_id=? AND reference_id=?", (run_id, audit["reference_id"])).fetchone())


class ActionStore:
    def transition_task(self, claims: CapabilityClaims, *, transition: Mapping[str, Any],
                        expected_metadata: Mapping[str, Any] | None = None,
                        metadata_updates: Mapping[str, Any] | None = None,
                        project_mode: str | None = None, branch: Mapping[str, str] | None = None,
                        restartable_action: str | None = None) -> dict[str, Any]:
        updates = json.loads(canonical(dict(metadata_updates or {})))
        transition = json.loads(canonical(dict(transition)))
        expected_metadata = None if expected_metadata is None else json.loads(canonical(dict(expected_metadata)))
        branch = None if branch is None else json.loads(canonical(dict(branch)))
        if (transition.get("run_id") != claims.run_id or transition.get("expected_state") != claims.issued_state.value
            or transition.get("actor") != claims.role.value or not transition.get("increment_epoch", True)
            or project_mode not in {None, "compact", "full"} or len(canonical(updates).encode()) > 1024 * 1024
            or (restartable_action is not None and RESTARTABLE_ACTION_STATES.get(restartable_action) != claims.issued_state.value)):
            raise conflict()
        now = utc_now()
        with self.transaction() as connection:
            recheck_authority(connection, claims)
            receipt = check_task(connection, claims, transition["trace_id"], restartable_action)
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (claims.run_id,)).fetchone()
            metadata = json.loads(row["metadata_json"])
            if expected_metadata is not None and metadata != expected_metadata:
                raise conflict()
            metadata.update(updates)
            if updates:
                connection.execute("UPDATE runs SET metadata_json=?,updated_at=? WHERE run_id=?", (canonical(metadata), now, claims.run_id))
            if project_mode is not None:
                connection.execute("UPDATE project_runs SET effective_workflow_mode=?,updated_at=? WHERE run_id=?", (project_mode, now, claims.run_id))
            if branch is not None:
                if (claims.role.value != "branch" or set(branch) != {"branch_id", "result_path"}
                    or not isinstance(branch["result_path"], str) or len(branch["result_path"]) > 4096):
                    raise conflict()
                changed = connection.execute("UPDATE branches SET status='sealed',result_path=?,sealed_at=? WHERE branch_id=? AND run_id=? AND domain_id=? AND status<>'sealed'",
                                             (branch["result_path"], now, branch["branch_id"], claims.run_id, claims.domain_id)).rowcount
                remaining = connection.execute("SELECT COUNT(*) FROM branches WHERE run_id=? AND status<>'sealed'", (claims.run_id,)).fetchone()[0]
                if changed != 1 or transition["after_state"] != ("branch_join" if remaining == 0 else "branch_run"):
                    raise conflict()
            changed = connection.execute("UPDATE domains SET status='sealed',sealed_at=? WHERE domain_id=? AND run_id=? AND status='open'", (now, claims.domain_id, claims.run_id)).rowcount
            if changed != 1:
                raise conflict()
            connection.execute("UPDATE capabilities SET revoked=1,revoked_at=?,revoke_reason='domain_sealed' WHERE domain_id=? AND revoked=0", (now, claims.domain_id))
            if restartable_action is not None and receipt is not None:
                connection.execute("UPDATE step_write_journals SET marker_json=? WHERE capability_sha256=?", (canonical({"kind": "between"}), receipt["capability_sha256"]))
            return self._transition_on(connection, **dict(transition), now=now)

    def complete_partial_task(self, claims: CapabilityClaims, *, trace_id: str,
                              expected_metadata: Mapping[str, Any], metadata_updates: Mapping[str, Any],
                              result: Mapping[str, Any]) -> dict[str, Any]:
        """Accept incomplete direct screening without closing the task domain."""
        result = validate_result(result)
        updates = json.loads(canonical(dict(metadata_updates)))
        expected_metadata = json.loads(canonical(dict(expected_metadata)))
        if (claims.issued_state.value != "direct_proving" or result["state"] != "direct_proving"
            or result["disposition"] != "applied" or result["complete"]
            or len(canonical(updates).encode()) > 1024 * 1024):
            raise conflict()
        now = utc_now()
        with self.transaction() as connection:
            recheck_authority(connection, claims)
            receipt = check_task(connection, claims, trace_id, "direct_proving_complete")
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (claims.run_id,)).fetchone()
            metadata = json.loads(row["metadata_json"])
            if metadata != expected_metadata:
                raise conflict()
            if receipt is not None:
                checkpoint = checkpoint_on(connection, receipt["capability_sha256"])
                if checkpoint["accepted_writes"] != result["writes_applied"]:
                    raise receipt_error()
            metadata.update(updates)
            connection.execute("UPDATE runs SET metadata_json=?,updated_at=? WHERE run_id=?", (canonical(metadata), now, claims.run_id))
            if receipt is not None:
                connection.execute("UPDATE step_write_journals SET marker_json=? WHERE capability_sha256=?", (canonical({"kind": "between"}), receipt["capability_sha256"]))
                finish_on(connection, receipt, result, now)
            value = dict(connection.execute("SELECT * FROM runs WHERE run_id=?", (claims.run_id,)).fetchone())
            value["metadata"] = json.loads(value.pop("metadata_json"))
            return value

    def complete_latex_gate(self, *, transition: Mapping[str, Any], expected_metadata: Mapping[str, Any], latex_result: Mapping[str, Any]) -> dict[str, Any]:
        if (transition.get("expected_state") != "latex_validate" or transition.get("after_state") not in {"verify", "repair"}
            or transition.get("actor") != "latex_gate" or not transition.get("increment_epoch", True)
            or transition.get("round_delta", 0) != 0 or type(transition.get("latex_passed")) is not bool):
            raise conflict("MECHANICAL_TRANSITION_CONFLICT")
        transition = json.loads(canonical(dict(transition)))
        expected_metadata = json.loads(canonical(dict(expected_metadata)))
        latex_result = json.loads(canonical(dict(latex_result)))
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (transition["run_id"],)).fetchone()
            if row is None or row["state"] != "latex_validate" or json.loads(row["metadata_json"]) != expected_metadata:
                raise conflict("MECHANICAL_TRANSITION_CONFLICT")
            metadata = {**dict(expected_metadata), "latex_result": dict(latex_result)}
            connection.execute("UPDATE runs SET metadata_json=?,updated_at=? WHERE run_id=?", (canonical(metadata), now, transition["run_id"]))
            return self._transition_on(connection, **dict(transition), now=now)

    def complete_branch_preparation(self, *, transition: Mapping[str, Any], expected_branch_requests: Sequence[Any],
                                    snapshot_id: str, branches: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        if (transition.get("expected_state") != "branch_prepare" or transition.get("after_state") != "branch_run"
            or transition.get("actor") != "system" or not transition.get("increment_epoch", True)
            or transition.get("round_delta", 0) != 1 or not 1 <= len(branches) <= 64
            or len(expected_branch_requests) != len(branches) or not isinstance(snapshot_id, str) or not 1 <= len(snapshot_id) <= 128):
            raise conflict("MECHANICAL_TRANSITION_CONFLICT")
        fields = {"branch_id", "plan_id", "domain_id", "snapshot_id", "order_index", "domain_metadata", "branch_metadata"}
        order = set()
        for branch in branches:
            if (set(branch) != fields or branch["snapshot_id"] != snapshot_id or type(branch["order_index"]) is not int
                or not 0 <= branch["order_index"] < len(branches) or branch["order_index"] in order
                or not isinstance(branch["domain_metadata"], Mapping) or not isinstance(branch["branch_metadata"], Mapping)):
                raise conflict("MECHANICAL_TRANSITION_CONFLICT")
            order.add(branch["order_index"])
            canonical(dict(branch))
        transition = json.loads(canonical(dict(transition)))
        expected_branch_requests = json.loads(canonical(list(expected_branch_requests)))
        branches = json.loads(canonical(list(branches)))
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute("SELECT * FROM runs WHERE run_id=?", (transition["run_id"],)).fetchone()
            if row is None or row["state"] != "branch_prepare":
                raise conflict("MECHANICAL_TRANSITION_CONFLICT")
            metadata = json.loads(row["metadata_json"])
            if metadata.get("branch_requests") != list(expected_branch_requests):
                raise conflict("MECHANICAL_TRANSITION_CONFLICT")
            prefix = f"round-{row['round_index'] + 1}-%"
            if connection.execute("SELECT 1 FROM branches WHERE run_id=? AND snapshot_id LIKE ?", (transition["run_id"], prefix)).fetchone():
                raise ReCTMError("MECHANICAL_LEGACY_PARTIAL_UNKNOWN", "Legacy branch rows have no completed transition; automatic adoption is refused.", category="conflict")
            for branch in branches:
                connection.execute("INSERT INTO domains(domain_id,run_id,role,status,snapshot_id,order_index,metadata_json,created_at) VALUES(?,?,'branch','open',?,?,?,?)",
                                   (branch["domain_id"], transition["run_id"], snapshot_id, branch["order_index"], canonical(dict(branch["domain_metadata"])), now))
                connection.execute("INSERT INTO branches(branch_id,run_id,plan_id,domain_id,snapshot_id,order_index,status,metadata_json,created_at) VALUES(?,?,?,?,?,?,'pending',?,?)",
                                   (branch["branch_id"], transition["run_id"], branch["plan_id"], branch["domain_id"], snapshot_id, branch["order_index"], canonical(dict(branch["branch_metadata"])), now))
            metadata.update(active_snapshot_id=snapshot_id, branch_requests=[])
            connection.execute("UPDATE runs SET metadata_json=?,updated_at=? WHERE run_id=?", (canonical(metadata), now, transition["run_id"]))
            return self._transition_on(connection, **dict(transition), now=now)

    def write_submission_manifest(self, execution: Mapping[str, Any], index: int, manifest: Mapping[str, Any]) -> dict[str, Any]:
        import hashlib
        encoded = canonical(dict(manifest))
        if len(encoded.encode("utf-8")) > 1024 * 1024:
            raise ReCTMError("SUBMISSION_DATABASE_WRITE_TOO_LARGE", "Normalized proof manifest exceeds 1 MiB.", category="validation")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        now = utc_now()
        with self.transaction() as connection:
            receipt = _database_slot(connection, execution, index, "proof_manifest")
            manifest_on(connection, receipt["run_id"], encoded, digest, now)
            _accept_database_slot(connection, receipt, index)
        return {"run_id": receipt["run_id"], "manifest": json.loads(encoded), "sha256": digest}

    def write_submission_reference_audit(self, execution: Mapping[str, Any], index: int, audit: Mapping[str, Any]) -> dict[str, Any]:
        encoded = canonical(dict(audit))
        if len(encoded.encode("utf-8")) > 1024 * 1024:
            raise ReCTMError("SUBMISSION_DATABASE_WRITE_TOO_LARGE", "Normalized reference audit exceeds 1 MiB.", category="validation")
        prepared = json.loads(encoded)
        now = utc_now()
        with self.transaction() as connection:
            receipt = _database_slot(connection, execution, index, "reference_audit")
            if prepared.get("verifier_domain_id") != receipt["domain_id"]:
                raise receipt_error()
            result = audit_on(connection, receipt["run_id"], prepared, now)
            _accept_database_slot(connection, receipt, index)
            return result


def _database_slot(connection: sqlite3.Connection, execution: Mapping[str, Any], index: int, resource: str) -> dict[str, Any]:
    if type(index) is not int or not 0 <= index < 65536:
        raise receipt_error()
    receipt, checkpoint = execution_on(connection, execution)
    recheck_authority(connection, execution["claims"], resource, "write")
    require_between(connection, receipt["capability_sha256"])
    if checkpoint["phase"] != "running" or checkpoint["accepted_writes"] != index or checkpoint["expected_writes"] <= index:
        raise receipt_error()
    return receipt


def _accept_database_slot(connection: sqlite3.Connection, receipt: Mapping[str, Any], index: int) -> None:
    changed = connection.execute("UPDATE step_checkpoints SET accepted_writes=? WHERE capability_sha256=? AND phase='running' AND accepted_writes=? AND expected_writes>?",
                                 (index + 1, receipt["capability_sha256"], index, index)).rowcount
    if changed != 1:
        raise receipt_error()
    require_between(connection, receipt["capability_sha256"])
