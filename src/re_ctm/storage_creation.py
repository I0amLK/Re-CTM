"""Hash-only creation receipts and immutable, restartable initialization records."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from typing import Any, Mapping, Sequence

from .debug import utc_now
from .errors import ReCTMError
from .storage_receipts import canonical, require_digest

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def creation_error(code: str = "CREATION_RECEIPT_INVALID", message: str = "Creation binding or persisted evidence is invalid.") -> ReCTMError:
    return ReCTMError(code, message, category="conflict", retryable=False)


def digest_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def find_creation(connection: sqlite3.Connection, owner_id: str, key_sha256: str) -> dict[str, Any] | None:
    row = connection.execute("SELECT * FROM creation_receipts WHERE owner_id=? AND key_sha256=?", (owner_id, key_sha256)).fetchone()
    if row is None:
        return None
    data = dict(row)
    for key in ("key_sha256", "workspace_sha256", "request_sha256"):
        require_digest(data[key])
    if (data["status"] not in {"pending", "completed"} or not data["owner_id"] or not data["created_at"]
        or not _ID.fullmatch(data["run_id"]) or not re.fullmatch(r"[0-9a-f]{32}", data["execution_id"])
        or (data["status"] == "completed") != bool(data["completed_at"])):
        raise creation_error()
    data["grants_authority"] = False
    return data


def bind_creation(receipt: Mapping[str, Any], workspace: str, request: str) -> None:
    if receipt["workspace_sha256"] != workspace:
        raise creation_error("CREATION_WORKSPACE_MISMATCH", "Creation belongs to another workspace.")
    if receipt["request_sha256"] != request:
        raise creation_error("IDEMPOTENCY_CONFLICT", "This creation key identifies different input; retain the original key.")


def current_creation(connection: sqlite3.Connection, expected: Mapping[str, Any]) -> dict[str, Any]:
    actual = find_creation(connection, expected["owner_id"], expected["key_sha256"])
    if actual is None:
        raise creation_error()
    bind_creation(actual, expected["workspace_sha256"], expected["request_sha256"])
    if actual["run_id"] != expected["run_id"] or actual["execution_id"] != expected["execution_id"]:
        raise creation_error()
    return actual


def projection(connection: sqlite3.Connection, run_id: str) -> tuple[str, dict[str, Any]]:
    row = connection.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if row is None or row["state"] != "created" or row["transition_seq"] != 0 or row["status"] != "active":
        raise creation_error()
    run = dict(row)
    run["metadata"] = json.loads(run.pop("metadata_json"))
    run["latex_passed"] = bool(run["latex_passed"])
    run["sealed"] = bool(run["sealed"])
    value: list[Any] = [run]
    for sql in (
        "SELECT * FROM project_runs WHERE run_id=?",
        "SELECT * FROM project_snapshots WHERE snapshot_id IN (SELECT project_snapshot_id FROM project_runs WHERE run_id=?)",
        "SELECT * FROM references_registry WHERE run_id=? ORDER BY reference_id",
        "SELECT * FROM source_snapshots WHERE reference_id IN (SELECT reference_id FROM references_registry WHERE run_id=?) ORDER BY source_snapshot_id",
    ):
        rows = connection.execute(sql, (run_id,)).fetchall()
        if len(rows) > 128:
            raise creation_error()
        value.append([dict(item) for item in rows])
    return digest_text(canonical(value)), run


class CreationStore:
    def creation_receipt(self, owner_id: str, key_sha256: str, workspace_sha256: str, request_sha256: str) -> dict[str, Any] | None:
        for value in (key_sha256, workspace_sha256, request_sha256):
            require_digest(value)
        with self._lock:
            receipt = find_creation(self._connection, owner_id, key_sha256)
            if receipt is not None:
                bind_creation(receipt, workspace_sha256, request_sha256)
                if receipt["status"] == "completed":
                    run = self._connection.execute("SELECT owner_id FROM runs WHERE run_id=?", (receipt["run_id"],)).fetchone()
                    if run is None or run[0] != owner_id:
                        raise creation_error()
            return receipt

    def reserve_creation(self, owner_id: str, key_sha256: str, workspace_sha256: str, request_sha256: str, run_id: str) -> dict[str, Any]:
        for value in (key_sha256, workspace_sha256, request_sha256):
            require_digest(value)
        if not isinstance(owner_id, str) or not 1 <= len(owner_id) <= 512 or not isinstance(run_id, str) or not _ID.fullmatch(run_id):
            raise creation_error()
        execution_id, now = secrets.token_hex(16), utc_now()
        with self.transaction() as connection:
            existing = find_creation(connection, owner_id, key_sha256)
            if existing is not None:
                bind_creation(existing, workspace_sha256, request_sha256)
                if existing["status"] == "completed":
                    run = connection.execute("SELECT owner_id FROM runs WHERE run_id=?", (existing["run_id"],)).fetchone()
                    if run is None or run[0] != owner_id:
                        raise creation_error()
                return {**existing, "reserved": False}
            total = connection.execute("SELECT COUNT(*) FROM creation_receipts").fetchone()[0]
            owned = connection.execute("SELECT COUNT(*) FROM creation_receipts WHERE owner_id=?", (owner_id,)).fetchone()[0]
            if total >= 100000 or owned >= 10000:
                raise creation_error("CREATION_RECEIPT_CAPACITY", "Safety receipt capacity reached; no records were removed.")
            if connection.execute("SELECT 1 FROM runs WHERE run_id=?", (run_id,)).fetchone():
                raise creation_error("RUN_ALREADY_EXISTS", "Creation requires a new server-issued run identity.")
            connection.execute(
                "INSERT INTO creation_receipts(owner_id,key_sha256,workspace_sha256,request_sha256,run_id,execution_id,status,created_at) VALUES(?,?,?,?,?,?,'pending',?)",
                (owner_id, key_sha256, workspace_sha256, request_sha256, run_id, execution_id, now),
            )
            connection.execute("INSERT INTO creation_initializations(run_id) VALUES(?)", (run_id,))
            return {**find_creation(connection, owner_id, key_sha256), "reserved": True}

    def observe_creation(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            return current_creation(self._connection, receipt)

    def resume_creation(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Rebind enrolled evidence only; caller must hold its private OS lock."""
        with self._lock:
            actual = current_creation(self._connection, receipt)
            if self._connection.execute("SELECT 1 FROM creation_initializations WHERE run_id=?", (actual["run_id"],)).fetchone() is None:
                raise creation_error("CREATION_RESULT_UNKNOWN", "Legacy creation has no restartable evidence; it was not restarted.")
            return actual

    def prepare_creation_records(self, receipt: Mapping[str, Any], *, problem_id: str, metadata: Mapping[str, Any],
                                 project_id: str | None = None, target_claim_id: str | None = None,
                                 workflow_mode: str = "auto", register_result: bool = True,
                                 references: Sequence[Mapping[str, str]] = ()) -> dict[str, Any]:
        material = {"problem_id": problem_id, "metadata": dict(metadata), "project_id": project_id,
                    "target_claim_id": target_claim_id, "workflow_mode": workflow_mode,
                    "register_result": register_result, "references": [dict(r) for r in references]}
        encoded = canonical(material)
        if (len(encoded.encode()) > 16 * 1024 * 1024 or len(references) > 128 or not _ID.fullmatch(problem_id)
            or workflow_mode not in {"auto", "compact", "full"} or (target_claim_id is not None and project_id is None)
            or type(register_result) is not bool):
            raise creation_error()
        names: set[str] = set()
        for reference in references:
            if (set(reference) != {"name", "content", "source"} or not all(isinstance(v, str) for v in reference.values())
                or not reference["name"] or reference["name"] in names):
                raise creation_error()
            names.add(reference["name"])
        # Freeze the validated bytes before locking: mutable caller mappings
        # must not change the rows after their initialization hash was computed.
        material = json.loads(encoded)
        metadata, references = material["metadata"], material["references"]
        material_hash = digest_text(encoded)
        with self.transaction() as connection:
            actual = current_creation(connection, receipt)
            if actual["status"] != "pending":
                raise creation_error()
            run_id, now = actual["run_id"], actual["created_at"]
            checkpoint = connection.execute("SELECT * FROM creation_initializations WHERE run_id=?", (run_id,)).fetchone()
            if checkpoint is None:
                raise creation_error("CREATION_RESULT_UNKNOWN", "Legacy creation has no restartable evidence.")
            if checkpoint["database_sha256"] is not None:
                current_hash, run = projection(connection, run_id)
                if checkpoint["material_sha256"] != material_hash or current_hash != checkpoint["database_sha256"]:
                    raise creation_error("CREATION_DATABASE_CONFLICT", "Initialization facts changed; no records were replaced.")
                return run
            if checkpoint["material_sha256"] is not None or connection.execute("SELECT 1 FROM runs WHERE run_id=?", (run_id,)).fetchone():
                raise creation_error()
            snapshot_id, base_revision = _prepare_project(connection, actual, project_id, target_claim_id)
            prepared_metadata = {**dict(metadata), "project_snapshot_id": snapshot_id}
            connection.execute("INSERT INTO runs(run_id,problem_id,owner_id,state,status,metadata_json,created_at,updated_at) VALUES(?,?,?,'created','active',?,?,?)",
                               (run_id, problem_id, actual["owner_id"], canonical(prepared_metadata), now, now))
            if project_id is not None:
                connection.execute("INSERT INTO project_runs(run_id,project_id,project_snapshot_id,target_claim_id,base_revision_id,requested_workflow_mode,effective_workflow_mode,register_result,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                   (run_id, project_id, snapshot_id, target_claim_id, base_revision, workflow_mode,
                                    "full" if workflow_mode == "full" else "pending", int(register_result), now, now))
            _insert_references(connection, actual, project_id, references)
            database_hash, run = projection(connection, run_id)
            connection.execute("UPDATE creation_initializations SET material_sha256=?,database_sha256=? WHERE run_id=?", (material_hash, database_hash, run_id))
            return run

    def complete_creation(self, receipt: Mapping[str, Any], trace_id: str | None = None) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as connection:
            actual = current_creation(connection, receipt)
            if actual["status"] == "completed":
                row = connection.execute("SELECT * FROM runs WHERE run_id=? AND owner_id=?", (actual["run_id"], actual["owner_id"])).fetchone()
                if row is None:
                    raise creation_error()
                result = dict(row)
                result["metadata"] = json.loads(result.pop("metadata_json"))
                return result
            checkpoint = connection.execute("SELECT * FROM creation_initializations WHERE run_id=?", (actual["run_id"],)).fetchone()
            if checkpoint is None or not checkpoint["database_sha256"]:
                raise creation_error("CREATION_RESULT_UNKNOWN", "Initialization lacks a completed database checkpoint.")
            if projection(connection, actual["run_id"])[0] != checkpoint["database_sha256"]:
                raise creation_error("CREATION_DATABASE_CONFLICT", "Initialization facts changed; no transition was committed.")
            if trace_id is not None and trace_id != actual["execution_id"]:
                raise creation_error()
            return self._transition_on(connection, run_id=actual["run_id"], expected_state="created", after_state="assess",
                                       trace_id=actual["execution_id"], actor="system", reason="run_initialized", now=now)


def _prepare_project(connection: sqlite3.Connection, receipt: Mapping[str, Any], project_id: str | None,
                     target_claim_id: str | None) -> tuple[str | None, str | None]:
    if project_id is None:
        return None, None
    project = connection.execute("SELECT owner_id FROM projects WHERE project_id=?", (project_id,)).fetchone()
    if project is None or project[0] != receipt["owner_id"]:
        raise creation_error()
    base_revision = None
    if target_claim_id is not None:
        claim = connection.execute("SELECT project_id FROM claims WHERE claim_id=?", (target_claim_id,)).fetchone()
        if claim is None or claim[0] != project_id:
            raise creation_error()
        base = connection.execute("SELECT revision_id FROM claim_revisions WHERE claim_id=? AND lifecycle_status='ACTIVE' ORDER BY revision_number DESC LIMIT 1", (target_claim_id,)).fetchone()
        base_revision = base[0] if base else None
    rows = connection.execute(
        "SELECT cr.revision_id,cr.claim_id,cr.revision_number,cr.statement_tex,cr.evidence_status,cr.lifecycle_status,cr.conditions_json,cr.proof_sha256 "
        "FROM claim_revisions cr JOIN claims c USING(claim_id) WHERE c.project_id=? "
        "AND (cr.lifecycle_status='ACTIVE' OR cr.evidence_status IN ('VERIFIED','CONDITIONAL')) "
        "ORDER BY cr.claim_id,cr.revision_number LIMIT 4097", (project_id,),
    ).fetchall()
    if len(rows) > 4096:
        raise creation_error()
    revisions = []
    for row in rows:
        revision = dict(row)
        revision["conditions"] = json.loads(revision.pop("conditions_json"))
        revisions.append(revision)
    encoded = canonical(revisions)
    if len(encoded.encode()) > 8 * 1024 * 1024:
        raise creation_error()
    snapshot = f"ps-{receipt['execution_id']}"
    connection.execute("INSERT INTO project_snapshots VALUES(?,?,?,?,?,?)", (snapshot, project_id, receipt["owner_id"], encoded, digest_text(encoded), receipt["created_at"]))
    return snapshot, base_revision


def _insert_references(connection: sqlite3.Connection, receipt: Mapping[str, Any], project_id: str | None,
                       references: Sequence[Mapping[str, str]]) -> None:
    for index, reference in enumerate(references):
        digest = digest_text(reference["content"])
        reference_id = f"ref-{receipt['execution_id']}-{index}"
        source_id = f"source-{receipt['execution_id']}-{index}"
        metadata = canonical({"vault_name": reference["name"], "size": len(reference["content"].encode())})
        connection.execute("INSERT INTO references_registry(reference_id,run_id,project_id,identity_key,provider,title,source_uri,source_state,source_sha256,content_sha256,metadata_json,created_at,updated_at) VALUES(?,?,?,?,'inline',?,?,'candidate',?,?,?,?,?)",
                           (reference_id, receipt["run_id"], project_id, f"inline:{reference['name']}:{digest}", reference["name"], reference["source"], digest, digest, metadata, receipt["created_at"], receipt["created_at"]))
        connection.execute("INSERT INTO source_snapshots(source_snapshot_id,reference_id,provider,source_uri,content_sha256,content_type,metadata_json,created_at) VALUES(?,?,'inline',?,?,'text/plain',?,?)",
                           (source_id, reference_id, reference["source"], digest, canonical({"vault_name": reference["name"], "content": reference["content"]}), receipt["created_at"]))


def record_initialization(connection: sqlite3.Connection, *, before: Mapping[str, Any], run_id: str, expected_state: str,
                          after_state: str, actor: str, reason: str, trace_id: str, now: str) -> None:
    if expected_state != "created" or after_state != "assess":
        return
    row = connection.execute("SELECT * FROM creation_receipts WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        return
    if (row["status"] != "pending" or row["execution_id"] != trace_id or row["owner_id"] != before["owner_id"]
        or actor != "system" or reason != "run_initialized"):
        raise creation_error()
    connection.execute("UPDATE creation_receipts SET status='completed',completed_at=? WHERE run_id=?", (now, run_id))
