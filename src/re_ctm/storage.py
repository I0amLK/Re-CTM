from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .debug import utc_now
from .errors import ReCTMError
from .storage_schema import (
    SCHEMA_MIGRATIONS_TABLE_SQL,
    V1_WORKFLOW_SCHEMA_SQL,
    V2_RESEARCH_SCHEMA_SQL,
)


STATE_SCHEMA_VERSION = 2
_REGISTRY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class StateStore:
    """Transactional SQLite store for workflow facts and capability revocation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA synchronous=FULL")
        try:
            self._initialize()
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")

    def _initialize(self) -> None:
        with self._lock:
            raw_version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if raw_version > STATE_SCHEMA_VERSION:
            raise ReCTMError(
                "STATE_SCHEMA_NEWER_THAN_RUNTIME",
                "The Re-CTM state database was created by a newer runtime.",
                category="conflict",
                details={"database_version": raw_version, "runtime_version": STATE_SCHEMA_VERSION},
            )
        version = raw_version
        if raw_version == 0:
            # The pre-v0.2 runtime did not set PRAGMA user_version. Re-running
            # the additive baseline CREATE IF NOT EXISTS script preserves any
            # existing run rows while ensuring every v1 table is present.
            self._migrate_0_to_1()
            version = 1
        if version == 1:
            self._migrate_1_to_2()
            version = 2
        if version != STATE_SCHEMA_VERSION:
            raise ReCTMError(
                "STATE_SCHEMA_MIGRATION_FAILED",
                "The Re-CTM state database could not be migrated to the current schema.",
                category="internal",
                details={"database_version": version, "runtime_version": STATE_SCHEMA_VERSION},
            )

    def schema_version(self) -> int:
        with self._lock:
            return int(self._connection.execute("PRAGMA user_version").fetchone()[0])

    def _migrate_0_to_1(self) -> None:
        applied_at = utc_now().replace("'", "''")
        with self._lock:
            self._connection.executescript(
                "BEGIN IMMEDIATE;\n"
                + V1_WORKFLOW_SCHEMA_SQL
                + SCHEMA_MIGRATIONS_TABLE_SQL
                + f"INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES(1, '{applied_at}', 'baseline workflow schema');\n"
                + "PRAGMA user_version = 1;\nCOMMIT;"
            )

    def _migrate_1_to_2(self) -> None:
        applied_at = utc_now().replace("'", "''")
        with self._lock:
            self._connection.executescript(
                "BEGIN IMMEDIATE;\n"
                + SCHEMA_MIGRATIONS_TABLE_SQL
                + V2_RESEARCH_SCHEMA_SQL
                + f"INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES(1, '{applied_at}', 'baseline workflow schema');\n"
                + f"INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES(2, '{applied_at}', 'v0.2 research registry and provenance schema');\n"
                + "PRAGMA user_version = 2;\nCOMMIT;"
            )

    def create_run(
        self,
        *,
        run_id: str,
        problem_id: str,
        owner_id: str,
        state: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        try:
            with self.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO runs (
                        run_id, problem_id, owner_id, state, status,
                        metadata_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
                    """,
                    (
                        run_id,
                        problem_id,
                        owner_id,
                        state,
                        _json(metadata or {}),
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ReCTMError(
                "RUN_ALREADY_EXISTS",
                f"Run already exists: {run_id}",
                category="conflict",
                details={"run_id": run_id},
            ) from exc
        return self.get_run(run_id)

    def get_run(self, run_id: str) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM runs WHERE run_id = ?", (run_id,))
        if row is None:
            raise ReCTMError(
                "RUN_NOT_FOUND",
                f"Unknown run: {run_id}",
                category="not_found",
                details={"run_id": run_id},
            )
        return _row_payload(row, json_fields=("metadata_json",))

    def list_runs(self, owner_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            """
            SELECT * FROM runs
            WHERE owner_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (owner_id, limit),
        )
        return [_row_payload(row, json_fields=("metadata_json",)) for row in rows]

    def update_run_metadata(
        self,
        run_id: str,
        updates: Mapping[str, Any],
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT metadata_json FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise ReCTMError("RUN_NOT_FOUND", f"Unknown run: {run_id}", category="not_found")
            metadata = _loads(row["metadata_json"])
            metadata.update(dict(updates))
            connection.execute(
                "UPDATE runs SET metadata_json = ?, updated_at = ? WHERE run_id = ?",
                (_json(metadata), utc_now(), run_id),
            )
        return self.get_run(run_id)

    # ------------------------------------------------------------------
    # Research project / claim registry (schema v2)

    def create_project(
        self,
        *,
        owner_id: str,
        title: str,
        project_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not owner_id.strip() or not title.strip():
            raise ReCTMError("INVALID_PROJECT", "Project owner and title are required.", category="validation")
        resolved = (project_id or f"project-{secrets.token_hex(6)}").strip()
        if not _REGISTRY_ID.fullmatch(resolved):
            raise ReCTMError(
                "INVALID_PROJECT_ID",
                "Project id must use only letters, digits, '.', '_', or '-' and start with an alphanumeric character.",
                category="validation",
            )
        now = utc_now()
        try:
            with self.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO projects(project_id, owner_id, title, metadata_json, created_at, updated_at)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (resolved, owner_id, title.strip(), _json(metadata or {}), now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ReCTMError(
                "PROJECT_ALREADY_EXISTS",
                "A project with this id already exists.",
                category="conflict",
                details={"project_id": resolved},
            ) from exc
        return self.get_project(resolved, owner_id=owner_id)

    def get_project(self, project_id: str, *, owner_id: str | None = None) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM projects WHERE project_id = ?", (project_id,))
        if row is None:
            raise ReCTMError("PROJECT_NOT_FOUND", "Unknown project.", category="not_found", details={"project_id": project_id})
        payload = _row_payload(row, json_fields=("metadata_json",))
        if owner_id is not None and payload["owner_id"] != owner_id:
            raise ReCTMError("PROJECT_OWNER_MISMATCH", "Project is not owned by the authenticated principal.", category="permission")
        return payload

    def list_projects(self, owner_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            "SELECT * FROM projects WHERE owner_id = ? ORDER BY updated_at DESC LIMIT ?",
            (owner_id, limit),
        )
        return [_row_payload(row, json_fields=("metadata_json",)) for row in rows]

    def create_claim(
        self,
        *,
        owner_id: str,
        project_id: str,
        title: str,
        claim_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.get_project(project_id, owner_id=owner_id)
        if not title.strip():
            raise ReCTMError("INVALID_CLAIM", "Claim title is required.", category="validation")
        resolved = (claim_id or f"claim-{secrets.token_hex(6)}").strip()
        if not _REGISTRY_ID.fullmatch(resolved):
            raise ReCTMError(
                "INVALID_CLAIM_ID",
                "Claim id must use only letters, digits, '.', '_', or '-' and start with an alphanumeric character.",
                category="validation",
            )
        now = utc_now()
        try:
            with self.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO claims(claim_id, project_id, title, metadata_json, created_at, updated_at)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (resolved, project_id, title.strip(), _json(metadata or {}), now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ReCTMError("CLAIM_ALREADY_EXISTS", "A claim with this id already exists.", category="conflict") from exc
        return self.get_claim(resolved, owner_id=owner_id)

    def get_claim(self, claim_id: str, *, owner_id: str | None = None) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM claims WHERE claim_id = ?", (claim_id,))
        if row is None:
            raise ReCTMError("CLAIM_NOT_FOUND", "Unknown claim.", category="not_found", details={"claim_id": claim_id})
        payload = _row_payload(row, json_fields=("metadata_json",))
        if owner_id is not None:
            self.get_project(payload["project_id"], owner_id=owner_id)
        return payload

    def list_claims(self, project_id: str, *, owner_id: str) -> list[dict[str, Any]]:
        self.get_project(project_id, owner_id=owner_id)
        rows = self._fetch_all("SELECT * FROM claims WHERE project_id = ? ORDER BY created_at", (project_id,))
        return [_row_payload(row, json_fields=("metadata_json",)) for row in rows]

    def list_claim_revisions(self, claim_id: str, *, owner_id: str) -> list[dict[str, Any]]:
        self.get_claim(claim_id, owner_id=owner_id)
        rows = self._fetch_all(
            "SELECT * FROM claim_revisions WHERE claim_id = ? ORDER BY revision_number",
            (claim_id,),
        )
        return [_row_payload(row, json_fields=("conditions_json", "metadata_json")) for row in rows]

    def get_claim_revision(self, revision_id: str, *, owner_id: str | None = None) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM claim_revisions WHERE revision_id = ?", (revision_id,))
        if row is None:
            raise ReCTMError("CLAIM_REVISION_NOT_FOUND", "Unknown claim revision.", category="not_found")
        payload = _row_payload(row, json_fields=("conditions_json", "metadata_json"))
        if owner_id is not None:
            self.get_claim(payload["claim_id"], owner_id=owner_id)
        return payload

    def current_claim_revision(self, claim_id: str, *, owner_id: str) -> dict[str, Any] | None:
        self.get_claim(claim_id, owner_id=owner_id)
        row = self._fetch_one(
            """
            SELECT * FROM claim_revisions
            WHERE claim_id = ? AND lifecycle_status = 'ACTIVE'
            ORDER BY revision_number DESC LIMIT 1
            """,
            (claim_id,),
        )
        return None if row is None else _row_payload(row, json_fields=("conditions_json", "metadata_json"))

    def create_open_claim_revision(
        self,
        *,
        owner_id: str,
        claim_id: str,
        statement_tex: str,
        conditions: Sequence[str] = (),
        expected_base_revision_id: str | None = None,
    ) -> dict[str, Any]:
        self.get_claim(claim_id, owner_id=owner_id)
        if not statement_tex.strip():
            raise ReCTMError("INVALID_CLAIM_REVISION", "Open claim revision requires a statement.", category="validation")
        if not isinstance(conditions, Sequence) or isinstance(conditions, (str, bytes)):
            raise ReCTMError("INVALID_CLAIM_REVISION", "Claim conditions must be an array of strings.", category="validation")
        normalized_conditions: list[str] = []
        for item in conditions:
            if not isinstance(item, str) or not item.strip():
                raise ReCTMError(
                    "INVALID_CLAIM_REVISION",
                    "Claim conditions must contain only non-empty strings.",
                    category="validation",
                )
            normalized_conditions.append(item.strip())
        now = utc_now()
        with self.transaction() as connection:
            active = connection.execute(
                "SELECT revision_id, revision_number FROM claim_revisions WHERE claim_id=? AND lifecycle_status='ACTIVE' ORDER BY revision_number DESC LIMIT 1",
                (claim_id,),
            ).fetchone()
            active_id = active["revision_id"] if active else None
            if expected_base_revision_id is not None and active_id != expected_base_revision_id:
                raise ReCTMError(
                    "CLAIM_REVISION_CONFLICT",
                    "The active claim revision changed before the owner revision was written.",
                    category="conflict",
                    retryable=True,
                    details={"expected": expected_base_revision_id, "actual": active_id},
                )
            revision_number = 1 if active is None else int(active["revision_number"]) + 1
            revision_id = f"{claim_id}-r{revision_number}"
            if active_id:
                connection.execute(
                    "UPDATE claim_revisions SET lifecycle_status='SUPERSEDED' WHERE revision_id=?",
                    (active_id,),
                )
            connection.execute(
                """
                INSERT INTO claim_revisions(
                    revision_id, claim_id, revision_number, statement_tex, evidence_status,
                    lifecycle_status, conditions_json, metadata_json, created_at
                ) VALUES(?, ?, ?, ?, 'OPEN', 'ACTIVE', ?, '{}', ?)
                """,
                (
                    revision_id,
                    claim_id,
                    revision_number,
                    statement_tex.strip(),
                    json.dumps(normalized_conditions, ensure_ascii=False),
                    now,
                ),
            )
        return self.get_claim_revision(revision_id, owner_id=owner_id)

    def create_project_snapshot(self, project_id: str, *, owner_id: str) -> dict[str, Any]:
        self.get_project(project_id, owner_id=owner_id)
        rows = self._fetch_all(
            """
            SELECT cr.revision_id, cr.claim_id, cr.revision_number, cr.statement_tex,
                   cr.evidence_status, cr.lifecycle_status, cr.conditions_json, cr.proof_sha256
            FROM claim_revisions cr
            JOIN claims c ON c.claim_id = cr.claim_id
            WHERE c.project_id = ?
              AND (cr.lifecycle_status = 'ACTIVE' OR cr.evidence_status IN ('VERIFIED', 'CONDITIONAL'))
            ORDER BY cr.claim_id, cr.revision_number
            """,
            (project_id,),
        )
        revisions: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["conditions"] = json.loads(item.pop("conditions_json") or "[]")
            revisions.append(item)
        canonical = json.dumps(revisions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        snapshot_id = f"ps-{secrets.token_hex(8)}"
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO project_snapshots(snapshot_id, project_id, owner_id, revisions_json, snapshot_sha256, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                (snapshot_id, project_id, owner_id, canonical, digest, utc_now()),
            )
        return self.get_project_snapshot(snapshot_id, owner_id=owner_id)

    def get_project_snapshot(self, snapshot_id: str, *, owner_id: str) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM project_snapshots WHERE snapshot_id = ?", (snapshot_id,))
        if row is None:
            raise ReCTMError("PROJECT_SNAPSHOT_NOT_FOUND", "Unknown project snapshot.", category="not_found")
        payload = dict(row)
        if payload["owner_id"] != owner_id:
            raise ReCTMError("PROJECT_OWNER_MISMATCH", "Project snapshot is not owned by the authenticated principal.", category="permission")
        payload["revisions"] = json.loads(payload.pop("revisions_json") or "[]")
        return payload

    def link_run_to_project(
        self,
        *,
        run_id: str,
        owner_id: str,
        project_id: str,
        project_snapshot_id: str,
        target_claim_id: str | None,
        base_revision_id: str | None,
        requested_workflow_mode: str,
        effective_workflow_mode: str,
        register_result: bool,
    ) -> dict[str, Any]:
        self.get_project(project_id, owner_id=owner_id)
        self.get_project_snapshot(project_snapshot_id, owner_id=owner_id)
        if target_claim_id:
            claim = self.get_claim(target_claim_id, owner_id=owner_id)
            if claim["project_id"] != project_id:
                raise ReCTMError("CLAIM_PROJECT_MISMATCH", "Target claim does not belong to the selected project.", category="validation")
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO project_runs(
                    run_id, project_id, project_snapshot_id, target_claim_id, base_revision_id,
                    requested_workflow_mode, effective_workflow_mode, register_result,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, project_id, project_snapshot_id, target_claim_id, base_revision_id,
                    requested_workflow_mode, effective_workflow_mode, int(register_result), now, now,
                ),
            )
        return self.get_project_run(run_id, owner_id=owner_id) or {}

    def get_project_run(self, run_id: str, *, owner_id: str | None = None) -> dict[str, Any] | None:
        row = self._fetch_one("SELECT * FROM project_runs WHERE run_id = ?", (run_id,))
        if row is None:
            return None
        payload = _row_payload(row, json_fields=("promotion_json",))
        payload["register_result"] = bool(payload["register_result"])
        if owner_id is not None:
            self.get_project(payload["project_id"], owner_id=owner_id)
        return payload

    def set_project_run_mode(self, run_id: str, mode: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE project_runs SET effective_workflow_mode = ?, updated_at = ? WHERE run_id = ?",
                (mode, utc_now(), run_id),
            )

    def write_proof_manifest(self, run_id: str, manifest: Mapping[str, Any]) -> dict[str, Any]:
        canonical = json.dumps(dict(manifest), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO proof_manifests(run_id, manifest_json, sha256, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET manifest_json=excluded.manifest_json, sha256=excluded.sha256, updated_at=excluded.updated_at
                """,
                (run_id, canonical, digest, now, now),
            )
        return {"run_id": run_id, "manifest": json.loads(canonical), "sha256": digest}

    def read_proof_manifest(self, run_id: str) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM proof_manifests WHERE run_id = ?", (run_id,))
        if row is None:
            raise ReCTMError("PROOF_MANIFEST_NOT_FOUND", "The run has no proof manifest.", category="not_found")
        return {"run_id": run_id, "manifest": json.loads(row["manifest_json"]), "sha256": row["sha256"]}

    def register_reference(
        self,
        *,
        run_id: str,
        project_id: str | None,
        provider: str,
        identity_key: str,
        title: str = "",
        paper_id: str = "",
        arxiv_id: str = "",
        doi: str = "",
        theorem_id: str = "",
        source_uri: str = "",
        source_state: str = "candidate",
        source_sha256: str = "",
        content_sha256: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        existing = self._fetch_one(
            "SELECT reference_id FROM references_registry WHERE run_id=? AND identity_key=?",
            (run_id, identity_key),
        )
        if existing is not None:
            return self.get_reference(existing["reference_id"])
        reference_id = f"ref-{secrets.token_hex(8)}"
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO references_registry(
                    reference_id, run_id, project_id, identity_key, provider, title, paper_id,
                    arxiv_id, doi, theorem_id, source_uri, source_state, source_sha256,
                    content_sha256, metadata_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reference_id, run_id, project_id, identity_key, provider, title, paper_id,
                    arxiv_id, doi, theorem_id, source_uri, source_state, source_sha256,
                    content_sha256, _json(metadata or {}), now, now,
                ),
            )
        return self.get_reference(reference_id)

    def get_reference(self, reference_id: str) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM references_registry WHERE reference_id=?", (reference_id,))
        if row is None:
            raise ReCTMError("REFERENCE_NOT_FOUND", "Unknown reference.", category="not_found")
        return _row_payload(row, json_fields=("metadata_json",))

    def create_source_snapshot(
        self,
        *,
        reference_id: str,
        provider: str,
        source_uri: str,
        content: str,
        content_type: str = "application/json",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.get_reference(reference_id)
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        snapshot_id = f"source-{secrets.token_hex(8)}"
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO source_snapshots(
                    source_snapshot_id, reference_id, provider, source_uri,
                    content_sha256, content_type, metadata_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id, reference_id, provider, source_uri, digest,
                    content_type, _json({**dict(metadata or {}), "content": content}), utc_now(),
                ),
            )
            connection.execute(
                "UPDATE references_registry SET source_sha256=?, content_sha256=?, updated_at=? WHERE reference_id=?",
                (digest, digest, utc_now(), reference_id),
            )
        return {
            "source_snapshot_id": snapshot_id,
            "reference_id": reference_id,
            "content_sha256": digest,
            "source_uri": source_uri,
        }

    def list_source_snapshots(self, reference_id: str) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            "SELECT * FROM source_snapshots WHERE reference_id=? ORDER BY created_at",
            (reference_id,),
        )
        return [_row_payload(row, json_fields=("metadata_json",)) for row in rows]

    def list_run_references(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            "SELECT * FROM references_registry WHERE run_id=? ORDER BY created_at",
            (run_id,),
        )
        return [_row_payload(row, json_fields=("metadata_json",)) for row in rows]

    def write_reference_audit(
        self,
        *,
        run_id: str,
        reference_id: str,
        disposition: str,
        evidence_basis: str,
        evidence_locator: str,
        verifier_domain_id: str,
        proof_sha256: str,
        proof_manifest_sha256: str,
        material: bool,
        assumptions_checked: bool,
        notation_checked: bool,
        source_checked: bool,
        independently_rederived: bool,
        notes: str = "",
    ) -> dict[str, Any]:
        reference = self.get_reference(reference_id)
        if reference["run_id"] != run_id:
            raise ReCTMError(
                "REFERENCE_RUN_MISMATCH",
                "Reference does not belong to this run.",
                category="permission",
            )
        if disposition not in {"SOURCE_VERIFIED", "INDEPENDENTLY_REDERIVED", "UNRESOLVED", "NOT_MATERIAL"}:
            raise ReCTMError("INVALID_REFERENCE_DISPOSITION", "Unsupported reference audit disposition.", category="validation")
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO reference_audits(
                    run_id, reference_id, disposition, evidence_basis, evidence_locator,
                    verifier_domain_id, proof_sha256, proof_manifest_sha256,
                    material, assumptions_checked, notation_checked, source_checked,
                    independently_rederived, notes, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, reference_id) DO UPDATE SET
                    disposition=excluded.disposition,
                    evidence_basis=excluded.evidence_basis,
                    evidence_locator=excluded.evidence_locator,
                    verifier_domain_id=excluded.verifier_domain_id,
                    proof_sha256=excluded.proof_sha256,
                    proof_manifest_sha256=excluded.proof_manifest_sha256,
                    material=excluded.material,
                    assumptions_checked=excluded.assumptions_checked,
                    notation_checked=excluded.notation_checked,
                    source_checked=excluded.source_checked,
                    independently_rederived=excluded.independently_rederived,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
                """,
                (
                    run_id, reference_id, disposition, evidence_basis, evidence_locator,
                    verifier_domain_id, proof_sha256, proof_manifest_sha256,
                    int(material), int(assumptions_checked), int(notation_checked),
                    int(source_checked), int(independently_rederived), notes, now, now,
                ),
            )
        return self.get_reference_audit(run_id, reference_id)

    def get_reference_audit(self, run_id: str, reference_id: str) -> dict[str, Any]:
        row = self._fetch_one(
            "SELECT * FROM reference_audits WHERE run_id=? AND reference_id=?",
            (run_id, reference_id),
        )
        if row is None:
            raise ReCTMError("REFERENCE_AUDIT_NOT_FOUND", "Reference has not been audited.", category="not_found")
        return _row_payload(row)

    def list_reference_audits(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            """
            SELECT ra.*, rr.title, rr.paper_id, rr.arxiv_id, rr.doi, rr.theorem_id,
                   rr.source_uri, rr.source_state, rr.source_sha256, rr.content_sha256
            FROM reference_audits ra
            JOIN references_registry rr ON rr.reference_id = ra.reference_id
            WHERE ra.run_id=? ORDER BY ra.audit_id
            """,
            (run_id,),
        )
        return [_row_payload(row) for row in rows]

    def promote_verified_run(
        self,
        *,
        run_id: str,
        owner_id: str,
        statement_tex: str,
        proof_sha256: str,
        effective_conditions: Sequence[str],
        manifest: Mapping[str, Any],
    ) -> dict[str, Any]:
        project_run = self.get_project_run(run_id, owner_id=owner_id)
        if project_run is None:
            return {"status": "not_requested"}
        if not project_run["register_result"] or not project_run.get("target_claim_id"):
            result = {"status": "not_requested"}
            with self.transaction() as connection:
                connection.execute(
                    "UPDATE project_runs SET promotion_status='not_requested', promotion_json=?, updated_at=? WHERE run_id=?",
                    (_json(result), utc_now(), run_id),
                )
            return result
        if project_run.get("promoted_revision_id"):
            return {
                "status": "already_promoted",
                "revision": self.get_claim_revision(project_run["promoted_revision_id"], owner_id=owner_id),
            }
        claim_id = str(project_run["target_claim_id"])
        current = self.current_claim_revision(claim_id, owner_id=owner_id)
        expected_base = project_run.get("base_revision_id")
        current_id = current["revision_id"] if current else None
        if current_id != expected_base:
            conflict = {
                "status": "conflict",
                "expected_base_revision_id": expected_base,
                "current_revision_id": current_id,
            }
            with self.transaction() as connection:
                connection.execute(
                    "UPDATE project_runs SET promotion_status='conflict', promotion_json=?, updated_at=? WHERE run_id=?",
                    (_json(conflict), utc_now(), run_id),
                )
            return conflict
        revision_number = 1 if current is None else int(current["revision_number"]) + 1
        revision_id = f"{claim_id}-r{revision_number}"
        conditions = sorted(set(str(item).strip() for item in effective_conditions if str(item).strip()))
        evidence_status = "CONDITIONAL" if conditions else "VERIFIED"
        dependencies = [
            str(item) for item in manifest.get("dependency_revision_ids", []) if isinstance(item, str)
        ]
        now = utc_now()
        with self.transaction() as connection:
            active = connection.execute(
                "SELECT revision_id, revision_number FROM claim_revisions WHERE claim_id=? AND lifecycle_status='ACTIVE' ORDER BY revision_number DESC LIMIT 1",
                (claim_id,),
            ).fetchone()
            active_id = active["revision_id"] if active else None
            if active_id != expected_base:
                conflict = {
                    "status": "conflict",
                    "expected_base_revision_id": expected_base,
                    "current_revision_id": active_id,
                }
                connection.execute(
                    "UPDATE project_runs SET promotion_status='conflict', promotion_json=?, updated_at=? WHERE run_id=?",
                    (_json(conflict), now, run_id),
                )
                return conflict
            if active_id:
                connection.execute(
                    "UPDATE claim_revisions SET lifecycle_status='SUPERSEDED' WHERE revision_id=?",
                    (active_id,),
                )
            connection.execute(
                """
                INSERT INTO claim_revisions(
                    revision_id, claim_id, revision_number, statement_tex, evidence_status,
                    lifecycle_status, source_run_id, proof_sha256, conditions_json, metadata_json, created_at
                ) VALUES(?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
                """,
                (
                    revision_id, claim_id, revision_number, statement_tex, evidence_status,
                    run_id, proof_sha256, json.dumps(conditions, ensure_ascii=False),
                    _json({"workflow_protocol_version": 2}), now,
                ),
            )
            project_id = str(project_run["project_id"])
            for dependency_id in dependencies:
                dep = connection.execute(
                    "SELECT cr.revision_id FROM claim_revisions cr JOIN claims c ON c.claim_id=cr.claim_id WHERE cr.revision_id=? AND c.project_id=?",
                    (dependency_id, project_id),
                ).fetchone()
                if dep is None:
                    raise ReCTMError(
                        "DEPENDENCY_NOT_IN_PROJECT",
                        "Proof manifest dependency is not a revision in the project.",
                        category="validation",
                        details={"revision_id": dependency_id},
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO claim_edges(project_id, from_revision_id, to_revision_id, edge_type, created_at) VALUES(?, ?, ?, 'depends_on', ?)",
                    (project_id, revision_id, dependency_id, now),
                )
            if active_id:
                connection.execute(
                    "INSERT OR IGNORE INTO claim_edges(project_id, from_revision_id, to_revision_id, edge_type, created_at) VALUES(?, ?, ?, 'supersedes', ?)",
                    (project_id, revision_id, active_id, now),
                )
            promotion = {"status": "promoted", "revision_id": revision_id}
            connection.execute(
                "UPDATE project_runs SET promotion_status='promoted', promoted_revision_id=?, promotion_json=?, updated_at=? WHERE run_id=?",
                (revision_id, _json(promotion), now, run_id),
            )
        return {"status": "promoted", "revision": self.get_claim_revision(revision_id, owner_id=owner_id)}

    def project_dependency_graph(self, project_id: str, *, owner_id: str) -> dict[str, Any]:
        project = self.get_project(project_id, owner_id=owner_id)
        claims = self.list_claims(project_id, owner_id=owner_id)
        revisions: list[dict[str, Any]] = []
        for claim in claims:
            revisions.extend(self.list_claim_revisions(claim["claim_id"], owner_id=owner_id))
        edges = [dict(row) for row in self._fetch_all("SELECT * FROM claim_edges WHERE project_id=? ORDER BY edge_id", (project_id,))]
        return {"project": project, "claims": claims, "revisions": revisions, "edges": edges}

    def transition_run(
        self,
        *,
        run_id: str,
        expected_state: str,
        after_state: str,
        trace_id: str,
        actor: str,
        reason: str,
        evidence: Mapping[str, Any] | None = None,
        increment_epoch: bool = True,
        status: str | None = None,
        latex_passed: bool | None = None,
        verdict: str | None = None,
        sealed: bool | None = None,
        round_delta: int = 0,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise ReCTMError("RUN_NOT_FOUND", f"Unknown run: {run_id}", category="not_found")
            if row["state"] != expected_state:
                raise ReCTMError(
                    "STATE_CONFLICT",
                    "The run changed state before this transition was committed.",
                    category="conflict",
                    retryable=True,
                    details={
                        "run_id": run_id,
                        "expected": expected_state,
                        "actual": row["state"],
                    },
                )
            sequence = int(row["transition_seq"]) + 1
            epoch = int(row["epoch"]) + (1 if increment_epoch else 0)
            fields = {
                "state": after_state,
                "epoch": epoch,
                "transition_seq": sequence,
                "round_index": int(row["round_index"]) + round_delta,
                "updated_at": now,
                "status": status if status is not None else row["status"],
                "latex_passed": (
                    int(latex_passed) if latex_passed is not None else row["latex_passed"]
                ),
                "verdict": verdict if verdict is not None else row["verdict"],
                "sealed": int(sealed) if sealed is not None else row["sealed"],
            }
            connection.execute(
                """
                UPDATE runs SET
                    state = :state,
                    epoch = :epoch,
                    transition_seq = :transition_seq,
                    round_index = :round_index,
                    updated_at = :updated_at,
                    status = :status,
                    latex_passed = :latex_passed,
                    verdict = :verdict,
                    sealed = :sealed
                WHERE run_id = :run_id
                """,
                {**fields, "run_id": run_id},
            )
            connection.execute(
                """
                INSERT INTO transitions (
                    run_id, sequence, trace_id, before_state, after_state,
                    actor, reason, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    sequence,
                    trace_id,
                    expected_state,
                    after_state,
                    actor,
                    reason,
                    _json(evidence or {}),
                    now,
                ),
            )
            if increment_epoch:
                connection.execute(
                    """
                    UPDATE capabilities
                    SET revoked = 1, revoked_at = ?, revoke_reason = 'run_epoch_advanced'
                    WHERE run_id = ? AND revoked = 0
                    """,
                    (now, run_id),
                )
        return self.get_run(run_id)

    def create_domain(
        self,
        *,
        domain_id: str,
        run_id: str,
        role: str,
        snapshot_id: str | None = None,
        order_index: int | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO domains (
                    domain_id, run_id, role, status, snapshot_id,
                    order_index, metadata_json, created_at
                ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?)
                """,
                (
                    domain_id,
                    run_id,
                    role,
                    snapshot_id,
                    order_index,
                    _json(metadata or {}),
                    now,
                ),
            )
        return self.get_domain(domain_id)

    def get_domain(self, domain_id: str) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM domains WHERE domain_id = ?", (domain_id,))
        if row is None:
            raise ReCTMError(
                "DOMAIN_NOT_FOUND",
                f"Unknown domain: {domain_id}",
                category="not_found",
            )
        return _row_payload(row, json_fields=("metadata_json",))

    def list_domains(
        self,
        run_id: str,
        *,
        role: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["run_id = ?"]
        values: list[Any] = [run_id]
        if role is not None:
            clauses.append("role = ?")
            values.append(role)
        if status is not None:
            clauses.append("status = ?")
            values.append(status)
        rows = self._fetch_all(
            f"SELECT * FROM domains WHERE {' AND '.join(clauses)} ORDER BY order_index, created_at",
            tuple(values),
        )
        return [_row_payload(row, json_fields=("metadata_json",)) for row in rows]

    def seal_domain(self, domain_id: str) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT status FROM domains WHERE domain_id = ?",
                (domain_id,),
            ).fetchone()
            if row is None:
                raise ReCTMError("DOMAIN_NOT_FOUND", f"Unknown domain: {domain_id}", category="not_found")
            if row["status"] != "open":
                raise ReCTMError(
                    "DOMAIN_NOT_OPEN",
                    f"Domain is not open: {domain_id}",
                    category="conflict",
                )
            connection.execute(
                "UPDATE domains SET status = 'sealed', sealed_at = ? WHERE domain_id = ?",
                (now, domain_id),
            )
            connection.execute(
                """
                UPDATE capabilities
                SET revoked = 1, revoked_at = ?, revoke_reason = 'domain_sealed'
                WHERE domain_id = ? AND revoked = 0
                """,
                (now, domain_id),
            )
        return self.get_domain(domain_id)

    def insert_capability(
        self,
        *,
        nonce: str,
        run_id: str,
        domain_id: str,
        role: str,
        epoch: int,
        issued_state: str,
        permissions: Sequence[str],
        issued_at: int,
        expires_at: int,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO capabilities (
                    nonce, run_id, domain_id, role, epoch, issued_state,
                    permissions_json, issued_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    nonce,
                    run_id,
                    domain_id,
                    role,
                    epoch,
                    issued_state,
                    _json(list(permissions)),
                    issued_at,
                    expires_at,
                ),
            )

    def get_capability(self, nonce: str) -> dict[str, Any] | None:
        row = self._fetch_one("SELECT * FROM capabilities WHERE nonce = ?", (nonce,))
        return None if row is None else _row_payload(row, json_fields=("permissions_json",))

    def revoke_capability(self, nonce: str, reason: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                UPDATE capabilities
                SET revoked = 1, revoked_at = ?, revoke_reason = ?
                WHERE nonce = ? AND revoked = 0
                """,
                (utc_now(), reason, nonce),
            )

    def create_branch(
        self,
        *,
        branch_id: str,
        run_id: str,
        plan_id: str,
        domain_id: str,
        snapshot_id: str,
        order_index: int,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO branches (
                    branch_id, run_id, plan_id, domain_id, snapshot_id,
                    order_index, status, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    branch_id,
                    run_id,
                    plan_id,
                    domain_id,
                    snapshot_id,
                    order_index,
                    _json(metadata or {}),
                    utc_now(),
                ),
            )
        return self.get_branch(branch_id)

    def get_branch(self, branch_id: str) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM branches WHERE branch_id = ?", (branch_id,))
        if row is None:
            raise ReCTMError(
                "BRANCH_NOT_FOUND",
                f"Unknown branch: {branch_id}",
                category="not_found",
            )
        return _row_payload(row, json_fields=("metadata_json",))

    def list_branches(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            "SELECT * FROM branches WHERE run_id = ? ORDER BY order_index",
            (run_id,),
        )
        return [_row_payload(row, json_fields=("metadata_json",)) for row in rows]

    def update_branch_status(
        self,
        branch_id: str,
        status: str,
        *,
        result_path: str | None = None,
    ) -> dict[str, Any]:
        sealed_at = utc_now() if status == "sealed" else None
        with self.transaction() as connection:
            result = connection.execute(
                """
                UPDATE branches
                SET status = ?, result_path = COALESCE(?, result_path), sealed_at = COALESCE(?, sealed_at)
                WHERE branch_id = ?
                """,
                (status, result_path, sealed_at, branch_id),
            )
            if result.rowcount != 1:
                raise ReCTMError("BRANCH_NOT_FOUND", f"Unknown branch: {branch_id}", category="not_found")
        return self.get_branch(branch_id)

    def add_steering(self, run_id: str, owner_id: str, message: str) -> int:
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO steering (run_id, owner_id, message, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (run_id, owner_id, message, utc_now()),
            )
            return int(cursor.lastrowid)

    def consume_steering(self, run_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        with self.transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM steering
                WHERE run_id = ? AND consumed = 0
                ORDER BY id
                LIMIT ?
                """,
                (run_id, limit),
            ).fetchall()
            if rows:
                ids = [int(row["id"]) for row in rows]
                placeholders = ",".join("?" for _ in ids)
                connection.execute(
                    f"UPDATE steering SET consumed = 1, consumed_at = ? WHERE id IN ({placeholders})",
                    (utc_now(), *ids),
                )
        return [dict(row) for row in rows]

    def list_transitions(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            "SELECT * FROM transitions WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        )
        return [_row_payload(row, json_fields=("evidence_json",)) for row in rows]

    def _fetch_one(self, query: str, values: tuple[Any, ...]) -> sqlite3.Row | None:
        with self._lock:
            return self._connection.execute(query, values).fetchone()

    def _fetch_all(self, query: str, values: tuple[Any, ...]) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._connection.execute(query, values).fetchall())


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value: str) -> dict[str, Any]:
    loaded = json.loads(value or "{}")
    return loaded if isinstance(loaded, dict) else {}


def _row_payload(
    row: sqlite3.Row,
    *,
    json_fields: Sequence[str] = (),
) -> dict[str, Any]:
    payload = dict(row)
    for field in json_fields:
        raw = payload.pop(field, None)
        name = field.removesuffix("_json")
        payload[name] = json.loads(raw or "{}")
    for boolean in (
        "revoked", "sealed", "latex_passed", "consumed", "register_result",
        "material", "assumptions_checked", "notation_checked", "source_checked",
        "independently_rederived",
    ):
        if boolean in payload:
            payload[boolean] = bool(payload[boolean])
    return payload
