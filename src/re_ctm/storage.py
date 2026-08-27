from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .debug import utc_now
from .errors import ReCTMError


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
        self._initialize()

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
        schema = """
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            problem_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            state TEXT NOT NULL,
            status TEXT NOT NULL,
            epoch INTEGER NOT NULL DEFAULT 1,
            round_index INTEGER NOT NULL DEFAULT 0,
            transition_seq INTEGER NOT NULL DEFAULT 0,
            latex_passed INTEGER NOT NULL DEFAULT 0,
            verdict TEXT,
            sealed INTEGER NOT NULL DEFAULT 0,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS domains (
            domain_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            snapshot_id TEXT,
            order_index INTEGER,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            sealed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_domains_run
            ON domains(run_id, role, status, order_index);

        CREATE TABLE IF NOT EXISTS capabilities (
            nonce TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            domain_id TEXT NOT NULL REFERENCES domains(domain_id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            issued_state TEXT NOT NULL,
            permissions_json TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            revoked_at TEXT,
            revoke_reason TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_capabilities_run
            ON capabilities(run_id, domain_id, revoked);

        CREATE TABLE IF NOT EXISTS branches (
            branch_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            plan_id TEXT NOT NULL,
            domain_id TEXT NOT NULL REFERENCES domains(domain_id) ON DELETE CASCADE,
            snapshot_id TEXT NOT NULL,
            order_index INTEGER NOT NULL,
            status TEXT NOT NULL,
            result_path TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            sealed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_branches_run
            ON branches(run_id, status, order_index);

        CREATE TABLE IF NOT EXISTS steering (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            owner_id TEXT NOT NULL,
            message TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            consumed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS transitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL,
            trace_id TEXT NOT NULL,
            before_state TEXT NOT NULL,
            after_state TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            UNIQUE(run_id, sequence)
        );
        """
        with self._lock:
            self._connection.executescript(schema)

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
    for boolean in ("revoked", "sealed", "latex_passed", "consumed"):
        if boolean in payload:
            payload[boolean] = bool(payload[boolean])
    return payload
