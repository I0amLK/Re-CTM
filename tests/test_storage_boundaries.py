from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from re_ctm.errors import ReCTMError
from re_ctm.storage import StateStore


class StorageBoundaryTestCase(unittest.TestCase):
    def test_failed_v2_migration_rolls_back_partial_schema_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE projects(x TEXT);
                PRAGMA user_version = 1;
                """
            )
            connection.close()

            with self.assertRaises(sqlite3.OperationalError):
                StateStore(path)

            inspection = sqlite3.connect(path)
            try:
                version = int(inspection.execute("PRAGMA user_version").fetchone()[0])
                tables = {
                    str(row[0])
                    for row in inspection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
            finally:
                inspection.close()
            self.assertEqual(version, 1)
            self.assertEqual(tables, {"projects"})

    def _linked_project_run(self, store: StateStore) -> tuple[str, str, str]:
        owner = "owner"
        project = store.create_project(owner_id=owner, title="Project")
        claim = store.create_claim(
            owner_id=owner,
            project_id=project["project_id"],
            title="Claim",
        )
        base = store.create_open_claim_revision(
            owner_id=owner,
            claim_id=claim["claim_id"],
            statement_tex=r"$1=1$.",
        )
        snapshot = store.create_project_snapshot(project["project_id"], owner_id=owner)
        run_id = "run-storage-boundary"
        store.create_run(
            run_id=run_id,
            problem_id="storage-boundary",
            owner_id=owner,
            state="done",
            metadata={"workflow_protocol_version": 2},
        )
        store.link_run_to_project(
            run_id=run_id,
            owner_id=owner,
            project_id=project["project_id"],
            project_snapshot_id=snapshot["snapshot_id"],
            target_claim_id=claim["claim_id"],
            base_revision_id=base["revision_id"],
            requested_workflow_mode="compact",
            effective_workflow_mode="compact",
            register_result=True,
        )
        return run_id, claim["claim_id"], base["revision_id"]

    def test_promotion_dependency_failure_rolls_back_entire_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                run_id, claim_id, base_revision_id = self._linked_project_run(store)
                with self.assertRaises(ReCTMError) as caught:
                    store.promote_verified_run(
                        run_id=run_id,
                        owner_id="owner",
                        statement_tex=r"$1=1$.",
                        proof_sha256="a" * 64,
                        effective_conditions=[],
                        manifest={"dependency_revision_ids": ["missing-revision"]},
                    )
                self.assertEqual(caught.exception.code, "DEPENDENCY_NOT_IN_PROJECT")

                current = store.current_claim_revision(claim_id, owner_id="owner")
                assert current is not None
                self.assertEqual(current["revision_id"], base_revision_id)
                self.assertEqual(current["lifecycle_status"], "ACTIVE")
                revisions = store.list_claim_revisions(claim_id, owner_id="owner")
                self.assertEqual([item["revision_id"] for item in revisions], [base_revision_id])
                project_run = store.get_project_run(run_id, owner_id="owner")
                assert project_run is not None
                self.assertEqual(project_run["promotion_status"], "pending")
                self.assertIsNone(project_run["promoted_revision_id"])
            finally:
                store.close()

    def test_repeated_promotion_is_idempotent_by_source_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.sqlite3")
            try:
                run_id, claim_id, _ = self._linked_project_run(store)
                first = store.promote_verified_run(
                    run_id=run_id,
                    owner_id="owner",
                    statement_tex=r"$1=1$.",
                    proof_sha256="b" * 64,
                    effective_conditions=[],
                    manifest={"dependency_revision_ids": []},
                )
                second = store.promote_verified_run(
                    run_id=run_id,
                    owner_id="owner",
                    statement_tex=r"$1=1$.",
                    proof_sha256="b" * 64,
                    effective_conditions=[],
                    manifest={"dependency_revision_ids": []},
                )
                self.assertEqual(first["status"], "promoted")
                self.assertEqual(second["status"], "already_promoted")
                self.assertEqual(
                    second["revision"]["revision_id"],
                    first["revision"]["revision_id"],
                )
                revisions = store.list_claim_revisions(claim_id, owner_id="owner")
                self.assertEqual(len(revisions), 2)
                self.assertEqual(
                    [item["lifecycle_status"] for item in revisions],
                    ["SUPERSEDED", "ACTIVE"],
                )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
