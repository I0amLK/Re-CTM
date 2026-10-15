from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from re_ctm.capabilities import CapabilityClaims, default_permissions, role_for_state
from re_ctm.enums import WorkflowState
from re_ctm.errors import ReCTMError
from re_ctm.storage import StateStore
from re_ctm import storage_schema as schema


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


MIGRATIONS = [
    schema.V1_WORKFLOW_SCHEMA_SQL + schema.SCHEMA_MIGRATIONS_TABLE_SQL,
    schema.V2_RESEARCH_SCHEMA_SQL, schema.V3_SUBMISSION_RECEIPTS_SQL,
    schema.V4_RECOVERY_SQL, schema.V5_CREATION_INITIALIZATION_SQL,
    schema.V6_CALLER_WRITE_JOURNAL_SQL, schema.V7_ATOMIC_ACTION_SQL,
    schema.V8_FACT_MEMORY_SQL,
]


class MigrationEightTests(unittest.TestCase):
    def test_every_supported_schema_preserves_runs_and_existing_receipts(self) -> None:
        for version in range(1, 9):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.db"
                connection = sqlite3.connect(path)
                for index, sql in enumerate(MIGRATIONS[:version], 1):
                    connection.executescript(sql)
                    connection.execute("INSERT INTO schema_migrations VALUES(?, 'past', 'historical')", (index,))
                connection.executescript("""
                    INSERT INTO runs(run_id,problem_id,owner_id,state,status,metadata_json,created_at,updated_at)
                    VALUES('run','problem','owner','assess','active','{"workflow_protocol_version":2}','past','past');
                    INSERT INTO domains(domain_id,run_id,role,status,created_at) VALUES('domain','run','generator','open','past');
                """)
                if version >= 3:
                    connection.execute("INSERT INTO step_receipts(capability_sha256,owner_id,workspace_sha256,request_sha256,run_id,domain_id,role,epoch,issued_state,status,created_at) VALUES(?,'owner',?,?,'run','domain','generator',1,'assess','pending','past')", ("a" * 64, "b" * 64, "c" * 64))
                connection.execute(f"PRAGMA user_version={version}")
                connection.commit()
                connection.close()
                store = StateStore(path)
                try:
                    self.assertEqual(store.schema_version(), 8)
                    run = store.get_run("run")
                    self.assertEqual(run["metadata"]["workflow_protocol_version"], 2)
                    self.assertEqual(run["created_at"], "past")
                    self.assertEqual(store._fetch_one("SELECT COUNT(*) FROM schema_migrations", ())[0], 8)
                    columns = {row[1] for row in store._connection.execute("PRAGMA table_info(claim_revisions)")}
                    self.assertIn("fact_id", columns)
                    if version >= 3:
                        receipt = store.find_submission_receipt("a" * 64, "owner", "run")
                        self.assertEqual(receipt["status"], "pending")
                        self.assertEqual(store.pending_submission_status("owner", "run")["phase"], "legacy_unknown")
                        with self.assertRaises(ReCTMError) as caught:
                            store.reconcile_unstarted_submission(receipt)
                        self.assertEqual(caught.exception.code, "RESULT_UNKNOWN")
                finally:
                    store.close()

    def test_v8_failure_rolls_back_facts_column_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            connection = sqlite3.connect(path)
            for sql in MIGRATIONS[:7]:
                connection.executescript(sql)
            connection.execute("CREATE TABLE fact_edges(legacy TEXT)")
            connection.execute("PRAGMA user_version=7")
            connection.commit()
            connection.close()
            with self.assertRaises(sqlite3.OperationalError):
                StateStore(path)
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 7)
                self.assertNotIn("fact_id", {row[1] for row in connection.execute("PRAGMA table_info(claim_revisions)")})
                self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='facts'").fetchone())
            finally:
                connection.close()

    def test_newer_database_is_rejected_without_schema_edits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version=9")
            connection.close()
            with self.assertRaises(ReCTMError) as caught:
                StateStore(path)
            self.assertEqual(caught.exception.code, "STATE_SCHEMA_NEWER_THAN_RUNTIME")
            connection = sqlite3.connect(path)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0], 0)
            connection.close()


    def test_read_only_store_neither_migrates_nor_creates_and_blocks_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            with self.assertRaises(sqlite3.OperationalError):
                StateStore.open_read_only(path)
            self.assertFalse(path.exists())
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version=7")
            connection.close()
            before = path.read_bytes()
            with self.assertRaises(ReCTMError) as caught:
                StateStore.open_read_only(path)
            self.assertEqual(caught.exception.code, "STATE_SCHEMA_NOT_CURRENT")
            self.assertEqual(path.read_bytes(), before)
            path.unlink()
            store = StateStore(path)
            store.create_run(run_id="run", problem_id="problem", owner_id="owner", state="assess")
            store.close()
            before = path.read_bytes()
            reader = StateStore.open_read_only(path)
            try:
                self.assertEqual(reader.get_run("run")["state"], "assess")
                with self.assertRaises(ReCTMError) as caught:
                    reader.update_run_metadata("run", {"write": True})
                self.assertEqual(caught.exception.code, "STATE_READ_ONLY")
                with self.assertRaises(sqlite3.OperationalError):
                    reader._connection.execute("UPDATE runs SET state='done'")
            finally:
                reader.close()
            self.assertEqual(path.read_bytes(), before)


class ReceiptRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.store = StateStore(self.path)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def task(self, state: str = "assess", run_id: str = "run") -> CapabilityClaims:
        role = role_for_state(WorkflowState(state))
        self.store.create_run(run_id=run_id, problem_id="problem", owner_id="owner", state=state)
        self.store.create_domain(domain_id=f"{run_id}-domain", run_id=run_id, role=role.value)
        now = int(time.time())
        claims = CapabilityClaims(f"{run_id}-nonce", run_id, "owner", f"{run_id}-domain", role, 1,
                                  WorkflowState(state), default_permissions(role), now, now + 3600)
        self.store.insert_capability(nonce=claims.nonce, run_id=run_id, domain_id=claims.domain_id,
                                     role=role.value, epoch=1, issued_state=state, permissions=claims.permissions,
                                     issued_at=now, expires_at=now + 3600)
        return claims

    def reserve(self, claims: CapabilityClaims) -> dict:
        return self.store.reserve_submission(claims, capability_sha256=digest(claims.nonce),
                                             workspace_sha256=digest("workspace"), request_sha256=digest("request"))

    def execution(self, state: str = "assess", writes: int = 1) -> tuple[CapabilityClaims, dict, dict]:
        claims = self.task(state)
        receipt = self.reserve(claims)
        execution = self.store.activate_submission(receipt, claims, writes)
        return claims, receipt, execution

    def restart(self) -> None:
        self.store.close()
        self.store = StateStore(self.path)

    def trigger(self, table: str, event: str) -> None:
        with self.store.transaction() as connection:
            connection.execute(f"CREATE TRIGGER inject_failure BEFORE {event} ON {table} BEGIN SELECT RAISE(ABORT,'injected storage failure'); END")

    def assert_code(self, code: str, action) -> None:
        with self.assertRaises(ReCTMError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_reservation_replay_binding_and_pending_fence(self) -> None:
        claims = self.task()
        receipt = self.reserve(claims)
        self.assertTrue(receipt["reserved"])
        self.assertFalse(self.reserve(claims)["reserved"])
        self.assert_code("IDEMPOTENCY_CONFLICT", lambda: self.store.reserve_submission(claims,
            capability_sha256=digest(claims.nonce), workspace_sha256=digest("workspace"), request_sha256=digest("different")))
        self.assert_code("SUBMISSION_WORKSPACE_MISMATCH", lambda: self.store.reserve_submission(claims,
            capability_sha256=digest(claims.nonce), workspace_sha256=digest("other"), request_sha256=digest("request")))
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.reserve_submission(claims,
            capability_sha256=digest("fresh-token"), workspace_sha256=digest("workspace"), request_sha256=digest("request")))

    def test_stale_or_mismatched_authority_never_reserves(self) -> None:
        claims = self.task()
        for change in ({"epoch": 2}, {"owner_id": "other"}, {"permissions": ("commit:workflow",)}, {"expires_at": int(time.time()) - 1}):
            with self.subTest(change=change):
                self.assert_code("SUBMISSION_AUTHORITY_CHANGED", lambda: self.reserve(replace(claims, **change)))
        self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM step_receipts", ())[0], 0)

    def test_prepared_recovery_after_restart_blocks_late_executor(self) -> None:
        claims = self.task()
        receipt = self.reserve(claims)
        self.restart()
        result = self.store.reconcile_unstarted_submission(receipt)
        self.assertEqual(result["result"]["error_code"], "SUBMISSION_NOT_STARTED")
        self.assert_code("SUBMISSION_NOT_STARTED", lambda: self.store.activate_submission(receipt, claims, 1))
        self.assertEqual(self.store.get_run("run")["state"], "assess")

    def test_file_recovery_counts_exact_observed_effect_without_reexecution(self) -> None:
        _, receipt, execution = self.execution()
        evidence = {"relative_path": "memory/generation/observations.jsonl", "before": None,
                    "after": {"bytes": 13, "sha256": digest("private body")}}
        self.store.begin_submission_write(execution, 0, evidence)
        self.restart()
        recovery = self.store.submission_recovery(receipt)
        result = self.store.reconcile_caller_writes(recovery, observed=evidence["after"])
        self.assertEqual(result["result"], {"disposition": "correction_required", "state": "assess",
                         "writes_applied": 1, "complete": False, "error_code": "SUBMISSION_INTERRUPTED"})
        self.assertEqual(self.store.get_run("run")["state"], "assess")
        self.assertEqual(list(Path(self.temp.name).rglob("*.jsonl")), [])

    def test_missing_file_is_zero_writes_and_unknown_bytes_are_not_guessed(self) -> None:
        _, receipt, execution = self.execution()
        evidence = {"relative_path": "memory/generation/x.jsonl", "before": None,
                    "after": {"bytes": 2, "sha256": digest("x")}}
        self.store.begin_submission_write(execution, 0, evidence)
        recovery = self.store.submission_recovery(receipt)
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.reconcile_caller_writes(recovery))
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.reconcile_caller_writes(recovery, observed={"bytes": 3, "sha256": digest("other")}))
        self.assertEqual(self.store.reconcile_caller_writes(recovery, observed=None)["result"]["writes_applied"], 0)

    def test_equal_byte_overwrite_and_opaque_effect_stay_unknown(self) -> None:
        _, receipt, execution = self.execution()
        image = {"bytes": 2, "sha256": digest("same")}
        self.store.begin_submission_write(execution, 0, {"relative_path": "memory/generation/x.jsonl", "before": image, "after": image})
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.reconcile_caller_writes(self.store.submission_recovery(receipt), observed=image))
        # A category or elapsed time cannot prove an opaque write failed.
        with self.store.transaction() as connection:
            connection.execute("UPDATE step_write_journals SET marker_json='{" + '"kind":"opaque"' + "}'")
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.reconcile_caller_writes(self.store.submission_recovery(receipt)))
        self.assert_code("SUBMISSION_RECEIPT_INVALID", lambda: self.store.record_submission_outcome(receipt,
            {"disposition": "correction_required", "state": "assess", "writes_applied": 0, "complete": False, "error_code": "VALIDATION_ERROR"}))

    def test_recovery_snapshot_fences_concurrent_progress(self) -> None:
        _, receipt, execution = self.execution()
        recovery = self.store.submission_recovery(receipt)
        self.store.begin_submission_write(execution, 0)
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.reconcile_caller_writes(recovery))

    def test_completed_caller_write_then_restart_returns_lower_bound(self) -> None:
        _, receipt, execution = self.execution(writes=2)
        self.store.begin_submission_write(execution, 0)
        self.store.checkpoint_submission_write(execution, 1)
        self.restart()
        result = self.store.reconcile_caller_writes(self.store.submission_recovery(receipt))
        self.assertEqual(result["result"]["writes_applied"], 1)
        self.assertFalse(result["result"]["complete"])

    def test_commit_ready_without_explicit_enrollment_is_unknown(self) -> None:
        _, receipt, execution = self.execution(writes=0)
        self.store.arm_submission_commit(execution)
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.reconcile_caller_writes(self.store.submission_recovery(receipt)))

    def test_enrolled_atomic_action_recovery_never_executes_action(self) -> None:
        claims, receipt, execution = self.execution(writes=0)
        self.store.arm_submission_commit(execution)
        self.store.enroll_atomic_action(claims, execution["trace_id"], "assessment_complete")
        self.restart()
        result = self.store.reconcile_caller_writes(self.store.submission_recovery(receipt))
        self.assertEqual(result["result"]["error_code"], "SUBMISSION_INTERRUPTED")
        self.assertEqual(self.store.get_run("run")["state"], "assess")
        self.assertEqual(self.store.list_transitions("run"), [])

    def test_restartable_action_recovery_never_runs_the_action(self) -> None:
        claims, receipt, execution = self.execution("propose_plans", writes=0)
        self.store.arm_submission_commit(execution)
        self.store.enroll_restartable_action(claims, execution["trace_id"], "plans_proposed")
        result = self.store.reconcile_caller_writes(self.store.submission_recovery(receipt))
        self.assertEqual(result["result"]["error_code"], "SUBMISSION_INTERRUPTED")
        self.assertEqual(self.store.get_run("run")["state"], "propose_plans")

    def test_normalized_database_writes_are_bounded_before_transaction(self) -> None:
        _, receipt, execution = self.execution("assemble")
        with self.assertRaises(ReCTMError) as caught:
            self.store.write_submission_manifest(execution, 0, {"large": "x" * (1024 * 1024)})
        self.assertEqual(caught.exception.code, "SUBMISSION_DATABASE_WRITE_TOO_LARGE")
        self.assertEqual(self.store.submission_accepted_writes(execution["execution_id"]), 0)
        with self.assertRaises(ReCTMError) as caught:
            self.store.write_submission_reference_audit(execution, 0, {"notes": "x" * (1024 * 1024)})
        self.assertEqual(caught.exception.code, "SUBMISSION_DATABASE_WRITE_TOO_LARGE")
        self.assertIsNone(self.store.observe_submission(receipt)["result"])

    def test_database_write_and_checkpoint_roll_back_together(self) -> None:
        _, receipt, execution = self.execution("assemble")
        self.trigger("step_checkpoints", "UPDATE")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.write_submission_manifest(execution, 0, {"private": "body"})
        self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM proof_manifests", ())[0], 0)
        self.assertEqual(self.store.submission_recovery(receipt)["checkpoint"]["accepted_writes"], 0)
        self.store._connection.execute("DROP TRIGGER inject_failure")
        self.store.write_submission_manifest(execution, 0, {"private": "body"})
        self.restart()
        result = self.store.reconcile_caller_writes(self.store.submission_recovery(receipt))
        self.assertEqual(result["result"]["writes_applied"], 1)
        self.assertEqual(self.store.read_proof_manifest("run")["manifest"], {"private": "body"})

    def test_database_write_rechecks_scope_and_does_not_accept_skipped_slot(self) -> None:
        _, receipt, execution = self.execution("assemble", writes=2)
        self.assert_code("SUBMISSION_RECEIPT_INVALID", lambda: self.store.write_submission_manifest(execution, 1, {}))
        self.store.revoke_capability(execution["claims"].nonce, "test")
        self.assert_code("SUBMISSION_AUTHORITY_CHANGED", lambda: self.store.write_submission_manifest(execution, 0, {}))
        self.assertEqual(self.store.submission_recovery(receipt)["checkpoint"]["accepted_writes"], 0)

    def test_transition_effects_and_receipt_are_one_transaction(self) -> None:
        claims, receipt, execution = self.execution(writes=0)
        self.store.arm_submission_commit(execution)
        self.store.enroll_atomic_action(claims, execution["trace_id"], "assessment_complete")
        transition = dict(run_id="run", expected_state="assess", after_state="explore", actor="generator",
                          trace_id=execution["trace_id"], reason="assessment_complete")
        self.trigger("transitions", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.transition_task(claims, transition=transition, metadata_updates={"decision": "compact"})
        self.assertEqual(self.store.get_run("run")["state"], "assess")
        self.assertEqual(self.store.get_run("run")["metadata"], {})
        self.assertEqual(self.store.get_domain("run-domain")["status"], "open")
        self.assertFalse(self.store.get_capability(claims.nonce)["revoked"])
        self.assertEqual(self.store.observed_submission(receipt)["status"], "pending")
        self.store._connection.execute("DROP TRIGGER inject_failure")
        self.store.transition_task(claims, transition=transition, metadata_updates={"decision": "compact"})
        self.restart()
        result = self.store.observed_submission(receipt)
        self.assertEqual(result["result"]["disposition"], "applied")
        self.assertEqual(self.store.get_domain("run-domain")["status"], "sealed")
        self.assertTrue(self.store.get_capability(claims.nonce)["revoked"])
        self.assertFalse(self.reserve(claims)["reserved"])

    def test_receipt_failure_rolls_back_transition_and_revocation(self) -> None:
        claims, receipt, execution = self.execution(writes=0)
        self.store.arm_submission_commit(execution)
        self.trigger("step_receipts", "UPDATE")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.transition_task(claims, transition=dict(run_id="run", expected_state="assess", after_state="explore",
                actor="generator", trace_id=execution["trace_id"], reason="assessment_complete"))
        self.assertEqual(self.store.list_transitions("run"), [])
        self.assertFalse(self.store.get_capability(claims.nonce)["revoked"])
        self.assertEqual(self.store.observed_submission(receipt)["status"], "pending")

    def test_receipts_and_journals_store_no_raw_tokens_or_model_bodies(self) -> None:
        _, receipt, execution = self.execution()
        private = "raw-capability-model-proof-body"
        self.store.begin_submission_write(execution, 0, {"relative_path": "memory/generation/x.jsonl", "before": None,
                                                        "after": {"bytes": len(private), "sha256": digest(private)}})
        self.store.checkpoint_submission_write(execution, 1)
        self.store.record_submission_outcome(receipt, {"disposition": "correction_required", "state": "assess",
            "writes_applied": 1, "complete": False, "error_code": "VALIDATION_ERROR"})
        values = []
        for table in ("step_receipts", "step_checkpoints", "step_write_journals"):
            values.extend(dict(row) for row in self.store._connection.execute(f"SELECT * FROM {table}"))
        self.assertNotIn(private, json.dumps(values))
        self.assert_code("SUBMISSION_RECEIPT_INVALID", lambda: self.store.record_submission_outcome(receipt,
            {"disposition": "correction_required", "state": "assess", "writes_applied": 1,
             "complete": False, "error_code": "VALIDATION_ERROR", "body": private}))

    def test_creation_preparation_restarts_without_duplicates(self) -> None:
        receipt = self.store.reserve_creation("owner", digest("key"), digest("workspace"), digest("request"), "run")
        project = self.store.create_project(owner_id="owner", title="Project")
        material = dict(problem_id="problem", metadata={"workflow_protocol_version": 3}, project_id=project["project_id"],
                        references=[{"name": "notes.txt", "content": "private source", "source": "inline"}])
        first = self.store.prepare_creation_records(receipt, **material)
        self.restart()
        resumed = self.store.resume_creation(receipt)
        self.assertEqual(self.store.prepare_creation_records(resumed, **material), first)
        self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM project_snapshots", ())[0], 1)
        self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM references_registry", ())[0], 1)
        self.assertEqual(self.store.complete_creation(resumed)["state"], "assess")
        self.assertEqual(self.store.observe_creation(receipt)["status"], "completed")
        self.assertFalse(self.store.reserve_creation("owner", digest("key"), digest("workspace"), digest("request"), "different")["reserved"])

    def test_creation_database_corruption_is_not_silently_adopted(self) -> None:
        receipt = self.store.reserve_creation("owner", digest("key"), digest("workspace"), digest("request"), "run")
        self.store.prepare_creation_records(receipt, problem_id="problem", metadata={})
        self.store.update_run_metadata("run", {"changed": True})
        self.assert_code("CREATION_DATABASE_CONFLICT", lambda: self.store.prepare_creation_records(receipt, problem_id="problem", metadata={}))
        self.assert_code("CREATION_DATABASE_CONFLICT", lambda: self.store.complete_creation(receipt))
        self.assertEqual(self.store.observe_creation(receipt)["status"], "pending")

    def test_creation_checkpoint_failure_rolls_back_all_rows(self) -> None:
        receipt = self.store.reserve_creation("owner", digest("key"), digest("workspace"), digest("request"), "run")
        self.trigger("creation_initializations", "UPDATE")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.prepare_creation_records(receipt, problem_id="problem", metadata={},
                references=[{"name": "a", "content": "body", "source": "inline"}])
        self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM runs", ())[0], 0)
        self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM references_registry", ())[0], 0)
        self.assertEqual(self.store.observe_creation(receipt)["status"], "pending")

    def test_creation_completion_receipt_failure_rolls_back_transition(self) -> None:
        receipt = self.store.reserve_creation("owner", digest("key"), digest("workspace"), digest("request"), "run")
        self.store.prepare_creation_records(receipt, problem_id="problem", metadata={})
        self.trigger("creation_receipts", "UPDATE")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.complete_creation(receipt)
        self.assertEqual(self.store.get_run("run")["state"], "created")
        self.assertEqual(self.store.list_transitions("run"), [])
        self.assertEqual(self.store.observe_creation(receipt)["status"], "pending")

    def test_legacy_creation_is_not_resumed_from_apparent_run_state(self) -> None:
        receipt = self.store.reserve_creation("owner", digest("key"), digest("workspace"), digest("request"), "run")
        self.store._connection.execute("DELETE FROM creation_initializations")
        self.store.create_run(run_id="run", problem_id="problem", owner_id="owner", state="assess")
        self.assert_code("CREATION_RESULT_UNKNOWN", lambda: self.store.resume_creation(receipt))
        self.assert_code("CREATION_RESULT_UNKNOWN", lambda: self.store.complete_creation(receipt))
        self.assertEqual(self.store.observe_creation(receipt)["status"], "pending")

    def test_mechanical_latex_result_and_transition_rollback(self) -> None:
        self.store.create_run(run_id="run", problem_id="problem", owner_id="owner", state="latex_validate", metadata={"proof": "digest"})
        transition = dict(run_id="run", expected_state="latex_validate", after_state="verify", actor="latex_gate",
                          trace_id="latex-test", reason="latex_passed", latex_passed=True)
        self.trigger("transitions", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.complete_latex_gate(transition=transition, expected_metadata={"proof": "digest"}, latex_result={"passed": True})
        self.assertEqual(self.store.get_run("run")["metadata"], {"proof": "digest"})
        self.assertFalse(self.store.get_run("run")["latex_passed"])

    def test_mechanical_branch_rows_rollback_and_legacy_partial_refusal(self) -> None:
        requests = [{"plan_id": "plan"}]
        self.store.create_run(run_id="run", problem_id="problem", owner_id="owner", state="branch_prepare", metadata={"branch_requests": requests})
        transition = dict(run_id="run", expected_state="branch_prepare", after_state="branch_run", actor="system",
                          trace_id="branches-test", reason="branches_prepared", round_delta=1)
        branch = dict(branch_id="branch", plan_id="plan", domain_id="branch-domain", snapshot_id="round-1-snapshot",
                      order_index=0, domain_metadata={"branch_id": "branch"}, branch_metadata={})
        self.trigger("transitions", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.complete_branch_preparation(transition=transition, expected_branch_requests=requests,
                snapshot_id="round-1-snapshot", branches=[branch])
        self.assertEqual(self.store.list_branches("run"), [])
        self.assertEqual(self.store.list_domains("run"), [])
        self.store._connection.execute("DROP TRIGGER inject_failure")
        self.store.create_domain(domain_id="old", run_id="run", role="branch")
        self.store.create_branch(branch_id="old", run_id="run", plan_id="plan", domain_id="old", snapshot_id="round-1-old", order_index=0)
        self.assert_code("MECHANICAL_LEGACY_PARTIAL_UNKNOWN", lambda: self.store.complete_branch_preparation(
            transition=transition, expected_branch_requests=requests, snapshot_id="round-1-snapshot", branches=[branch]))


    def test_partial_task_metadata_and_receipt_are_atomic(self) -> None:
        claims, receipt, execution = self.execution("direct_proving", writes=0)
        self.store.arm_submission_commit(execution)
        self.store.enroll_restartable_action(claims, execution["trace_id"], "direct_proving_complete")
        result = {"disposition": "applied", "state": "direct_proving", "writes_applied": 0,
                  "complete": False, "error_code": None}
        self.trigger("step_receipts", "UPDATE")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.complete_partial_task(claims, trace_id=execution["trace_id"], expected_metadata={},
                metadata_updates={"direct_screening_progress": {"plan": "partial"}}, result=result)
        self.assertEqual(self.store.get_run("run")["metadata"], {})
        self.assertEqual(self.store.submission_recovery(receipt)["marker"]["kind"], "restartable_action")
        self.store._connection.execute("DROP TRIGGER inject_failure")
        self.store.complete_partial_task(claims, trace_id=execution["trace_id"], expected_metadata={},
            metadata_updates={"direct_screening_progress": {"plan": "partial"}}, result=result)
        self.restart()
        self.assertEqual(self.store.observed_submission(receipt)["result"], result)
        self.assertEqual(self.store.get_run("run")["state"], "direct_proving")
        self.assertEqual(self.store.get_run("run")["epoch"], 1)
        self.assertEqual(self.store.get_domain("run-domain")["status"], "open")

    def test_concurrent_reservations_share_one_fenced_execution(self) -> None:
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        claims = self.task()
        second = StateStore(self.path)
        barrier = Barrier(2)
        def reserve(store: StateStore) -> dict:
            barrier.wait()
            return store.reserve_submission(claims, capability_sha256=digest(claims.nonce),
                workspace_sha256=digest("workspace"), request_sha256=digest("request"))
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(reserve, store) for store in (self.store, second)]
                receipts = [future.result() for future in futures]
            self.assertEqual(sorted(r["reserved"] for r in receipts), [False, True])
            self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM step_checkpoints", ())[0], 1)
        finally:
            second.close()

    def test_legacy_receipt_cannot_be_completed_from_claimed_success(self) -> None:
        claims = self.task()
        receipt = self.reserve(claims)
        self.store._connection.execute("DELETE FROM step_checkpoints")
        self.assert_code("RESULT_UNKNOWN", lambda: self.store.record_submission_outcome(receipt,
            {"disposition": "applied", "state": "assess", "writes_applied": 0, "complete": True, "error_code": None}))
        self.assertEqual(self.store.observed_submission(receipt)["status"], "pending")

    def test_file_evidence_rejects_other_branch_and_verifier_private_memory(self) -> None:
        claims, receipt, execution = self.execution("verify")
        evidence = {"relative_path": "memory/generation/private.jsonl", "before": None,
                    "after": {"bytes": 1, "sha256": digest("x")}}
        with self.assertRaises(ReCTMError):
            self.store.begin_submission_write(execution, 0, evidence)
        self.assertEqual(self.store.submission_recovery(receipt)["marker"], {"kind": "between"})
        evidence["relative_path"] = "../../private"
        self.assert_code("SUBMISSION_RECEIPT_INVALID", lambda: self.store.begin_submission_write(execution, 0, evidence))

    def finalized_project(self) -> tuple[str, str, object]:
        from re_ctm.fact_memory import VerifiedFact, compute_fact_id
        project = self.store.create_project(owner_id="owner", title="Project")
        claim = self.store.create_claim(project_id=project["project_id"], owner_id="owner", title="Claim")
        base = self.store.create_open_claim_revision(claim_id=claim["claim_id"], owner_id="owner", statement_tex="A=A")
        snapshot = self.store.create_project_snapshot(project["project_id"], owner_id="owner")
        self.store.create_run(run_id="run", problem_id="problem", owner_id="owner", state="done", metadata={"workflow_protocol_version": 3})
        with self.store.transaction() as connection:
            connection.execute("UPDATE runs SET latex_passed=1,verdict='correct' WHERE run_id='run'")
        self.store.link_run_to_project(run_id="run", owner_id="owner", project_id=project["project_id"],
            project_snapshot_id=snapshot["snapshot_id"], target_claim_id=claim["claim_id"], base_revision_id=base["revision_id"],
            requested_workflow_mode="compact", effective_workflow_mode="compact", register_result=True)
        fact = VerifiedFact(compute_fact_id(project["project_id"], (), {}, "A=A", "Reflexivity."),
                            "A=A", "Reflexivity.", "", {}, ())
        return project["project_id"], claim["claim_id"], fact

    def test_fact_promotion_revision_and_finding_status_roll_back_together(self) -> None:
        from re_ctm.fact_memory import ProjectFinding
        project, claim, fact = self.finalized_project()
        self.store.insert_project_findings(project, "run", "owner", [ProjectFinding(digest("finding"), "conclusion", "A=A", "Axiom", True, "{}")])
        kwargs = dict(run_id="run", owner_id="owner", statement_tex="A=A", proof_sha256=digest("finalized proof"),
                      effective_conditions=[], manifest={"dependency_revision_ids": []}, facts=[fact])
        self.trigger("claim_revisions", "INSERT")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.promote_verified_run(**kwargs)
        self.assertEqual(self.store.list_project_facts(project, owner_id="owner"), [])
        self.assertEqual(self.store.list_project_findings(project, owner_id="owner")[0]["status"], "active")
        self.assertEqual(self.store.current_claim_revision(claim, owner_id="owner")["evidence_status"], "OPEN")
        self.store._connection.execute("DROP TRIGGER inject_failure")
        result = self.store.promote_verified_run(**kwargs)
        self.assertEqual(result["revision"]["fact_id"], fact.fact_id)
        self.assertEqual(self.store.list_project_findings(project, owner_id="owner")[0]["status"], "verified")
        self.assertEqual(self.store.promote_verified_run(**kwargs)["status"], "already_promoted")
        self.assertEqual(len(self.store.list_project_facts(project, owner_id="owner")), 1)

    def test_fact_promotion_requires_finalization_and_matching_target(self) -> None:
        project, _, fact = self.finalized_project()
        kwargs = dict(run_id="run", owner_id="owner", statement_tex="different", proof_sha256=digest("proof"),
                      effective_conditions=[], manifest={"dependency_revision_ids": []}, facts=[fact])
        self.assert_code("FACT_TARGET_MISMATCH", lambda: self.store.promote_verified_run(**kwargs))
        self.assertEqual(self.store.list_project_facts(project, owner_id="owner"), [])
        kwargs["statement_tex"] = "A=A"
        with self.store.transaction() as connection:
            connection.execute("UPDATE runs SET latex_passed=0 WHERE run_id='run'")
        self.assert_code("FACT_FINALIZATION_REQUIRED", lambda: self.store.promote_verified_run(**kwargs))
        kwargs["facts"] = None
        self.assert_code("FACT_PROMOTION_REQUIRED", lambda: self.store.promote_verified_run(**kwargs))


if __name__ == "__main__":
    unittest.main()
