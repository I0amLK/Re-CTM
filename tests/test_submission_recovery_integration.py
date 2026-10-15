"""Disposable public-tool crash/replay tests; no real databases or native execution."""
from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.capabilities import CapabilityAuthority
from re_ctm.debug import DebugEventBus
from re_ctm.enums import LatexPolicy, NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.latex import LatexGate
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.oauth import OAuthPrincipal
from re_ctm.storage import StateStore
from re_ctm.tools import ToolRuntime
from re_ctm.vault import PrivateVault
from re_ctm.workflow import WorkflowEngine
from re_ctm import vault_effects


class PublicSubmissionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private = self.root / "private"
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.debug = DebugEventBus(self.root / "events.jsonl", self.private, enabled=True)
        self.store = StateStore(self.private / "state.db")
        self.vault = PrivateVault(self.private)
        self.authority = CapabilityAuthority(b"r" * 32, self.store, self.debug)
        self.engine = WorkflowEngine(self.store, self.vault, self.authority, self.debug, LatexGate(LatexPolicy.STATIC_ONLY))
        self.native = NativeRuntime(NativeWorkspace(self.workspace, private_root=self.private), NativeMode.DANGEROUS, self.debug)
        self.tools = ToolRuntime(self.native, self.engine, self.debug)
        self.owner = OAuthPrincipal("owner", "owner", "mcp")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def call(self, tool: str, arguments: dict, *, error: str | None = None, owner: OAuthPrincipal | None = None) -> dict:
        output = self.tools.call(tool, arguments, owner or self.owner)
        result = output["structuredContent"]
        if error is None:
            self.assertFalse(output["isError"], result)
        else:
            self.assertTrue(output["isError"], result)
            self.assertEqual(result["error"]["code"], error, result)
        return result

    def start(self, mode: str = "full") -> dict:
        result = self.call("rethlas_start", {"problem_tex": "Prove A=A.", "workflow_mode": mode,
                                            "creation_key": "durable-create-01"})
        self.assertEqual(result["workflow_protocol_version"], 3)
        return result

    def task(self, run_id: str) -> dict:
        return self.call("rethlas_step", {"run_id": run_id})

    def request(self, task: dict) -> dict:
        return {"run_id": task["run_id"], "capability": task["capability"], **copy.deepcopy(task["task"]["minimal_submission"])}

    def receipt(self, request: dict) -> dict:
        return self.store.find_submission_receipt(hashlib.sha256(request["capability"].encode()).hexdigest(), "owner", request["run_id"])

    def reload_store(self) -> None:
        path = self.store.path
        self.store.close()
        self.store = StateStore(path)
        self.engine.store = self.store
        self.authority.store = self.store

    def test_public_creation_key_replay_and_changed_input_conflict(self) -> None:
        first = self.start()
        second = self.start()
        self.assertEqual(second["run_id"], first["run_id"])
        self.assertTrue(second["creation_replayed"])
        self.assertEqual(len(self.store.list_runs("owner")), 1)
        self.call("rethlas_start", {"problem_tex": "Changed body", "workflow_mode": "full", "creation_key": "durable-create-01"}, error="IDEMPOTENCY_CONFLICT")
        self.assertEqual(len(self.store.list_runs("owner")), 1)

    def test_public_creation_restart_after_prepared_database_has_one_run(self) -> None:
        with mock.patch.object(self.store, "complete_creation", side_effect=RuntimeError("simulated crash")):
            self.call("rethlas_start", {"problem_tex": "Prove A=A.", "workflow_mode": "full", "creation_key": "durable-create-01"}, error="INTERNAL_ERROR")
        self.assertEqual(len(self.store.list_runs("owner")), 1)
        self.reload_store()
        completed = self.start()
        self.assertTrue(completed["creation_replayed"])
        self.assertEqual(self.store.get_run(completed["run_id"])["state"], "assess")
        self.assertEqual(len(self.store.list_transitions(completed["run_id"])), 1)

    def test_exact_step_replay_after_epoch_change_never_reapplies_writes(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        result = self.call("rethlas_step", original)
        self.assertEqual(result["state"], "explore")
        transitions = self.store.list_transitions(run_id)
        contents = self.vault.read_generation_memory(run_id, "immediate_conclusions")
        replay = self.call("rethlas_step", original)
        self.assertTrue(replay["state_is_historical"])
        self.assertTrue(replay["submission"]["replayed"])
        self.assertEqual(replay["writes_applied"], 0)
        self.assertEqual(self.store.list_transitions(run_id), transitions)
        self.assertEqual(self.vault.read_generation_memory(run_id, "immediate_conclusions"), contents)
        changed = copy.deepcopy(original)
        changed["payload"]["route_reason"] = "A changed request"
        self.call("rethlas_step", changed, error="IDEMPOTENCY_CONFLICT")

    def test_pending_submission_blocks_task_issuance_and_mechanical_advancement(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        with mock.patch.object(self.store, "checkpoint_submission_write", side_effect=RuntimeError("crash after file")):
            self.call("rethlas_step", original, error="INTERNAL_ERROR")
        cap_count = self.store._fetch_one("SELECT COUNT(*) FROM capabilities", ())[0]
        with mock.patch.object(self.engine, "_advance_mechanical", side_effect=AssertionError("must not advance")):
            self.call("rethlas_step", {"run_id": run_id}, error="RESULT_UNKNOWN")
        self.assertEqual(self.store._fetch_one("SELECT COUNT(*) FROM capabilities", ())[0], cap_count)

    def test_recover_only_observes_file_after_restart_without_write_or_action(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        with mock.patch.object(self.store, "checkpoint_submission_write", side_effect=RuntimeError("crash after file")):
            self.call("rethlas_step", original, error="INTERNAL_ERROR")
        first = self.vault.read_generation_memory(run_id, "immediate_conclusions")
        self.assertEqual(len(first), 1)
        self.call("rethlas_step", original, error="RESULT_UNKNOWN")
        self.reload_store()
        with mock.patch.object(self.engine, "write_submission", side_effect=AssertionError("must not write")), \
             mock.patch.object(self.engine, "commit", side_effect=AssertionError("must not execute action")):
            recovered = self.call("rethlas_step", {**original, "recover_only": True})
        self.assertEqual(recovered["receipt"]["writes_applied"], 1)
        self.assertEqual(recovered["receipt"]["error_code"], "SUBMISSION_INTERRUPTED")
        self.assertEqual(self.store.get_run(run_id)["state"], "assess")
        self.assertEqual(self.vault.read_generation_memory(run_id, "immediate_conclusions"), first)
        with self.assertRaises(ReCTMError) as caught:
            self.engine.write(owner_id="owner", capability=original["capability"],
                              resource=original["writes"][0]["resource"], content=original["writes"][0]["content"])
        self.assertEqual(caught.exception.code, "CAPABILITY_REVOKED")

    def test_recover_only_missing_receipt_never_starts_submission(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        with mock.patch.object(self.engine, "write_submission", side_effect=AssertionError("must not write")):
            self.call("rethlas_step", {**original, "recover_only": True}, error="SUBMISSION_RECEIPT_NOT_FOUND")
        self.assertIsNone(self.receipt(original))
        self.assertEqual(self.vault.read_generation_memory(run_id, "immediate_conclusions"), [])

    def test_postcommit_task_failure_returns_durable_result_and_replay(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        with mock.patch.object(self.engine, "next_task", side_effect=RuntimeError("task renderer failure")):
            result = self.call("rethlas_step", original)
        self.assertEqual(result["receipt"]["disposition"], "applied")
        self.assertTrue(result["state_is_historical"])
        self.assertEqual(self.store.get_run(run_id)["state"], "explore")
        self.assertEqual(self.call("rethlas_step", original)["writes_applied"], 0)
        self.assertEqual(self.task(run_id)["state"], "explore")

    def test_atomic_action_crash_recovery_does_not_transition(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        with mock.patch.object(self.store, "transition_task", side_effect=RuntimeError("crash before transaction")):
            self.call("rethlas_step", original, error="INTERNAL_ERROR")
        checkpoint = self.store.submission_recovery(self.receipt(original))["checkpoint"]
        self.assertEqual(checkpoint["atomic_action"], "assessment_complete")
        with mock.patch.object(self.engine, "commit", side_effect=AssertionError("recovery must not execute")):
            recovered = self.call("rethlas_step", {**original, "recover_only": True})
        self.assertFalse(recovered["receipt"]["complete"])
        self.assertEqual(self.store.get_run(run_id)["state"], "assess")
        self.assertEqual(len(self.store.list_transitions(run_id)), 1)

    def test_restartable_action_crash_recovery_does_not_repeat_action_files(self) -> None:
        run_id = self.start()["run_id"]
        task = self.task(run_id)
        for state in ("assess", "explore"):
            self.assertEqual(task["state"], state)
            task = self.call("rethlas_step", self.request(task))
        self.assertEqual(task["state"], "propose_plans")
        original = self.request(task)
        with mock.patch.object(self.store, "transition_task", side_effect=RuntimeError("crash after action files")):
            self.call("rethlas_step", original, error="INTERNAL_ERROR")
        before = self.vault.read_generation_memory(run_id, "subgoals")
        self.assertEqual(len(before), 2)
        self.reload_store()
        with mock.patch("re_ctm.workflow_actions.PreparedAction.apply_files", side_effect=AssertionError("must not write action files")):
            self.call("rethlas_step", {**original, "recover_only": True})
        self.assertEqual(self.store.get_run(run_id)["state"], "propose_plans")
        self.assertEqual(self.vault.read_generation_memory(run_id, "subgoals"), before)
        corrected = self.request(self.task(run_id))
        corrected["payload"] = original["payload"]
        completed = self.call("rethlas_step", corrected)
        self.assertEqual(completed["state"], "direct_proving")
        self.assertEqual(self.vault.read_generation_memory(run_id, "subgoals"), before)

    def test_failed_outcome_journal_does_not_claim_correction(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        original["action"] = "exploration_complete"
        with mock.patch.object(self.store, "record_submission_outcome", side_effect=ReCTMError("SUBMISSION_RECEIPT_INVALID", "journal unavailable", category="conflict")):
            self.call("rethlas_step", original, error="RESULT_UNKNOWN")
        self.assertEqual(self.receipt(original)["status"], "pending")

    def test_commit_permission_failure_is_never_caller_write_correction(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        with mock.patch.object(self.engine, "commit", side_effect=ReCTMError("ROLE_ACCESS_DENIED", "commit denial", category="permission")):
            result = self.call("rethlas_step", original, error="ROLE_ACCESS_DENIED")
        self.assertEqual(result["error"]["category"], "permission")
        self.assertEqual(self.receipt(original)["status"], "pending")

    def test_cross_owner_receipt_lookup_is_hard_denial(self) -> None:
        run_id = self.start()["run_id"]
        original = self.request(self.task(run_id))
        self.call("rethlas_step", original)
        self.call("rethlas_step", original, error="CAPABILITY_OWNER_MISMATCH", owner=OAuthPrincipal("other", "other", "mcp"))


    def interrupted_plan_action(self) -> tuple[str, dict, list]:
        run_id = self.start()["run_id"]
        task = self.task(run_id)
        for _ in range(2):
            task = self.call("rethlas_step", self.request(task))
        original = self.request(task)
        with mock.patch.object(self.store, "transition_task", side_effect=RuntimeError("crash after action files")):
            self.call("rethlas_step", original, error="INTERNAL_ERROR")
        contents = self.vault.read_generation_memory(run_id, "subgoals")
        self.call("rethlas_step", {**original, "recover_only": True})
        return run_id, original, contents

    def test_changed_action_payload_cannot_bypass_retained_effect_binding(self) -> None:
        run_id, original, contents = self.interrupted_plan_action()
        corrected = self.request(self.task(run_id))
        corrected["payload"]["plans"][0]["summary"] = "Changed route after interrupted files"
        result = self.call("rethlas_step", corrected)
        self.assertFalse(result["submission"]["ok"])
        self.assertEqual(result["receipt"]["error_code"], "ACTION_EFFECT_CONFLICT")
        self.assertEqual(self.store.get_run(run_id)["state"], "propose_plans")
        self.assertEqual(self.vault.read_generation_memory(run_id, "subgoals"), contents)
        self.assertEqual(len(list(self.vault.run_root(run_id).glob("debug/state/action-*.json"))), 1)

    def test_missing_prior_action_receipt_does_not_authorize_changed_payload(self) -> None:
        run_id, original, contents = self.interrupted_plan_action()
        fingerprint = hashlib.sha256(original["capability"].encode()).hexdigest()
        # Disposable corruption fixture: retained action sidecar outlives its
        # receipt. Missing evidence must not mean successfully applied.
        with self.store.transaction() as connection:
            connection.execute("DELETE FROM step_write_journals WHERE capability_sha256=?", (fingerprint,))
            connection.execute("DELETE FROM step_checkpoints WHERE capability_sha256=?", (fingerprint,))
            connection.execute("DELETE FROM step_receipts WHERE capability_sha256=?", (fingerprint,))
        changed = self.request(self.task(run_id))
        changed["payload"]["plans"][0]["summary"] = "Cannot silently adopt missing evidence"
        result = self.call("rethlas_step", changed)
        self.assertEqual(result["receipt"]["error_code"], "ACTION_EFFECT_CONFLICT")
        self.assertEqual(self.vault.read_generation_memory(run_id, "subgoals"), contents)
        self.assertEqual(self.store.get_run(run_id)["state"], "propose_plans")


if __name__ == "__main__":
    unittest.main()
