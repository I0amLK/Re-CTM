"""Independent disposable action-effect and lock-boundary regression tests."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_submission_recovery_integration as recovery_fixtures
from test_workflow import VALID_PROOF
from re_ctm import vault_effects, workflow_actions
from re_ctm.errors import ReCTMError


class PrivateObserverReviewTests(unittest.TestCase):
    def test_nested_different_run_observers_wait_for_every_lock_to_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            events = []
            root = Path(temporary)
            with vault_effects.lock_run(root, "outer"):
                with vault_effects.lock_run(root, "inner"):
                    vault_effects.defer_observer(lambda event: events.append((event, len(vault_effects._held.get()))), "inner")
                self.assertEqual(events, [], "observer ran while outer private lock was held")
                vault_effects.defer_observer(lambda event: events.append((event, len(vault_effects._held.get()))), "outer")
            self.assertEqual(events, [("inner", 0), ("outer", 0)])

    def test_same_run_reentrancy_flushes_once_even_after_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            events = []
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "test failure"):
                with vault_effects.lock_run(root, "run"):
                    with vault_effects.lock_run(root, "run"):
                        vault_effects.defer_observer(lambda event: events.append((event, len(vault_effects._held.get()))), "queued")
                    self.assertEqual(events, [])
                    raise RuntimeError("test failure")
            self.assertEqual(events, [("queued", 0)])


class ActionEffectReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = recovery_fixtures.PublicSubmissionRecoveryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def direct_screening(self) -> tuple[str, dict]:
        fixture = self.fixture
        run_id = fixture.start()["run_id"]
        task = fixture.task(run_id)
        for state in ("assess", "explore", "propose_plans"):
            self.assertEqual(task["state"], state)
            task = fixture.call("rethlas_step", fixture.request(task))
        plans = task["context"]["active_plans"]
        payload = {"screening": {plan["plan_id"]: {
            subgoal["subgoal_id"]: {"status": "solved", "summary": "Fixture established this subgoal.", "method": "direct"}
            for subgoal in plan["subgoals"]} for plan in plans},
            "selected_plan_id": plans[0]["plan_id"], "proof_route": "Fixture complete route."}
        return run_id, {"run_id": run_id, "capability": task["capability"], "action": "direct_proving_complete", "writes": [], "payload": payload}

    def interrupt_after_first_action_file(self, request: dict) -> None:
        original = workflow_actions.publish
        def publish(path, data, **kwargs):
            if path.parts[-2:] == ("join", "result.json"):
                raise RuntimeError("crash before second action file")
            return original(path, data, **kwargs)
        with mock.patch.object(workflow_actions, "publish", side_effect=publish):
            self.fixture.call("rethlas_step", request, error="INTERNAL_ERROR")

    def test_partial_multi_file_action_reuses_exact_prefix_without_duplicate_record(self) -> None:
        fixture = self.fixture
        run_id, request = self.direct_screening()
        self.interrupt_after_first_action_file(request)
        before = fixture.vault.read_generation_memory(run_id, "proof_steps")
        self.assertEqual(len(before), 1)
        self.assertFalse((fixture.vault.run_root(run_id) / "join" / "result.json").exists())
        with mock.patch.object(workflow_actions.PreparedAction, "apply_files", side_effect=AssertionError("recovery executed action")):
            fixture.call("rethlas_step", {**request, "recover_only": True})
        task = fixture.task(run_id)
        corrected = {**request, "capability": task["capability"]}
        completed = fixture.call("rethlas_step", corrected)
        self.assertEqual(completed["state"], "assemble")
        self.assertEqual(fixture.vault.read_generation_memory(run_id, "proof_steps"), before)
        self.assertEqual(fixture.vault.read_join_result(run_id)["proof_route"], request["payload"]["proof_route"])

    def test_changed_payload_cannot_adopt_partial_action_effects(self) -> None:
        fixture = self.fixture
        run_id, request = self.direct_screening()
        self.interrupt_after_first_action_file(request)
        before = fixture.vault.read_generation_memory(run_id, "proof_steps")
        fixture.call("rethlas_step", {**request, "recover_only": True})
        task = fixture.task(run_id)
        changed = copy.deepcopy(request)
        changed["capability"] = task["capability"]
        changed["payload"]["proof_route"] = "A different route cannot adopt the retained effect."
        output = fixture.tools.call("rethlas_step", changed, fixture.owner)
        result = output["structuredContent"]
        error = result.get("error") or result.get("submission", {}).get("error")
        self.assertIsNotNone(error)
        self.assertEqual(error["code"], "ACTION_EFFECT_CONFLICT")
        self.assertEqual(fixture.store.get_run(run_id)["state"], "direct_proving")
        self.assertEqual(fixture.vault.read_generation_memory(run_id, "proof_steps"), before)
        self.assertFalse((fixture.vault.run_root(run_id) / "join" / "result.json").exists())

    def test_unreceipted_direct_action_cannot_adopt_changed_partial_effects(self) -> None:
        fixture = self.fixture
        run_id, request = self.direct_screening()
        original = workflow_actions.publish
        def publish(path, data, **kwargs):
            if path.parts[-2:] == ("join", "result.json"):
                raise RuntimeError("interrupted direct action")
            return original(path, data, **kwargs)
        with mock.patch.object(workflow_actions, "publish", side_effect=publish):
            with self.assertRaisesRegex(RuntimeError, "interrupted direct action"):
                fixture.engine.commit(owner_id="owner", capability=request["capability"],
                                      action=request["action"], payload=request["payload"])
        before = fixture.vault.read_generation_memory(run_id, "proof_steps")
        self.assertEqual(len(before), 1)
        self.assertIsNone(fixture.receipt(request))
        changed = {**request["payload"], "proof_route": "Unreceipted effects cannot authorize a different route."}
        with self.assertRaises(ReCTMError) as caught:
            fixture.engine.commit(owner_id="owner", capability=request["capability"],
                                  action=request["action"], payload=changed)
        self.assertEqual(caught.exception.code, "ACTION_EFFECT_CONFLICT")
        self.assertEqual(fixture.vault.read_generation_memory(run_id, "proof_steps"), before)
        self.assertEqual(fixture.store.get_run(run_id)["state"], "direct_proving")
        self.assertFalse((fixture.vault.run_root(run_id) / "join" / "result.json").exists())

    def test_verifier_server_gap_is_idempotent_after_retained_action_files(self) -> None:
        fixture = self.fixture
        run_id = fixture.start("compact")["run_id"]
        task = fixture.call("rethlas_step", fixture.request(fixture.task(run_id)))
        self.assertEqual(task["state"], "assemble")
        reference = fixture.store.register_reference(run_id=run_id, project_id=None, provider="fixture",
                                                     identity_key="review-reference", title="Fixture reference")
        proof = fixture.request(task)
        proof["writes"][0]["content"] = VALID_PROOF
        proof["writes"][1]["content"]["reference_ids"] = [reference["reference_id"]]
        verifier = fixture.call("rethlas_step", proof)
        self.assertEqual(verifier["state"], "verify")
        request = fixture.request(verifier)
        with mock.patch.object(fixture.store, "transition_task", side_effect=RuntimeError("crash after action files")):
            fixture.call("rethlas_step", request, error="INTERNAL_ERROR")
        report = fixture.vault.read_verification_report(run_id)
        self.assertEqual(len(report["verification_report"]["gaps"]), 1)
        fixture.call("rethlas_step", {**request, "recover_only": True})
        fresh = fixture.task(run_id)
        corrected = {"run_id": run_id, "capability": fresh["capability"], "writes": [],
                     "action": request["action"], "payload": request["payload"]}
        completed = fixture.call("rethlas_step", corrected)
        self.assertEqual(completed["state"], "repair")
        self.assertEqual(fixture.vault.read_verification_report(run_id), report)
        self.assertEqual(len(fixture.vault.read_verifier_memory(run_id, "verification_reports")), 1)
        self.assertEqual(len(fixture.vault.read_generation_memory(run_id, "verification_reports")), 1)


if __name__ == "__main__":
    unittest.main()
