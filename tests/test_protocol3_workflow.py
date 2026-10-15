from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from re_ctm.enums import WorkflowRole, WorkflowState
from re_ctm.errors import ReCTMError
from re_ctm.methodology import task_for_state
from re_ctm.research_state import normalize_protocol3_generation_record, ProtocolRecordStamp, ProtocolResearchScope, normalize_protocol3_replan_decision
from re_ctm.tools import _validate_schema_value
from re_ctm.workflow import _merge_direct_screening
import test_workflow as workflow_tests
from test_research_state import plans


class ProtocolThreeMethodologyTests(unittest.TestCase):
    def test_protocol_one_two_catalogs_are_unchanged(self) -> None:
        for state in WorkflowState:
            if state in (WorkflowState.CREATED, WorkflowState.BRANCH_PREPARE, WorkflowState.LATEX_VALIDATE, WorkflowState.FINALIZE, WorkflowState.DONE, WorkflowState.CANCELLED):
                continue
            try:
                legacy = task_for_state(state, 1)
            except ReCTMError:
                continue
            self.assertEqual(legacy, task_for_state(state, 2))
            self.assertNotIn("mathematical_research_contract", legacy)

    def test_all_protocol3_examples_match_final_contracts(self) -> None:
        for state in WorkflowState:
            try:
                task = task_for_state(state, 3)
            except ReCTMError:
                continue
            self.assertTrue(task["mathematical_research_contract"]["advisory_only"])
            contracts = {item["resource"]: item for item in task["write_contract"]}
            examples = [task[key] for key in ("minimal_submission", "minimal_submission_template") if key in task] + task.get("submission_examples", [])
            for example in examples:
                with self.subTest(state=state.value):
                    self.assertEqual(example["action"], task["commit_action"])
                    _validate_schema_value(example.get("payload", {}), task["commit_payload_schema"], path="payload")
                    for write in example.get("writes", []):
                        self.assertIn(write["resource"], contracts)
                        _validate_schema_value(write["content"], contracts[write["resource"]]["content_schema"], path="content")

    def test_assessment_example_and_replan_causal_example_really_normalize(self) -> None:
        scope = ProtocolResearchScope.from_active_plans([])
        task = task_for_state(WorkflowState.ASSESS, 3)
        value = task["minimal_submission"]["writes"][1]["content"]
        record = normalize_protocol3_generation_record("events", value, ProtocolRecordStamp("r", "generator", "g", 0, "now"), scope)
        self.assertEqual(record["record_type"], "assessment")
        decision = task_for_state(WorkflowState.REPLAN, 3)["minimal_submission"]["payload"]["decision"]
        self.assertEqual(normalize_protocol3_replan_decision(decision, scope)["selected_focus_node_id"], "target")

    def test_screening_requires_no_duplicate_logical_record(self) -> None:
        task = task_for_state(WorkflowState.DIRECT_PROVING, 3)
        self.assertEqual(task["write_contract"], [])
        self.assertEqual(task["required_records"], [])
        self.assertEqual(task["minimal_submission_template"]["writes"], [])


class ProtocolThreeWorkflowTests(unittest.TestCase):
    setUp = workflow_tests.WorkflowTestCase.setUp
    tearDown = workflow_tests.WorkflowTestCase.tearDown
    _next = workflow_tests.WorkflowTestCase._next
    _write = workflow_tests.WorkflowTestCase._write
    _commit = workflow_tests.WorkflowTestCase._commit

    def start(self, version: int = 3) -> str:
        return self.engine.start(owner_id=self.owner, problem_id="p3", problem_tex="Prove a simple theorem.", workflow_protocol_version=version, workflow_mode="full")["run_id"]

    def advance_to_plans(self) -> tuple[str, dict]:
        run_id = self.start()
        assess = self._next(run_id)
        self._write(assess, "memory:generation:immediate_conclusions", {"summary": "Initial"})
        self._write(assess, "memory:generation:events", {"event_type": "assessment", "summary": "Initial plan"})
        self._commit(assess, "assessment_complete", {"route": "full"})
        explore = self._next(run_id)
        self._write(explore, "memory:generation:events", {"event_type": "toy_example_result", "node_id": "target", "outcome": "inconclusive", "summary": "Small cases inconclusive"})
        self._commit(explore, "exploration_complete")
        task = self._next(run_id)
        self._commit(task, "plans_proposed", {"plans": plans()})
        return run_id, self._next(run_id)

    def test_task_and_generation_record_use_server_identity(self) -> None:
        run_id = self.start()
        task = self._next(run_id)
        self.assertEqual(task["task"]["workflow_protocol_version"], 3)
        self.assertTrue(task["context"]["mathematical_research_state"]["advisory_only"])
        self._write(task, "memory:generation:events", {"event_type": "assessment", "summary": "Initial plan"})
        record = self.vault.read_generation_memory(run_id, "events")[-1]
        self.assertEqual(record["actor_domain_id"], task["domain_id"])
        self.assertEqual(record["actor_role"], "generator")
        self.assertEqual(record["round_index"], 0)
        self.assertTrue(record["record_id"].startswith("research-"))
        with self.assertRaises(ReCTMError): self._write(task, "memory:generation:events", {"event_type": "assessment", "summary": "Forged", "actor_domain_id": "other"})

    def test_protocol1_and2_freeform_records_remain_resumable(self) -> None:
        for version in (1, 2):
            run_id = self.start(version)
            task = self._next(run_id)
            self._write(task, "memory:generation:events", {"freeform": "legacy", "status": "complete"})
            self.assertEqual(self.vault.read_generation_memory(run_id, "events")[-1], {"freeform": "legacy", "status": "complete"})
            self.assertNotIn("mathematical_research_state", task["context"])
            self.assertNotIn("mathematical_research_contract", task["task"])

    def test_persisted_legacy_runs_resume_after_engine_restart_without_contract_upgrade(self) -> None:
        from re_ctm.capabilities import CapabilityAuthority
        from re_ctm.storage import StateStore
        from re_ctm.workflow import WorkflowEngine
        runs = []
        for version in (1, 2):
            run_id = self.start(version)
            task = self._next(run_id)
            self._write(task, "memory:generation:events", {"status": "legacy", "arbitrary": [1, 2]})
            runs.append((version, run_id))
        path = self.store.path
        self.store.close()
        self.store = StateStore(path)
        self.capabilities = CapabilityAuthority(b"c" * 32, self.store, self.debug, default_ttl_seconds=600)
        self.engine = WorkflowEngine(self.store, self.vault, self.capabilities, self.debug, self.engine.latex_gate)
        for version, run_id in runs:
            self.engine.resume(owner_id=self.owner, run_id=run_id)
            task = self._next(run_id)
            self.assertEqual(task["task"]["workflow_protocol_version"], version)
            self.assertNotIn("mathematical_research_contract", task["task"])
            self.assertNotIn("mathematical_research_state", task["context"])
            self.assertEqual(self.vault.read_generation_memory(run_id, "events")[-1]["arbitrary"], [1, 2])

    def test_partial_screening_retains_typed_results_then_server_derives_branch_set(self) -> None:
        run_id, task = self.advance_to_plans()
        active = self.store.get_run(run_id)["metadata"]["active_plans"]
        self.assertEqual(self.vault.read_generation_memory(run_id, "proof_steps"), [])
        first = active[0]
        payload = {"screening": {first["plan_id"]: {first["subgoal_ids"][0]: {"status": "partial", "summary": "Some progress", "method": "reduction"}}}}
        result = self._commit(task, "direct_proving_complete", payload)
        self.assertFalse(result["screening_complete"])
        progress = self.store.get_run(run_id)["metadata"]["direct_screening_progress"]
        self.assertEqual(progress[first["plan_id"]][first["subgoal_ids"][0]]["method"], "reduction")
        self.assertEqual(len(result["missing_screening"]), 2)
        self.assertEqual(self.vault.read_generation_memory(run_id, "proof_steps"), [])
        task = self._next(run_id)
        rest = {plan["plan_id"]: {goal: {"status": "stuck", "summary": "Need lemma", "method": "direct", "obstruction": "missing_lemma"} for goal in plan["subgoal_ids"] if goal not in progress.get(plan["plan_id"], {})} for plan in active}
        self._commit(task, "direct_proving_complete", {"screening": rest})
        record = self.vault.read_generation_memory(run_id, "proof_steps")[-1]
        self.assertEqual(record["record_type"], "direct_screening_round")
        self.assertEqual(record["actor_role"], "generator")
        self.assertEqual(record["plans"][0]["status"], "stuck")
        branch = self._next(run_id)
        self.assertEqual(branch["role"], "branch")
        self.assertNotIn("mathematical_research_state", branch["context"])
        self.assertTrue(branch["context"]["assigned_research_subgoals"])
        self.assertEqual(len(self.store.list_branches(run_id)), 2)

    def test_branch_scope_failure_and_replan_records_end_to_end(self) -> None:
        run_id, task = self.advance_to_plans()
        active = self.store.get_run(run_id)["metadata"]["active_plans"]
        screening = {plan["plan_id"]: {goal: {"status": "stuck", "summary": "Need source", "method": "retrieval", "obstruction": "missing_reference"} for goal in plan["subgoal_ids"]} for plan in active}
        self._commit(task, "direct_proving_complete", {"screening": screening})
        first = self._next(run_id)
        own = first["context"]["assigned_research_subgoals"][0]["node_id"]
        foreign = next(goal["node_id"] for plan in active if plan["plan_id"] != first["context"]["plan_id"] for goal in plan["research_subgoals"])
        self._write(first, "memory:branch:proof_steps", {"summary": "Local attempt"})
        with self.assertRaises(ReCTMError):
            self._commit(first, "branch_complete", {"status": "partial", "summary": "Wrong scope", "unproved_subgoals": [foreign]})
        first = self._next(run_id)
        self._commit(first, "branch_complete", {"status": "partial", "summary": "Need reference", "obstructions": [{"node_id": own, "class": "missing_reference", "summary": "A precise source is needed"}]})
        second = self._next(run_id)
        self.assertNotIn("mathematical_research_state", second["context"])
        self._write(second, "memory:branch:proof_steps", {"summary": "Independent attempt"})
        node = second["context"]["assigned_research_subgoals"][0]["node_id"]
        self._commit(second, "branch_complete", {"status": "failed", "summary": "Need lemma", "unproved_subgoals": [node]})
        join = self._next(run_id)
        self.assertEqual(join["role"], "join")
        self.assertNotIn("mathematical_research_state", join["context"])
        self._commit(join, "join_complete", {"common_failures": ["Missing lemma and reference"]})
        failure = self._next(run_id)
        self.assertIn("mathematical_research_state", failure["context"])
        self._commit(failure, "failures_identified", {"summary": {"obstruction": "Missing theorem", "next_step": "Strengthen assumptions", "affected_node_ids": ["target"], "obstruction_class": "missing_hypothesis"}})
        record = self.vault.read_generation_memory(run_id, "failed_paths")[-1]
        self.assertEqual(record["record_type"], "key_failures_summary")
        self.assertEqual(record["actor_domain_id"], failure["domain_id"])
        replan = self._next(run_id)
        self._commit(replan, "replan_complete", {"decision": {"reason": "Use additional assumptions", "new_constraints": ["Explicitly assume compactness"], "preserved_node_ids": [own]}})
        record = self.vault.read_generation_memory(run_id, "big_decisions")[-1]
        self.assertEqual(record["record_type"], "replan_decision")
        self.assertEqual(record["preserved_node_ids"], [own])
        self.assertEqual(self._next(run_id)["state"], "propose_plans")

    def test_screening_rejects_labels_and_status_inconsistent_obstructions(self) -> None:
        run_id, task = self.advance_to_plans()
        active = self.store.get_run(run_id)["metadata"]["active_plans"]
        first = active[0]
        for entry in ({"status": "stuck", "summary": "No obstruction", "method": "direct"}, {"status": "solved", "summary": "Contradiction", "method": "direct", "obstruction": "missing_lemma"}):
            with self.assertRaises(ReCTMError): _merge_direct_screening({first["plan_id"]: {"sg-1": entry}}, active, protocol_version=3)
        first["source_plan_id"] = "caller-label"
        with self.assertRaises(ReCTMError): _merge_direct_screening({"caller-label": {"sg-1": {"status": "solved", "summary": "x", "method": "direct"}}}, active, protocol_version=3)
        self.assertEqual(_merge_direct_screening({"caller-label": {"sg-1": {"status": "solved", "summary": "x"}}}, active, protocol_version=2)[1][first["plan_id"]]["sg-1"]["status"], "solved")

    def test_private_roles_do_not_read_broad_research_history(self) -> None:
        run_id = self.start()
        run = self.store.get_run(run_id)
        with patch.object(self.vault, "read_generation_memory", side_effect=AssertionError("private history read")):
            for role in (WorkflowRole.VERIFIER, WorkflowRole.BRANCH, WorkflowRole.JOIN, WorkflowRole.ASSEMBLER, WorkflowRole.FINALIZER):
                self.assertIsNone(self.engine._research_context(run, role))

    def test_every_runtime_protocol3_task_example_is_schema_valid(self) -> None:
        run_id = self.start()
        run = self.store.get_run(run_id)
        for state in WorkflowState:
            try:
                task = self.engine._task_for_run(run, state)
            except ReCTMError as exc:
                if exc.code != "NO_MODEL_TASK": raise
                continue
            examples = [task[key] for key in ("minimal_submission", "minimal_submission_template") if key in task] + task.get("submission_examples", [])
            for example in examples:
                _validate_schema_value(example.get("payload", {}), task["commit_payload_schema"], path=state.value)
