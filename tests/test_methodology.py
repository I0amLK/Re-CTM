from __future__ import annotations

import unittest

from re_ctm.enums import WorkflowState
from re_ctm.methodology import task_for_state
from re_ctm.tools import _validate_schema_value


MODEL_STATES = (
    WorkflowState.ASSESS,
    WorkflowState.EXPLORE,
    WorkflowState.PROPOSE_PLANS,
    WorkflowState.DIRECT_PROVING,
    WorkflowState.BRANCH_RUN,
    WorkflowState.BRANCH_JOIN,
    WorkflowState.IDENTIFY_FAILURES,
    WorkflowState.REPLAN,
    WorkflowState.ASSEMBLE,
    WorkflowState.VERIFY,
    WorkflowState.REPAIR,
)


class MethodologyContractTestCase(unittest.TestCase):
    def test_every_model_task_is_zero_guess_self_describing(self) -> None:
        for state in MODEL_STATES:
            with self.subTest(state=state.value):
                task = task_for_state(state)
                self.assertIsInstance(task.get("write_contract"), list)
                self.assertIsInstance(task.get("commit_payload_schema"), dict)
                self.assertEqual(task["step_protocol"]["tool"], "rethlas_step")
                self.assertIn("run_id", task["step_protocol"]["use_current_envelope_fields"])
                self.assertIn("capability", task["step_protocol"]["use_current_envelope_fields"])
                self.assertTrue(
                    any(
                        key in task
                        for key in (
                            "minimal_submission",
                            "minimal_submission_template",
                            "submission_examples",
                        )
                    ),
                    state.value,
                )

    def test_memory_write_contracts_explicitly_require_objects(self) -> None:
        for state in MODEL_STATES:
            task = task_for_state(state)
            for contract in task["write_contract"]:
                resource = str(contract.get("resource") or "")
                if resource.startswith("memory:"):
                    self.assertEqual(
                        contract["content_schema"].get("type"),
                        "object",
                        f"{state.value}:{resource}",
                    )

    def test_server_derived_records_are_not_misreported_as_required_writes(self) -> None:
        planning = task_for_state(WorkflowState.PROPOSE_PLANS)
        self.assertEqual(planning["required_records"], [])
        self.assertEqual(planning["write_contract"], [])
        self.assertEqual(planning["commit_payload_schema"]["required"], ["plans"])
        self.assertEqual(planning["minimal_submission"]["writes"], [])

        failures = task_for_state(WorkflowState.IDENTIFY_FAILURES)
        self.assertEqual(failures["required_records"], [])
        self.assertEqual(failures["commit_payload_schema"]["required"], ["summary"])

        replan = task_for_state(WorkflowState.REPLAN)
        self.assertEqual(replan["required_records"], [])
        self.assertEqual(replan["commit_payload_schema"]["required"], ["decision"])

    def test_verifier_and_repair_keep_logical_writes_out_of_commit_payload(self) -> None:
        verify = task_for_state(WorkflowState.VERIFY)
        self.assertEqual(verify["commit_payload_schema"]["properties"], {})
        self.assertIn(
            "verification_report",
            [item["resource"] for item in verify["write_contract"]],
        )

        repair = task_for_state(WorkflowState.REPAIR)
        self.assertEqual(repair["commit_payload_schema"]["properties"], {})
        self.assertEqual(repair["write_contract"][0]["resource"], "proof")

    def test_documented_submission_examples_validate_against_their_contracts(self) -> None:
        for state in MODEL_STATES:
            task = task_for_state(state)
            if "minimal_submission" in task:
                examples = [task["minimal_submission"]]
            elif "minimal_submission_template" in task:
                examples = [task["minimal_submission_template"]]
            else:
                examples = task["submission_examples"]
            contracts = {
                item["resource"]: item
                for item in task["write_contract"]
                if isinstance(item, dict) and isinstance(item.get("resource"), str)
            }
            for index, example in enumerate(examples):
                with self.subTest(state=state.value, example=index):
                    self.assertEqual(example["action"], task["commit_action"])
                    _validate_schema_value(
                        example.get("payload", {}),
                        task["commit_payload_schema"],
                        path=f"{state.value}.payload",
                    )
                    for write in example.get("writes", []):
                        resource = write["resource"]
                        self.assertIn(resource, contracts)
                        _validate_schema_value(
                            write["content"],
                            contracts[resource]["content_schema"],
                            path=f"{state.value}.{resource}.content",
                        )


if __name__ == "__main__":
    unittest.main()
