from __future__ import annotations

import json
import sqlite3
import unittest
from unittest import mock

import test_v020 as legacy
from re_ctm.enums import WorkflowRole
from re_ctm.tools import _validate_schema_value


PROOF_WITH_LEMMA = (
    "\\documentclass{article}\n\\usepackage{amsthm}\n\\newtheorem{theorem}{Theorem}\n"
    "\\begin{document}\n\\begin{theorem}$0=0$.\\end{theorem}\n"
    "\\begin{proof}Reflexivity gives $0=0$.\\end{proof}\n"
    "\\begin{theorem}$1=1$.\\end{theorem}\n"
    "\\begin{proof}Reflexivity gives $1=1$.\\end{proof}\n\\end{document}\n"
)
FACTS = [
    {"key": "lemma", "statement_tex": "$0=0$.", "proof_tex": "Reflexivity gives $0=0$.",
     "predecessors": [], "glossary_introduces": {}},
    {"key": "target", "statement_tex": "$1=1$.", "proof_tex": "Reflexivity gives $1=1$.",
     "predecessors": ["lemma"], "glossary_introduces": {}, "intuition": "Reflexivity"},
]


class FactWorkflowTests(unittest.TestCase):
    tearDown = legacy.V020MCPTestCase.tearDown
    call = legacy.V020MCPTestCase.call
    create_project_claim = legacy.V020MCPTestCase.create_project_claim
    finish_compact = legacy.V020MCPTestCase.finish_compact

    def setUp(self) -> None:
        legacy.V020MCPTestCase.setUp(self)
        self.tools.workflow_protocol_version = 3

    def _assemble(self, project_id: str, claim_id: str) -> dict:
        start = self.call("rethlas_start", {"problem_tex": "Prove $1=1$.", "project_id": project_id,
                                            "target_claim_id": claim_id, "workflow_mode": "compact"})
        assess = self.call("rethlas_step", {"run_id": start["run_id"]})
        return self.call("rethlas_step", {"run_id": start["run_id"], "capability": assess["capability"],
                                          **assess["task"]["minimal_submission"]})

    def _finish_facts(self, project_id: str, claim_id: str, *, facts: list = FACTS,
                      dependencies: list[str] | None = None) -> dict:
        assembled = self._assemble(project_id, claim_id)
        manifest = {"target_statement_tex": "$1=1$.", "dependency_revision_ids": dependencies or [],
                    "reference_ids": [], "conditional_hypotheses": [], "computational_evidence": [], "facts": facts}
        contract = next(item for item in assembled["task"]["write_contract"] if item["resource"] == "proof_manifest")
        self.assertIn("facts", contract["content_schema"]["properties"])
        _validate_schema_value(manifest, contract["content_schema"], path="proof_manifest")
        verify = self.call("rethlas_step", {"run_id": assembled["run_id"], "capability": assembled["capability"],
                                            "writes": [{"resource": "proof", "content": PROOF_WITH_LEMMA},
                                                       {"resource": "proof_manifest", "content": manifest}],
                                            "action": "proof_submitted", "payload": {"outcome": "proof"}})
        self.assertEqual(verify["state"], "verify")
        self.assertNotIn("mathematical_research_state", verify["context"])
        return self.call("rethlas_step", {"run_id": verify["run_id"], "capability": verify["capability"],
                                          **verify["task"]["minimal_submission"]})

    def test_new_protocol_implicit_target_promotes_fact_and_retries_idempotently(self) -> None:
        project_id, claim_id, _ = self.create_project_claim("Target", "$1=1$.")
        done = self.finish_compact(project_id=project_id, claim_id=claim_id)
        self.assertEqual(done["state"], "done")
        revision = self.store.current_claim_revision(claim_id, owner_id="owner")
        self.assertEqual(revision["evidence_status"], "VERIFIED")
        self.assertEqual(len(revision["fact_id"]), 16)
        self.assertEqual(len(self.store.list_project_facts(project_id, owner_id="owner")), 1)
        self.call("rethlas_step", {"run_id": done["run_id"]})
        self.assertEqual(len(self.store.list_project_facts(project_id, owner_id="owner")), 1)
        self.assertEqual(self.tools.workflow.vault.read_final_proof(done["run_id"]), legacy.PROOF)

    def test_explicit_facts_and_whole_proof_dependencies_promote_atomically(self) -> None:
        project_id, dependency_claim, _ = self.create_project_claim("Dependency", "$1=1$.")
        self.finish_compact(project_id=project_id, claim_id=dependency_claim)
        dependency = self.store.current_claim_revision(dependency_claim, owner_id="owner")
        created = self.call("rethlas_control", {"action": "claim_create", "project_id": project_id,
                                                "title": "Target", "statement_tex": "$1=1$."})
        target_claim = created["claim"]["claim_id"]
        done = self._finish_facts(project_id, target_claim, dependencies=[dependency["revision_id"]])
        self.assertEqual(done["state"], "done")
        revision = self.store.current_claim_revision(target_claim, owner_id="owner")
        self.assertEqual(revision["evidence_status"], "VERIFIED")
        facts = self.store.list_project_facts(project_id, owner_id="owner")
        self.assertEqual(len(facts), 3)
        lemma = next(fact for fact in facts if fact["statement_tex"] == "$0=0$.")
        self.assertEqual(self.store.memory_fact_predecessors(project_id, lemma["fact_id"]), [])
        self.assertEqual(set(self.store.memory_fact_predecessors(project_id, revision["fact_id"])),
                         {lemma["fact_id"], dependency["fact_id"]})

    def test_unverified_fact_provenance_leaves_final_proof_valid_and_registry_pending(self) -> None:
        project_id, claim_id, _ = self.create_project_claim("Target", "$1=1$.")
        facts = [{**FACTS[-1], "proof_tex": "Unverified proof fragment", "predecessors": []}]
        done = self._finish_facts(project_id, claim_id, facts=facts)
        self.assertEqual(done["state"], "done")
        self.assertEqual(self.tools.workflow.vault.read_final_proof(done["run_id"]), PROOF_WITH_LEMMA)
        revision = self.store.current_claim_revision(claim_id, owner_id="owner")
        self.assertEqual(revision["evidence_status"], "OPEN")
        self.assertEqual(self.store.list_project_facts(project_id, owner_id="owner"), [])
        promotion = self.store.get_run(done["run_id"])["metadata"]["registry_promotion"]
        self.assertEqual(promotion["error"]["code"], "INVALID_PROOF_FACTS")

    def test_legacy_dependency_is_visible_but_not_silently_promoted_to_fact(self) -> None:
        self.tools.workflow_protocol_version = 2
        project_id, dependency_claim, _ = self.create_project_claim("Legacy", "$1=1$.")
        self.finish_compact(project_id=project_id, claim_id=dependency_claim)
        dependency = self.store.current_claim_revision(dependency_claim, owner_id="owner")
        self.assertIsNone(dependency["fact_id"])
        self.tools.workflow_protocol_version = 3
        target = self.call("rethlas_control", {"action": "claim_create", "project_id": project_id,
                                               "title": "Target", "statement_tex": "$1=1$."})
        done = self.finish_compact(project_id=project_id, claim_id=target["claim"]["claim_id"],
                                   dependencies=[dependency["revision_id"]])
        self.assertEqual(done["state"], "done")
        promotion = self.store.get_run(done["run_id"])["metadata"]["registry_promotion"]
        self.assertEqual(promotion["error"]["code"], "INVALID_PROOF_FACTS")
        self.assertEqual(self.store.list_project_facts(project_id, owner_id="owner"), [])

    def test_project_memory_is_generator_only_and_finding_failure_is_nonfatal(self) -> None:
        project_id, claim_id, _ = self.create_project_claim("Target", "$1=1$.")
        done = self.finish_compact(project_id=project_id, claim_id=claim_id)
        started = self.call("rethlas_start", {"problem_tex": "Prove $1=1$.", "project_id": project_id,
                                              "target_claim_id": claim_id, "workflow_mode": "compact"})
        assess = self.call("rethlas_step", {"run_id": started["run_id"]})
        memory = assess["context"]["mathematical_research_state"]["project_memory"]
        self.assertTrue(memory["advisory_only"])
        self.assertEqual(len(memory["fact_graph"]["nodes"]), 1)
        run = self.store.get_run(assess["run_id"])
        engine = self.tools.workflow
        with mock.patch.object(engine, "_normalized_research_state", side_effect=AssertionError("must not read")):
            for role in (WorkflowRole.VERIFIER, WorkflowRole.BRANCH, WorkflowRole.JOIN, WorkflowRole.ASSEMBLER):
                self.assertIsNone(engine._research_context(run, role))
        with mock.patch.object(self.store, "insert_project_findings", side_effect=sqlite3.OperationalError("full")):
            view = engine._research_context(run, WorkflowRole.GENERATOR)
        self.assertIn("project_memory", view)
        self.assertLessEqual(len(json.dumps(view, ensure_ascii=False, separators=(",", ":")).encode()), 24576)
        self.assertEqual(self.store.get_run(done["run_id"])["state"], "done")

    def test_transition_projects_findings_before_an_assembler_task(self) -> None:
        project_id, claim_id, _ = self.create_project_claim("Target", "$1=1$.")
        started = self.call("rethlas_start", {"problem_tex": "Prove $1=1$.", "project_id": project_id,
                                              "target_claim_id": claim_id, "workflow_mode": "compact"})
        assess = self.call("rethlas_step", {"run_id": started["run_id"]})
        submission = assess["task"]["minimal_submission"]
        assembled = self.call("rethlas_step", {
            "run_id": started["run_id"], "capability": assess["capability"], **submission,
            "writes": [*submission["writes"], {"resource": "memory:generation:counterexamples", "content": {
                "event_type": "counterexample_probe", "node_id": "target", "outcome": "not_found_within_scope",
                "summary": "No small counterexample", "probe_scope": "Integers from zero to three"}}],
        })
        self.assertEqual(assembled["role"], "assembler")
        self.assertNotIn("mathematical_research_state", assembled["context"])
        findings = self.store.list_project_findings(project_id, owner_id="owner")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "counterexample")
        self.assertFalse(findings[0]["verifiable"])
        self.tools.workflow._persist_project_findings_after_transition(self.store.get_run(started["run_id"]), "test-replay")
        self.assertEqual(len(self.store.list_project_findings(project_id, owner_id="owner")), 1)


if __name__ == "__main__":
    unittest.main()
