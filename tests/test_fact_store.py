from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from re_ctm.debug import utc_now
from re_ctm.errors import ReCTMError
from re_ctm.fact_memory import ProjectFinding, prepare_promotion_facts, prepare_verified_facts
from re_ctm.fact_store import insert_promoted_facts, verify_matching_findings
from re_ctm.storage import StateStore


class FactStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.directory.name) / "state.sqlite3")
        self.store.create_project(owner_id="owner", title="Project", project_id="P")
        self._run("R", "P")

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def _run(self, run_id: str, project_id: str) -> None:
        self.store.create_run(run_id=run_id, problem_id="problem", owner_id="owner", state="done",
                              metadata={"workflow_protocol_version": 3})
        snapshot = self.store.create_project_snapshot(project_id, owner_id="owner")
        self.store.link_run_to_project(run_id=run_id, owner_id="owner", project_id=project_id,
                                      project_snapshot_id=snapshot["snapshot_id"], target_claim_id=None,
                                      base_revision_id=None, requested_workflow_mode="compact",
                                      effective_workflow_mode="compact", register_result=False)

    def _facts(self, *, project_id: str = "P", dependencies: list[str] | None = None,
               statement: str = "Target.", proof: str = "Proof.") -> list:
        return prepare_verified_facts(project_id, statement, proof, {}, dependencies or [], set(dependencies or []))

    def _insert(self, facts: list, *, project_id: str = "P", run_id: str = "R") -> str:
        with self.store.transaction() as connection:
            return insert_promoted_facts(connection, project_id, run_id, facts, utc_now())

    def _finding(self, claim: str = "Target.", *, verifiable: bool = True,
                  kind: str = "conclusion") -> ProjectFinding:
        return ProjectFinding(hashlib.sha256((claim + str(verifiable) + kind).encode()).hexdigest(), kind,
                              claim, "Evidence", verifiable, '{"node_id":"lemma"}')

    def test_insert_is_content_addressed_immutable_idempotent(self) -> None:
        facts = self._facts()
        fact_id = self._insert(facts)
        self.assertEqual(self._insert(facts), fact_id)
        self.assertEqual(len(self.store.list_project_facts("P", owner_id="owner")), 1)
        with self.assertRaises(ReCTMError):
            self._insert([replace(facts[0], statement_tex="Changed statement")])
        with self.assertRaises(ReCTMError):
            insert_promoted_facts(self.store._connection, "P", "R", facts, utc_now())
        for field, value in (("statement_tex", 123), ("glossary_introduces", {"x": 123}),
                             ("predecessors", [False]), ("intuition", "汉" * 1366)):
            with self.subTest(field=field), self.assertRaises(ReCTMError):
                self._insert([replace(facts[0], **{field: value})])

    def test_missing_foreign_revoked_predecessors_rollback_complete_batch(self) -> None:
        self.store.create_project(owner_id="owner", title="Other", project_id="Q")
        self._run("Q-run", "Q")
        foreign = self._insert(self._facts(project_id="Q"), project_id="Q", run_id="Q-run")
        active = self._insert(self._facts(statement="Ancestor."))
        self.store.revoke_project_fact(active, "operator", "Incorrect lemma")
        for predecessor in ("f" * 16, foreign, active):
            with self.subTest(predecessor=predecessor):
                first = self._facts(statement="Intermediate.")
                second = self._facts(statement="Dependent.", dependencies=[predecessor])
                with self.assertRaises(ReCTMError):
                    self._insert(first + second)
                ids = {row["fact_id"] for row in self.store.list_project_facts("P", owner_id="owner")}
                self.assertEqual(ids, {active})

    def test_local_predecessor_chain_and_failed_late_hook_are_atomic(self) -> None:
        first = self._facts(statement="Lemma.")
        second = self._facts(dependencies=[first[0].fact_id])
        with self.assertRaisesRegex(RuntimeError, "late failure"):
            with self.store.transaction() as connection:
                insert_promoted_facts(connection, "P", "R", first + second, utc_now())
                raise RuntimeError("late failure")
        self.assertEqual(self.store.list_project_facts("P", owner_id="owner"), [])
        self._insert(first + second)
        self.assertEqual(self.store.memory_fact_predecessors("P", second[0].fact_id), [first[0].fact_id])

    def test_finding_projection_replay_verification_and_cascade_append_only(self) -> None:
        findings = [self._finding("Lemma."), self._finding(), self._finding("Plan.", verifiable=False, kind="plan")]
        self.store.insert_project_findings("P", "R", "owner", findings)
        self.store.insert_project_findings("P", "R", "owner", findings)
        self.assertEqual(len(self.store.list_project_findings("P", owner_id="owner")), 3)
        first = self._facts(statement="Lemma.")
        second = self._facts(dependencies=[first[0].fact_id])
        facts = first + second
        with self.store.transaction() as connection:
            insert_promoted_facts(connection, "P", "R", facts, utc_now())
            verify_matching_findings(connection, "R", facts, utc_now())
            verify_matching_findings(connection, "R", facts, utc_now())
        states = {row["claim"]: row["status"] for row in self.store.list_project_findings("P", owner_id="owner")}
        self.assertEqual(states, {"Lemma.": "verified", "Target.": "verified", "Plan.": "active"})
        revoked = self.store.revoke_project_fact(first[0].fact_id, "operator", "Counterexample found")
        self.assertEqual(set(revoked["revoked_fact_ids"]), {fact.fact_id for fact in facts})
        self.assertEqual(self.store.revoke_project_fact(first[0].fact_id, "operator", "Again")["revoked_fact_ids"], [])
        self.assertEqual(self.store.active_project_fact_ids("P", owner_id="owner"), set())
        states = {row["claim"]: row["status"] for row in self.store.list_project_findings("P", owner_id="owner")}
        self.assertEqual(states, {"Lemma.": "superseded", "Target.": "superseded", "Plan.": "active"})
        history = self.store._fetch_all("SELECT status FROM memory_finding_status WHERE finding_id=? ORDER BY seq",
                                        (findings[0].finding_id,))
        self.assertEqual([row["status"] for row in history], ["active", "verified", "superseded"])
        self.assertEqual(self.store._fetch_one("SELECT count(*) AS n FROM facts", ())["n"], 2)
        with self.assertRaises(ReCTMError):
            self._insert(first)

    def test_findings_verification_rolls_back_with_fact_transaction(self) -> None:
        finding = self._finding()
        self.store.insert_project_findings("P", "R", "owner", [finding])
        facts = self._facts()
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as connection:
                insert_promoted_facts(connection, "P", "R", facts, utc_now())
                verify_matching_findings(connection, "R", facts, utc_now())
                raise RuntimeError("later revision failure")
        self.assertEqual(self.store.list_project_facts("P", owner_id="owner"), [])
        self.assertEqual(self.store.list_project_findings("P", owner_id="owner")[0]["status"], "active")

    def test_owner_boundaries_and_export_determinism(self) -> None:
        first = self._facts(statement="Lemma.")
        second = self._facts(dependencies=[first[0].fact_id])
        self._insert(first + second)
        exported = self.store.project_fact_graph("P", owner_id="owner")
        encoded = json.dumps(exported, ensure_ascii=False)
        self.assertEqual(encoded, json.dumps(self.store.project_fact_graph("P", owner_id="owner"), ensure_ascii=False))
        self.assertEqual(exported["graph"]["edges"], [{"source": second[0].fact_id, "target": first[0].fact_id,
                                                      "relation": "depends_on"}])
        self.assertNotIn("proof_tex", encoded)
        self.assertNotIn("owner_id", encoded)
        for method in (self.store.project_fact_graph, self.store.list_project_facts,
                       self.store.list_project_findings, self.store.memory_fact_candidates):
            with self.subTest(method=method.__name__), self.assertRaises(ReCTMError) as caught:
                method("P", owner_id="other-owner")
            self.assertEqual(caught.exception.category, "permission")
        with self.assertRaises(ReCTMError):
            self.store.revoke_project_fact(first[0].fact_id, "operator", "reason", owner_id="other-owner")
        self.assertEqual(len(self.store.active_project_fact_ids("P", owner_id="owner")), 2)

    def test_project_findings_reject_wrong_project_and_bad_batch_atomically(self) -> None:
        self.store.create_project(owner_id="owner", title="Other", project_id="Q")
        with self.assertRaises(ReCTMError):
            self.store.insert_project_findings("Q", "R", "owner", [self._finding()])
        with self.assertRaises(ReCTMError):
            self.store.insert_project_findings("P", "R", "owner", [self._finding(), replace(self._finding(), kind="unknown")])
        self.assertEqual(self.store.list_project_findings("P", owner_id="owner"), [])
        finding = self._finding()
        self.store.insert_project_findings("P", "R", "owner", [finding])
        with self.assertRaises(ReCTMError):
            self.store.insert_project_findings("P", "R", "owner", [replace(finding, claim="Changed")])
        self.assertEqual(self.store.list_project_findings("P", owner_id="owner")[0]["claim"], "Target.")

    def test_legacy_null_fact_revision_is_not_promotable_dependency(self) -> None:
        claim = self.store.create_claim(owner_id="owner", project_id="P", title="Legacy")
        revision = self.store.create_open_claim_revision(owner_id="owner", claim_id=claim["claim_id"], statement_tex="Legacy.")
        manifest = {"target_statement_tex": "Target.", "dependency_revision_ids": [revision["revision_id"]]}
        with self.assertRaises(ReCTMError) as caught:
            prepare_promotion_facts(self.store, {"project_id": "P"}, "owner", manifest, "Proof.")
        self.assertEqual(caught.exception.code, "INVALID_PROOF_FACTS")
        self.assertIn("legacy dependency", caught.exception.message)


if __name__ == "__main__":
    unittest.main()
