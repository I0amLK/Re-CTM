from __future__ import annotations

import copy
import hashlib
import json
import unittest

from re_ctm.errors import ReCTMError
from re_ctm.fact_graph import FactGraph, bm25_rank, tokenize
from re_ctm.fact_memory import (
    attach_project_memory, compute_fact_id, prepare_verified_facts, project_findings,
    project_memory_view, validate_manifest_facts,
)
from re_ctm.research_state.model import ResearchAttempt, ResearchNode, ResearchSnapshot, project


def manifest_entry(key: str = "target", statement: str = "Target.", proof: str = "Proof.",
                   predecessors: list[str] | None = None) -> dict:
    return {"key": key, "statement_tex": statement, "proof_tex": proof,
            "predecessors": predecessors or [], "glossary_introduces": {}}


class FactPreparationTests(unittest.TestCase):
    def test_mtm_content_id_golden_vectors(self) -> None:
        self.assertEqual(compute_fact_id("project-main", [], {}, "$1=1$.", r"Proof.  1=1.\qed"),
                         "3931cde730056bca")
        self.assertEqual(compute_fact_id("P", ["bbb", "aaa"], {"x": "the variable", "α": "alpha"},
                                         " A  implies B ", " Proof\n done "), "d6efc332d3843518")

    def test_exact_substring_provenance_and_target(self) -> None:
        manifest = {"facts": [manifest_entry()]}
        self.assertEqual(len(prepare_verified_facts("P", "Target.", "Target. Proof.", manifest, [], set())), 1)
        for target, proof in (("Other.", "Target. Proof."), ("Target.", "Target. Other."),
                              ("Target.", "Not target. Proof.")):
            with self.subTest(target=target, proof=proof), self.assertRaises(ReCTMError) as caught:
                prepare_verified_facts("P", target, proof, manifest, [], set())
            self.assertEqual(caught.exception.code, "INVALID_PROOF_FACTS")

    def test_implicit_target_can_use_full_proof_without_statement_substring(self) -> None:
        facts = prepare_verified_facts("P", "Target.", "Entire verified proof", {}, [], set())
        self.assertEqual(facts[0].statement_tex, "Target.")
        self.assertEqual(facts[0].proof_tex, "Entire verified proof")

    def test_revision_dependencies_attach_only_to_target(self) -> None:
        manifest = {"facts": [manifest_entry("a", "Lemma A.", "Step A."),
                               manifest_entry("b", "Lemma B.", "Step B.", ["a"]),
                               manifest_entry(predecessors=["b"])]}
        proof = "Lemma A. Step A. Lemma B. Step B. Target. Proof."
        known = {"1" * 16, "2" * 16}
        baseline = prepare_verified_facts("P", "Target.", proof, manifest, [], known)
        changed = prepare_verified_facts("P", "Target.", proof, manifest, list(known), known)
        self.assertEqual(baseline[:2], changed[:2])
        self.assertEqual(set(changed[-1].predecessors), known | {changed[1].fact_id})
        self.assertNotEqual(baseline[-1].fact_id, changed[-1].fact_id)

    def test_local_order_unknown_cycle_duplicate_and_merged_limit(self) -> None:
        for entries in ([manifest_entry(predecessors=["target"])],
                        [manifest_entry(predecessors=["missing"])],
                        [manifest_entry("a"), manifest_entry()]):
            with self.subTest(entries=entries), self.assertRaises(ReCTMError):
                prepare_verified_facts("P", "Target.", "Target. Proof.", {"facts": entries}, [], set())
        ids = [f"{index:016x}" for index in range(65)]
        with self.assertRaises(ReCTMError):
            prepare_verified_facts("P", "Target.", "Proof.", {}, ids, set(ids))

    def test_names_and_intuition_do_not_change_content_address(self) -> None:
        manifest = {"facts": [manifest_entry("a", "Lemma.", "Step."), manifest_entry(predecessors=["a"])]}
        changed = copy.deepcopy(manifest)
        changed["facts"][0].update(key="renamed", intuition="An advisory explanation")
        changed["facts"][1]["predecessors"] = ["renamed"]
        proof = "Lemma. Step. Target. Proof."
        first = prepare_verified_facts("P", "Target.", proof, manifest, [], set())
        second = prepare_verified_facts("P", "Target.", proof, changed, [], set())
        self.assertEqual([f.fact_id for f in first], [f.fact_id for f in second])

    def test_strict_manifest_fields_and_byte_bounds(self) -> None:
        for value in (None, [], [manifest_entry()] * 33, [42],
                      [{**manifest_entry(), "external_refs": []}],
                      [{**manifest_entry(), "intuition": False}],
                      [{**manifest_entry(), "key": "汉字"}],
                      [{**manifest_entry(), "glossary_introduces": {"x": 3}}],
                      [{**manifest_entry(), "proof_tex": "汉" * 21846}]):
            with self.subTest(value=repr(value)[:80]), self.assertRaises(ReCTMError):
                validate_manifest_facts(value, "Target.")

    def test_findings_are_typed_stable_and_target_is_excluded(self) -> None:
        state = project(ResearchSnapshot(nodes=(ResearchNode("target", "Target", "target", "partial"),
                                                  ResearchNode("lemma", "Partial lemma", status="partial")),
                                         attempts=(ResearchAttempt("attempt", "lemma", "domain", "counterexample",
                                                                   "failed", "This route fails", "missing_lemma"),)))
        first = project_findings("P", "R", state)
        self.assertEqual(first, project_findings("P", "R", state))
        self.assertEqual({f.kind for f in first}, {"conclusion", "counterexample", "dead_end", "obstacle"})
        self.assertTrue(all(f.verifiable == (f.kind == "conclusion") for f in first))
        self.assertFalse(any(f.claim == "Target" for f in first))


class FactGraphTests(unittest.TestCase):
    def test_topology_cycle_missing_revocation_and_descendants(self) -> None:
        graph = FactGraph({"c": {"b"}, "b": {"a"}, "a": set()})
        self.assertEqual(graph.topological_order, ("a", "b", "c"))
        self.assertEqual(graph.descendants("a"), {"b", "c"})
        for dependencies, revoked in (({"a": {"b"}}, set()), ({"a": {"a"}}, set()),
                                       ({"a": {"b"}, "b": {"a"}}, set()), ({"a": set()}, {"a"})):
            with self.subTest(dependencies=dependencies), self.assertRaises(ReCTMError):
                FactGraph(dependencies, revoked)

    def test_bm25_stable_ties_and_ascii_tokenization(self) -> None:
        docs = ["algebraic geometry", "number theory", "algebraic geometry"]
        self.assertEqual(bm25_rank("geometry", docs), [0, 2, 1])
        self.assertEqual(bm25_rank("", docs), [0, 1, 2])
        self.assertEqual(tokenize("K Γ A_B ß foo42"), ["a_b", "foo42"])


class MemoryStub:
    def __init__(self, count: int = 12, *, chain: bool = True, text: str = "Target") -> None:
        self.facts = {f"{i:016x}": {"fact_id": f"{i:016x}", "statement_tex": text, "intuition": ""}
                      for i in range(count)}
        self.predecessors = {key: ([f"{i - 1:016x}"] if chain and i else [])
                             for i, key in enumerate(self.facts)}
        self.findings = [{"finding_id": hashlib.sha256(f"{kind}{index}".encode()).hexdigest(),
                          "kind": kind, "claim": text * 100, "evidence": text * 100, "verifiable": False,
                          "status": "active", "run_id": "current" if index == 0 else "old"}
                         for kind in ("dead_end", "counterexample", "obstacle", "plan") for index in range(8)]

    def memory_fact_candidates(self, project_id: str, *, owner_id: str) -> list[dict]:
        return list(reversed(list(self.facts.values())))

    def memory_fact_predecessors(self, project_id: str, fact_id: str) -> list[str]:
        return self.predecessors[fact_id]

    def memory_fact_summary(self, project_id: str, fact_id: str) -> dict:
        return self.facts[fact_id]

    def list_project_findings(self, project_id: str, *, owner_id: str) -> list[dict]:
        return self.findings


class MemoryViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = project(ResearchSnapshot(nodes=(ResearchNode("target", "Target", "target"),)))

    def test_fact_count_closure_current_run_exclusion_and_budget(self) -> None:
        store = MemoryStub()
        view = project_memory_view(store, "P", "owner", "current", self.state)
        ids = {row["fact_id"] for row in view["fact_graph"]["nodes"]}
        self.assertEqual(len(ids), 8)
        self.assertTrue(all(predecessor in ids for key in ids for predecessor in store.predecessors[key]))
        current = {row["finding_id"] for row in store.findings if row["run_id"] == "current"}
        for name in ("prior_dead_ends", "prior_counterexamples", "obstacles", "other_findings"):
            self.assertLessEqual(len(view[name]), 5)
            self.assertFalse(current & {row["finding_id"] for row in view[name]})
        self.assertLessEqual(len(json.dumps(view, ensure_ascii=False, separators=(",", ":")).encode()), 6000)
        self.assertEqual(view, project_memory_view(store, "P", "owner", "current", self.state))

    def test_escaped_utf8_trimming_preserves_graph_closure(self) -> None:
        store = MemoryStub(text='汉\x00"\\' * 80)
        view = project_memory_view(store, "P", "owner", "current", self.state)
        ids = {row["fact_id"] for row in view["fact_graph"]["nodes"]}
        self.assertTrue(all(predecessor in ids for key in ids for predecessor in store.predecessors[key]))
        self.assertLessEqual(len(json.dumps(view, ensure_ascii=False, separators=(",", ":")).encode()), 6000)

    def test_combined_research_budget_is_checked(self) -> None:
        view = project_memory_view(MemoryStub(), "P", "owner", "current", self.state)
        self.assertIn("project_memory", attach_project_memory({"target": "Target"}, view))
        with self.assertRaises(ReCTMError):
            attach_project_memory({"target": "x" * 24576}, view)


if __name__ == "__main__":
    unittest.main()
