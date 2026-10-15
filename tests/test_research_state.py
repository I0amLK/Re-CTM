from __future__ import annotations

import copy
import itertools
import json
import unittest
from dataclasses import replace

from re_ctm.errors import ReCTMError
from re_ctm.research_state import (
    ProtocolRecordStamp, ProtocolResearchScope, ResearchAttempt, ResearchDecision,
    ResearchNode, ResearchSnapshot, normalize_protocol3_plans, normalize_protocol3_generation_record,
    normalize_protocol3_branch_payload, normalize_protocol3_failure_summary, normalize_protocol3_replan_decision,
    protocol3_screening_fields, stamp_protocol3_record, normalize_research, project, task_view, select_advice,
)
from re_ctm.research_state.protocol import RESERVED_RECORD_FIELDS, identifier


def plans() -> list[dict]:
    return [
        {"summary": "Local route", "subgoals": [
            {"key": "local", "statement": "Local lemma", "depends_on": [], "critical": False},
            {"key": "global", "statement": "Global consequence", "depends_on": ["local"], "critical": True}]},
        {"summary": "Construction route", "subgoals": [
            {"key": "build", "statement": "Construct a witness", "depends_on": [], "critical": True, "kind": "construction"}]},
    ]


def stamp() -> ProtocolRecordStamp:
    return ProtocolRecordStamp("research-1", "generator", "generation-1", 2, "2026-10-14T00:00:00Z")


class ProtocolThreeRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plans = normalize_protocol3_plans(plans(), 2)
        self.scope = ProtocolResearchScope.from_active_plans(self.plans, ["ref-1"])

    def test_typed_plans_have_canonical_ids_and_dependency_edges(self) -> None:
        self.assertEqual(self.plans[0]["plan_id"], "plan-r2-1")
        self.assertEqual(self.plans[0]["research_subgoals"][1]["depends_on"], ["node:plan-r2-1:sg-1"])
        self.assertEqual(self.plans[1]["research_subgoals"][0]["kind"], "construction")
        self.assertEqual(self.plans[0]["subgoals"], ["Local lemma", "Global consequence"])

    def test_graph_rejects_unknown_self_cycle_duplicate_and_extra_fields(self) -> None:
        for change in ("unknown", "self", "cycle", "duplicate", "extra", "badkey", "kind", "critical"):
            value = plans()
            goals = value[0]["subgoals"]
            if change == "unknown": goals[0]["depends_on"] = ["missing"]
            if change == "self": goals[0]["depends_on"] = ["local"]
            if change == "cycle": goals[0]["depends_on"] = ["global"]
            if change == "duplicate": goals[1]["key"] = "local"
            if change == "extra": value[0]["authority"] = True
            if change == "badkey": goals[0]["key"] = "a:b"
            if change == "kind": goals[0]["kind"] = "target"
            if change == "critical": goals[0]["critical"] = "true"
            with self.subTest(change=change), self.assertRaises(ReCTMError):
                normalize_protocol3_plans(value, 1)

    def test_plan_count_and_nested_bounds(self) -> None:
        for value in ([plans()[0]], [dict(plans()[0], summary=str(i)) for i in range(65)],
                      [dict(plans()[0], subgoals=[dict(plans()[0]["subgoals"][0], key=f"n{i}") for i in range(65)]), plans()[1]]):
            with self.assertRaises(ReCTMError): normalize_protocol3_plans(value, 1)

    def test_scope_rejects_forged_and_duplicate_canonical_nodes(self) -> None:
        for mutation in ("duplicate", "missing", "forged"):
            value = copy.deepcopy(self.plans)
            if mutation == "duplicate": value[0]["research_subgoals"].append(value[0]["research_subgoals"][0])
            if mutation == "missing": del value[0]["research_subgoals"]
            if mutation == "forged": value[0]["research_subgoals"][0]["node_id"] = "node:other:sg-1"
            with self.assertRaises(ReCTMError): ProtocolResearchScope.from_active_plans(value)

    def test_reserved_stamp_fields_rejected(self) -> None:
        for field in RESERVED_RECORD_FIELDS:
            with self.subTest(field=field), self.assertRaises(ReCTMError):
                stamp_protocol3_record("assessment", {field: "forged"}, stamp())
            with self.assertRaises(ReCTMError):
                normalize_protocol3_generation_record("events", {"event_type": "assessment", "summary": "initial", field: "forged"}, stamp(), self.scope)
        value = normalize_protocol3_generation_record("events", {"event_type": "assessment", "summary": "initial"}, stamp(), self.scope)
        self.assertEqual(value["record_id"], "research-1")
        self.assertEqual(value["actor_domain_id"], "generation-1")

    def test_counterexample_scope_and_witness(self) -> None:
        value = {"node_id": "target", "outcome": "found", "summary": "Fails for n=0", "probe_scope": "n=0", "witness": "n=0"}
        record = normalize_protocol3_generation_record("counterexamples", value, stamp(), self.scope)
        self.assertEqual(record["obstruction_class"], "false_claim")
        for key, bad in (("node_id", "unknown"), ("witness", ""), ("probe_scope", ""), ("outcome", "proved")):
            with self.assertRaises(ReCTMError): normalize_protocol3_generation_record("counterexamples", {**value, key: bad}, stamp(), self.scope)
        negative = normalize_protocol3_generation_record("counterexamples", {**value, "outcome": "not_found_within_scope"}, stamp(), self.scope)
        self.assertIsNone(negative["obstruction_class"])

    def test_typed_retrieval_requires_registered_material(self) -> None:
        value = {"event_type": "retrieval_assessment", "outcome": "new_material", "summary": "A lemma", "reference_ids": ["ref-1"]}
        self.assertEqual(normalize_protocol3_generation_record("events", value, stamp(), self.scope)["reference_ids"], ["ref-1"])
        for refs in ([], ["ref-other"], ["ref-1", "ref-1"]):
            with self.assertRaises(ReCTMError): normalize_protocol3_generation_record("events", {**value, "reference_ids": refs}, stamp(), self.scope)

    def test_candidate_and_notation_events_bound_utf8_and_ids(self) -> None:
        value = {"event_type": "new_candidate_lemma", "statement": "∀x, x=x", "summary": "Identity", "depends_on": ["target"]}
        result = normalize_protocol3_generation_record("events", value, stamp(), self.scope)
        self.assertEqual(result["candidate_id"], "research-1")
        for key, bad in (("statement", "中" * 6000), ("depends_on", ["other"]), ("kind", "target"), ("critical", 1)):
            with self.assertRaises(ReCTMError): normalize_protocol3_generation_record("events", {**value, key: bad}, stamp(), self.scope)
        notation = {"event_type": "notation_resolution", "symbol": "q", "resolution": "Prime power", "summary": "Fixed"}
        self.assertEqual(normalize_protocol3_generation_record("events", notation, stamp(), self.scope)["symbol"], "q")

    def test_screening_fields_are_typed_and_status_consistent(self) -> None:
        value = {"status": "stuck", "summary": "Missing lemma", "method": "direct", "obstruction": "missing_lemma"}
        self.assertEqual(protocol3_screening_fields(value, "stuck")["obstruction"], "missing_lemma")
        for status, change in (("solved", {}), ("stuck", {"obstruction": None}), ("partial", {"method": "guess"}), ("partial", {"extra": True})):
            with self.assertRaises(ReCTMError): protocol3_screening_fields({**value, **change}, status)

    def test_branch_scope_and_status_are_not_model_authority(self) -> None:
        node = "node:plan-r2-1:sg-1"
        value = {"status": "partial", "summary": "Need reference", "obstructions": [{"node_id": node, "class": "missing_reference", "summary": "Need source"}]}
        self.assertEqual(normalize_protocol3_branch_payload(value, self.scope, "plan-r2-1")["obstructions"][0]["node_id"], node)
        for patch in ({"obstructions": [{"node_id": "node:plan-r2-2:sg-1", "class": "missing_reference", "summary": "foreign"}]}, {"status": "solved", "proof_route": "x"}, {"obstructions": []}, {"proved_subgoals": [node], "unproved_subgoals": [node]}):
            with self.assertRaises(ReCTMError): normalize_protocol3_branch_payload({**value, **patch}, self.scope, "plan-r2-1")

    def test_failures_and_replan_require_canonical_scope_and_causal_change(self) -> None:
        value = {"obstruction": "Need lemma", "next_step": "Prove lemma", "affected_node_ids": ["target"], "obstruction_class": "missing_lemma"}
        self.assertEqual(normalize_protocol3_failure_summary(value, self.scope)["affected_node_ids"], ["target"])
        with self.assertRaises(ReCTMError): normalize_protocol3_failure_summary({**value, "affected_node_ids": ["unknown"]}, self.scope)
        with self.assertRaises(ReCTMError): normalize_protocol3_replan_decision({"reason": "Again"}, self.scope)
        result = normalize_protocol3_replan_decision({"reason": "Focus", "selected_focus_node_id": "target"}, self.scope)
        self.assertEqual(result["selected_focus_node_id"], "target")


class ResearchGraphTests(unittest.TestCase):
    def chain(self, status: str = "open") -> ResearchSnapshot:
        return ResearchSnapshot(nodes=(ResearchNode("target", "Target", "target", dependencies=("b",)), ResearchNode("b", "B", dependencies=("a",)), ResearchNode("a", "A", status=status)))

    def test_chain_dependency_order_and_frontier(self) -> None:
        state = project(self.chain())
        self.assertEqual(state.graph["topological_order"], ["a", "b", "target"])
        self.assertEqual(state.actionable_frontier, ("a",))
        self.assertEqual(project(self.chain("route_solved")).actionable_frontier, ("b",))

    def test_refutation_propagates_and_superseded_dependency_invalidates(self) -> None:
        for status in ("refuted", "superseded"):
            state = project(self.chain(status))
            invalid = {item["node_id"] for item in state.invalid_routes}
            self.assertTrue({"target", "b"} <= invalid)
            self.assertEqual(state.actionable_frontier, ())

    def test_cycles_are_deterministic_and_rejected_before_projection(self) -> None:
        snapshot = ResearchSnapshot(nodes=(ResearchNode("target", "T", "target"), ResearchNode("a", "A", dependencies=("b",)), ResearchNode("b", "B", dependencies=("a",))))
        state = project(snapshot, reject_cycles=False)
        self.assertEqual(state.graph["cycle_components"], [["a", "b"]])
        with self.assertRaises(ReCTMError): project(snapshot)
        with self.assertRaises(ReCTMError): project(ResearchSnapshot(nodes=(ResearchNode("target", "T", "target", dependencies=("target",)),)))

    def test_unknown_duplicate_target_and_revision_fail_closed(self) -> None:
        for nodes in ((ResearchNode("a", "A"),), (ResearchNode("target", "T", "target", dependencies=("missing",)),), (ResearchNode("target", "T", "target"), ResearchNode("target", "Again", "target")), (ResearchNode("target", "T", "target"), ResearchNode("another", "T2", "target"))):
            with self.assertRaises(ReCTMError): project(ResearchSnapshot(nodes=nodes))
        with self.assertRaises(ReCTMError): ResearchNode("a", "A", revision=0)
        for bad in ("", "a/b", " a", "中", "a" * 129):
            with self.assertRaises(ReCTMError): identifier(bad)

    def test_record_and_global_limits(self) -> None:
        with self.assertRaises(ReCTMError): ResearchNode("a", "A", dependencies=tuple(f"n{i}" for i in range(65)))
        with self.assertRaises(ReCTMError): project(ResearchSnapshot(nodes=(ResearchNode("target", "T", "target"),) + tuple(ResearchNode(f"n{i}", "N") for i in range(256))))
        with self.assertRaises(ReCTMError): ResearchAttempt("a", "target", "d", "direct", "failed", "x", evidence_ids=("e",) * 33)
        nodes = tuple(ResearchNode(f"n{i}", "N", dependencies=tuple(f"n{j}" for j in range(i))) for i in range(47))
        with self.assertRaises(ReCTMError): project(ResearchSnapshot(nodes=(ResearchNode("target", "T", "target"),) + nodes))

    def test_attempt_decision_references_and_duplicates(self) -> None:
        target = ResearchNode("target", "T", "target")
        attempt = ResearchAttempt("a", "target", "d", "direct", "failed", "x")
        decision = ResearchDecision("decision", "Why")
        for kwargs in ({"attempts": (attempt, attempt)}, {"decisions": (decision, decision)}, {"attempts": (replace(attempt, node_id="other"),)}, {"decisions": (replace(decision, preserved_node_ids=("other",)),)}, {"decisions": (replace(decision, superseded_plan_ids=("other",)),)}):
            with self.assertRaises(ReCTMError): project(ResearchSnapshot(nodes=(target,), **kwargs))

    def test_digest_is_independent_of_order_and_changes_with_status(self) -> None:
        snapshot = self.chain()
        self.assertEqual(project(snapshot).digest, project(replace(snapshot, nodes=tuple(reversed(snapshot.nodes)))).digest)
        self.assertNotEqual(project(snapshot).digest, project(self.chain("partial")).digest)

    def test_alternative_plans_are_disjunctive_and_solved_is_only_advisory(self) -> None:
        nodes = (ResearchNode("target", "T", "target"), ResearchNode("a", "A", status="refuted", plan_id="p1"), ResearchNode("b", "B", status="route_solved", plan_id="p2"))
        state = project(ResearchSnapshot(nodes=nodes, active_plan_ids=("p1", "p2")))
        self.assertTrue(state.plan_routes["p2"]["route_solved"])
        self.assertEqual(select_advice(state)["rule_id"], "R08_ASSEMBLE")
        self.assertEqual(state.nodes["target"].status, "open")
        self.assertNotIn("verified", json.dumps(select_advice(state)))

    def test_required_dependency_must_be_solved_before_complete_route(self) -> None:
        nodes = (ResearchNode("target", "T", "target"), ResearchNode("a", "A", plan_id="p"), ResearchNode("b", "B", status="route_solved", dependencies=("a",), plan_id="p", declared_critical=True))
        state = project(ResearchSnapshot(nodes=nodes, active_plan_ids=("p",)))
        self.assertFalse(state.plan_routes["p"]["route_solved"])
        self.assertEqual(state.plan_routes["p"]["goal_node_ids"], ["b"])

    def test_small_dags_have_valid_deterministic_topological_order(self) -> None:
        edges = [(i, j) for i in range(4) for j in range(i)]
        for mask in range(1 << len(edges)):
            nodes = [ResearchNode("target", "T", "target")]
            for i in range(4):
                dependencies = tuple(f"n{j}" for bit, (a, j) in enumerate(edges) if a == i and mask & (1 << bit))
                nodes.append(ResearchNode(f"n{i}", "N", dependencies=dependencies))
            order = project(ResearchSnapshot(nodes=tuple(nodes))).graph["topological_order"]
            for node in nodes:
                self.assertTrue(all(order.index(dep) < order.index(node.node_id) for dep in node.dependencies))


class LegacyNormalizationTests(unittest.TestCase):
    def legacy_plan(self) -> list[dict]:
        return [{"plan_id": "plan-a", "subgoals": ["A", "B"], "subgoal_ids": ["sg-1", "sg-2"]}]

    def test_legacy_screening_and_partial_branch_mapping(self) -> None:
        normalized = normalize_research("T", 1, self.legacy_plan(), {"plan-a": {"sg-1": {"status": "partial"}}}, branch_results=[{"plan_id": "plan-a", "status": "partial", "proved_subgoals": ["A"], "unproved_subgoals": ["sg-2"], "summary": "Partial"}])
        self.assertEqual(normalized.state.nodes["node:plan-a:sg-1"].status, "route_solved")
        self.assertEqual(normalized.state.nodes["node:plan-a:sg-2"].status, "blocked")
        self.assertEqual(len(normalized.state.attempts), 2)

    def test_claimed_counterexamples_need_witness_and_known_node(self) -> None:
        for witness in (None, "", " ", [], {}):
            value = normalize_research("T", 0, [], {}, counterexamples=[{"status": "found", "witness": witness}])
            self.assertEqual(value.state.nodes["target"].status, "open")
        unknown = normalize_research("T", 0, [], {}, counterexamples=[{"node_id": "unknown", "outcome": "found", "witness": "x=0"}])
        self.assertEqual(unknown.state.nodes["target"].status, "open")
        found = normalize_research("T", 0, [], {}, counterexamples=[{"outcome": "found", "witness": "x=0"}])
        self.assertEqual(found.state.nodes["target"].status, "refuted")

    def test_retrieval_novelty_and_assessment_are_separate(self) -> None:
        events = [{"event_type": "external_search", "results": [{"reference_id": "ref1"}]}, {"event_type": "retrieval_assessment", "outcome": "new_material", "reference_ids": ["ref1"], "summary": "Useful"}]
        value = normalize_research("T", 0, [], {}, events=events + [events[1]], registered_reference_ids=["ref1"])
        self.assertEqual([attempt.outcome for attempt in value.state.attempts], ["progress", "progress", "inconclusive"])
        self.assertEqual(value.summary["novel_reference_ids"], 1)
        self.assertEqual(value.summary["repeated_reference_ids"], 2)
        with self.assertRaises(ReCTMError): normalize_research("T", 0, [], {}, events=[events[1]])

    def test_retrieval_negative_stays_inconclusive_and_unknown_external_refs_warn(self) -> None:
        value = normalize_research("T", 0, [], {}, events=[{"event_type": "external_search", "results": [{"reference_id": "unknown"}]}, {"event_type": "retrieval_assessment", "outcome": "no_new_material", "reference_ids": ["ref1"]}], registered_reference_ids=["ref1"])
        self.assertTrue(all(item.outcome == "inconclusive" for item in value.state.attempts))
        self.assertEqual(value.warnings[0]["code"], "unregistered_retrieval_reference")

    def test_unknown_status_is_inconclusive_not_failed(self) -> None:
        record = {"record_type": "direct_screening_round", "plans": [{"plan_id": "plan-a", "subgoal_results": [{"subgoal_id": "sg-1", "status": "unexpected", "summary": "x"}]}]}
        value = normalize_research("T", 0, self.legacy_plan(), {}, proof_steps=[record])
        self.assertEqual(value.state.attempts[0].outcome, "inconclusive")
        self.assertEqual(value.warnings[0]["code"], "unknown_direct_screening_status")

    def test_failures_replans_repairs_and_join_are_normalized(self) -> None:
        value = normalize_research("T", 1, self.legacy_plan(), {}, failed_paths=[{"obstruction": "Need lemma", "obstruction_class": "missing_lemma"}], big_decisions=[{"reason": "Try another", "preserved_node_ids": ["node:plan-a:sg-1"]}], verification_reports=[{"verification_report": {"critical_errors": [], "gaps": [{}]}}], branch_results=[{"branch_id": "b", "plan_id": "plan-a", "status": "partial", "proved_subgoals": ["A"]}], join_result={"outcome": "partial", "selected_branch_id": "b"})
        self.assertIn("repair", [item.method for item in value.state.attempts])
        self.assertEqual(value.state.decisions[-1].selected_focus_node_id, "node:plan-a:sg-2")
        self.assertFalse(any(item["code"] == "unknown_join_branch" for item in value.warnings))

    def test_warning_and_channel_bounds_utf8(self) -> None:
        value = normalize_research("T", 0, [], {}, failed_paths=[{}] * 200)
        self.assertEqual(len(value.warnings), 128)
        self.assertEqual(value.warnings[-1]["code"], "warnings_truncated")
        with self.assertRaises(ReCTMError): normalize_research("T", 0, [], {}, events=[{}] * 2049)
        with self.assertRaises(ReCTMError): normalize_research("T", 0, [], {}, events=[{"event_type": "external_search", "results": [{}] * 65}])

    def test_bounded_deterministic_private_scope_view(self) -> None:
        plan = [{"plan_id": "p", "subgoals": ["中" * 500 + str(i) for i in range(12)], "subgoal_ids": [f"sg-{i}" for i in range(12)]}]
        value = normalize_research("中" * 2000, 1, plan, {"p": {f"sg-{i}": {"status": "partial"} for i in range(12)}}, failed_paths=[{}] * 6)
        view = task_view(value, "generator")
        self.assertEqual(view, task_view(value, "repair"))
        self.assertTrue(view["advisory_only"])
        self.assertTrue(view["truncated"])
        self.assertLessEqual(len(view["frontier"]), 5)
        self.assertLessEqual(len(view["preserved_partial_results"]), 5)
        self.assertLessEqual(len(view["warnings"]), 3)
        self.assertLessEqual(len(json.dumps(view, ensure_ascii=False, separators=(",", ":")).encode()), 16384)
        for role in ("verifier", "branch", "join", "assembler", "finalizer", "unknown"):
            self.assertIsNone(task_view(value, role))
        for secret in ("actor_domain_id", "capability", "private_vault", "verified"):
            self.assertNotIn(secret, json.dumps(view))

    def test_repeated_retrieval_advice_stops_unproductive_search(self) -> None:
        value = normalize_research("T", 0, [], {}, events=[{"event_type": "retrieval_assessment", "outcome": "no_new_material", "summary": "Nothing"}] * 2)
        self.assertEqual(task_view(value, "generator")["suggested_next_action"]["rule_id"], "R05_STOP_RETRIEVAL")


if __name__ == "__main__":
    unittest.main()
