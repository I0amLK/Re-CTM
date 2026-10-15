"""Pure protocol-3 research validation, ported from MTM's pinned protocol.rs.

Authority (identity, clock, capabilities and persistence) belongs to WorkflowEngine.
These functions accept its stamp and never infer or grant authority themselves.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..errors import ReCTMError

MAX_ACTIVE_PLANS = 64
MAX_NODE_DEPENDENCIES = 64
MAX_IDENTIFIER_BYTES = 128
MAX_STATEMENT_BYTES = 16384
MAX_SUMMARY_BYTES = 8192
MAX_EVIDENCE_IDS = 32
MAX_EVIDENCE_ID_BYTES = 1024
METHODS = ("direct", "reduction", "toy_example", "counterexample", "retrieval", "computation", "synthesis", "repair")
OBSTRUCTIONS = ("false_claim", "missing_hypothesis", "missing_lemma", "missing_reference", "computational_bottleneck", "notation_mismatch", "circular_dependency", "incompatible_partial_results", "no_progress", "unknown")
NODE_KINDS = ("lemma", "construction", "definition")
RESERVED_RECORD_FIELDS = ("record_type", "record_id", "actor_role", "actor_domain_id", "round_index", "created_at")
_MISSING = object()


def malformed(location: str, reason: str) -> ReCTMError:
    return ReCTMError("INVALID_RESEARCH_RECORD", "The protocol-3 mathematical research record is invalid.", category="validation", details={"location": location, "reason": reason})


def bounded_count(location: str, value: int, maximum: int) -> None:
    if value > maximum:
        raise malformed(location, f"limit exceeded: {value} > {maximum}")


def object_value(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise malformed(location, "expected an object")
    return value


def reject_unknown(value: Mapping[str, Any], allowed: Iterable[str], location: str) -> None:
    for key in value:
        if key not in allowed:
            raise malformed(location, f"unknown field {key}")


def required_text(value: Any, location: str, maximum: int = MAX_SUMMARY_BYTES) -> str:
    if not isinstance(value, str):
        raise malformed(location, "non-empty bounded string required")
    value = value.strip()
    if not value or len(value.encode("utf-8")) > maximum or "\0" in value:
        raise malformed(location, "non-empty bounded string required")
    return value


def optional_text(value: Any, location: str, maximum: int = MAX_SUMMARY_BYTES) -> str | None:
    return None if value is None else required_text(value, location, maximum)


def identifier(value: Any, location: str = "identifier", *, local: bool = False) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*" if local else r"[A-Za-z0-9][A-Za-z0-9_.:-]*", value):
        raise malformed(location, "an unambiguous bounded ASCII identifier is required")
    return value


def text_array(value: Any = _MISSING, location: str = "array", maximum: int = 64, *, required: bool = False, unique: bool = False, text_maximum: int = MAX_SUMMARY_BYTES) -> list[str]:
    if value is _MISSING:
        if required:
            raise malformed(location, "non-empty array required")
        return []
    if not isinstance(value, list) or (required and not value):
        raise malformed(location, "non-empty array required" if required else "array required")
    bounded_count(location, len(value), maximum)
    result = [required_text(item, f"{location}[{index}]", text_maximum) for index, item in enumerate(value)]
    if unique and len(set(result)) != len(result):
        raise malformed(location, "array entries must be unique")
    return result


@dataclass(frozen=True)
class ProtocolRecordStamp:
    record_id: str
    actor_role: str
    actor_domain_id: str
    round_index: int
    created_at: str


@dataclass(frozen=True)
class ProtocolResearchScope:
    plan_nodes: dict[str, frozenset[str]] = field(default_factory=dict)
    node_plans: dict[str, str | None] = field(default_factory=lambda: {"target": None})
    registered_reference_ids: frozenset[str] = frozenset()

    @classmethod
    def from_active_plans(cls, active_plans: Any, registered_reference_ids: Iterable[str] = ()) -> ProtocolResearchScope:
        if not isinstance(active_plans, list):
            raise malformed("active_plans", "expected an array")
        bounded_count("active_plans", len(active_plans), MAX_ACTIVE_PLANS)
        plan_nodes: dict[str, frozenset[str]] = {}
        node_plans: dict[str, str | None] = {"target": None}
        for index, raw in enumerate(active_plans):
            location = f"active_plans[{index}]"
            plan = object_value(raw, location)
            plan_id = identifier(plan.get("plan_id"), location + ".plan_id")
            if plan_id in plan_nodes:
                raise malformed(location, "duplicate canonical plan_id")
            nodes = plan.get("research_subgoals")
            if not isinstance(nodes, list) or not nodes:
                raise malformed(location, "protocol-3 active plan is missing canonical research_subgoals")
            bounded_count(location + ".research_subgoals", len(nodes), MAX_NODE_DEPENDENCIES)
            bucket = set()
            for raw_node in nodes:
                node = object_value(raw_node, location + ".research_subgoals")
                node_id = identifier(node.get("node_id"), location + ".node_id")
                if node_id in node_plans:
                    raise malformed(location, "canonical node_id is duplicated or shared by plans")
                if node_id != protocol_node_id(plan_id, node.get("subgoal_id")):
                    raise malformed(location, "canonical node_id does not match plan/subgoal identity")
                bucket.add(node_id)
                node_plans[node_id] = plan_id
            plan_nodes[plan_id] = frozenset(bucket)
        return cls(plan_nodes, node_plans, frozenset(registered_reference_ids))

    def contains_node(self, node_id: str) -> bool:
        return node_id in self.node_plans

    def contains_plan(self, plan_id: str) -> bool:
        return plan_id in self.plan_nodes

    def plan_contains_node(self, plan_id: str, node_id: str) -> bool:
        return node_id in self.plan_nodes.get(plan_id, ())


def protocol_node_id(plan_id: str, subgoal_id: str) -> str:
    identifier(plan_id, "plan_id", local=True)
    identifier(subgoal_id, "subgoal_id", local=True)
    return identifier(f"node:{plan_id}:{subgoal_id}", "node_id")


def stamp_protocol3_record(record_type: str, content: Any, stamp: ProtocolRecordStamp) -> dict[str, Any]:
    content = object_value(content, record_type)
    for name in RESERVED_RECORD_FIELDS:
        if name in content:
            raise malformed(record_type, f"client may not supply server-owned field {name}")
    return {**copy.deepcopy(content), "record_type": record_type, "record_id": stamp.record_id,
            "actor_role": stamp.actor_role, "actor_domain_id": stamp.actor_domain_id,
            "round_index": stamp.round_index, "created_at": stamp.created_at}


def _known_node(value: Any, scope: ProtocolResearchScope, location: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    result = identifier(required_text(value, location, MAX_IDENTIFIER_BYTES), location)
    if not scope.contains_node(result):
        raise malformed(location, "unknown canonical node_id")
    return result


def _known_array(value: Any, scope: ProtocolResearchScope, location: str, *, plans: bool = False, required: bool = False) -> list[str]:
    values = text_array(value, location, required=required, unique=True, text_maximum=MAX_IDENTIFIER_BYTES)
    for item in values:
        identifier(item, location)
        if not (scope.contains_plan(item) if plans else scope.contains_node(item)):
            raise malformed(location, "unknown canonical plan_id" if plans else "unknown canonical node_id")
    return values


def _evidence(value: Any = _MISSING, location: str = "evidence_ids") -> list[str]:
    return text_array(value, location, MAX_EVIDENCE_IDS, unique=True, text_maximum=MAX_EVIDENCE_ID_BYTES)


def _enum(value: Any, choices: Iterable[str], location: str) -> str:
    result = required_text(value, location, 64)
    if result not in choices:
        raise malformed(location, "unknown value")
    return result


def normalize_protocol3_plans(value: Any, plan_round: int) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < 2:
        raise malformed("plans", "at least two plans are required")
    bounded_count("plans", len(value), MAX_ACTIVE_PLANS)
    result, summaries = [], set()
    for index, raw in enumerate(value):
        location = f"plans[{index}]"
        plan = object_value(raw, location)
        reject_unknown(plan, ("plan_id", "summary", "subgoals", "motivation", "dependencies", "risks"), location)
        summary = required_text(plan.get("summary"), location + ".summary")
        if summary.lower() in summaries:
            raise malformed(location, "plans must have materially distinct summaries")
        summaries.add(summary.lower())
        source_id = optional_text(plan.get("plan_id"), location + ".plan_id", MAX_IDENTIFIER_BYTES)
        plan_id = f"plan-r{max(1, plan_round)}-{index + 1}"
        raw_goals = plan.get("subgoals")
        if not isinstance(raw_goals, list) or not raw_goals:
            raise malformed(location + ".subgoals", "non-empty array required")
        bounded_count(location + ".subgoals", len(raw_goals), MAX_NODE_DEPENDENCIES)
        local = {}
        for goal_index, raw_goal in enumerate(raw_goals):
            goal_location = f"{location}.subgoals[{goal_index}]"
            goal = object_value(raw_goal, goal_location)
            reject_unknown(goal, ("key", "statement", "depends_on", "critical", "kind"), goal_location)
            key = identifier(required_text(goal.get("key"), goal_location + ".key", MAX_IDENTIFIER_BYTES), goal_location + ".key", local=True)
            if key in local:
                raise malformed(goal_location, "duplicate local subgoal key")
            if type(goal.get("critical")) is not bool:
                raise malformed(goal_location + ".critical", "boolean is required")
            subgoal_id = f"sg-{goal_index + 1}"
            local[key] = {"source_key": key, "subgoal_id": subgoal_id, "node_id": protocol_node_id(plan_id, subgoal_id),
                          "statement": required_text(goal.get("statement"), goal_location + ".statement", MAX_STATEMENT_BYTES),
                          "kind": _enum(goal.get("kind", "lemma"), NODE_KINDS, goal_location + ".kind"),
                          "critical": goal["critical"], "depends_on": text_array(goal.get("depends_on", _MISSING), goal_location + ".depends_on", unique=True, text_maximum=MAX_IDENTIFIER_BYTES)}
        _validate_local_graph(local, location)
        goals = [{**goal, "depends_on": [local[key]["node_id"] for key in goal["depends_on"]]} for goal in local.values()]
        result.append({"plan_id": plan_id, "source_plan_id": source_id, "summary": summary,
                       "subgoals": [goal["statement"] for goal in goals], "subgoal_ids": [goal["subgoal_id"] for goal in goals],
                       "research_subgoals": goals, **{key: text_array(plan.get(key, _MISSING), location + "." + key) for key in ("motivation", "dependencies", "risks")}})
    bounded_count("research_nodes", 1 + sum(len(plan["research_subgoals"]) for plan in result), 256)
    bounded_count("research_edges", sum(len(node["depends_on"]) for plan in result for node in plan["research_subgoals"]), 1024)
    return result


def _validate_local_graph(local: Mapping[str, Mapping[str, Any]], location: str) -> None:
    visited, visiting = set(), set()
    def visit(key: str) -> None:
        if key in visited:
            return
        if key in visiting:
            raise malformed(location, f"subgoal dependency cycle contains {key}")
        if key not in local:
            raise malformed(location, f"unknown local dependency key {key}")
        visiting.add(key)
        for dependency in local[key]["depends_on"]:
            identifier(dependency, location + ".depends_on", local=True)
            visit(dependency)
        visiting.remove(key)
        visited.add(key)
    for key in local:
        visit(key)


def protocol3_screening_fields(result: Any, status: str, location: str = "screening") -> dict[str, Any]:
    result = object_value(result, location)
    reject_unknown(result, ("subgoal_id", "subgoal", "status", "summary", "method", "obstruction", "evidence_ids"), location)
    method = _enum(result.get("method", "direct"), METHODS, location + ".method")
    obstruction = None if result.get("obstruction") is None else _enum(result["obstruction"], OBSTRUCTIONS, location + ".obstruction")
    if status == "stuck" and obstruction is None:
        raise malformed(location + ".obstruction", "stuck screening requires an obstruction class")
    if status == "solved" and obstruction is not None:
        raise malformed(location + ".obstruction", "solved screening may not declare an obstruction")
    return {"method": method, "obstruction": obstruction, "evidence_ids": _evidence(result.get("evidence_ids", _MISSING), location + ".evidence_ids")}


def normalize_protocol3_generation_record(channel: str, content: Any, stamp: ProtocolRecordStamp, scope: ProtocolResearchScope) -> Any:
    if channel not in ("events", "counterexamples"):
        return copy.deepcopy(content)
    event = object_value(content, channel)
    event_type = required_text(event.get("event_type", "counterexample_probe" if channel == "counterexamples" else None), channel + ".event_type", 64)
    if channel == "counterexamples" and event_type != "counterexample_probe":
        raise malformed("counterexamples.event_type", "counterexample channel accepts only counterexample_probe")
    allowed = {
        "assessment": ("event_type", "summary"),
        "toy_example_result": ("event_type", "node_id", "outcome", "summary", "evidence_ids"),
        "counterexample_probe": ("event_type", "node_id", "outcome", "summary", "probe_scope", "witness", "evidence_ids"),
        "retrieval_assessment": ("event_type", "node_id", "outcome", "summary", "query", "reference_ids"),
        "new_candidate_lemma": ("event_type", "statement", "summary", "depends_on", "critical", "kind", "evidence_ids"),
        "notation_resolution": ("event_type", "node_id", "symbol", "resolution", "summary", "evidence_ids"),
    }
    if event_type not in allowed:
        raise malformed(channel + ".event_type", "unknown protocol-3 research event type")
    reject_unknown(event, allowed[event_type], channel)
    result = {"event_type": event_type, "summary": required_text(event.get("summary"), channel + ".summary")}
    if event_type == "assessment":
        return stamp_protocol3_record(event_type, result, stamp)
    if event_type == "new_candidate_lemma":
        critical = event.get("critical", False)
        if type(critical) is not bool:
            raise malformed("events.critical", "boolean required")
        result.update(candidate_id=stamp.record_id, statement=required_text(event.get("statement"), "events.statement", MAX_STATEMENT_BYTES),
                      depends_on=_known_array(event.get("depends_on", _MISSING), scope, "events.depends_on"), critical=critical,
                      kind=_enum(event.get("kind", "lemma"), NODE_KINDS, "events.kind"))
    else:
        result["node_id"] = _known_node(event.get("node_id"), scope, channel + ".node_id", optional=event_type in ("retrieval_assessment", "notation_resolution"))
    if event_type == "toy_example_result":
        result["outcome"] = _enum(event.get("outcome"), ("progress", "refuted", "inconclusive"), "events.outcome")
    elif event_type == "counterexample_probe":
        outcome = _enum(event.get("outcome"), ("found", "not_found_within_scope", "inconclusive"), "counterexamples.outcome")
        witness = optional_text(event.get("witness"), "counterexamples.witness")
        if outcome == "found" and witness is None:
            raise malformed("counterexamples.witness", "found counterexample requires a non-empty witness")
        result.update(outcome=outcome, witness=witness, probe_scope=required_text(event.get("probe_scope"), "counterexamples.probe_scope"), obstruction_class="false_claim" if outcome == "found" else None)
    elif event_type == "retrieval_assessment":
        references = _evidence(event.get("reference_ids", _MISSING), "events.reference_ids")
        if not set(references) <= scope.registered_reference_ids:
            raise malformed("events.reference_ids", "reference_id is not registered for this run")
        outcome = _enum(event.get("outcome"), ("new_material", "no_new_material", "inconclusive"), "events.outcome")
        if outcome == "new_material" and not references:
            raise malformed("events.reference_ids", "new_material requires at least one registered reference_id")
        result.update(outcome=outcome, query=optional_text(event.get("query"), "events.query", 4096), reference_ids=references)
    elif event_type == "notation_resolution":
        result.update(symbol=required_text(event.get("symbol"), "events.symbol", 256), resolution=required_text(event.get("resolution"), "events.resolution"))
    if event_type != "retrieval_assessment":
        result["evidence_ids"] = _evidence(event.get("evidence_ids", _MISSING), channel + ".evidence_ids")
    return stamp_protocol3_record(event_type, result, stamp)


def normalize_protocol3_branch_obstructions(value: Any, scope: ProtocolResearchScope, plan_id: str, location: str = "branch_complete.obstructions") -> list[dict[str, Any]]:
    if value is _MISSING:
        return []
    if not isinstance(value, list):
        raise malformed(location, "array required")
    bounded_count(location, len(value), 64)
    result, seen = [], set()
    for index, raw in enumerate(value):
        item = object_value(raw, f"{location}[{index}]")
        reject_unknown(item, ("node_id", "class", "summary", "evidence_ids"), location)
        node_id = _known_node(item.get("node_id"), scope, location + ".node_id")
        if not scope.plan_contains_node(plan_id, node_id) or node_id in seen:
            raise malformed(location, "duplicate node or node not assigned to this branch plan")
        seen.add(node_id)
        result.append({"node_id": node_id, "class": _enum(item.get("class"), OBSTRUCTIONS, location + ".class"), "summary": required_text(item.get("summary"), location + ".summary"), "evidence_ids": _evidence(item.get("evidence_ids", _MISSING), location + ".evidence_ids")})
    return result


def normalize_protocol3_branch_payload(value: Any, scope: ProtocolResearchScope, plan_id: str) -> dict[str, Any]:
    location = "branch_complete"
    value = object_value(value, location)
    reject_unknown(value, ("status", "summary", "proof_route", "proved_subgoals", "unproved_subgoals", "failure_evidence", "obstructions"), location)
    if not scope.contains_plan(plan_id):
        raise malformed(location, "unknown branch plan")
    status = _enum(value.get("status"), ("solved", "partial", "failed"), location + ".status")
    route = optional_text(value.get("proof_route"), location + ".proof_route")
    if status == "solved" and route is None:
        raise malformed(location, "solved branch requires a proof route")
    proved = _known_array(value.get("proved_subgoals", _MISSING), scope, location + ".proved_subgoals")
    unproved = _known_array(value.get("unproved_subgoals", _MISSING), scope, location + ".unproved_subgoals")
    if set(proved) & set(unproved):
        raise malformed(location, "a node may not be both proved and unproved")
    if any(not scope.plan_contains_node(plan_id, node) for node in proved + unproved):
        raise malformed(location, "proved and unproved node IDs must belong to the branch plan")
    evidence = text_array(value.get("failure_evidence", _MISSING), location + ".failure_evidence")
    obstructions = normalize_protocol3_branch_obstructions(value.get("obstructions", _MISSING), scope, plan_id)
    if status == "solved" and (unproved or evidence or obstructions):
        raise malformed(location, "solved branch may not declare failures or unproved nodes")
    if status != "solved" and not (unproved or evidence or obstructions):
        raise malformed(location, "partial or failed branch requires unproved nodes, failure evidence, or obstructions")
    return {"status": status, "summary": required_text(value.get("summary"), location + ".summary"), "proof_route": route, "proved_node_ids": proved, "unproved_node_ids": unproved, "failure_evidence": evidence, "obstructions": obstructions}


def normalize_protocol3_failure_summary(value: Any, scope: ProtocolResearchScope) -> dict[str, Any]:
    location = "failures_identified.summary"
    value = object_value(value, location)
    reject_unknown(value, ("obstruction", "next_step", "affected_node_ids", "obstruction_class", "excluded_plan_ids", "preserved_node_ids", "required_hypotheses", "required_reference_queries", "selected_focus_node_id"), location)
    return {"obstruction": required_text(value.get("obstruction"), location + ".obstruction"), "next_step": required_text(value.get("next_step"), location + ".next_step"),
            "affected_node_ids": _known_array(value.get("affected_node_ids", _MISSING), scope, location + ".affected_node_ids", required=True),
            "obstruction_class": _enum(value.get("obstruction_class"), OBSTRUCTIONS, location + ".obstruction_class"),
            "excluded_plan_ids": _known_array(value.get("excluded_plan_ids", _MISSING), scope, location + ".excluded_plan_ids", plans=True),
            "preserved_node_ids": _known_array(value.get("preserved_node_ids", _MISSING), scope, location + ".preserved_node_ids"),
            "required_hypotheses": text_array(value.get("required_hypotheses", _MISSING), location + ".required_hypotheses"),
            "required_reference_queries": text_array(value.get("required_reference_queries", _MISSING), location + ".required_reference_queries", text_maximum=4096),
            "selected_focus_node_id": _known_node(value.get("selected_focus_node_id"), scope, location + ".selected_focus_node_id", optional=True)}


def normalize_protocol3_replan_decision(value: Any, scope: ProtocolResearchScope) -> dict[str, Any]:
    location = "replan_complete.decision"
    value = object_value(value, location)
    reject_unknown(value, ("reason", "superseded_plan_ids", "preserved_node_ids", "new_constraints", "selected_focus_node_id"), location)
    result = {"reason": required_text(value.get("reason"), location + ".reason"),
              "superseded_plan_ids": _known_array(value.get("superseded_plan_ids", _MISSING), scope, location + ".superseded_plan_ids", plans=True),
              "preserved_node_ids": _known_array(value.get("preserved_node_ids", _MISSING), scope, location + ".preserved_node_ids"),
              "new_constraints": text_array(value.get("new_constraints", _MISSING), location + ".new_constraints"),
              "selected_focus_node_id": _known_node(value.get("selected_focus_node_id"), scope, location + ".selected_focus_node_id", optional=True)}
    if not (result["superseded_plan_ids"] or result["new_constraints"] or result["selected_focus_node_id"]):
        raise malformed(location, "decision must supersede a plan, add a constraint, or select a focus node")
    return result
