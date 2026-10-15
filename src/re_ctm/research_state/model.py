"""Bounded, deterministic mathematical graph projection without workflow authority."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .protocol import (MAX_STATEMENT_BYTES, MAX_SUMMARY_BYTES, METHODS, NODE_KINDS,
                       OBSTRUCTIONS, bounded_count, identifier, malformed, required_text,
                       text_array)

RESEARCH_STATE_SCHEMA_VERSION = 1
MAX_RESEARCH_NODES = 256
MAX_RESEARCH_EDGES = 1024
MAX_RESEARCH_ATTEMPTS = 2048
MAX_RESEARCH_DECISIONS = 256
STATUSES = ("open", "partial", "route_solved", "refuted", "blocked", "superseded")
OUTCOMES = ("progress", "route_solved", "failed", "refuted", "inconclusive")


@dataclass(frozen=True)
class ResearchNode:
    node_id: str
    statement: str
    kind: str = "lemma"
    status: str = "open"
    dependencies: tuple[str, ...] = ()
    plan_id: str | None = None
    declared_critical: bool | None = None
    revision: int = 1
    created_round: int = 0
    plan_order: int = 0
    node_order: int = 0

    def __post_init__(self) -> None:
        identifier(self.node_id, "node_id")
        object.__setattr__(self, "statement", required_text(self.statement, "node.statement", MAX_STATEMENT_BYTES))
        if self.kind not in (*NODE_KINDS, "target") or self.status not in STATUSES:
            raise malformed("node", "unknown node kind or status")
        if type(self.revision) is not int or self.revision <= 0:
            raise malformed("node.revision", "positive integer required")
        if self.plan_id is not None:
            identifier(self.plan_id, "node.plan_id")
        if self.declared_critical is not None and type(self.declared_critical) is not bool:
            raise malformed("node.declared_critical", "boolean required")
        _position(self.created_round, self.plan_order, self.node_order)
        bounded_count("node.dependencies", len(self.dependencies), 64)
        if len(set(self.dependencies)) != len(self.dependencies):
            raise malformed("node.dependencies", "duplicate dependency")
        for value in self.dependencies:
            identifier(value, "dependency")


@dataclass(frozen=True)
class ResearchAttempt:
    attempt_id: str
    node_id: str
    actor_domain_id: str
    method: str
    outcome: str
    summary: str
    obstruction: str | None = None
    evidence_ids: tuple[str, ...] = ()
    created_round: int = 0
    event_seq: int = 0

    def __post_init__(self) -> None:
        for name in ("attempt_id", "node_id", "actor_domain_id"):
            identifier(getattr(self, name), name)
        object.__setattr__(self, "summary", required_text(self.summary, "attempt.summary", MAX_SUMMARY_BYTES))
        if self.method not in METHODS or self.outcome not in OUTCOMES or (self.obstruction is not None and self.obstruction not in OBSTRUCTIONS):
            raise malformed("attempt", "unknown method, outcome or obstruction")
        _position(self.created_round, self.event_seq)
        text_array(list(self.evidence_ids), "attempt.evidence_ids", 32, text_maximum=1024)


@dataclass(frozen=True)
class ResearchDecision:
    decision_id: str
    reason: str
    superseded_plan_ids: tuple[str, ...] = ()
    preserved_node_ids: tuple[str, ...] = ()
    new_constraints: tuple[str, ...] = ()
    selected_focus_node_id: str | None = None
    event_seq: int = 0

    def __post_init__(self) -> None:
        identifier(self.decision_id, "decision_id")
        object.__setattr__(self, "reason", required_text(self.reason, "decision.reason"))
        _position(self.event_seq)
        for name in ("superseded_plan_ids", "preserved_node_ids", "new_constraints"):
            text_array(list(getattr(self, name)), "decision." + name, 64)
        for value in (*self.superseded_plan_ids, *self.preserved_node_ids):
            identifier(value)
        if self.selected_focus_node_id is not None:
            identifier(self.selected_focus_node_id)


def _position(*values: int) -> None:
    if any(type(value) is not int or value < 0 for value in values):
        raise malformed("position", "non-negative integers required")


@dataclass(frozen=True)
class ResearchSnapshot:
    target_node_id: str = "target"
    nodes: tuple[ResearchNode, ...] = ()
    attempts: tuple[ResearchAttempt, ...] = ()
    decisions: tuple[ResearchDecision, ...] = ()
    active_plan_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResearchState:
    schema_version: int
    target_node_id: str
    nodes: dict[str, ResearchNode]
    attempts: tuple[ResearchAttempt, ...]
    decisions: tuple[ResearchDecision, ...]
    active_plan_ids: tuple[str, ...]
    graph: dict[str, Any]
    plan_routes: dict[str, dict[str, Any]]
    critical_nodes: tuple[str, ...]
    critical_blockers: tuple[str, ...]
    actionable_frontier: tuple[str, ...]
    invalid_routes: tuple[dict[str, Any], ...]
    digest: str = ""


def _key(node: ResearchNode) -> tuple[int, int, int, str]:
    return node.created_round, node.plan_order, node.node_order, node.node_id


def _closure(root: str, dependencies: dict[str, set[str]]) -> set[str]:
    found, pending = set(), [root]
    while pending:
        node = pending.pop()
        if node not in found:
            found.add(node)
            pending.extend(dependencies.get(node, ()))
    return found


def project(snapshot: ResearchSnapshot, *, reject_cycles: bool = True) -> ResearchState:
    """Validate every reference, then derive an advisory graph. Never verifies a proof."""
    for name, values, maximum in (("nodes", snapshot.nodes, 256), ("attempts", snapshot.attempts, 2048),
                                  ("decisions", snapshot.decisions, 256), ("active_plans", snapshot.active_plan_ids, 64)):
        bounded_count("research_" + name, len(values), maximum)
    nodes = {node.node_id: node for node in snapshot.nodes}
    if len(nodes) != len(snapshot.nodes):
        raise malformed("nodes", "duplicate node identifier")
    nodes = dict(sorted(nodes.items()))
    target = nodes.get(snapshot.target_node_id)
    if target is None or target.kind != "target" or target.status == "superseded" or sum(node.kind == "target" for node in nodes.values()) != 1:
        raise malformed("target", "exactly one nonsuperseded target is required")
    bounded_count("research_edges", sum(len(node.dependencies) for node in nodes.values()), 1024)
    known_plans = {node.plan_id for node in nodes.values() if node.plan_id is not None}
    declared = {node.plan_id for node in nodes.values() if node.status != "superseded"}
    if any(plan not in declared for plan in snapshot.active_plan_ids):
        raise malformed("active_plan_ids", "unknown active plan")
    if len(set(snapshot.active_plan_ids)) != len(snapshot.active_plan_ids):
        raise malformed("active_plan_ids", "duplicate active plan")
    dependencies, dependents = {}, {}
    superseded_seeds = []
    for node in nodes.values():
        if any(dependency not in nodes for dependency in node.dependencies):
            raise malformed("node.dependencies", "unknown dependency")
        if node.status != "superseded":
            dependencies[node.node_id] = set()
            dependents[node.node_id] = set()
    for node in nodes.values():
        if node.status == "superseded":
            continue
        for dependency in node.dependencies:
            if nodes[dependency].status == "superseded":
                superseded_seeds.append((node.node_id, "superseded_dependency", dependency))
            else:
                dependencies[node.node_id].add(dependency)
                dependents[dependency].add(node.node_id)
    attempts = _canonical_records(snapshot.attempts, "attempt_id", lambda attempt: (attempt.created_round, attempt.event_seq, attempt.attempt_id))
    decisions = _canonical_records(snapshot.decisions, "decision_id", lambda decision: (decision.event_seq, decision.decision_id))
    for attempt in attempts:
        if attempt.node_id not in nodes:
            raise malformed("attempt.node_id", "unknown attempt node")
    for decision in decisions:
        if any(node not in nodes for node in (*decision.preserved_node_ids, *((decision.selected_focus_node_id,) if decision.selected_focus_node_id else ()))):
            raise malformed("decision", "unknown decision node")
        if any(plan not in known_plans for plan in decision.superseded_plan_ids):
            raise malformed("decision", "unknown decision plan")
    order = lambda values: sorted(values, key=lambda node: _key(nodes[node]))
    cycles = _cycles(dependencies, dependents, order)
    if reject_cycles and cycles:
        raise malformed("dependencies", "active dependency cycle: " + " -> ".join(cycles[0]))
    remaining = {key: len(value) for key, value in dependencies.items()}
    ready = order(key for key, count in remaining.items() if count == 0)
    topological = []
    while ready:
        node = ready.pop(0)
        topological.append(node)
        for dependent in order(dependents[node]):
            remaining[dependent] -= 1
            if remaining[dependent] == 0:
                ready.append(dependent)
                ready = order(ready)
    issues: dict[str, set[tuple[str, str]]] = {}
    pending = [(node.node_id, "refuted_dependency", node.node_id) for node in nodes.values() if node.status == "refuted"] + superseded_seeds
    for cycle in cycles:
        pending.extend((node, "dependency_cycle", cycle[0]) for node in cycle)
    while pending:
        node, kind, source = pending.pop()
        issue = kind, source
        if issue not in issues.setdefault(node, set()):
            issues[node].add(issue)
            pending.extend((dependent, kind, source) for dependent in dependents.get(node, ()))
    actionable = {node.node_id for node in nodes.values() if node.status in ("open", "partial", "blocked")
                  and (node.kind != "target" or not snapshot.active_plan_ids) and node.node_id not in issues
                  and all(nodes[dependency].status == "route_solved" for dependency in dependencies[node.node_id])}
    routes = {}
    critical = _closure(snapshot.target_node_id, dependencies)
    for plan_id in sorted(snapshot.active_plan_ids):
        plan_nodes = {node.node_id for node in nodes.values() if node.plan_id == plan_id and node.status != "superseded"}
        candidates = {node for node in plan_nodes if nodes[node].declared_critical} or plan_nodes
        goals = {node for node in candidates if not dependents[node] & candidates} or plan_nodes
        route_critical = set().union(*(_closure(goal, dependencies) for goal in goals)) if goals else set()
        critical.update(route_critical)
        invalid = route_critical & issues.keys()
        routes[plan_id] = {"plan_id": plan_id, "goal_node_ids": order(goals), "critical_nodes": order(route_critical),
                           "blockers": order(node for node in route_critical if nodes[node].status != "route_solved"),
                           "actionable_frontier": order(route_critical & actionable), "invalid_nodes": order(invalid),
                           "route_solved": bool(goals) and not invalid and all(nodes[node].status == "route_solved" for node in route_critical)}
    critical_order = lambda values: sorted(values, key=lambda node: (node not in critical, *_key(nodes[node])))
    state = ResearchState(1, snapshot.target_node_id, nodes, attempts, decisions, tuple(sorted(snapshot.active_plan_ids)),
                          {"dependencies": {key: sorted(value) for key, value in dependencies.items()},
                           "dependents": {key: sorted(value) for key, value in dependents.items()}, "topological_order": topological, "cycle_components": cycles},
                          routes, tuple(order(critical)), tuple(order(node for node in critical if nodes[node].status != "route_solved")),
                          tuple(critical_order(actionable)), tuple({"node_id": node, "issues": [{"kind": kind, "source_node_id": source} for kind, source in sorted(issues[node])]} for node in critical_order(issues)))
    payload = asdict(state)
    payload.pop("digest")
    object.__setattr__(state, "digest", hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest())
    return state


def _canonical_records(records: Iterable[Any], key: str, order: Any) -> tuple[Any, ...]:
    result = tuple(sorted(records, key=order))
    if len({getattr(record, key) for record in result}) != len(result):
        raise malformed(key, "duplicate identifier")
    return result


def _cycles(dependencies: dict[str, set[str]], dependents: dict[str, set[str]], order: Any) -> list[list[str]]:
    visited, finishing = set(), []
    def finish(node: str) -> None:
        if node not in visited:
            visited.add(node)
            for other in sorted(dependencies.get(node, ())):
                finish(other)
            finishing.append(node)
    for node in order(dependencies):
        finish(node)
    assigned, cycles = set(), []
    for root in reversed(finishing):
        if root in assigned:
            continue
        component, pending = set(), [root]
        while pending:
            node = pending.pop()
            if node not in assigned:
                assigned.add(node)
                component.add(node)
                pending.extend(dependents.get(node, ()))
        if len(component) > 1 or root in dependencies[root]:
            cycles.append(order(component))
    return sorted(cycles, key=lambda cycle: order(dependencies).index(cycle[0]))
