#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = ROOT / "code-optimization-graph.json"
NODE_ID = re.compile(r"^OPT-\d{3}$")
EDGE_ID = re.compile(r"^EDGE-\d{3}$")
RECEIPT_ID = re.compile(r"^REC-\d{4}-\d{2}-\d{2}-\d{3}$")
PRIORITIES = {"P0", "P1", "P2", "P3"}
TERMINAL_STATUSES = {"completed", "rejected", "superseded"}
ACTIONABLE_STATUSES = {"proposed", "approved", "in_progress", "blocked"}

NODE_FIELDS = {
    "id",
    "kind",
    "title",
    "status",
    "priority",
    "problem",
    "functional_outcome",
    "evidence",
    "scope",
    "non_goals",
    "acceptance_criteria",
    "validation_commands",
    "rollback",
    "risk",
    "dependencies",
    "receipt_required",
}

TODO_FIELDS = {
    "order",
    "optimization_id",
    "phase",
    "functional_goal",
    "start_condition",
    "tasks",
    "receipt_expectations",
    "stop_condition",
}


def load_graph() -> dict[str, Any]:
    payload = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("code-optimization-graph.json must contain one JSON object")
    return payload


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must be an object")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be an array")
    return value


def _require_nonempty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _require_string_list(
    value: Any,
    path: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    items = _require_list(value, path)
    if not allow_empty and not items:
        raise ValueError(f"{path} must not be empty")
    if not all(isinstance(item, str) and item.strip() for item in items):
        raise ValueError(f"{path} must contain only non-empty strings")
    return items


def _unique(values: Sequence[str], path: str) -> None:
    duplicates = sorted(item for item, count in Counter(values).items() if count > 1)
    if duplicates:
        raise ValueError(f"{path} contains duplicates: {duplicates}")


def validate_graph(data: Mapping[str, Any]) -> dict[str, Any]:
    _require_nonempty_string(data.get("schema_version"), "schema_version")
    _require_nonempty_string(data.get("graph_id"), "graph_id")
    one_sentence_rule = _require_nonempty_string(
        data.get("one_sentence_rule"),
        "one_sentence_rule",
    )
    if "\n" in one_sentence_rule or len(one_sentence_rule) > 180:
        raise ValueError("one_sentence_rule must remain one concise sentence")

    governance = _require_mapping(data.get("governance"), "governance")
    source_of_truth = _require_nonempty_string(
        governance.get("source_of_truth"),
        "governance.source_of_truth",
    )
    source_path = ROOT / source_of_truth
    if not source_path.is_file():
        raise ValueError(f"governance source_of_truth does not exist: {source_of_truth}")
    statuses = _require_string_list(governance.get("statuses"), "governance.statuses")
    _unique(statuses, "governance.statuses")
    status_set = set(statuses)
    required_statuses = TERMINAL_STATUSES | ACTIONABLE_STATUSES
    if not required_statuses.issubset(status_set):
        raise ValueError(
            "governance.statuses is incomplete: "
            f"missing={sorted(required_statuses - status_set)}"
        )
    transitions = _require_mapping(
        governance.get("allowed_transitions"),
        "governance.allowed_transitions",
    )
    if set(transitions) != status_set:
        raise ValueError("allowed_transitions must define every and only declared status")
    for status, targets in transitions.items():
        values = _require_string_list(
            targets,
            f"governance.allowed_transitions.{status}",
            allow_empty=True,
        )
        unknown = set(values) - status_set
        if unknown:
            raise ValueError(f"unknown transition targets for {status}: {sorted(unknown)}")
    _require_string_list(governance.get("entry_gate"), "governance.entry_gate")
    _require_string_list(governance.get("completion_gate"), "governance.completion_gate")
    _require_string_list(governance.get("non_goals"), "governance.non_goals")

    nodes = _require_list(data.get("nodes"), "nodes")
    if not nodes:
        raise ValueError("nodes must not be empty")
    node_by_id: dict[str, Mapping[str, Any]] = {}
    for index, raw_node in enumerate(nodes):
        path = f"nodes[{index}]"
        node = _require_mapping(raw_node, path)
        missing = NODE_FIELDS - set(node)
        if missing:
            raise ValueError(f"{path} is missing fields: {sorted(missing)}")
        node_id = _require_nonempty_string(node.get("id"), f"{path}.id")
        if not NODE_ID.fullmatch(node_id):
            raise ValueError(f"{path}.id has invalid format: {node_id}")
        if node_id in node_by_id:
            raise ValueError(f"duplicate optimization node id: {node_id}")
        node_by_id[node_id] = node
        status = _require_nonempty_string(node.get("status"), f"{path}.status")
        if status not in status_set:
            raise ValueError(f"{path}.status is unknown: {status}")
        priority = _require_nonempty_string(node.get("priority"), f"{path}.priority")
        if priority not in PRIORITIES:
            raise ValueError(f"{path}.priority must be one of {sorted(PRIORITIES)}")
        for field in (
            "kind",
            "title",
            "problem",
            "functional_outcome",
            "rollback",
            "risk",
        ):
            _require_nonempty_string(node.get(field), f"{path}.{field}")
        for field in ("evidence", "scope", "non_goals", "acceptance_criteria"):
            _require_string_list(node.get(field), f"{path}.{field}")
        validation_commands = _require_string_list(
            node.get("validation_commands"),
            f"{path}.validation_commands",
            allow_empty=status == "rejected",
        )
        if status == "completed" and not validation_commands:
            raise ValueError(f"{path} completed node must retain validation commands")
        _require_string_list(
            node.get("dependencies"),
            f"{path}.dependencies",
            allow_empty=True,
        )
        if not isinstance(node.get("receipt_required"), bool):
            raise ValueError(f"{path}.receipt_required must be boolean")
        if status == "blocked":
            _require_string_list(node.get("blockers"), f"{path}.blockers")

    for node_id, node in node_by_id.items():
        dependencies = list(node["dependencies"])
        _unique(dependencies, f"node {node_id} dependencies")
        unknown = set(dependencies) - set(node_by_id)
        if unknown:
            raise ValueError(f"node {node_id} has unknown dependencies: {sorted(unknown)}")
        if node_id in dependencies:
            raise ValueError(f"node {node_id} cannot depend on itself")

    edges = _require_list(data.get("edges"), "edges")
    edge_ids: set[str] = set()
    dependency_edges: set[tuple[str, str]] = set()
    for index, raw_edge in enumerate(edges):
        path = f"edges[{index}]"
        edge = _require_mapping(raw_edge, path)
        edge_id = _require_nonempty_string(edge.get("id"), f"{path}.id")
        if not EDGE_ID.fullmatch(edge_id):
            raise ValueError(f"{path}.id has invalid format: {edge_id}")
        if edge_id in edge_ids:
            raise ValueError(f"duplicate edge id: {edge_id}")
        edge_ids.add(edge_id)
        source = _require_nonempty_string(edge.get("source"), f"{path}.source")
        target = _require_nonempty_string(edge.get("target"), f"{path}.target")
        relation = _require_nonempty_string(edge.get("relation"), f"{path}.relation")
        _require_nonempty_string(edge.get("reason"), f"{path}.reason")
        if source not in node_by_id or target not in node_by_id:
            raise ValueError(f"{path} references an unknown node")
        if source == target:
            raise ValueError(f"{path} cannot be a self edge")
        if relation == "depends_on":
            pair = (source, target)
            if pair in dependency_edges:
                raise ValueError(f"duplicate dependency edge: {source} -> {target}")
            dependency_edges.add(pair)

    declared_dependencies = {
        (node_id, dependency)
        for node_id, node in node_by_id.items()
        for dependency in node["dependencies"]
    }
    if dependency_edges != declared_dependencies:
        raise ValueError(
            "dependency edges and node.dependencies disagree: "
            f"missing_edges={sorted(declared_dependencies - dependency_edges)}, "
            f"extra_edges={sorted(dependency_edges - declared_dependencies)}"
        )
    _reject_dependency_cycles(node_by_id)

    todo_list = _require_list(data.get("todo_list"), "todo_list")
    todo_ids: list[str] = []
    todo_order: dict[str, int] = {}
    for index, raw_item in enumerate(todo_list):
        path = f"todo_list[{index}]"
        item = _require_mapping(raw_item, path)
        missing = TODO_FIELDS - set(item)
        if missing:
            raise ValueError(f"{path} is missing fields: {sorted(missing)}")
        order = item.get("order")
        if not isinstance(order, int) or isinstance(order, bool) or order < 1:
            raise ValueError(f"{path}.order must be a positive integer")
        optimization_id = _require_nonempty_string(
            item.get("optimization_id"),
            f"{path}.optimization_id",
        )
        if optimization_id not in node_by_id:
            raise ValueError(f"{path} references unknown node {optimization_id}")
        if node_by_id[optimization_id]["status"] not in ACTIONABLE_STATUSES:
            raise ValueError(f"terminal node {optimization_id} must not remain in todo_list")
        todo_ids.append(optimization_id)
        todo_order[optimization_id] = order
        for field in (
            "phase",
            "functional_goal",
            "start_condition",
            "stop_condition",
        ):
            _require_nonempty_string(item.get(field), f"{path}.{field}")
        _require_string_list(item.get("tasks"), f"{path}.tasks")
        _require_string_list(
            item.get("receipt_expectations"),
            f"{path}.receipt_expectations",
        )
    _unique(todo_ids, "todo_list optimization ids")
    orders = [int(item["order"]) for item in todo_list]
    if sorted(orders) != list(range(1, len(orders) + 1)):
        raise ValueError("todo_list order values must be contiguous starting at 1")
    actionable_ids = {
        node_id
        for node_id, node in node_by_id.items()
        if node["status"] in ACTIONABLE_STATUSES
    }
    if set(todo_ids) != actionable_ids:
        raise ValueError(
            "todo_list must cover every actionable node exactly once: "
            f"missing={sorted(actionable_ids - set(todo_ids))}, "
            f"extra={sorted(set(todo_ids) - actionable_ids)}"
        )
    for node_id in todo_ids:
        for dependency in node_by_id[node_id]["dependencies"]:
            dependency_status = node_by_id[dependency]["status"]
            if dependency_status in ACTIONABLE_STATUSES:
                if todo_order[dependency] >= todo_order[node_id]:
                    raise ValueError(
                        f"todo order violates dependency: {dependency} must precede {node_id}"
                    )
            elif dependency_status not in {"completed", "superseded"}:
                raise ValueError(
                    f"actionable node {node_id} depends on non-executable {dependency} "
                    f"with status {dependency_status}"
                )

    receipt_contract = _require_mapping(
        data.get("receipt_contract"),
        "receipt_contract",
    )
    if receipt_contract.get("append_only") is not True:
        raise ValueError("receipt_contract.append_only must be true")
    required_receipt_fields = set(
        _require_string_list(
            receipt_contract.get("required_fields"),
            "receipt_contract.required_fields",
        )
    )
    decision_values = set(
        _require_string_list(
            receipt_contract.get("decision_values"),
            "receipt_contract.decision_values",
        )
    )
    receipts = _require_list(data.get("receipts"), "receipts")
    receipt_ids: set[str] = set()
    receipts_by_node: dict[str, list[Mapping[str, Any]]] = {}
    for index, raw_receipt in enumerate(receipts):
        path = f"receipts[{index}]"
        receipt = _require_mapping(raw_receipt, path)
        missing = required_receipt_fields - set(receipt)
        if missing:
            raise ValueError(f"{path} is missing receipt fields: {sorted(missing)}")
        receipt_id = _require_nonempty_string(receipt.get("receipt_id"), f"{path}.receipt_id")
        if not RECEIPT_ID.fullmatch(receipt_id):
            raise ValueError(f"{path}.receipt_id has invalid format: {receipt_id}")
        if receipt_id in receipt_ids:
            raise ValueError(f"duplicate receipt id: {receipt_id}")
        receipt_ids.add(receipt_id)
        optimization_id = _require_nonempty_string(
            receipt.get("optimization_id"),
            f"{path}.optimization_id",
        )
        if optimization_id not in node_by_id:
            raise ValueError(f"{path} references unknown node {optimization_id}")
        receipts_by_node.setdefault(optimization_id, []).append(receipt)
        status_before = _require_nonempty_string(
            receipt.get("status_before"),
            f"{path}.status_before",
        )
        status_after = _require_nonempty_string(
            receipt.get("status_after"),
            f"{path}.status_after",
        )
        if status_before not in status_set or status_after not in status_set:
            raise ValueError(f"{path} has unknown status")
        if status_after not in transitions[status_before]:
            raise ValueError(
                f"{path} records an illegal transition: {status_before} -> {status_after}"
            )
        decision = _require_nonempty_string(receipt.get("decision"), f"{path}.decision")
        if decision not in decision_values:
            raise ValueError(f"{path}.decision is unknown: {decision}")
        for field in (
            "started_at",
            "completed_at",
            "functional_goal",
            "behavior_before",
            "behavior_after",
            "risk_review",
            "rollback",
        ):
            _require_nonempty_string(receipt.get(field), f"{path}.{field}")
        _require_string_list(
            receipt.get("files_changed"),
            f"{path}.files_changed",
            allow_empty=decision == "rejected",
        )
        commands = _require_list(receipt.get("commands"), f"{path}.commands")
        for command_index, raw_command in enumerate(commands):
            command_path = f"{path}.commands[{command_index}]"
            command = _require_mapping(raw_command, command_path)
            _require_nonempty_string(command.get("command"), f"{command_path}.command")
            exit_code = command.get("exit_code")
            if not isinstance(exit_code, int) or isinstance(exit_code, bool):
                raise ValueError(f"{command_path}.exit_code must be an integer")
            _require_nonempty_string(command.get("result"), f"{command_path}.result")
        _require_string_list(
            receipt.get("tests"),
            f"{path}.tests",
            allow_empty=decision == "rejected",
        )
        _require_string_list(
            receipt.get("unresolved"),
            f"{path}.unresolved",
            allow_empty=True,
        )
        if status_after == "completed":
            if decision != "accepted":
                raise ValueError(f"{path} completed receipt must be accepted")
            if not commands or not any(command["exit_code"] == 0 for command in commands):
                raise ValueError(f"{path} completed receipt needs a successful command")
        if status_after == "rejected" and decision != "rejected":
            raise ValueError(f"{path} rejected receipt must have rejected decision")

    for node_id, node in node_by_id.items():
        if not node["receipt_required"] or node["status"] not in TERMINAL_STATUSES:
            continue
        matching = [
            receipt
            for receipt in receipts_by_node.get(node_id, [])
            if receipt["status_after"] == node["status"]
        ]
        if not matching:
            raise ValueError(
                f"terminal node {node_id} ({node['status']}) requires a matching receipt"
            )

    status_counts = Counter(str(node["status"]) for node in nodes)
    return {
        "graph_id": data["graph_id"],
        "node_count": len(nodes),
        "edge_count": len(edges),
        "todo_count": len(todo_list),
        "receipt_count": len(receipts),
        "status_counts": dict(sorted(status_counts.items())),
        "source_of_truth": source_of_truth,
    }


def _reject_dependency_cycles(node_by_id: Mapping[str, Mapping[str, Any]]) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str, trail: list[str]) -> None:
        if node_id in visiting:
            cycle_start = trail.index(node_id)
            cycle = trail[cycle_start:] + [node_id]
            raise ValueError(f"dependency cycle detected: {' -> '.join(cycle)}")
        if node_id in visited:
            return
        visiting.add(node_id)
        trail.append(node_id)
        for dependency in node_by_id[node_id]["dependencies"]:
            visit(str(dependency), trail)
        trail.pop()
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in sorted(node_by_id):
        visit(node_id, [])


def main() -> int:
    try:
        summary = validate_graph(load_graph())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

