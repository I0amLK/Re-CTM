#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = ROOT / "engineering-graph.json"


def load_graph() -> dict[str, Any]:
    data = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("engineering-graph.json must contain a JSON object")
    return data


def calculate(data: dict[str, Any]) -> dict[str, Any]:
    _validate_jsonld_shape(data)
    vertices = [str(item["id"]) for item in data["vertices"]]
    if len(vertices) != len(set(vertices)):
        raise ValueError("vertex ids must be unique")
    names = [str(item["name"]) for item in data["vertices"]]
    if len(names) != len(set(names)):
        raise ValueError("vertex names must be unique")
    known = set(vertices)
    adjacency = {vertex: set() for vertex in vertices}
    edge_ids: set[str] = set()
    for edge in data["edges"]:
        edge_id = str(edge["id"])
        if edge_id in edge_ids:
            raise ValueError(f"duplicate edge id: {edge_id}")
        edge_ids.add(edge_id)
        source = str(edge["source"])
        target = str(edge["target"])
        if source not in known or target not in known:
            raise ValueError(f"edge {edge_id} references an unknown vertex")
        if not str(edge.get("guard", "")).strip():
            raise ValueError(f"edge {edge_id} has no guard")
        if source != target:
            adjacency[source].add(target)
            adjacency[target].add(source)

    components = _components(vertices, adjacency)
    articulation_points, bridges = _tarjan(vertices, adjacency)
    two_core = _two_core(vertices, adjacency)
    edge_count = sum(len(items) for items in adjacency.values()) // 2
    result = {
        "vertex_count": len(vertices),
        "edge_count_after_parallel_collapse": edge_count,
        "connected_components": len(components),
        "cycle_rank": edge_count - len(vertices) + len(components),
        "articulation_points": articulation_points,
        "bridges": [list(item) for item in bridges],
        "two_core_vertices": two_core,
    }
    _validate_security_shape(data)
    return result


def _components(vertices: list[str], adjacency: dict[str, set[str]]) -> list[list[str]]:
    seen: set[str] = set()
    result: list[list[str]] = []
    for start in vertices:
        if start in seen:
            continue
        stack = [start]
        seen.add(start)
        component: list[str] = []
        while stack:
            current = stack.pop()
            component.append(current)
            for neighbor in adjacency[current]:
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        result.append(sorted(component))
    return result


def _tarjan(
    vertices: list[str],
    adjacency: dict[str, set[str]],
) -> tuple[list[str], list[tuple[str, str]]]:
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    parent: dict[str, str] = {}
    articulation: set[str] = set()
    bridges: set[tuple[str, str]] = set()
    counter = 0

    def visit(vertex: str) -> None:
        nonlocal counter
        counter += 1
        index[vertex] = counter
        low[vertex] = counter
        children = 0
        for neighbor in sorted(adjacency[vertex]):
            if neighbor not in index:
                parent[neighbor] = vertex
                children += 1
                visit(neighbor)
                low[vertex] = min(low[vertex], low[neighbor])
                if vertex not in parent and children > 1:
                    articulation.add(vertex)
                if vertex in parent and low[neighbor] >= index[vertex]:
                    articulation.add(vertex)
                if low[neighbor] > index[vertex]:
                    bridges.add(tuple(sorted((vertex, neighbor))))
            elif parent.get(vertex) != neighbor:
                low[vertex] = min(low[vertex], index[neighbor])

    for vertex in vertices:
        if vertex not in index:
            visit(vertex)
    return sorted(articulation), sorted(bridges)


def _two_core(vertices: list[str], adjacency: dict[str, set[str]]) -> list[str]:
    work = {vertex: set(neighbors) for vertex, neighbors in adjacency.items()}
    queue = deque(vertex for vertex in vertices if len(work[vertex]) < 2)
    removed = set(queue)
    while queue:
        vertex = queue.popleft()
        for neighbor in list(work[vertex]):
            work[neighbor].discard(vertex)
            if neighbor not in removed and len(work[neighbor]) < 2:
                removed.add(neighbor)
                queue.append(neighbor)
        work[vertex].clear()
    return sorted(set(vertices) - removed)


def _validate_security_shape(data: dict[str, Any]) -> None:
    names = {item["name"]: item["id"] for item in data["vertices"]}
    native = names["native_workspace"]
    vault = names["private_vault"]
    direct_pairs = {
        frozenset((str(edge["source"]), str(edge["target"])))
        for edge in data["edges"]
    }
    if frozenset((native, vault)) in direct_pairs:
        raise ValueError("native_workspace must not have a direct edge to private_vault")
    invariant_ids = {item["id"] for item in data["security_invariants"]}
    required = {f"INV-{number:03d}" for number in range(1, 9)}
    if not required.issubset(invariant_ids):
        raise ValueError("required security invariants INV-001 through INV-008 are missing")


def _validate_jsonld_shape(data: dict[str, Any]) -> None:
    context = data.get("@context")
    if not isinstance(context, dict):
        raise ValueError("engineering graph must carry a JSON-LD @context")
    if context.get("id") != "@id" or context.get("kind") != "@type":
        raise ValueError("JSON-LD context must map id and kind to @id and @type")
    if not isinstance(data.get("@id"), str) or data.get("@type") != "EngineeringGraph":
        raise ValueError("engineering graph must have a stable JSON-LD @id and EngineeringGraph type")

    known = {str(item["id"]) for item in data.get("vertices", [])}
    snapshot = data.get("implementation_snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("implementation_snapshot is required")
    groups = (
        "implemented_local",
        "implemented_reference_target_pending",
        "partial_or_external",
        "manual_only",
    )
    classified: list[str] = []
    for group in groups:
        values = snapshot.get(group)
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise ValueError(f"implementation_snapshot.{group} must be an array of vertex ids")
        classified.extend(values)
    if len(classified) != len(set(classified)):
        raise ValueError("implementation snapshot must classify each vertex exactly once")
    if set(classified) != known:
        raise ValueError(
            "implementation snapshot coverage mismatch: "
            f"missing={sorted(known - set(classified))}, unknown={sorted(set(classified) - known)}"
        )
    evidence = snapshot.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("implementation snapshot must cite implementation evidence")


def main() -> int:
    data = load_graph()
    calculated = calculate(data)
    expected = data["derived_undirected_metrics"]
    keys = (
        "vertex_count",
        "edge_count_after_parallel_collapse",
        "connected_components",
        "cycle_rank",
        "articulation_points",
        "bridges",
        "two_core_vertices",
    )
    mismatches = {
        key: {"expected": expected.get(key), "actual": calculated[key]}
        for key in keys
        if expected.get(key) != calculated[key]
    }
    if mismatches:
        print(json.dumps({"ok": False, "mismatches": mismatches}, indent=2))
        return 1
    print(json.dumps({"ok": True, "metrics": calculated}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
