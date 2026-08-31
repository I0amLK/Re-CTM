from __future__ import annotations

import copy
import json
import runpy
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = ROOT / "code-optimization-graph.json"
VALIDATOR = runpy.run_path(str(ROOT / "scripts" / "validate_code_optimization_graph.py"))
validate_graph: Callable[[dict[str, Any]], dict[str, Any]] = VALIDATOR["validate_graph"]


class CodeOptimizationGraphTestCase(unittest.TestCase):
    def load_graph(self) -> dict[str, Any]:
        return json.loads(GRAPH_PATH.read_text(encoding="utf-8"))

    def test_repository_graph_is_valid(self) -> None:
        summary = validate_graph(self.load_graph())
        self.assertEqual(summary["graph_id"], "re-ctm-code-optimization")
        self.assertGreaterEqual(summary["receipt_count"], 1)

    def test_duplicate_node_id_is_rejected(self) -> None:
        graph = self.load_graph()
        graph["nodes"].append(copy.deepcopy(graph["nodes"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate optimization node id"):
            validate_graph(graph)

    def test_terminal_node_without_receipt_is_rejected(self) -> None:
        graph = self.load_graph()
        terminal = next(
            node
            for node in graph["nodes"]
            if node["receipt_required"]
            and node["status"] in {"completed", "rejected", "superseded"}
        )
        graph["receipts"] = [
            receipt
            for receipt in graph["receipts"]
            if receipt["optimization_id"] != terminal["id"]
        ]
        with self.assertRaisesRegex(ValueError, "requires a matching receipt"):
            validate_graph(graph)

    def test_todo_dependency_order_is_rejected(self) -> None:
        graph = self.load_graph()
        template = copy.deepcopy(graph["nodes"][0])
        dependency_node = copy.deepcopy(template)
        dependency_node.update(
            {
                "id": "OPT-900",
                "title": "Synthetic dependency",
                "status": "proposed",
                "dependencies": [],
            }
        )
        dependency_node.pop("blockers", None)
        dependent_node = copy.deepcopy(template)
        dependent_node.update(
            {
                "id": "OPT-901",
                "title": "Synthetic dependent",
                "status": "proposed",
                "dependencies": ["OPT-900"],
            }
        )
        dependent_node.pop("blockers", None)
        graph["nodes"].extend([dependency_node, dependent_node])

        next_edge_number = max(
            int(edge["id"].removeprefix("EDGE-")) for edge in graph["edges"]
        ) + 1
        graph["edges"].append(
            {
                "id": f"EDGE-{next_edge_number:03d}",
                "source": "OPT-901",
                "target": "OPT-900",
                "relation": "depends_on",
                "reason": "Synthetic dependency used only to exercise TODO order validation.",
            }
        )
        next_order = len(graph["todo_list"]) + 1
        graph["todo_list"].extend(
            [
                {
                    "order": next_order + 1,
                    "optimization_id": "OPT-900",
                    "phase": "synthetic dependency",
                    "functional_goal": "Exercise dependency order validation.",
                    "start_condition": "Test fixture only.",
                    "tasks": ["No runtime work."],
                    "receipt_expectations": ["Validator must reject reversed order."],
                    "stop_condition": "Test fixture only.",
                },
                {
                    "order": next_order,
                    "optimization_id": "OPT-901",
                    "phase": "synthetic dependent",
                    "functional_goal": "Exercise dependency order validation.",
                    "start_condition": "Test fixture only.",
                    "tasks": ["No runtime work."],
                    "receipt_expectations": ["Validator must reject reversed order."],
                    "stop_condition": "Test fixture only.",
                },
            ]
        )
        with self.assertRaisesRegex(ValueError, "todo order violates dependency"):
            validate_graph(graph)


if __name__ == "__main__":
    unittest.main()

