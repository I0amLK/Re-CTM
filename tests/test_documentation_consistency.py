from __future__ import annotations

import runpy
import unittest
from typing import Any, Callable


VALIDATOR = runpy.run_path("scripts/validate_documentation_consistency.py")
validate_documentation: Callable[[], dict[str, Any]] = VALIDATOR["validate_documentation"]


class DocumentationConsistencyTestCase(unittest.TestCase):
    def test_stable_documentation_facts_match_runtime_contracts(self) -> None:
        summary = validate_documentation()
        self.assertEqual(summary["version"], "0.3.0")
        self.assertEqual(summary["native_tool_count"], 18)
        self.assertEqual(summary["rethlas_tool_count"], 6)
        self.assertEqual(summary["public_tool_count"], 24)
        self.assertEqual(summary["hidden_legacy_alias_count"], 11)
        self.assertEqual(summary["local_markdown_link_failures"], 0)


if __name__ == "__main__":
    unittest.main()
