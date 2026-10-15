from __future__ import annotations

import json
import runpy
import unittest
from pathlib import Path
from typing import Any, Callable


VALIDATOR = runpy.run_path("scripts/validate_documentation_consistency.py")
validate_documentation: Callable[[], dict[str, Any]] = VALIDATOR["validate_documentation"]
validate_manual_validation: Callable[[dict[str, Any]], int] = VALIDATOR["validate_manual_validation"]


class DocumentationConsistencyTestCase(unittest.TestCase):
    def test_stable_documentation_facts_match_runtime_contracts(self) -> None:
        summary = validate_documentation()
        self.assertEqual(summary["version"], "0.4.1")
        self.assertEqual(summary["native_tool_count"], 19)
        self.assertEqual(summary["rethlas_tool_count"], 6)
        self.assertEqual(summary["public_tool_count"], 25)
        self.assertEqual(summary["retired_legacy_alias_count"], 11)
        self.assertEqual(summary["callable_legacy_alias_count"], 0)
        self.assertEqual(summary["state_schema_version"], 8)
        self.assertEqual(summary["local_markdown_link_failures"], 0)
        self.assertEqual(summary["active_release_check_count"], 11)


    def _manual_manifest(self) -> dict[str, Any]:
        return json.loads(Path("manual-validation.json").read_text(encoding="utf-8"))

    def test_active_manual_contract_rejects_old_catalog_count(self) -> None:
        manifest = self._manual_manifest()
        manifest["current_contract"]["public_tool_count"] = 24
        with self.assertRaisesRegex(ValueError, "active contract"):
            validate_manual_validation(manifest)

    def test_manual_pass_requires_scope_specific_evidence(self) -> None:
        manifest = self._manual_manifest()
        manifest["checks"][0]["status"] = "passed"
        manifest["checks"][0]["evidence"] = []
        with self.assertRaisesRegex(ValueError, "scope-specific evidence"):
            validate_manual_validation(manifest)

    def test_overall_pass_cannot_hide_incomplete_checks(self) -> None:
        manifest = self._manual_manifest()
        manifest["status"] = "passed"
        manifest["checks"][0]["status"] = "pending"
        with self.assertRaisesRegex(ValueError, "overall acceptance"):
            validate_manual_validation(manifest)

    def test_superseded_historical_manifest_cannot_be_dropped(self) -> None:
        manifest = self._manual_manifest()
        manifest["historical_checklists"] = []
        with self.assertRaisesRegex(ValueError, "historical checklist"):
            validate_manual_validation(manifest)

    def test_historical_status_cannot_be_promoted(self) -> None:
        manifest = self._manual_manifest()
        manifest["historical_checklists"][0]["manifest"]["status"] = "passed"
        with self.assertRaisesRegex(ValueError, "historical manifest status"):
            validate_manual_validation(manifest)


if __name__ == "__main__":
    unittest.main()
