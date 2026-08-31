from __future__ import annotations

import runpy
import unittest
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
AUDITOR = runpy.run_path(str(ROOT / "scripts" / "audit_error_contract.py"))
scan_error_contract: Callable[..., dict[str, Any]] = AUDITOR["scan_error_contract"]
audit_passed: Callable[[dict[str, Any]], bool] = AUDITOR["audit_passed"]
client_action: Callable[[str, bool], str] = AUDITOR["client_action"]


class ErrorContractTestCase(unittest.TestCase):
    def test_repository_error_contract_has_no_unapproved_drift(self) -> None:
        report = scan_error_contract()
        self.assertTrue(audit_passed(report), report["audit"])
        self.assertGreaterEqual(report["code_count"], 150)
        self.assertEqual(
            report["rethlas_step_recoverable_categories"],
            ["validation", "conflict"],
        )
        self.assertEqual(report["hard_failure_categories"], ["permission", "security"])

    def test_critical_error_semantics_are_distinct_and_stable(self) -> None:
        report = scan_error_contract()
        codes = report["codes"]

        def variants(code: str) -> set[tuple[str, bool]]:
            return {
                (item["category"], item["retryable"])
                for item in codes[code]["variants"]
            }

        self.assertEqual(variants("PAPER_SEARCH_UNAVAILABLE"), {("runtime", True)})
        self.assertEqual(variants("PAPER_SEARCH_UNSUPPORTED"), {("runtime", False)})
        self.assertEqual(variants("REFERENCE_RUN_MISMATCH"), {("permission", False)})

    def test_permission_and_security_errors_are_never_retryable(self) -> None:
        report = scan_error_contract()
        for code, entry in report["codes"].items():
            for variant in entry["variants"]:
                if variant["category"] in {"permission", "security"}:
                    with self.subTest(code=code, category=variant["category"]):
                        self.assertFalse(variant["retryable"])

    def test_client_action_policy_is_explicit(self) -> None:
        self.assertEqual(client_action("validation", False), "correct_request")
        self.assertEqual(client_action("conflict", False), "reconcile_state")
        self.assertEqual(client_action("conflict", True), "refresh_and_retry")
        self.assertEqual(client_action("permission", False), "stop_or_reauthorize")
        self.assertEqual(client_action("security", False), "stop_and_report_security")
        self.assertEqual(client_action("not_found", False), "refresh_identifier")
        self.assertEqual(client_action("runtime", True), "retry_later")
        self.assertEqual(client_action("runtime", False), "report_or_reconfigure")
        self.assertEqual(client_action("internal", False), "report_internal_error")


if __name__ == "__main__":
    unittest.main()

