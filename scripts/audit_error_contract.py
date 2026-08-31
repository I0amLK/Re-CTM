#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src" / "re_ctm"

KNOWN_CATEGORIES = {
    "validation",
    "conflict",
    "permission",
    "security",
    "not_found",
    "runtime",
    "internal",
}

# These codes intentionally vary by context. The variants are locked here so a
# new category/retryable combination is still treated as drift.
INTENTIONAL_VARIANTS: dict[str, set[tuple[str, bool]]] = {
    "NATIVE_HELPER_PROTOCOL_ERROR": {
        ("runtime", False),
        ("security", False),
    },
    "EXPORT_PATH_CONFLICT": {
        ("conflict", False),
        ("conflict", True),
    },
    "PATCH_CONFLICT": {
        ("conflict", False),
        ("conflict", True),
    },
    "RESEARCH_SERVICE_ERROR": {
        ("runtime", False),
        ("runtime", True),
    },
    "PAPER_SEARCH_ERROR": {
        ("runtime", False),
        ("runtime", True),
    },
}

INTENTIONAL_VARIANT_REASONS = {
    "NATIVE_HELPER_PROTOCOL_ERROR": (
        "Malformed/helper-process protocol failures are runtime failures, while "
        "request nonce or operation mismatches are trust-binding security failures; "
        "both remain non-retryable hard failures."
    ),
    "EXPORT_PATH_CONFLICT": (
        "A non-file target needs operator reconciliation, while changed content can "
        "be retried after an explicit baseline/path refresh."
    ),
    "PATCH_CONFLICT": (
        "Baseline races are retryable after refresh; semantic add-target collisions "
        "require the caller to change the requested patch."
    ),
    "RESEARCH_SERVICE_ERROR": (
        "HTTP 5xx responses are retryable service failures; 4xx responses require "
        "request/provider correction rather than automatic retry."
    ),
    "PAPER_SEARCH_ERROR": (
        "OpenAlex 5xx responses are retryable service failures; 4xx responses are not."
    ),
}

# Dynamic code propagation is deliberate only at these narrow boundaries.
ALLOWED_DYNAMIC_SOURCES = {
    ("capabilities.py", "_denied", "ReCTMError"),
    ("native.py", "_assert_inside", "ReCTMError"),
    ("native.py", "_validate_response", "ReCTMError"),
}

CRITICAL_VARIANTS = {
    "PAPER_SEARCH_UNAVAILABLE": {("runtime", True)},
    "PAPER_SEARCH_UNSUPPORTED": {("runtime", False)},
    "REFERENCE_RUN_MISMATCH": {("permission", False)},
}


def client_action(category: str, retryable: bool) -> str:
    if category == "validation":
        return "correct_request"
    if category == "conflict":
        return "refresh_and_retry" if retryable else "reconcile_state"
    if category == "permission":
        return "stop_or_reauthorize"
    if category == "security":
        return "stop_and_report_security"
    if category == "not_found":
        return "refresh_identifier"
    if category == "runtime":
        return "retry_later" if retryable else "report_or_reconfigure"
    if category == "internal":
        return "report_internal_error"
    raise ValueError(f"unknown ReCTMError category: {category}")


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _literal_bool(node: ast.AST | None) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _retryable_values(node: ast.AST | None) -> set[bool] | None:
    if node is None:
        return {False}
    literal = _literal_bool(node)
    if literal is not None:
        return {literal}
    if isinstance(node, ast.Compare):
        return {False, True}
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


class ErrorVisitor(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module = module
        self.function_stack: list[str] = []
        self.records: list[dict[str, Any]] = []
        self.dynamic_sources: list[tuple[str, str, str]] = []

    @property
    def function_name(self) -> str:
        return self.function_stack[-1] if self.function_stack else "<module>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name == "ReCTMError":
            self._record_re_ctm_error(node)
        elif name == "_denied":
            code = _literal_string(node.args[0] if node.args else None)
            if code is None:
                self._mark_dynamic(name)
            else:
                self._append(code, "permission", False)
        elif name == "invalid_argument":
            self._append("INVALID_ARGUMENT", "validation", False)
        elif name == "permission_denied":
            self._append("PERMISSION_DENIED", "permission", False)
        self.generic_visit(node)

    def _record_re_ctm_error(self, node: ast.Call) -> None:
        keyword = {item.arg: item.value for item in node.keywords if item.arg}
        code_node = node.args[0] if node.args else keyword.get("code")
        code = _literal_string(code_node)
        if code is None:
            self._mark_dynamic("ReCTMError")
            return

        category_node = node.args[2] if len(node.args) > 2 else keyword.get("category")
        if category_node is None:
            category = "runtime"
        else:
            category = _literal_string(category_node)
            if category is None:
                self._mark_dynamic("ReCTMError")
                return

        retryable_node = node.args[3] if len(node.args) > 3 else keyword.get("retryable")
        retryable_values = _retryable_values(retryable_node)
        if retryable_values is None:
            self._mark_dynamic("ReCTMError")
            return
        for retryable in retryable_values:
            self._append(code, category, retryable)

    def _append(self, code: str, category: str, retryable: bool) -> None:
        self.records.append(
            {
                "code": code,
                "category": category,
                "retryable": retryable,
                "module": self.module,
                "function": self.function_name,
            }
        )

    def _mark_dynamic(self, constructor: str) -> None:
        self.dynamic_sources.append((self.module, self.function_name, constructor))


def scan_error_contract(source_root: Path = SOURCE_ROOT) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    dynamic_sources: list[tuple[str, str, str]] = []
    for path in sorted(source_root.glob("*.py")):
        visitor = ErrorVisitor(path.name)
        visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        records.extend(visitor.records)
        dynamic_sources.extend(visitor.dynamic_sources)

    by_code: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_code[record["code"]].append(record)

    codes: dict[str, Any] = {}
    unexpected_variants: dict[str, list[list[Any]]] = {}
    for code, sites in sorted(by_code.items()):
        variants = {(str(site["category"]), bool(site["retryable"])) for site in sites}
        expected_exception = INTENTIONAL_VARIANTS.get(code)
        if len(variants) > 1 and expected_exception != variants:
            unexpected_variants[code] = [list(item) for item in sorted(variants)]
        if expected_exception is not None and expected_exception != variants:
            unexpected_variants[code] = [list(item) for item in sorted(variants)]
        codes[code] = {
            "variants": [
                {
                    "category": category,
                    "retryable": retryable,
                    "client_action": client_action(category, retryable),
                }
                for category, retryable in sorted(variants)
            ],
            "site_count": len(sites),
            "modules": sorted({str(site["module"]) for site in sites}),
        }

    dynamic_set = set(dynamic_sources)
    unexpected_dynamic = sorted(dynamic_set - ALLOWED_DYNAMIC_SOURCES)
    missing_dynamic = sorted(ALLOWED_DYNAMIC_SOURCES - dynamic_set)
    unknown_categories = sorted(
        {
            category
            for entry in codes.values()
            for category in (item["category"] for item in entry["variants"])
            if category not in KNOWN_CATEGORIES
        }
    )
    retryable_hard_failures = sorted(
        code
        for code, entry in codes.items()
        if any(
            item["category"] in {"permission", "security"} and item["retryable"]
            for item in entry["variants"]
        )
    )
    critical_mismatches = {
        code: {
            "expected": [list(item) for item in sorted(expected)],
            "actual": [
                [item["category"], item["retryable"]]
                for item in codes.get(code, {}).get("variants", [])
            ],
        }
        for code, expected in CRITICAL_VARIANTS.items()
        if {
            (item["category"], item["retryable"])
            for item in codes.get(code, {}).get("variants", [])
        }
        != expected
    }
    return {
        "code_count": len(codes),
        "site_count": len(records),
        "categories": sorted(KNOWN_CATEGORIES),
        "rethlas_step_recoverable_categories": ["validation", "conflict"],
        "hard_failure_categories": ["permission", "security"],
        "intentional_variant_exceptions": {
            code: {
                "variants": [list(item) for item in sorted(variants)],
                "reason": INTENTIONAL_VARIANT_REASONS[code],
            }
            for code, variants in sorted(INTENTIONAL_VARIANTS.items())
        },
        "dynamic_sources": [list(item) for item in sorted(dynamic_set)],
        "codes": codes,
        "audit": {
            "unexpected_variants": unexpected_variants,
            "unexpected_dynamic_sources": [list(item) for item in unexpected_dynamic],
            "missing_dynamic_sources": [list(item) for item in missing_dynamic],
            "unknown_categories": unknown_categories,
            "retryable_hard_failures": retryable_hard_failures,
            "critical_mismatches": critical_mismatches,
        },
    }


def audit_passed(report: dict[str, Any]) -> bool:
    audit = report["audit"]
    return all(not value for value in audit.values())


def main() -> int:
    report = scan_error_contract()
    summary = {
        "ok": audit_passed(report),
        "code_count": report["code_count"],
        "site_count": report["site_count"],
        "categories": report["categories"],
        "rethlas_step_recoverable_categories": report[
            "rethlas_step_recoverable_categories"
        ],
        "hard_failure_categories": report["hard_failure_categories"],
        "intentional_variant_exceptions": report["intentional_variant_exceptions"],
        "dynamic_sources": report["dynamic_sources"],
        "audit": report["audit"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

