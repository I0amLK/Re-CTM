#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from re_ctm import __version__  # noqa: E402
from re_ctm.rethlas_contracts import (  # noqa: E402
    HIDDEN_LEGACY_ALIAS_SEMANTICS,
    RETHLAS_TOOL_NAMES,
)
from re_ctm.tools import CTM_NATIVE_TOOL_NAMES, PUBLIC_TOOL_NAMES, TOOL_SPECS
from re_ctm.storage import STATE_SCHEMA_VERSION  # noqa: E402
from re_ctm.native_catalog import TOOL_CONTRACT_VERSION  # noqa: E402


MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _load_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _load_json(path: str) -> dict[str, Any]:
    payload = json.loads(_load_text(path))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _require(text: str, needle: str, *, source: str) -> None:
    if needle not in text:
        raise ValueError(f"{source} is missing stable documentation fact: {needle!r}")


def _validate_local_markdown_links(path: Path) -> list[str]:
    failures: list[str] = []
    text = path.read_text(encoding="utf-8")
    for raw_target in MARKDOWN_LINK.findall(text):
        target = raw_target.strip().split("#", 1)[0]
        if not target or target.startswith(("http://", "https://", "mailto:")):
            continue
        candidate = (path.parent / target).resolve()
        if not candidate.is_relative_to(ROOT.resolve()) or not candidate.exists():
            failures.append(f"{path.relative_to(ROOT)} -> {raw_target}")
    return failures


def validate_manual_validation(payload: dict[str, Any]) -> int:
    expected_contract = {
        "source_version": __version__,
        "tool_contract": TOOL_CONTRACT_VERSION,
        "native_tool_count": len(CTM_NATIVE_TOOL_NAMES),
        "workflow_tool_count": len(RETHLAS_TOOL_NAMES),
        "public_tool_count": len(PUBLIC_TOOL_NAMES),
        "workflow_protocol_default": 3,
        "preserved_workflow_protocols": [1, 2],
        "state_schema_version": STATE_SCHEMA_VERSION,
        "public_native_modes": ["dangerous"],
        "retired_native_modes": ["safe", "trusted"],
        "retired_workflow_alias_count": len(HIDDEN_LEGACY_ALIAS_SEMANTICS),
    }
    if payload.get("current_contract") != expected_contract:
        raise ValueError("manual-validation.json active contract differs from the current runtime")
    if payload.get("status") not in {"pending_target_validation", "passed", "failed"}:
        raise ValueError("manual-validation.json must record current target acceptance status")
    checks = payload.get("checks")
    if not isinstance(checks, list) or any(not isinstance(item, dict) for item in checks):
        raise ValueError("manual-validation.json needs an active release checklist")
    if [item.get("id") for item in checks] != [
        f"RC-{number:03d}" for number in range(1, 12)
    ]:
        raise ValueError("manual-validation.json active release checklist must be RC-001 through RC-011")
    for item in checks:
        if item.get("status") not in {"pending", "passed", "failed"}:
            raise ValueError(f"{item['id']} has an invalid acceptance status")
        if not isinstance(item.get("evidence"), list):
            raise ValueError(f"{item['id']} must retain an evidence list")
        if item["status"] == "passed" and not item["evidence"]:
            raise ValueError(f"{item['id']} cannot pass without scope-specific evidence")
    if payload["status"] == "passed" and any(item["status"] != "passed" for item in checks):
        raise ValueError("overall acceptance cannot pass while a release check remains incomplete")
    history = payload.get("historical_checklists")
    if not isinstance(history, list) or not history:
        raise ValueError("manual-validation.json must preserve the superseded historical checklist")
    historical_manifest = None
    for entry in history:
        if not isinstance(entry, dict) or entry.get("lifecycle") != "superseded":
            raise ValueError("historical checklist lifecycle must remain superseded")
        manifest = entry.get("manifest")
        if isinstance(manifest, dict) and manifest.get("schema_version") == "1.0.0":
            historical_manifest = manifest
    if not isinstance(historical_manifest, dict):
        raise ValueError("the original historical manifest is missing")
    historical_checks = historical_manifest.get("checks", [])
    if not isinstance(historical_checks, list) or any(
        not isinstance(item, dict) for item in historical_checks
    ):
        raise ValueError("the original historical checks are missing")
    if [item.get("id") for item in historical_checks] != [
        f"MV-{number:03d}" for number in range(1, 13)
    ]:
        raise ValueError("the original MV-001 through MV-012 historical checks must be retained")
    if historical_manifest.get("status") != "pending_post_push":
        raise ValueError("the historical manifest status must not be rewritten as current acceptance")
    return len(checks)


def validate_documentation() -> dict[str, Any]:
    project = tomllib.loads(_load_text("pyproject.toml"))["project"]
    project_version = str(project["version"])
    if project_version != __version__:
        raise ValueError(
            f"version drift: pyproject.toml={project_version}, re_ctm.__version__={__version__}"
        )

    native_count = len(CTM_NATIVE_TOOL_NAMES)
    rethlas_count = len(RETHLAS_TOOL_NAMES)
    public_count = len(PUBLIC_TOOL_NAMES)
    retired_alias_count = len(HIDDEN_LEGACY_ALIAS_SEMANTICS)
    callable_alias_count = len(set(HIDDEN_LEGACY_ALIAS_SEMANTICS) & set(TOOL_SPECS))
    if (native_count, rethlas_count, public_count, retired_alias_count, callable_alias_count) != (19, 6, 25, 11, 0):
        raise ValueError(
            "tool-catalog contract drift: "
            f"native={native_count}, rethlas={rethlas_count}, public={public_count}, "
            f"retired_aliases={retired_alias_count}, callable_aliases={callable_alias_count}"
        )

    readme = _load_text("README.md")
    agents = _load_text("AGENTS.md")
    deployment = _load_text("docs/DEPLOYMENT.md")
    code_quality = _load_text("docs/CODE_QUALITY.md")

    _require(readme, f"Re-CTM v{__version__}", source="README.md")
    _require(readme, "**25 个工具**", source="README.md")
    _require(readme, "19 个 MTM Native + 6 个 Rethlas façade", source="README.md")
    for name in RETHLAS_TOOL_NAMES:
        _require(readme, name, source="README.md")
    _require(readme, "scripts/run_local_checks.py", source="README.md")
    _require(readme, "docs/CODE_QUALITY.md", source="README.md")

    _require(
        agents,
        "exact 19 MTM Native tools followed by six Rethlas façade tools",
        source="AGENTS.md",
    )
    _require(agents, "docs/CODE_QUALITY.md", source="AGENTS.md")
    _require(agents, "code-optimization-graph.json", source="AGENTS.md")
    _require(agents, "scripts/run_local_checks.py", source="AGENTS.md")

    _require(deployment, f"Re-CTM v{__version__}", source="docs/DEPLOYMENT.md")
    _require(deployment, "manual-validation.json", source="docs/DEPLOYMENT.md")
    _require(deployment, "proof_verified.tex", source="docs/DEPLOYMENT.md")
    if "旧 `rethlas_export_final` 名称仍作为隐藏兼容入口接受。" in readme:
        raise ValueError("README.md still promises a callable retired artifact alias")
    if "names remain hidden compatibility aliases." in deployment:
        raise ValueError("docs/DEPLOYMENT.md still promises callable retired artifact aliases")
    manual_check_count = validate_manual_validation(_load_json("manual-validation.json"))
    _require(code_quality, "code-optimization-graph.json", source="docs/CODE_QUALITY.md")
    _require(code_quality, "scripts/run_local_checks.py", source="docs/CODE_QUALITY.md")

    graph = _load_json("engineering-graph.json")
    constraints = {
        str(item.get("id")): str(item.get("constraint") or "")
        for item in graph.get("product_constraints", [])
        if isinstance(item, dict)
    }
    catalog_constraint = constraints.get("PC-009", "")
    if "25 public tools total" not in catalog_constraint:
        raise ValueError("engineering-graph.json PC-009 does not record the active 25-tool contract")

    progress = _load_json("project-progress.json")
    decisions = {
        str(item.get("id")): str(item.get("decision") or "")
        for item in progress.get("architecture_decisions", [])
        if isinstance(item, dict)
    }
    if "exactly 24 tools" not in decisions.get("AD-031", ""):
        raise ValueError("project-progress.json AD-031 lost the historical v0.2 24-tool decision")
    if not any(all(marker in decision for marker in ("25 public tools", "protocol 3", "schema 8"))
               for decision in decisions.values()):
        raise ValueError("project-progress.json needs the explicit current MTM migration decision")
    if STATE_SCHEMA_VERSION != 8:
        raise ValueError("runtime schema differs from the approved schema-8 migration")
    migration = _load_text("docs/MTM_MIGRATION.md")
    _require(migration, "b5dbd2577869d2aaf7b0933373df6671d104581c", source="docs/MTM_MIGRATION.md")
    _require(migration, "protocol 3", source="docs/MTM_MIGRATION.md")
    _require(migration, "schema 8", source="docs/MTM_MIGRATION.md")

    link_failures: list[str] = []
    for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        link_failures.extend(_validate_local_markdown_links(path))
    if link_failures:
        raise ValueError(f"broken local markdown links: {link_failures}")

    return {
        "version": __version__,
        "native_tool_count": native_count,
        "rethlas_tool_count": rethlas_count,
        "public_tool_count": public_count,
        "retired_legacy_alias_count": retired_alias_count,
        "callable_legacy_alias_count": callable_alias_count,
        "state_schema_version": STATE_SCHEMA_VERSION,
        "active_release_check_count": manual_check_count,
        "checked_markdown_files": 1 + len(list((ROOT / "docs").glob("*.md"))),
        "local_markdown_link_failures": 0,
    }


def main() -> int:
    try:
        summary = validate_documentation()
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps({"ok": True, "summary": summary}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
