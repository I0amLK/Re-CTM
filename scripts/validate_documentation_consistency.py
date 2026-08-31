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
from re_ctm.tools import CTM_NATIVE_TOOL_NAMES, PUBLIC_TOOL_NAMES  # noqa: E402


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
    hidden_alias_count = len(HIDDEN_LEGACY_ALIAS_SEMANTICS)
    if (native_count, rethlas_count, public_count, hidden_alias_count) != (18, 6, 24, 11):
        raise ValueError(
            "tool-catalog contract drift: "
            f"native={native_count}, rethlas={rethlas_count}, public={public_count}, "
            f"hidden_aliases={hidden_alias_count}"
        )

    readme = _load_text("README.md")
    agents = _load_text("AGENTS.md")
    deployment = _load_text("docs/DEPLOYMENT.md")
    code_quality = _load_text("docs/CODE_QUALITY.md")

    _require(readme, f"Re-CTM v{__version__}", source="README.md")
    _require(readme, "**24 个工具**", source="README.md")
    _require(readme, "18 个 CTM Native + 6 个 Rethlas façade", source="README.md")
    for name in RETHLAS_TOOL_NAMES:
        _require(readme, name, source="README.md")
    _require(readme, "scripts/run_local_checks.py", source="README.md")
    _require(readme, "docs/CODE_QUALITY.md", source="README.md")

    _require(
        agents,
        "exact 18 CTM native tools followed by six Rethlas façade tools",
        source="AGENTS.md",
    )
    _require(agents, "docs/CODE_QUALITY.md", source="AGENTS.md")
    _require(agents, "code-optimization-graph.json", source="AGENTS.md")
    _require(agents, "scripts/run_local_checks.py", source="AGENTS.md")

    _require(deployment, f"Re-CTM v{__version__}", source="docs/DEPLOYMENT.md")
    _require(deployment, "manual-validation.json", source="docs/DEPLOYMENT.md")
    _require(deployment, "proof_verified.tex", source="docs/DEPLOYMENT.md")
    _require(code_quality, "code-optimization-graph.json", source="docs/CODE_QUALITY.md")
    _require(code_quality, "scripts/run_local_checks.py", source="docs/CODE_QUALITY.md")

    graph = _load_json("engineering-graph.json")
    constraints = {
        str(item.get("id")): str(item.get("constraint") or "")
        for item in graph.get("product_constraints", [])
        if isinstance(item, dict)
    }
    catalog_constraint = constraints.get("PC-009", "")
    if "24 public tools total" not in catalog_constraint:
        raise ValueError("engineering-graph.json PC-009 does not record the 24-tool contract")

    progress = _load_json("project-progress.json")
    decisions = {
        str(item.get("id")): str(item.get("decision") or "")
        for item in progress.get("architecture_decisions", [])
        if isinstance(item, dict)
    }
    if "exactly 24 tools" not in decisions.get("AD-031", ""):
        raise ValueError("project-progress.json AD-031 does not record the 24-tool contract")

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
        "hidden_legacy_alias_count": hidden_alias_count,
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
