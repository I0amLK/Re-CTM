#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "local-validation.json"


def run(name: str, command: list[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output = completed.stdout
    return {
        "name": name,
        "command": command,
        "passed": completed.returncode == 0,
        "exit_code": completed.returncode,
        "output_tail": output[-20_000:],
    }


def main() -> int:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    checks = [
        run(
            "compileall",
            [sys.executable, "-m", "compileall", "-q", "src"],
            env=environment,
        ),
        run(
            "unittest",
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            env=environment,
        ),
        run(
            "engineering_graph",
            [sys.executable, "scripts/validate_engineering_graph.py"],
            env=environment,
        ),
    ]
    manual = json.loads((ROOT / "manual-validation.json").read_text(encoding="utf-8"))
    payload = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
        },
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "local_claim": (
            "Only deterministic graph, compile, unit, loopback OAuth/MCP, authorization, "
            "state-machine, capability-gated external-retrieval integration, native fail-closed and "
            "reference bubblewrap isolation, debug-redaction, and isolated/static LaTeX behavior was tested. "
            "Target-PC and real webpage acceptance remain separate."
        ),
        "not_locally_validated": [
            check["name"]
            for check in manual["checks"]
            if check.get("status") != "passed"
        ],
        "manual_validation_status": manual["status"],
    }
    temporary = REPORT.with_name(REPORT.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(REPORT)
    print(json.dumps({"ok": payload["passed"], "report": str(REPORT)}, indent=2))
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
