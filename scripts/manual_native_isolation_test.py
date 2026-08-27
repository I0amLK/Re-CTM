#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from re_ctm.enums import NativeMode  # noqa: E402
from re_ctm.native import (  # noqa: E402
    BubblewrapExecBackend,
    ExternalHelperExecBackend,
    NativeWorkspace,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Target-PC adversarial validation for the Re-CTM native isolation boundary."
    )
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--private-root", required=True)
    parser.add_argument("--backend", choices=["bubblewrap", "external"], default="bubblewrap")
    parser.add_argument("--helper")
    parser.add_argument("--output", default="native-isolation-validation.json")
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve(strict=True)
    data_root = Path(args.data_root).expanduser().resolve(strict=False)
    private_root = Path(args.private_root).expanduser().resolve(strict=False)
    NativeWorkspace(workspace, private_root=private_root)
    private_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    data_root.mkdir(parents=True, exist_ok=True, mode=0o700)

    if args.backend == "external":
        if not args.helper:
            parser.error("--helper is required with --backend=external")
        backend = ExternalHelperExecBackend(Path(args.helper))
    else:
        backend = BubblewrapExecBackend()

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "backend": args.backend,
        "workspace": str(workspace),
        "data_root": str(data_root),
        "private_root": str(private_root),
        "checks": [],
        "passed": False,
        "operator_acknowledgement": (
            "A passing result is target-specific evidence. Review this JSON before setting "
            "RE_CTM_NATIVE_ISOLATION_ATTESTED=1."
        ),
    }
    canary_name = f"re-ctm-private-canary-{secrets.token_hex(8)}.txt"
    canary = private_root / canary_name
    canary_secret = f"PRIVATE-{secrets.token_hex(24)}"
    workspace_probe = workspace / f".re-ctm-native-write-{secrets.token_hex(6)}"
    canary.write_text(canary_secret + "\n", encoding="utf-8")
    try:
        attestation = backend.attest(
            workspace=workspace,
            forbidden_paths=(data_root, private_root),
        )
        _record(report, "helper_attestation", True, attestation=attestation)

        visible = backend.execute(
            workspace=workspace,
            argv=["/usr/bin/python3", "-c", "import os; print(os.path.isdir('/workspace'))"],
            workdir=".",
            timeout_ms=10_000,
            mode=NativeMode.SAFE,
        )
        _record(
            report,
            "workspace_is_mounted",
            visible.get("exit_code") == 0 and visible.get("stdout", "").strip() == "True",
            result=_summary(visible),
        )

        private_probe_script = (
            "import os,sys; p=sys.argv[1]; "
            "print(os.path.lexists(p)); "
            "print(open(p,encoding='utf-8').read() if os.path.isfile(p) else 'HIDDEN')"
        )
        private_probe = backend.execute(
            workspace=workspace,
            argv=["/usr/bin/python3", "-c", private_probe_script, str(canary)],
            workdir=".",
            timeout_ms=10_000,
            mode=NativeMode.DANGEROUS,
        )
        private_output = str(private_probe.get("stdout") or "")
        _record(
            report,
            "dangerous_cannot_read_private_canary",
            private_probe.get("exit_code") == 0
            and private_output.splitlines() == ["False", "HIDDEN"]
            and canary_secret not in private_output,
            result=_summary(private_probe),
            canary_sha256=_sha256_text(canary_secret),
        )

        os.environ["RE_CTM_MANUAL_PARENT_SECRET"] = canary_secret
        try:
            env_probe = backend.execute(
                workspace=workspace,
                argv=[
                    "/usr/bin/python3",
                    "-c",
                    "import os; print(os.environ.get('RE_CTM_MANUAL_PARENT_SECRET','CLEARED'))",
                ],
                workdir=".",
                timeout_ms=10_000,
                mode=NativeMode.DANGEROUS,
            )
        finally:
            os.environ.pop("RE_CTM_MANUAL_PARENT_SECRET", None)
        _record(
            report,
            "parent_secret_environment_is_cleared",
            env_probe.get("exit_code") == 0 and env_probe.get("stdout", "").strip() == "CLEARED",
            result=_summary(env_probe),
        )

        write_probe = backend.execute(
            workspace=workspace,
            argv=[
                "/usr/bin/python3",
                "-c",
                "from pathlib import Path; Path('/workspace/'+__import__('sys').argv[1]).write_text('ok')",
                workspace_probe.name,
            ],
            workdir=".",
            timeout_ms=10_000,
            mode=NativeMode.DANGEROUS,
        )
        _record(
            report,
            "dangerous_can_write_only_the_native_workspace",
            write_probe.get("exit_code") == 0
            and workspace_probe.read_text(encoding="utf-8") == "ok",
            result=_summary(write_probe),
        )

        network_probe = backend.execute(
            workspace=workspace,
            argv=[
                "/usr/bin/python3",
                "-c",
                "print([line.split(':',1)[0].strip() for line in open('/proc/net/dev') if ':' in line])",
            ],
            workdir=".",
            timeout_ms=10_000,
            mode=NativeMode.SAFE,
        )
        network_text = str(network_probe.get("stdout") or "")
        _record(
            report,
            "safe_mode_has_isolated_network_namespace",
            network_probe.get("exit_code") == 0
            and "lo" in network_text
            and network_probe.get("attestation", {}).get("network_isolated") is True,
            result=_summary(network_probe),
        )

        timeout_probe = backend.execute(
            workspace=workspace,
            argv=["/usr/bin/python3", "-c", "import time; time.sleep(5)"],
            workdir=".",
            timeout_ms=100,
            mode=NativeMode.SAFE,
        )
        _record(
            report,
            "command_timeout_is_enforced",
            timeout_probe.get("timed_out") is True,
            result=_summary(timeout_probe),
        )
    except Exception as exc:  # noqa: BLE001 - manual report must preserve failure evidence
        _record(
            report,
            "unhandled_validation_failure",
            False,
            exception_type=type(exc).__name__,
            message=str(exc),
        )
    finally:
        canary.unlink(missing_ok=True)
        workspace_probe.unlink(missing_ok=True)

    report["passed"] = bool(report["checks"]) and all(item["passed"] for item in report["checks"])
    output = Path(args.output).expanduser().resolve()
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["passed"], "report": str(output)}, indent=2))
    return 0 if report["passed"] else 1


def _record(report: dict[str, Any], name: str, passed: bool, **details: Any) -> None:
    report["checks"].append({"name": name, "passed": bool(passed), "details": details})


def _summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": payload.get("status"),
        "exit_code": payload.get("exit_code"),
        "signal": payload.get("signal"),
        "timed_out": payload.get("timed_out"),
        "stdout": str(payload.get("stdout") or "")[-2000:],
        "stderr": str(payload.get("stderr") or "")[-2000:],
        "attestation": payload.get("attestation"),
    }


def _sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
