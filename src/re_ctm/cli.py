from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from .app import build_application
from .config import Settings, materialize_secrets
from .enums import LatexPolicy, NativeMode
from .errors import ReCTMError
from .native import BubblewrapExecBackend, ExternalHelperExecBackend, NativeWorkspace
from .server import run_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-ctm",
        description="OAuth MCP runtime with native CMT tools and a capability-gated Rethlas workflow.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve", help="Run the OAuth-only HTTP MCP service.")
    serve.add_argument(
        "--host",
        default=os.environ.get("RE_CTM_HOST") or "127.0.0.1",
    )
    serve.add_argument(
        "--port",
        type=int,
        default=os.environ.get("RE_CTM_PORT") or "8765",
    )
    serve.add_argument("--workspace")
    serve.add_argument("--native-mode", choices=[item.value for item in NativeMode])
    serve.add_argument("--latex-policy", choices=[item.value for item in LatexPolicy])

    subcommands.add_parser("check-config", help="Validate configuration without starting HTTP.")
    subcommands.add_parser("validate-graph", help="Validate engineering-graph.json metrics and invariants.")
    attest = subcommands.add_parser(
        "attest-native",
        help="Probe a native isolation helper without enabling command execution.",
    )
    attest.add_argument("--backend", choices=["bubblewrap", "external"], default="bubblewrap")
    attest.add_argument("--helper", help="External helper path when --backend=external.")
    attest.add_argument("--workspace")
    attest.add_argument("--data-root")
    attest.add_argument("--private-root")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-graph":
            script = Path(__file__).resolve().parents[2] / "scripts" / "validate_engineering_graph.py"
            return subprocess.call([sys.executable, str(script)])
        if args.command == "attest-native":
            workspace = Path(
                args.workspace or os.environ.get("RE_CTM_WORKSPACE") or os.getcwd()
            ).expanduser().resolve()
            data_root = Path(
                args.data_root or os.environ.get("RE_CTM_DATA_ROOT") or "~/.re-ctm"
            ).expanduser().resolve()
            private_root = Path(
                args.private_root
                or os.environ.get("RE_CTM_PRIVATE_ROOT")
                or str(data_root / "private")
            ).expanduser().resolve()
            NativeWorkspace(workspace, private_root=private_root)
            if args.backend == "external":
                if not args.helper:
                    raise ReCTMError(
                        "NATIVE_HELPER_REQUIRED",
                        "--helper is required with --backend=external.",
                        category="validation",
                    )
                backend = ExternalHelperExecBackend(Path(args.helper))
            else:
                backend = BubblewrapExecBackend()
            attestation = backend.attest(
                workspace=workspace,
                forbidden_paths=(data_root, private_root),
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "backend": args.backend,
                        "workspace": str(workspace),
                        "data_root": str(data_root),
                        "private_root": str(private_root),
                        "attestation": attestation,
                        "operator_action": (
                            "After target-PC manual validation succeeds, set "
                            "RE_CTM_NATIVE_EXEC_BACKEND and RE_CTM_NATIVE_ISOLATION_ATTESTED=1."
                        ),
                    },
                    indent=2,
                )
            )
            return 0
        settings = Settings.from_env()
        if getattr(args, "workspace", None):
            settings = replace(settings, workspace=Path(args.workspace).expanduser().resolve())
        if getattr(args, "native_mode", None):
            settings = replace(settings, native_mode=NativeMode(args.native_mode))
        if getattr(args, "latex_policy", None):
            settings = replace(settings, latex_policy=LatexPolicy(args.latex_policy))
        settings.validate()
        settings = materialize_secrets(settings)
        if args.command == "check-config":
            print(
                json.dumps(
                    {
                        "ok": True,
                        "workspace": str(settings.workspace),
                        "data_root": str(settings.data_root),
                        "private_root": str(settings.private_root),
                        "native_mode": settings.native_mode.value,
                        "native_exec_backend": settings.native_exec_backend,
                        "native_isolation_attested": settings.native_isolation_attested,
                        "latex_policy": settings.latex_policy.value,
                        "oauth_server_url": settings.oauth_server_url,
                        "oauth_server_url_mode": (
                            "fixed" if settings.oauth_server_url else "dynamic_loopback_reverse_proxy"
                        ),
                        "oauth_authorization_key_mode": (
                            "configured" if settings.oauth_password else "generated_on_serve"
                        ),
                        "oauth_only": True,
                        "theorem_search_url": settings.theorem_search_url,
                        "theorem_search_timeout_seconds": settings.theorem_search_timeout_seconds,
                        "secrets_present": True,
                        "complete_flow_locally_validated": False,
                    },
                    indent=2,
                )
            )
            return 0
        generated_oauth_password = not bool(settings.oauth_password)
        if generated_oauth_password:
            settings = replace(settings, oauth_password=secrets.token_urlsafe(32))
        application = build_application(settings)
        return run_server(
            application,
            host=args.host,
            port=args.port,
            reveal_generated_oauth_password=generated_oauth_password,
        )
    except ReCTMError as exc:
        print(json.dumps({"ok": False, "error": exc.to_payload()}, indent=2), file=sys.stderr)
        return 2
