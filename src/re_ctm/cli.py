from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import sqlite3
import tempfile
from dataclasses import replace
from pathlib import Path

from . import __version__
from .app import build_application
from .config import Settings, materialize_secrets
from .enums import LatexPolicy, NativeMode
from .engineering_graph import main as validate_engineering_graph
from .errors import ReCTMError
from .native import BubblewrapExecBackend, ExternalHelperExecBackend, NativeWorkspace
from .quick_tunnel import QuickTunnel
from .server import run_server
from .storage import STATE_SCHEMA_VERSION, StateStore
from .terminal_ui import TerminalSession
from .toolchains import build_toolchain_exposure_plan, parse_native_exec_allow_roots


class _SingleFactOption(argparse.Action):
    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: str, option_string: str | None = None) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"Repeated fact-graph option: {option_string}")
        setattr(namespace, self.dest, values)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re-ctm",
        description="OAuth MCP runtime with native CMT tools and a capability-gated Rethlas workflow.",
    )
    parser.add_argument("--version", action="version", version=f"re-ctm {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    serve = subcommands.add_parser("serve", help="Run the OAuth-only HTTP MCP service.")
    tui = subcommands.add_parser(
        "tui",
        help="Run the OAuth MCP service with a minimal terminal session monitor.",
    )
    for command, default_port in (
        (serve, os.environ.get("RE_CTM_PORT") or "8765"),
        (tui, os.environ.get("RE_CTM_PORT") or None),
    ):
        command.add_argument(
            "--host",
            default=os.environ.get("RE_CTM_HOST") or "127.0.0.1",
        )
        command.add_argument(
            "--port",
            type=int,
            default=default_port,
        )
        command.add_argument("--workspace")
        command.add_argument("--native-mode", choices=[NativeMode.DANGEROUS.value])
        command.add_argument("--latex-policy", choices=[item.value for item in LatexPolicy])
    tui.add_argument(
        "--quick-tunnel",
        action="store_true",
        help="Start and manage one temporary Cloudflare Quick Tunnel for this TUI session.",
    )
    tui.add_argument(
        "--verbose",
        action="store_true",
        help="Show redacted tool completion and trace diagnostics in the terminal.",
    )

    subcommands.add_parser("check-config", help="Validate configuration without starting HTTP.")
    subcommands.add_parser("validate-graph", help="Validate engineering-graph.json metrics and invariants.")
    facts = subcommands.add_parser("fact-graph", help="Export or revoke private verified project facts.")
    fact_operations = facts.add_subparsers(dest="fact_operation", required=True)
    export = fact_operations.add_parser("export", help="Read-only deterministic fact graph export.")
    export.add_argument("--project", required=True, action=_SingleFactOption)
    export.add_argument("--out", action=_SingleFactOption)
    revoke = fact_operations.add_parser("revoke", help="Append an operator revocation including descendants.")
    revoke.add_argument("fact_id")
    revoke.add_argument("--reason", required=True, action=_SingleFactOption)
    for command in (export, revoke):
        command.add_argument("--state-db", action=_SingleFactOption)
    attest = subcommands.add_parser(
        "attest-native",
        help="Probe a native isolation helper without enabling command execution.",
    )
    attest.add_argument("--backend", choices=["bubblewrap", "external"], default="bubblewrap")
    attest.add_argument("--helper", help="External helper path when --backend=external.")
    attest.add_argument("--workspace")
    attest.add_argument("--data-root")
    attest.add_argument("--private-root")
    attest.add_argument(
        "--allow-root",
        action="append",
        default=[],
        help="Additional absolute Bubblewrap toolchain root; repeatable.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "fact-graph":
            return _fact_graph_command(args)
        if args.command == "validate-graph":
            source_root = Path(__file__).resolve().parents[2]
            graph = source_root / "engineering-graph.json"
            checkout = (source_root / "src" / "re_ctm" / "cli.py").resolve() == Path(__file__).resolve()
            return validate_engineering_graph(graph if checkout and graph.is_file() else None)
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
                if args.allow_root or os.environ.get("RE_CTM_NATIVE_EXEC_ALLOW_ROOTS"):
                    raise ReCTMError(
                        "NATIVE_TOOLCHAIN_ROOTS_UNSUPPORTED",
                        "--allow-root and RE_CTM_NATIVE_EXEC_ALLOW_ROOTS require the built-in Bubblewrap backend.",
                        category="validation",
                    )
                if not args.helper:
                    raise ReCTMError(
                        "NATIVE_HELPER_REQUIRED",
                        "--helper is required with --backend=external.",
                        category="validation",
                    )
                backend = ExternalHelperExecBackend(Path(args.helper))
                exposure: dict[str, object] = {
                    "policy": "external_helper_owned",
                    "resolved_read_only_root_count": 0,
                }
            else:
                explicit_roots = (
                    *parse_native_exec_allow_roots(
                        os.environ.get("RE_CTM_NATIVE_EXEC_ALLOW_ROOTS")
                    ),
                    *(Path(value).expanduser() for value in args.allow_root),
                )
                plan = build_toolchain_exposure_plan(
                    mode=NativeMode.DANGEROUS,
                    workspace=workspace,
                    forbidden_paths=(data_root, private_root),
                    explicit_roots=explicit_roots,
                    host_path=os.environ.get("PATH", ""),
                )
                backend = BubblewrapExecBackend(exposure_plan=plan)
                exposure = plan.summary(include_paths=True)
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
                        "toolchain_exposure": exposure,
                        "attestation": attestation,
                        "operator_action": (
                            "Retain this as target-specific evidence. The built-in Bubblewrap "
                            "backend will repeat fail-closed attestation at service startup."
                            if args.backend == "bubblewrap"
                            else "After independent review succeeds, configure the external helper and set RE_CTM_NATIVE_ISOLATION_ATTESTED=1."
                        ),
                    },
                    indent=2,
                )
            )
            return 0
        settings = Settings.from_env()
        quick_tunnel_requested = bool(
            args.command == "tui" and getattr(args, "quick_tunnel", False)
        )
        if quick_tunnel_requested:
            settings = replace(settings, oauth_server_url="")
        if getattr(args, "workspace", None):
            settings = replace(settings, workspace=Path(args.workspace).expanduser().resolve())
        if getattr(args, "native_mode", None):
            settings = replace(settings, native_mode=NativeMode(args.native_mode))
        if getattr(args, "latex_policy", None):
            settings = replace(settings, latex_policy=LatexPolicy(args.latex_policy))
        settings.validate()
        settings = materialize_secrets(settings)
        if args.command == "check-config":
            exposure = (
                build_toolchain_exposure_plan(
                    mode=settings.native_mode,
                    workspace=settings.workspace,
                    forbidden_paths=(settings.data_root, settings.private_root),
                    explicit_roots=settings.native_exec_allow_roots,
                    host_path=os.environ.get("PATH", ""),
                ).summary(include_paths=True)
                if settings.native_exec_backend == "bubblewrap"
                else {
                    "policy": "unavailable",
                    "resolved_read_only_root_count": 0,
                }
            )
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
                        "native_exec_allow_roots": [
                            str(path) for path in settings.native_exec_allow_roots
                        ],
                        "toolchain_exposure": exposure,
                        "native_startup_attestation": (
                            "automatic_fail_closed"
                            if settings.native_exec_backend == "bubblewrap"
                            else (
                                "operator_acknowledged_external"
                                if settings.native_exec_backend == "external"
                                else "not_applicable"
                            )
                        ),
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
                        "state_schema_version": STATE_SCHEMA_VERSION,
                        "workflow_protocol_version": 3,
                        "research_workspace": {
                            "project_registry": True,
                            "compact_verified_lane": True,
                            "proof_manifest": True,
                            "reference_audit": True,
                            "paper_search_provider": "https://api.openalex.org/works",
                        },
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
        terminal_session = (
            TerminalSession(verbose=args.verbose) if args.command == "tui" else None
        )
        quick_tunnel = (
            QuickTunnel(terminal_session)
            if quick_tunnel_requested and terminal_session is not None
            else None
        )
        resolved_port = args.port
        if resolved_port is None:
            resolved_port = 0 if quick_tunnel_requested else 8765
        application = build_application(
            settings,
            debug_observer=(terminal_session.observe if terminal_session is not None else None),
        )
        return run_server(
            application,
            host=args.host,
            port=resolved_port,
            reveal_generated_oauth_password=generated_oauth_password,
            terminal_session=terminal_session,
            quick_tunnel=quick_tunnel,
        )
    except ReCTMError as exc:
        print(json.dumps({"ok": False, "error": exc.to_payload()}, indent=2), file=sys.stderr)
        return 2


def _fact_graph_command(args: argparse.Namespace) -> int:
    if args.state_db is not None:
        path = Path(args.state_db)
    elif os.environ.get("RE_CTM_PRIVATE_ROOT"):
        path = Path(os.environ["RE_CTM_PRIVATE_ROOT"]).expanduser() / "state.sqlite3"
    else:
        root = Path(os.environ.get("RE_CTM_DATA_ROOT", "~/.re-ctm")).expanduser()
        path = root / "private" / "state.sqlite3"
    if not path.is_absolute() or not path.is_file():
        raise ReCTMError("INVALID_ARGUMENT", "fact-graph requires an existing absolute state database path.",
                        category="validation")
    try:
        store = StateStore.open_read_only(path) if args.fact_operation == "export" else StateStore(path)
        try:
            result = (store.project_fact_graph_operator(args.project) if args.fact_operation == "export" else
                      store.revoke_project_fact(args.fact_id, "operator", args.reason))
        finally:
            store.close()
        text = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        if args.fact_operation == "export" and args.out is not None:
            _publish_fact_graph(Path(args.out), text)
        else:
            print(text, end="")
        return 0
    except (OSError, sqlite3.Error) as exc:
        raise ReCTMError("FACT_GRAPH_IO_ERROR", str(exc), category="internal") from exc


def _publish_fact_graph(path: Path, text: str) -> None:
    """Publish complete bytes without ever replacing an existing destination."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                          prefix=".fact-graph-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
