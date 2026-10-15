#!/usr/bin/env python3
"""Bounded, offline target acceptance. Run from an ordinary target-host terminal.

Exit 0 means all requested evidence passed, 1 means a machine gate failed or was
blocked, and 2 means only manual/explicitly omitted evidence remains. This driver
never marks manual-validation.json passed and never modifies an existing service.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = (
    "AGENTS.md", "LICENSE", "NOTICE", "README.md", "pyproject.toml", "MANIFEST.in",
    "config.example.env", "engineering-graph.json", "code-optimization-graph.json",
    "project-progress.json", "manual-validation.json", "local-validation.json",
    "native-isolation-validation.json", ".gitignore",
)
SOURCE_DIRS = ("src", "tests", "scripts", "docs", ".github")
SOURCE_SUFFIXES = {".py", ".json", ".md", ".toml", ".yml", ".yaml", ".txt", ".tex"}
MANUAL_GATES = {
    "real_browser_client": "Actual intended browser/client OAuth, routing and resume are untested.",
    "external_retrieval": "Live fixed-provider retrieval and source quality require separate evidence.",
    "operator_mathematical_acceptance": "A scripted reflexivity fixture is not mathematical quality acceptance.",
    "operator_terminal_and_ingress": "Interactive terminal and any separately authorized ingress need review.",
}
PROOF = (
    "\\documentclass{article}\n\\usepackage{amsmath,amsthm}\n"
    "\\newtheorem{theorem}{Theorem}\n\\begin{document}\n"
    "\\begin{theorem}$1=1$.\\end{theorem}\n"
    "\\begin{proof}By reflexivity.\\end{proof}\n\\end{document}\n"
)


def _json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def _source_files(root: Path) -> list[Path]:
    """Allowlisted candidate inputs only; never follow symlinks or copy private state."""
    result = []
    for name in ROOT_FILES:
        path = root / name
        if path.is_symlink():
            raise ValueError(f"Source symlink refused: {name}")
        if path.is_file():
            result.append(path)
    for name in SOURCE_DIRS:
        directory = root / name
        if directory.is_symlink():
            raise ValueError(f"Source symlink refused: {name}")
        if not directory.exists():
            continue
        for current, dirs, files in os.walk(directory, followlinks=False):
            for child in dirs + files:
                path = Path(current) / child
                if path.is_symlink():
                    raise ValueError(f"Source symlink refused: {path.relative_to(root)}")
            dirs[:] = [item for item in dirs if item not in {"__pycache__", ".release-validation"}
                       and not item.endswith(".egg-info")]
            for child in files:
                path = Path(current) / child
                if path.suffix in SOURCE_SUFFIXES:
                    if not stat.S_ISREG(path.stat().st_mode):
                        raise ValueError("Source input is not a regular file")
                    result.append(path)
    return sorted(result)


def _source_manifest(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in _source_files(root)
    }


def _snapshot(root: Path, destination: Path) -> dict[str, str]:
    root, destination = root.resolve(), destination.resolve()
    if destination.is_relative_to(root) or root.is_relative_to(destination):
        raise ValueError("Source and snapshot destination must not overlap")
    destination.mkdir(mode=0o700)
    manifest = _source_manifest(root)
    for relative, digest in manifest.items():
        source = root / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Candidate changed while snapshotting")
        target.write_bytes(data)
    if _source_manifest(root) != manifest:
        raise ValueError("Candidate changed while snapshotting")
    return manifest


def _environment(root: Path, temporary: Path) -> dict[str, str]:
    # No real OAuth keys, provider credentials, proxy settings or user pip config.
    home = temporary / "home"
    scratch = temporary / "tmp"
    home.mkdir(mode=0o700, exist_ok=True)
    scratch.mkdir(mode=0o700, exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(home), "TMPDIR": str(scratch),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONPATH": str(root / "src"),
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "NO_PROXY": "127.0.0.1,localhost,::1",
    }


def _stop_owned_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)


def _command(
    name: str, argv: list[str], *, cwd: Path, environment: dict[str, str],
    evidence: Path, timeout: int,
) -> dict[str, Any]:
    stdout = evidence / f"{name}.stdout.log"
    stderr = evidence / f"{name}.stderr.log"
    gate: dict[str, Any] = {
        "name": name, "status": "blocked", "command": argv, "cwd": str(cwd),
        "stdout": str(stdout), "stderr": str(stderr), "exit_code": None,
    }
    with stdout.open("wb") as out, stderr.open("wb") as err:
        try:
            process = subprocess.Popen(
                argv, cwd=cwd, env=environment, stdout=out, stderr=err,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            gate["reason"] = f"Cannot start command: {type(exc).__name__}"
            return gate
        try:
            gate["exit_code"] = process.wait(timeout=timeout)
            gate["status"] = "passed" if gate["exit_code"] == 0 else "failed"
        except subprocess.TimeoutExpired:
            gate["reason"] = f"Command exceeded {timeout} seconds"
            _stop_owned_process(process)
            gate["exit_code"] = process.returncode
            gate["status"] = "failed"
        except BaseException:
            _stop_owned_process(process)
            raise
    return gate


def _finish(report: dict[str, Any]) -> int:
    statuses = [gate["status"] for gate in report["gates"]]
    failed = any(s in {"failed", "blocked"} for s in statuses)
    report["machine_gates_passed"] = all(
        gate["status"] == "passed" for gate in report["gates"] if gate["name"] not in MANUAL_GATES
    )
    report["release_ready"] = bool(statuses) and all(s == "passed" for s in statuses)
    report["exit_code"] = (
        1 if failed else 0 if report["release_ready"] else 2
    )
    return report["exit_code"]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _workflow_fixture(
    application: Any, *, required: bool, owner_id: str,
    transport: Callable[[str, dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Synthetic proof through OAuth-authenticated MCP HTTP and the real workflow."""
    exercised: set[str] = set()

    def call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        exercised.add(name)
        result = transport(name, arguments)
        payload = result["structuredContent"]
        if result.get("isError"):
            code = payload.get("error", {}).get("code", "TOOL_ERROR")
            raise RuntimeError(f"{name} refused: {code}")
        return payload

    project = call("rethlas_control", {"action": "project_create", "title": "Release fixture"})["project"]
    created = call("rethlas_control", {
        "action": "claim_create", "project_id": project["project_id"],
        "title": "Reflexivity", "statement_tex": "$1=1$.",
    })
    claim_id = created["claim"]["claim_id"]
    start = call("rethlas_start", {
        "problem_tex": "Prove $1=1$.", "workflow_mode": "compact",
        "project_id": project["project_id"], "target_claim_id": claim_id,
        "creation_key": "release-fixture-" + secrets.token_hex(12),
    })
    run_id = start["run_id"]
    assess = call("rethlas_step", {"run_id": run_id})
    assembled = call("rethlas_step", {
        "run_id": run_id, "capability": assess["capability"],
        **assess["task"]["minimal_submission"],
    })
    _require(assembled["state"] == "assemble", "Compact fixture did not reach assembly")
    verify = call("rethlas_step", {
        "run_id": run_id, "capability": assembled["capability"],
        "action": "proof_submitted", "payload": {"outcome": "proof"},
        "writes": [
            {"resource": "proof", "content": PROOF},
            {"resource": "proof_manifest", "content": {
                "target_statement_tex": "$1=1$.", "dependency_revision_ids": [],
                "reference_ids": [], "conditional_hypotheses": [], "computational_evidence": [],
            }},
        ],
    })
    run = application.state_store.get_run(run_id)
    latex = run["metadata"].get("latex_result", {})
    _require(application.tools.workflow_protocol_version == 3, "Fixture is not protocol 3")
    _require(verify["state"] == "verify", "LaTeX gate did not permit independent verification")
    if required:
        _require(
            latex.get("policy") == "required"
            and all(latex.get(key) is True for key in (
                "static_valid", "compile_available", "compile_attempted", "compile_passed", "gate_passed",
            )), "Actual required isolated LaTeX compilation is missing",
        )
    _require("mathematical_research_state" not in verify["context"], "Verifier advisory isolation failed")
    done = call("rethlas_step", {
        "run_id": run_id, "capability": verify["capability"],
        **verify["task"]["minimal_submission"],
    })
    _require(done["state"] == "done", "Mechanical finalizer did not complete")
    status = call("rethlas_inspect", {"operation": "status", "run_id": run_id})
    _require(status.get("state") == "done", "HTTP inspect did not observe terminal state")
    call("rethlas_artifact", {"action": "get", "artifact": "final_tex", "run_id": run_id})
    export_path = application.settings.workspace / done["workspace_export_path"]
    _require(export_path.is_relative_to(application.settings.workspace), "Invalid export path")
    content = export_path.read_bytes()
    _require(content == PROOF.encode(), "Export bytes differ from approved synthetic proof")
    before = export_path.stat().st_mtime_ns
    replay = call("rethlas_step", {"run_id": run_id})
    _require(replay["state"] == "done", "Terminal reconnect failed")
    _require(export_path.read_bytes() == content and export_path.stat().st_mtime_ns == before,
             "Terminal replay changed finalized output")
    revision = application.state_store.current_claim_revision(claim_id, owner_id=owner_id)
    _require(revision["evidence_status"] == "VERIFIED" and bool(revision["fact_id"]),
             "Finalizer did not promote a protocol-3 fact")
    facts = application.state_store.list_project_facts(project["project_id"], owner_id=owner_id)
    _require(len(facts) == 1, "Terminal replay duplicated a fact")
    return {
        "passed": True, "transport": "oauth_authenticated_mcp_http", "tools_exercised": sorted(exercised),
        "workflow_protocol": application.tools.workflow_protocol_version,
        "state_schema": application.state_store.schema_version(), "terminal_state": done["state"],
        "latex": {key: latex.get(key) for key in (
            "policy", "static_valid", "compile_available", "compile_attempted", "compile_passed", "gate_passed",
        )},
        "final_sha256": hashlib.sha256(content).hexdigest(),
        "final_bytes": len(content), "terminal_replay_unchanged": True,
        "verified_fact_count": len(facts),
        "scope": "Synthetic procedural fixture; no independent model or mathematical-quality acceptance.",
    }


def _fixture(output: Path, *, control_plane_only: bool) -> int:
    output = output.absolute()
    if output.exists() or output.is_symlink() or any(path.is_symlink() for path in output.parents):
        raise ValueError("Fixture evidence must be a new file under nonsymlinked parents")
    if not output.parent.is_dir() or output.with_name("oauth-mcp-smoke.json").exists():
        raise ValueError("Fixture evidence requires a fresh evidence directory")
    # This subprocess receives an allowlisted environment and creates all credentials
    # in memory. The HTTP server binds directly to port zero, avoiding free-port races.
    sys.path.insert(0, str(ROOT / "src"))
    from re_ctm.app import build_application
    from re_ctm.config import Settings
    from re_ctm.enums import LatexPolicy
    from re_ctm.server import ReCTMHTTPServer

    payload: dict[str, Any] = {
        "passed": False, "fixture": "control_plane_only" if control_plane_only else "required_target",
        "real_browser_validated": False, "external_retrieval_validated": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="re-ctm-fixture-") as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            password = secrets.token_urlsafe(32)
            settings = Settings(
                workspace=workspace, data_root=root / "data", private_root=root / "private",
                debug_root=root / "debug",
                native_exec_backend="disabled" if control_plane_only else "bubblewrap",
                latex_policy=LatexPolicy.STATIC_ONLY if control_plane_only else LatexPolicy.REQUIRED,
                oauth_password=password, token_secret=secrets.token_bytes(32),
                capability_secret=secrets.token_bytes(32), workflow_protocol_version=3,
            )
            application = build_application(settings)
            server = None
            thread = None
            try:
                server = ReCTMHTTPServer(("127.0.0.1", 0), application, access_log_enabled=False)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                spec = importlib.util.spec_from_file_location("release_smoke", ROOT / "scripts/smoke_oauth_mcp.py")
                assert spec is not None and spec.loader is not None
                smoke = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(smoke)
                smoke_path = output.with_name("oauth-mcp-smoke.json")
                def exercise(base: str, access_token: str, client_id: str) -> dict[str, Any]:
                    sequence = 100

                    def transport(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
                        nonlocal sequence
                        sequence += 1
                        response = smoke._mcp(base, access_token, {
                            "jsonrpc": "2.0", "id": sequence, "method": "tools/call",
                            "params": {"name": name, "arguments": arguments},
                        }, timeout=180 if not control_plane_only else 10)
                        if response.get("error") or not isinstance(response.get("result"), dict):
                            raise RuntimeError("Authenticated workflow MCP call failed")
                        return response["result"]

                    result = _workflow_fixture(
                        application, required=not control_plane_only, owner_id=client_id, transport=transport,
                    )
                    payload["workflow"] = result
                    return result

                smoke_exit = smoke.main([
                    "--base-url", f"http://127.0.0.1:{server.server_address[1]}",
                    "--output", str(smoke_path), "--timeout", "10",
                ], password=password, exercise=exercise)
                payload["oauth_mcp"] = {"passed": smoke_exit == 0, "report": str(smoke_path)}
                payload["passed"] = smoke_exit == 0 and payload.get("workflow", {}).get("passed") is True
            finally:
                if server is not None:
                    if thread is not None and thread.is_alive():
                        server.shutdown()
                    server.server_close()
                else:
                    application.close()
                if thread is not None:
                    thread.join(timeout=5)
    except Exception as exc:  # boundary: never dump a capability-bearing result or traceback
        payload["error"] = {"type": type(exc).__name__, "code": getattr(exc, "code", "FIXTURE_FAILED")}
    _json(output, payload)
    print(json.dumps({"passed": payload["passed"], "report": str(output)}))
    return 0 if payload["passed"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-plane-only", action="store_true",
                        help="Diagnostic only: omit physical isolation/LaTeX/full aggregate; release stays pending.")
    parser.add_argument("--timeout", type=int, default=1800, help="Maximum seconds per subprocess (default 1800).")
    parser.add_argument("--fixture-child", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    if args.fixture_child is not None:
        return _fixture(args.fixture_child, control_plane_only=args.control_plane_only)

    evidence_root = ROOT / ".release-validation"
    if evidence_root.is_symlink():
        parser.error(".release-validation must not be a symlink")
    evidence_root.mkdir(mode=0o700, exist_ok=True)
    evidence = evidence_root / (
        "host-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    )
    evidence.mkdir(mode=0o700)
    report: dict[str, Any] = {
        "schema_version": "1.0.0", "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(ROOT), "evidence_directory": str(evidence),
        "mode": "control_plane_only" if args.control_plane_only else "strict_target",
        "release_ready": False, "gates": [],
        "scope": "Offline disposable candidate deployment; no production state, browser, public ingress or release.",
        "exit_codes": {"0": "all gates passed", "1": "machine failure/blocker", "2": "manual or omitted gates pending"},
    }
    manifest = None
    try:
        with tempfile.TemporaryDirectory(prefix="re-ctm-release-target-") as directory:
            temporary = Path(directory)
            candidate = temporary / "candidate"
            manifest = _snapshot(ROOT, candidate)
            _json(evidence / "source-manifest.json", manifest)
            report["source_manifest_sha256"] = hashlib.sha256(
                json.dumps(manifest, sort_keys=True).encode()
            ).hexdigest()
            environment = _environment(candidate, temporary)

            def run(name: str, command: list[str]) -> None:
                report["gates"].append(_command(
                    name, command, cwd=candidate, environment=environment,
                    evidence=evidence, timeout=args.timeout,
                ))

            if args.control_plane_only:
                for name in ("full_local_checks", "native_isolation", "required_latex"):
                    report["gates"].append({
                        "name": name, "status": "manual_pending",
                        "reason": "Explicit control-plane diagnostic omits this physical target gate.",
                    })
            else:
                local_report = candidate / "local-validation.json"
                previous_report = local_report.read_bytes() if local_report.exists() else None
                run("full_local_checks", [sys.executable, "scripts/run_local_checks.py"])
                if local_report.exists() and local_report.read_bytes() != previous_report:
                    shutil.copyfile(local_report, evidence / "local-validation.json")
                elif report["gates"][-1]["status"] == "passed":
                    report["gates"][-1].update(status="failed", reason="Aggregate produced no fresh report")
                workspace = temporary / "native-workspace"
                workspace.mkdir()
                run("native_isolation", [
                    sys.executable, "scripts/manual_native_isolation_test.py", "--backend", "bubblewrap",
                    "--workspace", str(workspace), "--data-root", str(temporary / "native-data"),
                    "--private-root", str(temporary / "native-private"),
                    "--output", str(evidence / "native-isolation.json"),
                ])
            run("offline_package", [
                sys.executable, "scripts/release_package_checks.py", "--repo", str(candidate),
                "--output-dir", str(evidence / "package"),
            ])
            fixture = [sys.executable, "scripts/release_target_checks.py",
                       "--fixture-child", str(evidence / "runtime-fixture.json")]
            if args.control_plane_only:
                fixture.append("--control-plane-only")
            run("control_plane_fixture" if args.control_plane_only else "required_runtime_fixture", fixture)
    except Exception as exc:
        report["gates"].append({
            "name": "driver", "status": "blocked",
            "reason": type(exc).__name__, "code": getattr(exc, "code", "DRIVER_BLOCKED"),
        })
    finally:
        if manifest is not None:
            try:
                unchanged = _source_manifest(ROOT) == manifest
            except (OSError, ValueError):
                unchanged = False
            report["gates"].append({
                "name": "source_unchanged", "status": "passed" if unchanged else "failed",
            })
        report["gates"].extend(
            {"name": name, "status": "manual_pending", "reason": reason}
            for name, reason in MANUAL_GATES.items()
        )
        exit_code = _finish(report)
        _json(evidence / "report.json", report)
        print(json.dumps({
            "machine_gates_passed": report["machine_gates_passed"], "release_ready": report["release_ready"],
            "exit_code": exit_code, "report": str(evidence / "report.json"),
        }, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
