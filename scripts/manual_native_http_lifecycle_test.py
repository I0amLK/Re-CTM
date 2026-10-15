#!/usr/bin/env python3
"""Normal-host, real OAuth/HTTP/bwrap validation using disposable private state.

Run with the official host Python, outside an already sandboxed connector:
  /path/to/candidate/venv/bin/python -I -B scripts/manual_native_http_lifecycle_test.py --output /tmp/lifecycle.json

This never targets an installed/running service. Bubblewrap startup attestation
is mandatory. A nested-namespace denial is a failed check, never a reason to
disable isolation. The report is candidate-specific and does not claim browser,
LaTeX, mathematical-workflow, or general release acceptance.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from typing import Any
import urllib.parse


SERVER_CHILD = """
import hashlib, importlib.metadata, json, os, secrets, sys, traceback
from dataclasses import replace
from pathlib import Path
ready = Path(sys.argv[1])
stage = "import_candidate"
application = server = None
try:
    import re_ctm
    from re_ctm.app import build_application
    from re_ctm.config import Settings
    from re_ctm.server import ReCTMHTTPServer
    expected = Path(re_ctm.__file__).resolve().parent
    assert expected.is_relative_to(Path(sys.prefix).resolve()), "Package must be installed under candidate prefix"
    stage = "settings"
    settings = replace(Settings.from_env(), token_secret=secrets.token_bytes(32),
                       capability_secret=secrets.token_bytes(32))
    assert settings.native_exec_backend == "bubblewrap"
    stage = "build_application_and_attest"
    application = build_application(settings)
    stage = "bind_http"
    server = ReCTMHTTPServer(("127.0.0.1", 0), application, access_log_enabled=False)
    stage = "candidate_metadata"
    modules = {}
    for name, module in sorted(sys.modules.items()):
        if name == "re_ctm" or name.startswith("re_ctm."):
            path = Path(module.__file__).resolve()
            assert path.is_relative_to(expected), (name, str(path))
            modules[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    staged_ready = ready.with_suffix(".tmp")
    staged_ready.write_text(json.dumps({
        "port": server.server_address[1], "modules": modules,
        "package_identity": {"python_executable": sys.executable, "sys_prefix": sys.prefix,
                             "re_ctm_file": str(Path(re_ctm.__file__).resolve()),
                             "version": importlib.metadata.version("re-ctm")},
        "native": application.native.server_info(),
    }), encoding="utf-8")
    staged_ready.replace(ready)
    stage = "serve_http"
    try:
        server.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
except Exception as exc:
    # Persist only structural diagnostics before the temporary process exits.
    # Never serialize exception messages, locals, settings, logs or credentials.
    code = getattr(exc, "code", None)
    allowed_codes = {
        "CAPABILITY_SECRET_REQUIRED", "OAUTH_TOKEN_SECRET_REQUIRED", "OAUTH_PASSWORD_REQUIRED",
        "INVALID_SECRET", "INVALID_WORKSPACE", "UNSAFE_WORKSPACE", "TRUST_DOMAIN_OVERLAP",
        "INVALID_NATIVE_MODE", "INVALID_NATIVE_EXEC_BACKEND", "NATIVE_ISOLATION_REQUIRED",
        "NATIVE_BWRAP_NOT_FOUND", "NATIVE_TOOLCHAIN_ROOT_DENIED",
        "NATIVE_HELPER_REQUIRED", "NATIVE_HELPER_DENIED", "NATIVE_HELPER_INTERNAL_ERROR",
        "NATIVE_HELPER_ATTESTATION_FAILED", "NATIVE_HELPER_ATTESTATION_INVALID",
        "NATIVE_HELPER_PROTOCOL_ERROR", "NATIVE_HELPER_OUTPUT_TOO_LARGE",
        "NATIVE_HELPER_INVALID_ARGUMENT", "NATIVE_HELPER_TRUST_DOMAIN_OVERLAP",
    }
    if not isinstance(code, str) or code not in allowed_codes:
        code = None
    failure = {
        "stage": stage, "error_code": code, "exception_type": type(exc).__name__,
        "traceback_frames": [{"file": Path(frame.filename).name,
                              "function": frame.name, "line": frame.lineno}
                             for frame in traceback.extract_tb(exc.__traceback__)[-8:]],
    }
    staged_error = ready.with_name("startup-error.tmp")
    staged_error.write_text(json.dumps(failure), encoding="utf-8")
    staged_error.replace(ready.with_name("startup-error.json"))
    raise SystemExit(1) from None
finally:
    if server is not None:
        server.server_close()
    elif application is not None:
        application.close()
"""


def _record(report: dict[str, Any], name: str, passed: bool, **details: Any) -> None:
    report["checks"].append({"name": name, "passed": bool(passed), "details": details})


def _request(
    port: int, method: str, path: str, *, data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    # A new closed connection per call reproduces short-lived request threads.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=data, headers={"Connection": "close", **(headers or {})})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read(2 * 1024 * 1024)
    finally:
        connection.close()


def _json_request(port: int, path: str, body: dict[str, Any]) -> dict[str, Any]:
    status, _headers, raw = _request(
        port, "POST", path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    if status not in {200, 201}:
        raise RuntimeError("Unexpected HTTP status " + str(status))
    return json.loads(raw)


def _oauth(port: int, password: str) -> str:
    """Use the product's DCR/S256 PKCE contract, never a manufactured token."""
    resource = f"http://127.0.0.1:{port}/mcp"
    callback = "http://127.0.0.1/callback"
    client = _json_request(port, "/oauth/register", {
        "client_name": "Re-CTM disposable Native lifecycle validation",
        "redirect_uris": [callback], "grant_types": ["authorization_code"],
        "response_types": ["code"], "token_endpoint_auth_method": "none",
    })
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    fields = {
        "client_id": client["client_id"], "redirect_uri": callback, "response_type": "code",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
        "resource": resource, "password": password,
    }
    status, headers, _raw = _request(
        port, "POST", "/oauth/authorize", data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 302:
        raise RuntimeError("OAuth authorization did not redirect")
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["Location"]).query)
    if params.get("state") != [state]:
        raise RuntimeError("OAuth state mismatch")
    status, _headers, raw = _request(
        port, "POST", "/oauth/token",
        data=urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": params["code"][0],
            "redirect_uri": callback, "code_verifier": verifier,
            "client_id": client["client_id"], "resource": resource,
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        raise RuntimeError("OAuth token exchange failed")
    return json.loads(raw)["access_token"]


class StartupFailure(RuntimeError):
    def __init__(self, details: dict[str, Any]) -> None:
        super().__init__("Candidate startup failed; see structural diagnostics")
        self.startup_failure = details


class Session:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.workspace = root / "workspace"
        for name in ("workspace", "home", "tmp", "data"):
            (root / name).mkdir(parents=True)
        self.password = secrets.token_urlsafe(32)
        env = {
            "PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
            "RE_CTM_WORKSPACE": str(self.workspace), "RE_CTM_DATA_ROOT": str(root / "data"),
            "RE_CTM_PRIVATE_ROOT": str(root / "data/private"),
            "RE_CTM_DEBUG_ROOT": str(root / "data/debug"),
            "RE_CTM_NATIVE_MODE": "dangerous", "RE_CTM_NATIVE_EXEC_BACKEND": "bubblewrap",
            "RE_CTM_LATEX_POLICY": "static_only", "RE_CTM_OAUTH_PASSWORD": self.password,
        }
        self.log = (root / "server.log").open("wb")
        self.process = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", SERVER_CHILD, str(root / "ready.json")],
            cwd=self.workspace, env=env, stdin=subprocess.DEVNULL,
            stdout=self.log, stderr=self.log, start_new_session=True,
        )
        self.token = ""
        self.sequence = 0
        self.ready: dict[str, Any] = {}

    def connect(self) -> None:
        deadline = time.monotonic() + 35
        ready = self.root / "ready.json"
        while not ready.exists():
            if self.process.poll() is not None:
                failure = self.root / "startup-error.json"
                details = json.loads(failure.read_text(encoding="utf-8")) if failure.exists() else {
                    "stage": "child_startup", "error_code": None,
                    "exception_type": "UnreportedChildExit", "traceback_frames": [],
                }
                raise StartupFailure({**details, "child_exit_code": self.process.returncode})
            if time.monotonic() >= deadline:
                raise TimeoutError("Candidate startup deadline exceeded")
            time.sleep(0.05)
        self.ready = json.loads(ready.read_text(encoding="utf-8"))
        self.port = self.ready["port"]
        self.token = _oauth(self.port, self.password)

    def tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.sequence += 1
        status, _headers, raw = _request(
            self.port, "POST", "/mcp",
            data=json.dumps({
                "jsonrpc": "2.0", "id": self.sequence, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token},
        )
        if status != 200:
            raise RuntimeError("MCP HTTP status " + str(status))
        response = json.loads(raw)
        result = response.get("result", {})
        structured = result.get("structuredContent")
        if result.get("isError") or not isinstance(structured, dict) or structured.get("ok") is False:
            raise RuntimeError("MCP tool failed: " + name)
        return structured

    def start(self, script: str, **options: Any) -> dict[str, Any]:
        return self.tool("exec_command", {
            "argv": ["/usr/bin/python3", "-I", "-B", "-c", script], "workdir": ".",
            "yield_time_ms": 50, "timeout_ms": 5000, "verbosity": "full", **options,
        })

    def terminal(self, result: dict[str, Any], *, chars: str = "") -> dict[str, Any]:
        deadline = time.monotonic() + 8
        output = result.get("stdout", "")
        while result["operation_outcome"] == "running":
            if time.monotonic() >= deadline:
                raise TimeoutError("Native command terminal deadline exceeded")
            result = self.tool("write_stdin", {
                "command_id": result["command_id"], "chars": chars,
                "yield_time_ms": 100, "verbosity": "full",
            })
            output += result.get("stdout", "")
            chars = ""
            time.sleep(0.02)
        return {**result, "collected_stdout": output}

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.token = ""
        self.password = ""


def _summary(result: dict[str, Any]) -> dict[str, Any]:
    return {key: result.get(key) for key in (
        "operation_outcome", "exit_code", "signal", "timed_out", "elapsed_ms", "termination",
    )}


def _process_identity(pid: int) -> tuple[str, str] | None:
    try:
        tail = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return tail[19], tail[0]  # starttime and state; starttime guards PID reuse.
    except (OSError, IndexError):
        return None


def _descendants(pid: int) -> dict[int, str]:
    found: dict[int, str] = {}
    pending = [pid]
    while pending:
        parent = pending.pop()
        for task in Path(f"/proc/{parent}/task").glob("*"):
            try:
                children = (task / "children").read_text().split()
            except OSError:
                continue
            for raw in children:
                child = int(raw)
                identity = _process_identity(child)
                if identity is not None and child not in found:
                    found[child] = identity[0]
                    pending.append(child)
    return found


def _alive(processes: dict[int, str]) -> list[int]:
    live = []
    for pid, start in processes.items():
        identity = _process_identity(pid)
        if identity is not None and identity[0] == start and identity[1] not in {"Z", "X"}:
            live.append(pid)
    return live


def _exercise(session: Session, report: dict[str, Any]) -> None:
    info = session.tool("server_info", {})["native"]
    attestation = info["native_exec_attestation"]
    required = ("hard_isolation", "workspace_mounted", "forbidden_paths_hidden",
                "no_privilege_escalation", "mount_namespace", "user_namespace", "pid_namespace")
    passed = (info["native_exec_backend"] == "BubblewrapExecBackend"
              and all(attestation.get(key) is True for key in required)
              and attestation.get("private_vault_mounted") is False)
    _record(report, "real_bubblewrap_startup_attestation", passed, attestation=attestation)
    if not passed:
        raise RuntimeError("Mandatory attestation properties missing")

    script = "import time; time.sleep(.6); print('native-complete', flush=True)"
    sync = session.start(script, yield_time_ms=1000)
    _record(report, "synchronous_success",
            sync["operation_outcome"] == "exited_0" and sync["stdout"].strip() == "native-complete",
            result=_summary(sync))
    initial = session.start(script)
    final = session.terminal(initial)
    _record(report, "async_short_yield_success",
            initial["operation_outcome"] == "running" and final["operation_outcome"] == "exited_0"
            and final["collected_stdout"].strip() == "native-complete",
            initial=_summary(initial), final=_summary(final))

    # READY proves bwrap started its payload before the HTTP creator can exit.
    # The release file prevents completion from racing the response boundary.
    initial = session.start(
        "import time\nfrom pathlib import Path\nprint('PARENT-READY',flush=True)\n"
        "while not Path('/workspace/async.release').exists(): time.sleep(.01)\n"
        "print('native-complete',flush=True)\n", yield_time_ms=500,
    )
    armed_before_return = "PARENT-READY" in initial.get("stdout", "")
    time.sleep(0.1)  # Let the closed HTTP handler finish before releasing its child.
    (session.workspace / "async.release").touch()
    final = session.terminal(initial)
    _record(report, "async_success_after_ready_and_http_request_return",
            armed_before_return and initial["operation_outcome"] == "running"
            and final["operation_outcome"] == "exited_0"
            and "native-complete" in final["collected_stdout"],
            ready_in_initial_response=armed_before_return,
            initial=_summary(initial), final=_summary(final))

    initial = session.start("import sys,time; time.sleep(.3); print('INPUT:'+sys.stdin.read())",
                            stdin="one-shot")
    final = session.terminal(initial)
    _record(report, "initial_stdin_after_request_return",
            initial["operation_outcome"] == "running" and final["operation_outcome"] == "exited_0"
            and final["collected_stdout"].strip() == "INPUT:one-shot", result=_summary(final))

    initial = session.start("import sys; print('TTY-READY',flush=True); print('INPUT:'+sys.stdin.readline())",
                            tty=True, yield_time_ms=500)
    # Deliberately write in a separate request after the exec request has closed.
    final = session.terminal(initial, chars="later-input\n")
    _record(report, "tty_stdin_in_later_http_request",
            initial["operation_outcome"] == "running" and final["operation_outcome"] == "exited_0"
            and "TTY-READY" in initial.get("stdout", "")
            and "INPUT:later-input" in final["collected_stdout"], result=_summary(final))

    initial = session.start("import time; print('KILL-READY',flush=True); time.sleep(20)",
                            yield_time_ms=500)
    killed = session.tool("kill_command", {
        "command_id": initial["command_id"], "signal": "KILL",
        "wait_ms": 1000, "kill_wait_ms": 1000, "verbosity": "full",
    })
    _record(report, "explicit_kill",
            initial["operation_outcome"] == "running" and killed["operation_outcome"] == "signal"
            and "KILL-READY" in initial.get("stdout", "")
            and killed["termination"]["source"] == "explicit_kill"
            and killed["termination"]["kill_sent_by_re_ctm"] is True, result=_summary(killed))

    initial = session.start("import time; time.sleep(20)", timeout_ms=400)
    final = session.terminal(initial)
    _record(report, "command_timeout",
            initial["operation_outcome"] == "running" and final["operation_outcome"] == "timeout"
            and final["termination"]["source"] == "command_timeout", result=_summary(final))


def _server_exit(session: Session, report: dict[str, Any], *, abrupt: bool) -> None:
    heartbeat = session.workspace / "heartbeat"
    initial = session.start(
        "import time\nfrom pathlib import Path\np=Path('/workspace/heartbeat')\n"
        "while True:\n p.write_text(str(time.monotonic()))\n time.sleep(.02)\n",
        timeout_ms=15000,
    )
    deadline = time.monotonic() + 3
    while not heartbeat.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    descendants = _descendants(session.process.pid)
    alive_before = _alive(descendants)
    before = heartbeat.read_text() if heartbeat.exists() else None
    time.sleep(0.1)
    progressing = before is not None and heartbeat.read_text() != before
    session.process.send_signal(signal.SIGKILL if abrupt else signal.SIGINT)
    session.process.wait(timeout=5)
    deadline = time.monotonic() + 5
    while _alive(descendants) and time.monotonic() < deadline:
        time.sleep(0.02)
    remaining = _alive(descendants)
    last = heartbeat.read_text() if heartbeat.exists() else None
    time.sleep(0.15)
    stable = last is not None and heartbeat.read_text() == last
    _record(
        report, "abrupt_server_exit_kills_native_descendants" if abrupt else "graceful_server_exit_cleanup",
        initial["operation_outcome"] == "running" and bool(alive_before) and progressing
        and not remaining and stable
        and session.process.returncode == (-signal.SIGKILL if abrupt else 0),
        descendant_count=len(descendants), remaining_process_count=len(remaining),
        heartbeat_progressed_before_exit=progressing, heartbeat_stopped_after_exit=stable,
        server_exit_code=session.process.returncode,
    )
    # Only test-created descendants with the same starttime may need cleanup.
    for pid in remaining:
        identity = _process_identity(pid)
        if identity is not None and identity[0] == descendants[pid]:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("native-http-lifecycle-validation.json"))
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        parser.error("This real Bubblewrap lifecycle harness requires Linux.")
    if not sys.flags.isolated:
        parser.error("Run the installed candidate interpreter with -I -B; source injection is unsupported.")
    output = args.output.expanduser().resolve()
    if output.exists():
        parser.error("--output already exists; choose a fresh report path")
    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Exact-candidate real OAuth HTTP Native lifecycle and mandatory Bubblewrap isolation.",
        "python": sys.executable,
        "not_validated": ["browser interaction", "real LaTeX", "mathematical workflow", "full release"],
        "checks": [], "passed": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="re-ctm-native-http-") as temporary:
            for abrupt in (False, True):
                session = Session(Path(temporary) / ("abrupt" if abrupt else "graceful"))
                try:
                    session.connect()
                    identity = session.ready["package_identity"]
                    modules = session.ready["modules"]
                    if "package_identity" not in report:
                        report["package_identity"] = identity
                        report["candidate_modules"] = modules
                    else:
                        unchanged = (identity == report["package_identity"]
                                     and modules == report["candidate_modules"])
                        _record(report, "candidate_identity_unchanged_between_sessions", unchanged)
                        if not unchanged:
                            raise RuntimeError("Candidate changed between validation sessions")
                    _record(report, "oauth_pkce_abrupt" if abrupt else "oauth_pkce_graceful", True)
                    if not abrupt:
                        _exercise(session, report)
                    _server_exit(session, report, abrupt=abrupt)
                except BaseException:
                    try:
                        session.close()
                    except Exception:
                        report["cleanup_failed"] = True
                    raise
                else:
                    session.close()
    except Exception as exc:  # Boundary report must never include OAuth-bearing exception text.
        _record(report, "validation_blocked_or_failed", False,
                exception_type=type(exc).__name__,
                startup_failure=getattr(exc, "startup_failure", None),
                traceback_frames=[{"file": Path(frame.filename).name,
                                   "function": frame.name, "line": frame.lineno}
                                  for frame in traceback.extract_tb(exc.__traceback__)[-8:]],
                message="Candidate startup, attestation, HTTP, or lifecycle check failed. No isolation fallback was used.")
    report["passed"] = bool(report["checks"]) and all(check["passed"] for check in report["checks"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["passed"], "report": str(output)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
