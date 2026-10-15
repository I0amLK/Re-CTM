"""Linux creator-thread lifetime regressions, without claiming real bwrap isolation."""
from __future__ import annotations

import base64
from contextlib import ExitStack
import hashlib
import http.client
import importlib.util
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from types import SimpleNamespace
from typing import Any
from unittest import mock

from re_ctm.errors import ReCTMError
from re_ctm.processes import CommandManager


PDEATH_CHILD = """
import ctypes, os, signal, sys, time
from pathlib import Path
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_PDEATHSIG failed")
ready, release, operation = sys.argv[1:]
Path(ready).write_text("armed", encoding="ascii")
deadline = time.monotonic() + 10
while not Path(release).exists():
    if time.monotonic() >= deadline:
        raise TimeoutError("test release was not received")
    time.sleep(0.005)
if operation == "stdin":
    print("INPUT:" + sys.stdin.read(), flush=True)
elif operation == "tty":
    print("INPUT:" + sys.stdin.readline().strip(), flush=True)
else:
    print("completed-after-request", flush=True)
"""


@unittest.skipUnless(sys.platform.startswith("linux"), "PR_SET_PDEATHSIG is Linux-specific")
class CommandParentLifetimeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manager = CommandManager()
        self.request_threads: list[threading.Thread] = []
        self.spawns: list[tuple[subprocess.Popen[bytes], threading.Thread]] = []
        self.spawn_attempt_threads: list[threading.Thread] = []
        self.inject_owner_wait_error = False
        self.owner_wait_error_seen = threading.Event()
        original_popen = subprocess.Popen

        def tracked_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            creator = threading.current_thread()
            self.spawn_attempt_threads.append(creator)
            process = original_popen(*args, **kwargs)
            self.spawns.append((process, creator))
            if self.inject_owner_wait_error:
                original_wait = process.wait
                ready = Path(args[0][-3])

                def wait_once(*wait_args: Any, **wait_kwargs: Any) -> int:
                    if (threading.current_thread() is creator
                            and not self.owner_wait_error_seen.is_set()):
                        # Arm PDEATHSIG before injecting an observation error;
                        # otherwise an early creator exit could be a false pass.
                        deadline = time.monotonic() + 3
                        while not ready.exists() and time.monotonic() < deadline:
                            time.sleep(0.005)
                        if not ready.exists():
                            raise TimeoutError("child did not arm before injected wait error")
                        self.owner_wait_error_seen.set()
                        raise OSError("injected first owner wait failure")
                    return original_wait(*wait_args, **wait_kwargs)

                process.wait = wait_once
            return process

        self.popen_patch = mock.patch("re_ctm.processes.subprocess.Popen", side_effect=tracked_popen)
        self.popen_patch.start()
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                fixture.request_threads.append(threading.current_thread())
                arguments = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                try:
                    ready = arguments.pop("ready", None)
                    result = fixture.manager.start(**arguments)
                    if ready is not None:
                        deadline = time.monotonic() + 3
                        while not Path(ready).exists():
                            if time.monotonic() >= deadline:
                                raise TimeoutError("PDEATHSIG child did not arm")
                            time.sleep(0.005)
                except Exception as exc:  # HTTP boundary preserves the original exception type.
                    result = {"error_type": type(exc).__name__}
                data = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True,
        )
        self.server_thread.start()

    def tearDown(self) -> None:
        self.manager.close()
        for process, creator in self.spawns:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            if creator is not threading.current_thread():
                creator.join(timeout=2)
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)
        self.popen_patch.stop()
        self.temporary.cleanup()

    def _options(self, command: list[str], **overrides: Any) -> dict[str, Any]:
        return {
            "command_argv": command, "env": os.environ.copy(), "timeout_ms": 5000,
            "yield_time_ms": 0, "max_output_bytes": 4096, "stdin_text": "",
            "tty": False, "verbosity": "full", "preview_bytes": 1024, **overrides,
        }

    def _request(self, arguments: dict[str, Any]) -> dict[str, Any]:
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.request("POST", "/", json.dumps(arguments),
                               {"Content-Type": "application/json", "Connection": "close"})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            result = json.loads(response.read())
        finally:
            connection.close()
        request_thread = self.request_threads[-1]
        request_thread.join(timeout=3)
        self.assertFalse(request_thread.is_alive(), "HTTP handler must really have returned")
        return result

    def _start(self, operation: str = "complete", **options: Any) -> tuple[dict[str, Any], Path]:
        stem = str(len(self.spawns))
        ready, release = self.root / (stem + ".ready"), self.root / (stem + ".release")
        command = [sys.executable, "-I", "-B", "-c", PDEATH_CHILD,
                   str(ready), str(release), operation]
        started = self._request(self._options(command, ready=str(ready), **options))
        self.assertNotIn("error_type", started)
        self.assertEqual(ready.read_text(encoding="ascii"), "armed")
        return started, release

    def _terminal(self, command_id: str, *, chars: str = "") -> dict[str, Any]:
        deadline = time.monotonic() + 4
        while True:
            result = self.manager.poll(
                command_id, chars=chars, yield_time_ms=50, max_output_bytes=4096,
                verbosity="full", preview_bytes=1024,
            )
            chars = ""
            if result["operation_outcome"] != "running":
                return result
            self.assertLess(time.monotonic(), deadline, "command did not reach terminal state")
            time.sleep(0.01)

    def _assert_creator_finished(self) -> None:
        for _process, creator in self.spawns:
            creator.join(timeout=2)
            self.assertFalse(creator.is_alive(), "creator thread leaked after child exit")

    def test_async_child_survives_completed_http_request(self) -> None:
        started, release = self._start()
        self.assertEqual(started["operation_outcome"], "running")
        release.touch()
        result = self._terminal(started["command_id"])
        self.assertEqual(result["operation_outcome"], "exited_0", result)
        self.assertEqual(result["stdout"].strip(), "completed-after-request")
        self.assertIsNot(self.spawns[0][1], self.request_threads[0])
        self._assert_creator_finished()

    def test_stdin_survives_completed_http_request(self) -> None:
        started, release = self._start("stdin", stdin_text="one-shot-input")
        release.touch()
        result = self._terminal(started["command_id"])
        self.assertEqual(result["operation_outcome"], "exited_0", result)
        self.assertEqual(result["stdout"].strip(), "INPUT:one-shot-input")
        self._assert_creator_finished()

    def test_tty_write_after_request_thread_exits(self) -> None:
        started, release = self._start("tty", tty=True)
        release.touch()
        result = self._terminal(started["command_id"], chars="later-input\n")
        self.assertEqual(result["operation_outcome"], "exited_0", result)
        output = self.manager.read_output(
            started["output_refs"]["stdout"], stream=None, offset=0, limit=4096,
        )
        self.assertIn("INPUT:later-input", output["content"])
        self._assert_creator_finished()

    def test_explicit_kill_retains_lifecycle_and_releases_creator(self) -> None:
        started, _release = self._start()
        result = self.manager.kill(
            started["command_id"], signal_name="KILL", wait_ms=1000, kill_wait_ms=1000,
            max_output_bytes=4096, verbosity="full", preview_bytes=1024,
        )
        self.assertEqual(result["operation_outcome"], "signal", result)
        self.assertEqual(result["termination"]["source"], "explicit_kill")
        self.assertTrue(result["termination"]["kill_sent_by_re_ctm"])
        self._assert_creator_finished()

    def test_timeout_survives_request_and_releases_creator(self) -> None:
        started, _release = self._start(timeout_ms=300)
        result = self._terminal(started["command_id"])
        self.assertEqual(result["operation_outcome"], "timeout", result)
        self.assertEqual(result["termination"]["source"], "command_timeout")
        self.assertTrue(result["timed_out"])
        self._assert_creator_finished()

    def test_manager_close_terminates_active_child_and_rejects_new_start(self) -> None:
        started, _release = self._start()
        self.manager.close()
        result = self._terminal(started["command_id"])
        self.assertEqual(result["operation_outcome"], "signal", result)
        self.assertEqual(result["termination"]["source"], "parent_shutdown")
        self._assert_creator_finished()
        with self.assertRaises(ReCTMError) as closed:
            self.manager.start(**self._options(["/bin/true"]))
        self.assertEqual(closed.exception.code, "COMMAND_CLOSED")

    def test_original_spawn_failure_propagates_without_creator_leak(self) -> None:
        result = self._request(self._options([str(self.root / "missing-executable")]))
        self.assertEqual(result, {"error_type": "FileNotFoundError"})
        self.assertFalse(self.manager.active)
        self.assertFalse(self.manager.retained)
        for thread in self.spawn_attempt_threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_sync_completion_preserves_output(self) -> None:
        result = self._request(self._options(
            [sys.executable, "-I", "-B", "-c", "print('synchronous-output')"],
            yield_time_ms=1000,
        ))
        self.assertEqual(result["operation_outcome"], "exited_0", result)
        self.assertEqual(result["stdout"].strip(), "synchronous-output")
        self._assert_creator_finished()


    def test_owner_wait_error_does_not_abandon_live_pdeath_child(self) -> None:
        self.inject_owner_wait_error = True
        started, release = self._start()
        self.assertTrue(self.owner_wait_error_seen.wait(timeout=2))
        release.touch()
        result = self._terminal(started["command_id"])
        self.assertEqual(result["operation_outcome"], "exited_0", result)
        self.assertEqual(result["stdout"].strip(), "completed-after-request")
        self._assert_creator_finished()

    def test_owner_thread_start_failure_propagates_without_hanging_or_spawning(self) -> None:
        original_start = threading.Thread.start

        def start(thread: threading.Thread) -> None:
            if thread.name == "re-ctm-command-owner":
                raise RuntimeError("injected owner Thread.start failure")
            original_start(thread)

        with mock.patch("re_ctm.processes.threading.Thread.start", start):
            result = self._request(self._options(["/bin/true"]))
        self.assertEqual(result, {"error_type": "RuntimeError"})
        self.assertEqual(self.spawn_attempt_threads, [])
        self.assertFalse(self.manager.active)
        self.assertFalse(self.manager.retained)

    def test_close_cannot_miss_an_inflight_spawn(self) -> None:
        from re_ctm.processes import spawn_process

        spawning = threading.Event()
        release = threading.Event()
        closing = threading.Event()
        results: list[dict[str, Any]] = []
        errors: list[Exception] = []

        def blocked_spawn(*args: Any, **kwargs: Any) -> Any:
            spawning.set()
            if not release.wait(timeout=3):
                raise TimeoutError("spawn test release missing")
            return spawn_process(*args, **kwargs)

        def start() -> None:
            try:
                results.append(self.manager.start(**self._options(["/bin/sleep", "10"])))
            except Exception as exc:
                errors.append(exc)

        def close() -> None:
            closing.set()
            self.manager.close()

        starter = threading.Thread(target=start)
        closer = threading.Thread(target=close)
        with mock.patch("re_ctm.processes.spawn_process", side_effect=blocked_spawn):
            starter.start()
            try:
                self.assertTrue(spawning.wait(timeout=2))
                closer.start()
                self.assertTrue(closing.wait(timeout=2))
                time.sleep(0.03)
            finally:
                release.set()
                starter.join(timeout=3)
                if closer.ident is not None:
                    closer.join(timeout=3)
        self.assertFalse(starter.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertFalse(errors)
        self.assertEqual(len(results), 1)
        self.assertTrue(self.manager.closed)
        result = self._terminal(results[0]["command_id"])
        self.assertEqual(result["termination"]["source"], "parent_shutdown", result)
        self._assert_creator_finished()

    def test_concurrent_start_respects_active_capacity(self) -> None:
        from re_ctm.processes import spawn_process

        spawning = threading.Event()
        release = threading.Event()
        second_started = threading.Event()
        results: list[dict[str, Any]] = []
        errors: list[Exception] = []

        def blocked_spawn(*args: Any, **kwargs: Any) -> Any:
            spawning.set()
            if not release.wait(timeout=3):
                raise TimeoutError("capacity test release missing")
            return spawn_process(*args, **kwargs)

        def start(*, second: bool = False) -> None:
            if second:
                second_started.set()
            try:
                results.append(self.manager.start(**self._options(["/bin/sleep", "10"])))
            except Exception as exc:
                errors.append(exc)

        first = threading.Thread(target=start)
        second = threading.Thread(target=start, kwargs={"second": True})
        with mock.patch("re_ctm.processes.MAX_ACTIVE_COMMANDS", 1), mock.patch(
            "re_ctm.processes.spawn_process", side_effect=blocked_spawn,
        ):
            first.start()
            try:
                self.assertTrue(spawning.wait(timeout=2))
                second.start()
                self.assertTrue(second_started.wait(timeout=2))
                time.sleep(0.03)
            finally:
                release.set()
                first.join(timeout=3)
                if second.ident is not None:
                    second.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ReCTMError)
        self.assertEqual(errors[0].code, "COMMAND_LIMIT_REACHED")
        self.assertEqual(len(self.spawns), 1)
        self.assertEqual(len(self.manager.active), 1)
        self.manager.close()
        self._terminal(results[0]["command_id"])
        self._assert_creator_finished()


class NativeHTTPLifecycleHarnessTestCase(unittest.TestCase):
    """Contract tests only; these do not claim installed-host/bwrap acceptance."""

    @classmethod
    def setUpClass(cls) -> None:
        path = Path(__file__).resolve().parents[1] / "scripts/manual_native_http_lifecycle_test.py"
        spec = importlib.util.spec_from_file_location("native_http_lifecycle_harness_test", path)
        assert spec is not None and spec.loader is not None
        cls.harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.harness)

    def test_server_bootstrap_compiles_without_source_path_injection(self) -> None:
        compile(self.harness.SERVER_CHILD, "<native-http-server-child>", "exec")
        self.assertNotIn("sys.path", self.harness.SERVER_CHILD)
        self.assertIn('settings.native_exec_backend == "bubblewrap"', self.harness.SERVER_CHILD)
        self.assertIn("build_application(settings)", self.harness.SERVER_CHILD)

    def test_oauth_exchange_uses_s256_and_matching_resource(self) -> None:
        forms: list[dict[str, list[str]]] = []

        def request(port: int, method: str, path: str, **kwargs: Any) -> Any:
            self.assertEqual((port, method), (12345, "POST"))
            fields = urllib.parse.parse_qs(kwargs["data"].decode())
            forms.append(fields)
            if path == "/oauth/authorize":
                return 302, {"Location": "http://127.0.0.1/callback?" + urllib.parse.urlencode({
                    "state": fields["state"][0], "code": "ephemeral-test-code",
                })}, b""
            self.assertEqual(path, "/oauth/token")
            return 200, {}, b'{"access_token":"ephemeral-test-token"}'

        with mock.patch.object(self.harness, "_json_request", return_value={"client_id": "test-client"}), \
                mock.patch.object(self.harness, "_request", side_effect=request):
            token = self.harness._oauth(12345, "test-only-authorization-key")
        self.assertEqual(token, "ephemeral-test-token")
        authorization, exchange = forms
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(exchange["code_verifier"][0].encode()).digest(),
        ).rstrip(b"=").decode()
        self.assertEqual(authorization["code_challenge"], [challenge])
        self.assertEqual(authorization["code_challenge_method"], ["S256"])
        self.assertEqual(authorization["resource"], ["http://127.0.0.1:12345/mcp"])
        self.assertEqual(exchange["resource"], authorization["resource"])
        self.assertNotIn("password", exchange)

    def test_mcp_tool_rejects_errors_and_retains_structured_content(self) -> None:
        session = self.harness.Session.__new__(self.harness.Session)
        session.port, session.sequence, session.token = 12345, 0, "test-token"
        for response in (
            {"result": {"isError": True, "structuredContent": {"ok": False}}},
            {"error": {"code": -32603}},
            {"result": {"structuredContent": {"ok": False}}},
        ):
            with self.subTest(response=response), mock.patch.object(
                self.harness, "_request", return_value=(200, {}, json.dumps(response).encode()),
            ):
                with self.assertRaises(RuntimeError):
                    session.tool("server_info", {})
        expected = {"ok": True, "status": "running"}
        with mock.patch.object(self.harness, "_request", return_value=(
            200, {}, json.dumps({"result": {"structuredContent": expected}}).encode(),
        )):
            self.assertEqual(session.tool("server_info", {}), expected)

    def test_terminal_aggregates_output_and_sends_stdin_once(self) -> None:
        session = self.harness.Session.__new__(self.harness.Session)
        session.tool = mock.Mock(side_effect=[
            {"command_id": "test", "operation_outcome": "running", "stdout": "middle"},
            {"command_id": "test", "operation_outcome": "exited_0", "stdout": "end"},
        ])
        initial = {"command_id": "test", "operation_outcome": "running", "stdout": "begin"}
        result = session.terminal(initial, chars="input\n")
        self.assertEqual(result["collected_stdout"], "beginmiddleend")
        self.assertEqual(session.tool.call_args_list[0].args[1]["chars"], "input\n")
        self.assertEqual(session.tool.call_args_list[1].args[1]["chars"], "")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux /proc fixture")
    def test_process_identity_guards_pid_reuse(self) -> None:
        identity = self.harness._process_identity(os.getpid())
        self.assertIsNotNone(identity)
        self.assertEqual(self.harness._alive({os.getpid(): identity[0]}), [os.getpid()])
        self.assertEqual(self.harness._alive({os.getpid(): "not-the-same-starttime"}), [])

    def test_failure_report_never_contains_exception_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            fake_sys = SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=1),
                                       executable="/candidate/venv/bin/python")
            with mock.patch.object(self.harness, "sys", fake_sys), \
                    mock.patch.object(self.harness, "Session",
                                      side_effect=RuntimeError("SENSITIVE-EXCEPTION-TEXT")), \
                    mock.patch("builtins.print"):
                self.assertEqual(self.harness.main(["--output", str(output)]), 1)
            raw = output.read_text()
            report = json.loads(raw)
            self.assertFalse(report["passed"])
            self.assertNotIn("SENSITIVE-EXCEPTION-TEXT", raw)
            self.assertEqual(report["checks"][0]["name"], "validation_blocked_or_failed")
            frames = report["checks"][0]["details"]["traceback_frames"]
            self.assertTrue(frames)
            self.assertTrue(all(set(frame) == {"file", "function", "line"} for frame in frames))
            self.assertTrue(all("/" not in frame["file"] for frame in frames))


    def _bootstrap_fixture(
        self, root: Path, *, startup_error: Exception | None = None,
    ) -> dict[str, Any]:
        """Run the exact bootstrap with real app/OAuth/HTTP and a test-only backend.

        The fixture never spawns bwrap. Native command construction still passes
        product validation, then only this test maps its two sandbox file paths
        to this test's temporary workspace and runs the ordinary Python child.
        """
        import importlib.metadata
        import re_ctm
        import re_ctm.app
        import re_ctm.native
        import re_ctm.server

        workspace = root / "workspace"
        workspace.mkdir()
        ready = root / "ready.json"
        environment = {
            "PATH": os.defpath, "HOME": str(root / "home"), "TMPDIR": str(root),
            "RE_CTM_WORKSPACE": str(workspace), "RE_CTM_DATA_ROOT": str(root / "data"),
            "RE_CTM_PRIVATE_ROOT": str(root / "data/private"),
            "RE_CTM_DEBUG_ROOT": str(root / "data/debug"),
            "RE_CTM_NATIVE_EXEC_BACKEND": "bubblewrap", "RE_CTM_NATIVE_MODE": "dangerous",
            "RE_CTM_LATEX_POLICY": "static_only", "RE_CTM_OAUTH_PASSWORD": "fixture-password",
        }
        captured: dict[str, Any] = {"report": {"checks": []}}
        original_build = re_ctm.app.build_application
        original_serve = re_ctm.server.ReCTMHTTPServer.serve_forever

        def build(settings: Any) -> Any:
            captured["settings"] = settings
            if startup_error is not None:
                raise startup_error
            application = original_build(settings)
            captured["application"] = application
            return application

        def attest(backend: Any, **kwargs: Any) -> dict[str, Any]:
            backend.forbidden_paths = tuple(kwargs["forbidden_paths"])
            backend.attestation = {
                "backend": "bubblewrap", "hard_isolation": True, "workspace_mounted": True,
                "forbidden_paths_hidden": True, "private_vault_mounted": False,
                "network_isolated": True, "no_privilege_escalation": True,
                "mount_namespace": True, "user_namespace": True, "pid_namespace": True,
            }
            return backend.attestation

        def fixture_command(**kwargs: Any) -> list[str]:
            self.assertEqual(kwargs["workspace"], workspace)
            self.assertEqual(kwargs["mode"], "dangerous")
            argv = list(kwargs["argv"])
            self.assertEqual(argv[:4], ["/usr/bin/python3", "-I", "-B", "-c"])
            # No replacement can escape this fixture's own temporary workspace.
            for basename in ("async.release", "heartbeat"):
                argv[4] = argv[4].replace("/workspace/" + basename, str(workspace / basename))
            for basename in ("async.release", "heartbeat"):
                self.assertNotIn(repr("/workspace/" + basename), argv[4])
            return argv

        def serve(server: Any, **_kwargs: Any) -> None:
            worker = threading.Thread(
                target=original_serve, args=(server,), kwargs={"poll_interval": 0.01}, daemon=True,
            )
            worker.start()
            try:
                session = self.harness.Session.__new__(self.harness.Session)
                session.root, session.workspace = root, workspace
                session.port, session.sequence = server.server_address[1], 0
                session.token = self.harness._oauth(session.port, environment["RE_CTM_OAUTH_PASSWORD"])
                self.harness._exercise(session, captured["report"])
            finally:
                server.shutdown()
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())

        with ExitStack() as patches:
            patches.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            patches.enter_context(mock.patch.object(sys, "argv", ["bootstrap-fixture", str(ready)]))
            patches.enter_context(mock.patch.object(
                sys, "prefix", str(Path(re_ctm.__file__).resolve().parent.parent),
            ))
            patches.enter_context(mock.patch.object(importlib.metadata, "version", return_value=re_ctm.__version__))
            patches.enter_context(mock.patch.object(re_ctm.app, "build_application", side_effect=build))
            patches.enter_context(mock.patch.object(re_ctm.native.BubblewrapExecBackend, "attest", attest))
            patches.enter_context(mock.patch.object(re_ctm.native, "_bubblewrap_command", fixture_command))
            patches.enter_context(mock.patch.object(re_ctm.server.ReCTMHTTPServer, "serve_forever", serve))
            if startup_error is None:
                try:
                    exec(compile(self.harness.SERVER_CHILD, "<native-http-server-child>", "exec"), {})
                except SystemExit:
                    failure = root / "startup-error.json"
                    self.fail(failure.read_text() if failure.exists() else "Bootstrap exited without diagnostics")
            else:
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(self.harness.SERVER_CHILD, "<native-http-server-child>", "exec"), {})
                self.assertEqual(stopped.exception.code, 1)
        return captured

    @unittest.skipUnless(sys.platform.startswith("linux"), "Native lifecycle fixture is Linux-specific")
    def test_bootstrap_rewrites_paths_inside_workspace_mounted_temporary_root(self) -> None:
        # Package checks intentionally put TMPDIR below their source workspace.
        # The rewritten host path may still begin /workspace; only the exact
        # two original sandbox filenames must disappear from the child script.
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as temporary:
            captured = self._bootstrap_fixture(Path(temporary))
            self.assertTrue(all(check["passed"] for check in captured["report"]["checks"]))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Native lifecycle fixture is Linux-specific")
    def test_exact_bootstrap_generates_secrets_and_exercises_real_http_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captured = self._bootstrap_fixture(root)
            settings = captured["settings"]
            self.assertEqual(len(settings.token_secret), 32)
            self.assertEqual(len(settings.capability_secret), 32)
            self.assertNotEqual(settings.token_secret, settings.capability_secret)
            self.assertTrue((root / "ready.json").is_file())
            self.assertFalse((root / "ready.tmp").exists())
            self.assertFalse((root / "startup-error.json").exists())
            checks = captured["report"]["checks"]
            self.assertEqual({check["name"] for check in checks}, {
                "real_bubblewrap_startup_attestation", "synchronous_success",
                "async_short_yield_success", "async_success_after_ready_and_http_request_return",
                "initial_stdin_after_request_return", "tty_stdin_in_later_http_request",
                "explicit_kill", "command_timeout",
            })
            self.assertTrue(all(check["passed"] for check in checks), checks)
            # These are disposable signing keys, never persisted credentials.
            for path in root.rglob("*"):
                if path.is_file():
                    data = path.read_bytes()
                    for secret in (settings.token_secret, settings.capability_secret):
                        self.assertNotIn(secret, data)
                        self.assertNotIn(secret.hex().encode(), data)
            self.assertNotIn(b"fixture-password", (root / "data/debug/events.jsonl").read_bytes())

    def test_bootstrap_failure_preserves_only_allowlisted_structural_diagnostics(self) -> None:
        for code, expected in (
            ("CAPABILITY_SECRET_REQUIRED", "CAPABILITY_SECRET_REQUIRED"),
            ("SECRET_VALUE_MUST_NOT_BE_RECORDED", None),
        ):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self._bootstrap_fixture(root, startup_error=ReCTMError(code, "PRIVATE-EXCEPTION-MESSAGE"))
                raw = (root / "startup-error.json").read_text()
                failure = json.loads(raw)
                self.assertEqual(failure["stage"], "build_application_and_attest")
                self.assertEqual(failure["error_code"], expected)
                self.assertEqual(failure["exception_type"], "ReCTMError")
                self.assertTrue(failure["traceback_frames"])
                self.assertNotIn("PRIVATE-EXCEPTION-MESSAGE", raw)
                self.assertNotIn("SECRET_VALUE_MUST_NOT_BE_RECORDED", raw)
                self.assertFalse((root / "ready.json").exists())
                session = self.harness.Session.__new__(self.harness.Session)
                session.root = root
                session.process = SimpleNamespace(poll=lambda: 1, returncode=1)
                with self.assertRaises(self.harness.StartupFailure) as failed:
                    session.connect()
                self.assertEqual(failed.exception.startup_failure["error_code"], expected)
                self.assertEqual(failed.exception.startup_failure["child_exit_code"], 1)

    def test_cleanup_failure_does_not_mask_startup_diagnostics(self) -> None:
        details = {"stage": "settings", "error_code": "INVALID_SECRET",
                   "exception_type": "ReCTMError", "traceback_frames": []}
        session = SimpleNamespace(
            connect=mock.Mock(side_effect=self.harness.StartupFailure(details)),
            close=mock.Mock(side_effect=RuntimeError("PRIVATE-CLEANUP-MESSAGE")),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            fake_sys = SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=1),
                                       executable="/candidate/venv/bin/python")
            with mock.patch.object(self.harness, "sys", fake_sys), \
                    mock.patch.object(self.harness, "Session", return_value=session), \
                    mock.patch("builtins.print"):
                self.assertEqual(self.harness.main(["--output", str(output)]), 1)
            report = json.loads(output.read_text())
            self.assertTrue(report["cleanup_failed"])
            failure = report["checks"][0]["details"]
            self.assertEqual(failure["startup_failure"], details)
            self.assertNotIn("PRIVATE-CLEANUP-MESSAGE", output.read_text())

    def test_server_exit_contract_requires_progress_then_stopped_descendants(self) -> None:
        for abrupt, wrong_exit in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(abrupt=abrupt, wrong_exit=wrong_exit), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                heartbeat = workspace / "heartbeat"
                stopped = threading.Event()

                def advance() -> None:
                    while not stopped.is_set():
                        staged = workspace / "heartbeat.tmp"
                        staged.write_text(str(time.monotonic()))
                        staged.replace(heartbeat)
                        stopped.wait(0.01)

                updater = threading.Thread(target=advance)
                process = SimpleNamespace(pid=99999999, returncode=None)

                def stop(signum: int) -> None:
                    self.assertEqual(signum, signal.SIGKILL if abrupt else signal.SIGINT)
                    stopped.set()
                    updater.join(timeout=2)
                    process.returncode = 1 if wrong_exit else (-signum if abrupt else 0)

                process.send_signal = mock.Mock(side_effect=stop)
                process.wait = mock.Mock(return_value=0)
                session = SimpleNamespace(
                    workspace=workspace, process=process,
                    start=mock.Mock(return_value={"operation_outcome": "running"}),
                )
                report: dict[str, Any] = {"checks": []}
                updater.start()
                try:
                    with mock.patch.object(self.harness, "_descendants", return_value={99999998: "test"}), \
                            mock.patch.object(self.harness, "_alive",
                                              side_effect=lambda _p: [] if stopped.is_set() else [99999998]):
                        self.harness._server_exit(session, report, abrupt=abrupt)
                finally:
                    stopped.set()
                    updater.join(timeout=2)
                self.assertEqual(len(report["checks"]), 1)
                self.assertEqual(report["checks"][0]["passed"], not wrong_exit, report)
                self.assertEqual(report["checks"][0]["details"]["remaining_process_count"], 0)


if __name__ == "__main__":
    unittest.main()
