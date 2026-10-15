"""Real CLI subprocess regressions; Native is disabled and LaTeX is static-only."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import secrets
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

import re_ctm


ROOT = Path(__file__).resolve().parents[1]
CHILD = """
import io, os, sys
sys.path.insert(0, sys.argv[1])
assert isinstance(sys.stderr.buffer, io.BufferedWriter)
gate = int(sys.argv[2])
os.read(gate, 1)
os.close(gate)
from re_ctm.cli import main
raise SystemExit(main(["tui", "--verbose", "--host", "127.0.0.1", "--port", sys.argv[3]]))
"""


class TerminalProcessTestCase(unittest.TestCase):
    def _case(self, *, use_pty: bool, close_before_start: bool) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("workspace", "home", "data", "private", "debug", "tmp"):
                (root / name).mkdir()
            password = secrets.token_urlsafe(32)
            env = {
                "PATH": os.defpath, "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "RE_CTM_WORKSPACE": str(root / "workspace"),
                "RE_CTM_DATA_ROOT": str(root / "data"),
                "RE_CTM_PRIVATE_ROOT": str(root / "private"),
                "RE_CTM_DEBUG_ROOT": str(root / "debug"),
                "RE_CTM_NATIVE_MODE": "dangerous", "RE_CTM_NATIVE_EXEC_BACKEND": "disabled",
                "RE_CTM_LATEX_POLICY": "static_only", "RE_CTM_OAUTH_PASSWORD": password,
            }
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            reader, writer = pty.openpty() if use_pty else os.pipe()
            gate_reader, gate_writer = os.pipe()
            process = None
            try:
                process = subprocess.Popen(
                    [sys.executable, "-I", "-B", "-c", CHILD,
                     str(Path(re_ctm.__file__).resolve().parent.parent), str(gate_reader), str(port)],
                    cwd=root / "workspace", env=env, stdin=subprocess.DEVNULL,
                    stdout=writer, stderr=writer, pass_fds=(gate_reader,), start_new_session=True,
                )
                os.close(writer)
                writer = None
                os.close(gate_reader)
                gate_reader = None
                if close_before_start:
                    os.close(reader)
                    reader = None
                os.write(gate_writer, b"go")
                os.close(gate_writer)
                gate_writer = None
                base = f"http://127.0.0.1:{port}"
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                until = time.monotonic() + 10
                while True:
                    self.assertIsNone(process.poll(), "source CLI exited before health")
                    try:
                        with opener.open(base + "/health", timeout=0.3) as response:
                            self.assertTrue(json.loads(response.read(65536))["ok"])
                        break
                    except OSError:
                        if time.monotonic() > until:
                            self.fail("source CLI health deadline exceeded")
                        time.sleep(0.03)
                if reader is not None:
                    ready, _, _ = select.select([reader], [], [], 2)
                    self.assertTrue(ready)
                    banner = os.read(reader, 65536)
                    self.assertIn(b"configured externally", banner)
                    self.assertNotIn(password.encode(), banner)
                    os.close(reader)
                    reader = None
                spec = importlib.util.spec_from_file_location(
                    "terminal_process_smoke", ROOT / "scripts/smoke_oauth_mcp.py")
                smoke = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(smoke)
                # The real script performs DCR/PKCE and authenticated tool calls
                # after the output consumer has gone away; its report is redacted.
                import contextlib
                with contextlib.redirect_stdout(io.StringIO()):
                    code = smoke.main(
                        ["--base-url", base, "--timeout", "2",
                         "--output", str(root / "smoke.json")], password=password)
                self.assertEqual(code, 0)
                self.assertTrue(json.loads((root / "smoke.json").read_text())["passed"])
                self.assertIsNone(process.poll())
                os.killpg(process.pid, signal.SIGINT)
                self.assertEqual(process.wait(timeout=5), 130)
                with socket.socket() as probe:
                    probe.settimeout(0.3)
                    self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)
                self.assertNotIn(password.encode(), (root / "debug/events.jsonl").read_bytes())
            finally:
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                for descriptor in (reader, writer, gate_reader, gate_writer):
                    if descriptor is not None:
                        os.close(descriptor)

    def test_closed_pty_after_start_preserves_sigint_exit(self) -> None:
        self._case(use_pty=True, close_before_start=False)

    def test_closed_pipe_after_start_preserves_sigint_exit(self) -> None:
        self._case(use_pty=False, close_before_start=False)

    def test_closed_pty_before_start_preserves_sigint_exit(self) -> None:
        self._case(use_pty=True, close_before_start=True)

    def test_closed_pipe_before_start_preserves_sigint_exit(self) -> None:
        self._case(use_pty=False, close_before_start=True)


if __name__ == "__main__":
    unittest.main()
