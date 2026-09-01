from __future__ import annotations

import io
import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.quick_tunnel import QuickTunnel, extract_quick_tunnel_origin
from re_ctm.terminal_ui import TerminalSession


class FakeProcess:
    def __init__(
        self,
        output: str,
        *,
        return_code: int | None,
        stubborn: bool = False,
    ) -> None:
        self.stdout = io.StringIO(output)
        self.return_code = return_code
        self.stubborn = stubborn
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.return_code

    def wait(self, timeout: float | None = None) -> int:
        if self.return_code is None:
            raise subprocess.TimeoutExpired("cloudflared", timeout)
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True
        if not self.stubborn:
            self.return_code = 0

    def kill(self) -> None:
        self.killed = True
        self.return_code = -9


def started_session(stream: io.StringIO) -> TerminalSession:
    session = TerminalSession(stream=stream)
    session.start(
        version="0.2.1",
        workspace=Path("/tmp/project"),
        mcp_url="http://127.0.0.1:34567/mcp",
        generated_oauth_key="operator-key",
    )
    return session


class QuickTunnelParsingTestCase(unittest.TestCase):
    def test_only_strict_trycloudflare_https_origins_are_accepted(self) -> None:
        self.assertEqual(
            extract_quick_tunnel_origin(
                "INF Your quick Tunnel has been created! Visit it at "
                "https://random-words-123.trycloudflare.com"
            ),
            "https://random-words-123.trycloudflare.com",
        )
        for rejected in (
            "http://random.trycloudflare.com",
            "https://trycloudflare.com",
            "https://random.trycloudflare.com.evil.example",
            "https://user@random.trycloudflare.com",
            "https://random.trycloudflare.com:8443",
            "https://example.com/random.trycloudflare.com",
        ):
            self.assertIsNone(extract_quick_tunnel_origin(rejected), rejected)


class QuickTunnelLifecycleTestCase(unittest.TestCase):
    def test_missing_binary_is_nonfatal_and_does_not_spawn(self) -> None:
        stream = io.StringIO()
        session = started_session(stream)
        tunnel = QuickTunnel(session)
        with mock.patch("re_ctm.quick_tunnel.shutil.which", return_value=None), mock.patch(
            "re_ctm.quick_tunnel.subprocess.Popen"
        ) as popen:
            self.assertFalse(tunnel.start("http://127.0.0.1:34567"))
        session.close()
        popen.assert_not_called()
        self.assertIn("cloudflared not found", stream.getvalue())
        self.assertIn("local MCP remains available", stream.getvalue())

    def test_spawn_failure_is_nonfatal(self) -> None:
        stream = io.StringIO()
        session = started_session(stream)
        with mock.patch(
            "re_ctm.quick_tunnel.subprocess.Popen",
            side_effect=OSError("cannot execute"),
        ):
            tunnel = QuickTunnel(session, executable="/usr/bin/cloudflared")
            self.assertFalse(tunnel.start("http://127.0.0.1:34567"))
        session.close()
        self.assertIn("failed to start cloudflared", stream.getvalue())
        self.assertIn("OSError", stream.getvalue())

    def test_start_uses_quick_tunnel_flags_strips_credentials_and_publishes_url(self) -> None:
        stream = io.StringIO()
        session = started_session(stream)
        fake = FakeProcess(
            "2026-08-31 INF +---------------------------------------------+\n"
            "2026-08-31 INF https://unit-test.trycloudflare.com\n",
            return_code=None,
        )
        environment = {
            "RE_CTM_OAUTH_PASSWORD": "do-not-inherit",
            "RE_CTM_TOKEN_SECRET": "do-not-inherit",
            "RE_CTM_CAPABILITY_SECRET": "do-not-inherit",
            "TUNNEL_TOKEN": "named-tunnel-token",
            "TUNNEL_TOKEN_FILE": "/secret/token",
            "TUNNEL_CRED_FILE": "/secret/credentials.json",
            "TUNNEL_CRED_CONTENTS": "secret-json",
            "TUNNEL_ORIGIN_CERT": "/secret/cert.pem",
        }
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch(
            "re_ctm.quick_tunnel.subprocess.Popen",
            return_value=fake,
        ) as popen:
            tunnel = QuickTunnel(session, executable="/usr/bin/cloudflared")
            self.assertTrue(tunnel.start("http://127.0.0.1:34567"))
            assert tunnel._reader is not None
            tunnel._reader.join(timeout=1)
            call = popen.call_args
            command = call.args[0]
            child_env = call.kwargs["env"]
            self.assertEqual(command[0], "/usr/bin/cloudflared")
            self.assertEqual(command[1:3], ["tunnel", "--config"])
            self.assertEqual(command[3], os.devnull)
            self.assertIn("--no-autoupdate", command)
            self.assertEqual(command[-2:], ["--url", "http://127.0.0.1:34567"])
            for key in environment:
                self.assertNotIn(key, child_env)
            self.assertIn("https://unit-test.trycloudflare.com/mcp", stream.getvalue())
            self.assertIn("Quick Tunnel   connected", stream.getvalue())
            tunnel.close()
        session.close()
        self.assertTrue(fake.terminated)
        self.assertFalse(fake.killed)

    def test_early_exit_without_url_degrades_to_local_service(self) -> None:
        stream = io.StringIO()
        session = started_session(stream)
        fake = FakeProcess("failed before registration\n", return_code=17)
        with mock.patch("re_ctm.quick_tunnel.subprocess.Popen", return_value=fake):
            tunnel = QuickTunnel(session, executable="/usr/bin/cloudflared")
            self.assertTrue(tunnel.start("http://127.0.0.1:34567"))
            assert tunnel._reader is not None
            tunnel._reader.join(timeout=1)
            tunnel.close()
        session.close()
        output = stream.getvalue()
        self.assertIn("cloudflared exited with code 17", output)
        self.assertIn("local MCP remains available", output)

    def test_close_escalates_only_owned_stubborn_process_to_kill(self) -> None:
        session = started_session(io.StringIO())
        fake = FakeProcess("", return_code=None, stubborn=True)
        with mock.patch("re_ctm.quick_tunnel.subprocess.Popen", return_value=fake):
            tunnel = QuickTunnel(session, executable="/usr/bin/cloudflared")
            self.assertTrue(tunnel.start("http://127.0.0.1:34567"))
            tunnel.close()
        session.close()
        self.assertTrue(fake.terminated)
        self.assertTrue(fake.killed)


if __name__ == "__main__":
    unittest.main()
