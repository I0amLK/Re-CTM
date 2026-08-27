from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from re_ctm.cli import build_parser, main


class CLITestCase(unittest.TestCase):
    def test_serve_defaults_follow_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"RE_CTM_HOST": "127.0.0.2", "RE_CTM_PORT": "42424"},
            clear=False,
        ):
            args = build_parser().parse_args(["serve"])
        self.assertEqual(args.host, "127.0.0.2")
        self.assertEqual(args.port, 42424)

    def test_cli_flags_override_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"RE_CTM_HOST": "127.0.0.2", "RE_CTM_PORT": "42424"},
            clear=False,
        ):
            args = build_parser().parse_args(
                ["serve", "--host", "127.0.0.3", "--port", "43434"]
            )
        self.assertEqual(args.host, "127.0.0.3")
        self.assertEqual(args.port, 43434)

    def test_check_config_allows_dynamic_loopback_oauth_without_server_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            data = root / "data"
            workspace.mkdir()
            env = {
                "RE_CTM_WORKSPACE": str(workspace),
                "RE_CTM_DATA_ROOT": str(data),
                "RE_CTM_PRIVATE_ROOT": str(data / "private"),
                "RE_CTM_DEBUG_ROOT": str(data / "debug"),
                "RE_CTM_OAUTH_PASSWORD": "",
                "RE_CTM_SERVER_URL": "",
                "RE_CTM_LATEX_POLICY": "static_only",
            }
            output = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=False), redirect_stdout(output):
                code = main(["check-config"])
            self.assertEqual(code, 0)
            self.assertIn('"oauth_server_url_mode": "dynamic_loopback_reverse_proxy"', output.getvalue())
            self.assertIn('"oauth_authorization_key_mode": "generated_on_serve"', output.getvalue())

    def test_serve_generates_oauth_authorization_key_when_unset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            data = root / "data"
            workspace.mkdir()
            env = {
                "RE_CTM_WORKSPACE": str(workspace),
                "RE_CTM_DATA_ROOT": str(data),
                "RE_CTM_PRIVATE_ROOT": str(data / "private"),
                "RE_CTM_DEBUG_ROOT": str(data / "debug"),
                "RE_CTM_OAUTH_PASSWORD": "",
                "RE_CTM_SERVER_URL": "",
                "RE_CTM_LATEX_POLICY": "static_only",
            }
            with mock.patch.dict(os.environ, env, clear=False), mock.patch(
                "re_ctm.cli.run_server", return_value=0
            ) as run_server:
                code = main(["serve", "--host", "127.0.0.1", "--port", "45678"])
            self.assertEqual(code, 0)
            application = run_server.call_args.args[0]
            generated_key = application.oauth.password
            try:
                self.assertGreaterEqual(len(generated_key), 32)
                self.assertTrue(run_server.call_args.kwargs["reveal_generated_oauth_password"])
            finally:
                application.close()
            encoded_key = generated_key.encode("utf-8")
            for path in data.rglob("*"):
                if path.is_file():
                    self.assertNotIn(encoded_key, path.read_bytes(), str(path))


if __name__ == "__main__":
    unittest.main()
