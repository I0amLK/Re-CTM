from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from re_ctm import __version__
from re_ctm.cli import build_parser, main
from re_ctm.config import Settings
from re_ctm.errors import ReCTMError


class CLITestCase(unittest.TestCase):
    def test_top_level_version_flag(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as exited:
            build_parser().parse_args(["--version"])
        self.assertEqual(exited.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), f"re-ctm {__version__}")

    def test_attest_native_accepts_repeatable_generic_allow_roots(self) -> None:
        args = build_parser().parse_args(
            [
                "attest-native",
                "--allow-root",
                "/opt/vendor/one",
                "--allow-root",
                "/srv/runtime/two",
            ]
        )
        self.assertEqual(args.allow_root, ["/opt/vendor/one", "/srv/runtime/two"])

    def test_linux_bubblewrap_is_automatic_native_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            env = {
                "RE_CTM_WORKSPACE": str(workspace),
                "RE_CTM_DATA_ROOT": str(root / "data"),
                "RE_CTM_PRIVATE_ROOT": str(root / "data" / "private"),
                "RE_CTM_DEBUG_ROOT": str(root / "data" / "debug"),
                "RE_CTM_NATIVE_MODE": "dangerous",
            }
            with mock.patch.dict(os.environ, env, clear=True), mock.patch(
                "re_ctm.config.sys.platform", "linux"
            ), mock.patch("re_ctm.config.shutil.which", return_value="/usr/bin/bwrap"):
                settings = Settings.from_env()
            self.assertEqual(settings.native_exec_backend, "bubblewrap")
            self.assertFalse(settings.native_isolation_attested)
            settings.validate()

    def test_native_exec_allow_roots_are_parsed_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            data = root / "data"
            first = root / "toolchains" / "first"
            second = root / "toolchains" / "second"
            workspace.mkdir()
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            env = {
                "RE_CTM_WORKSPACE": str(workspace),
                "RE_CTM_DATA_ROOT": str(data),
                "RE_CTM_PRIVATE_ROOT": str(data / "private"),
                "RE_CTM_DEBUG_ROOT": str(data / "debug"),
                "RE_CTM_NATIVE_MODE": "dangerous",
                "RE_CTM_NATIVE_EXEC_BACKEND": "bubblewrap",
                "RE_CTM_NATIVE_EXEC_ALLOW_ROOTS": os.pathsep.join(
                    (str(first), str(second))
                ),
                "RE_CTM_LATEX_POLICY": "static_only",
            }
            output = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(output):
                code = main(["check-config"])
            self.assertEqual(code, 0)
            payload = output.getvalue()
            self.assertIn(str(first.resolve()), payload)
            self.assertIn(str(second.resolve()), payload)
            self.assertIn('"mount_mode": "read_only"', payload)
            self.assertIn('"explicit_root_count": 2', payload)

    def test_allow_roots_fail_closed_for_disabled_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            toolchain = root / "toolchain"
            workspace.mkdir()
            toolchain.mkdir()
            env = {
                "RE_CTM_WORKSPACE": str(workspace),
                "RE_CTM_DATA_ROOT": str(root / "data"),
                "RE_CTM_PRIVATE_ROOT": str(root / "data" / "private"),
                "RE_CTM_DEBUG_ROOT": str(root / "data" / "debug"),
                "RE_CTM_NATIVE_EXEC_BACKEND": "disabled",
                "RE_CTM_NATIVE_EXEC_ALLOW_ROOTS": str(toolchain),
            }
            with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(
                ReCTMError
            ) as error:
                Settings.from_env()
            self.assertEqual(error.exception.code, "NATIVE_TOOLCHAIN_ROOTS_UNSUPPORTED")

    def test_serve_defaults_follow_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"RE_CTM_HOST": "127.0.0.2", "RE_CTM_PORT": "42424"},
            clear=False,
        ):
            args = build_parser().parse_args(["serve"])
        self.assertEqual(args.host, "127.0.0.2")
        self.assertEqual(args.port, 42424)

    def test_tui_defaults_follow_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"RE_CTM_HOST": "127.0.0.4", "RE_CTM_PORT": "45454"},
            clear=False,
        ):
            args = build_parser().parse_args(["tui"])
        self.assertEqual(args.host, "127.0.0.4")
        self.assertEqual(args.port, 45454)

    def test_serve_does_not_construct_terminal_session(self) -> None:
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
                "RE_CTM_OAUTH_PASSWORD": "configured-for-test",
                "RE_CTM_LATEX_POLICY": "static_only",
            }
            with mock.patch.dict(os.environ, env, clear=False), mock.patch(
                "re_ctm.cli.TerminalSession"
            ) as terminal_session, mock.patch(
                "re_ctm.cli.run_server", return_value=0
            ) as run_server:
                code = main(["serve", "--host", "127.0.0.1", "--port", "45679"])
            self.assertEqual(code, 0)
            terminal_session.assert_not_called()
            application = run_server.call_args.args[0]
            try:
                self.assertIsNone(run_server.call_args.kwargs["terminal_session"])
            finally:
                application.close()

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
