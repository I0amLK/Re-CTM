from __future__ import annotations

import json
import os
import shlex
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from re_ctm.app import build_application
from re_ctm.config import Settings
from re_ctm.enums import LatexPolicy
from re_ctm.errors import ReCTMError
from re_ctm.latex import LatexGate
from re_ctm.native import HostExecBackend
from re_ctm.native_exec import prepare_host_command
from re_ctm.oauth import OAuthPrincipal
from re_ctm.tools import TOOL_SPECS, _validate_schema_value


DOCUMENT = "\\documentclass{article}\n\\begin{document}Fixture.\\end{document}\n"


@unittest.skipUnless(os.name == "posix", "POSIX host execution required")
class NativeHostTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="re-ctm-host-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.work = self.root / "workspace"
        self.work.mkdir()
        data = self.root / "data"
        self.settings = Settings(
            workspace=self.work, data_root=data, private_root=data / "private", debug_root=data / "debug",
            native_exec_backend="host", latex_policy=LatexPolicy.STATIC_ONLY,
            token_secret=b"t" * 32, capability_secret=b"c" * 32, oauth_password="fixture-password",
        )
        self.app = build_application(self.settings)
        self.addCleanup(self.app.close)
        self.native = self.app.native
        self.principal = OAuthPrincipal("owner", "client", "mcp")

    def call(self, name: str, arguments: dict | None = None, *, ok: bool = True) -> dict:
        result = self.app.tools.call(name, arguments or {}, self.principal)
        payload = result["structuredContent"]
        if TOOL_SPECS[name].output_schema is not None:
            _validate_schema_value(payload, TOOL_SPECS[name].output_schema, path=name)
        self.assertEqual(payload["ok"], ok, name)
        return payload

    def program(self, directory: Path, name: str, body: str) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return path

    def test_actual_child_path_cwd_stdin_stdout_and_stderr(self) -> None:
        cwd_before = Path.cwd()
        nested = self.work / "dir with spaces"
        nested.mkdir()
        script = "import json,os,sys; print(json.dumps([os.getcwd(),sys.stdin.read(),sys.argv[1]])); print('stderr-fixture',file=sys.stderr)"
        literal = "literal; $(not-a-shell-command)"
        result = self.call("exec_command", {
            "argv": [sys.executable, "-c", script, literal], "workdir": nested.name,
            "stdin": "input-fixture", "yield_time_ms": 2000, "verbosity": "full",
        })
        self.assertEqual(result["operation_outcome"], "exited_0")
        self.assertEqual(json.loads(result["stdout"]), [str(nested), "input-fixture", literal])
        self.assertIn("stderr-fixture", result["stderr"])
        self.assertEqual(Path.cwd(), cwd_before)

    def test_relative_empty_path_entries_and_override_replace_base_path(self) -> None:
        nested = self.work / "nested"
        nested.mkdir()
        self.program(nested / "bin", "fixture-program", "printf 'nested-bin\\n'\n")
        self.program(nested, "fixture-current", "printf 'current-dir\\n'\n")
        for path, name, expected in (("bin", "fixture-program", "nested-bin"), ("", "fixture-current", "current-dir")):
            with self.subTest(path=path):
                result = self.call("exec_command", {
                    "argv": [name], "workdir": "nested", "env": {"PATH": path},
                    "yield_time_ms": 1000, "verbosity": "full",
                })
                self.assertEqual(result["stdout"].strip(), expected)
        missing = self.call("exec_command", {"argv": ["sh"], "env": {"PATH": ""}}, ok=False)
        self.assertEqual(missing["error"]["code"], "NATIVE_EXECUTABLE_UNRESOLVED")

    def test_absolute_symlink_preserves_invocation_name_and_literal_arguments(self) -> None:
        executable = self.program(self.root / "external tools", "original", "printf '%s\\n' \"$0\" \"$1\"\n")
        alias = executable.with_name("invocation alias")
        alias.symlink_to(executable)
        result = self.call("exec_command", {
            "argv": [str(alias), "a b; c"], "env": {"PATH": ""}, "yield_time_ms": 1000, "verbosity": "full",
        })
        self.assertEqual(result["stdout"].splitlines(), [str(alias), "a b; c"])

    def test_shell_builtins_inline_path_and_nonzero_exit(self) -> None:
        directory = self.root / "shell-tools"
        self.program(directory, "fixture-program", "printf 'shell-program\\n'\n")
        result = self.call("exec_command", {
            "cmd": "printf 'builtin\\n'; PATH=" + shlex.quote(str(directory)) + " fixture-program; exit 7",
            "yield_time_ms": 1000, "verbosity": "full",
        })
        self.assertEqual(result["stdout"].splitlines(), ["builtin", "shell-program"])
        self.assertEqual(result["operation_outcome"], "exited_nonzero")
        self.assertEqual(result["exit_code"], 7)

    def test_host_report_and_direct_file_checks_do_not_imply_process_sandbox(self) -> None:
        canary = self.settings.private_root / "disposable-canary.txt"
        canary.write_text("fresh-test-canary")
        environment = self.call("check_exec_environment")
        self.assertTrue(environment["command_lifecycle_supported"])
        self.assertFalse(environment["hard_isolation_attested"])
        self.assertFalse(environment["os_sandbox"])
        self.assertTrue(environment["private_vault_visible"])
        denied = self.call("read_file", {"path": "../data/private/disposable-canary.txt"}, ok=False)
        self.assertEqual(denied["error"]["category"], "security")
        result = self.call("exec_command", {
            "argv": [sys.executable, "-c", "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())", str(canary)],
            "yield_time_ms": 2000, "verbosity": "full",
        })
        self.assertEqual(result["stdout"].strip(), "fresh-test-canary")

    def test_changed_executable_is_refused_before_process_creation(self) -> None:
        program = self.program(self.work, "changing-program", "exit 0\n")
        calls = 0

        def prepare(*args: object, **kwargs: object) -> tuple:
            nonlocal calls
            calls += 1
            if calls == 2:
                program.write_text("#!/bin/sh\nexit 1\n")
            return prepare_host_command(*args, **kwargs)

        with mock.patch("re_ctm.native.prepare_host_command", side_effect=prepare), \
                mock.patch.object(self.native.command_manager, "start") as start:
            result = self.call("exec_command", {"argv": ["./changing-program"]}, ok=False)
        self.assertEqual(result["error"]["code"], "NATIVE_EXECUTABLE_CHANGED")
        start.assert_not_called()

    def test_explicit_host_and_retired_configuration_are_distinct(self) -> None:
        replace(self.settings, native_exec_backend="disabled").validate()
        for settings in (
            replace(self.settings, native_exec_backend="bubblewrap"),
            replace(self.settings, native_exec_backend="external"),
            replace(self.settings, native_isolation_attested=True),
            replace(self.settings, native_exec_helper=self.root / "helper"),
        ):
            with self.subTest(settings=settings.native_exec_backend), self.assertRaises(ReCTMError) as denied:
                settings.validate()
            self.assertEqual(denied.exception.code, "INVALID_NATIVE_EXEC_BACKEND")

    def test_host_remains_subject_to_workdir_and_run_ownership_checks(self) -> None:
        for cwd in ("../outside", str(self.root)):
            with self.subTest(cwd=cwd):
                denied = self.call("exec_command", {"argv": [sys.executable], "cwd": cwd}, ok=False)
                self.assertEqual(denied["error"]["category"], "security")
        run = self.call("rethlas_start", {"problem_tex": "Ownership regression fixture."})
        foreign = self.app.tools.call("rethlas_step", {"run_id": run["run_id"]}, OAuthPrincipal("other", "other-client", "mcp"))
        self.assertTrue(foreign["isError"])
        self.assertEqual(foreign["structuredContent"]["error"]["category"], "permission")

    def test_host_environment_removes_server_settings_without_isolation_claim(self) -> None:
        with mock.patch.dict(os.environ, {"RE_CTM_OAUTH_PASSWORD": "fixture-secret"}):
            backend = HostExecBackend()
        self.assertNotIn("RE_CTM_OAUTH_PASSWORD", backend.child_environment({}))
        self.assertNotIn("fixture-secret", json.dumps(self.call("check_exec_environment")))


@unittest.skipUnless(os.name == "posix", "POSIX host compiler fixtures required")
class RequiredHostLatexFailureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="re-ctm-host-latex-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.work = self.root / "validation"
        self.gate = LatexGate(LatexPolicy.REQUIRED, timeout_seconds=1, environment={"PATH": str(self.bin)})

    def compiler(self, body: str, *, interpreter: str = "/bin/sh") -> None:
        path = self.bin / "latexmk"
        path.write_text("#!" + interpreter + "\n" + body)
        path.chmod(0o755)

    def test_missing_compiler_does_not_downgrade_required(self) -> None:
        result = self.gate.validate(DOCUMENT, self.work)
        self.assertFalse(result.compile_available)
        self.assertFalse(result.compile_attempted)
        self.assertFalse(result.gate_passed)
        self.assertEqual(result.policy, "required")

    def test_spawn_failure_does_not_downgrade_required(self) -> None:
        self.compiler("", interpreter=str(self.root / "missing-interpreter"))
        result = self.gate.validate(DOCUMENT, self.work)
        self.assertTrue(result.compile_attempted)
        self.assertFalse(result.gate_passed)

    def test_zero_exit_without_new_pdf_ignores_stale_workdir_artifact(self) -> None:
        self.work.mkdir()
        (self.work / "proof.pdf").write_bytes(b"%PDF-stale")
        self.compiler("exit 0\n")
        result = self.gate.validate(DOCUMENT, self.work)
        self.assertTrue(result.compile_attempted)
        self.assertFalse(result.compile_passed)
        self.assertFalse(result.gate_passed)

    def test_nonzero_exit_rejects_even_a_new_pdf(self) -> None:
        self.compiler("printf '%%PDF-fixture' > proof.pdf\nexit 7\n")
        result = self.gate.validate(DOCUMENT, self.work)
        self.assertFalse(result.gate_passed)
        self.assertTrue(any("code 7" in error for error in result.errors))

    def test_invalid_pdf_is_not_a_successful_compilation(self) -> None:
        self.compiler("printf 'not-a-pdf' > proof.pdf\nexit 0\n")
        self.assertFalse(self.gate.validate(DOCUMENT, self.work).gate_passed)

    def test_timeout_does_not_downgrade_required(self) -> None:
        self.compiler("trap '' TERM\n/bin/sleep 30\n")
        result = self.gate.validate(DOCUMENT, self.work)
        self.assertFalse(result.gate_passed)
        self.assertTrue(any("timed out" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
