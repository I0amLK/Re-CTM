from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.config import Settings
from re_ctm.debug import DebugEventBus
from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.native import BubblewrapExecBackend, NativeRuntime, NativeWorkspace
from re_ctm.native_exec import ExecInvocation, collect_executable_facts, shell_candidates


class ExecInvocationV11Tests(unittest.TestCase):
    def test_exactly_one_form_and_non_login_shell(self) -> None:
        shell = ExecInvocation.parse({"cmd": "printf '%s' \"$PATH\"", "env": {"PATH": "fixture"}})
        self.assertEqual(shell.argv, ["/bin/sh", "-c", "printf '%s' \"$PATH\""])
        self.assertEqual(shell.timeout_ms, 300_000)
        self.assertEqual(shell.yield_time_ms, 10_000)
        literal = ExecInvocation.parse({"argv": ["printf", "", "$(not-a-command)"]})
        self.assertEqual(literal.candidates(), ["printf"])
        self.assertEqual(literal.argv[1], "")
        for args in ({}, {"cmd": "x", "argv": ["x"]}, {"cmd": ""}, {"argv": []}, {"argv": [""]}):
            with self.subTest(args=args), self.assertRaises(ReCTMError):
                ExecInvocation.parse(args)

    def test_strict_types_bounds_nuls_and_unknown_fields(self) -> None:
        for extras in [
            {"timeout_ms": True}, {"timeout_ms": "1"}, {"timeout_ms": 0}, {"timeout_ms": 600001},
            {"yield_time_ms": -1}, {"yield_time_ms": 30001}, {"max_output_bytes": 0},
            {"preview_bytes": 1048577}, {"stdin": False}, {"tty": 1}, {"verbosity": "other"},
            {"verbosity": []},
            {"env": {"KEY": 1}}, {"env": {"": "x"}}, {"env": {"A=B": "x"}},
            {"env": {"KEY": "x\0"}}, {"workdir": ""}, {"cwd": 1}, {"unknown": 1},
            {"workdir": "a", "cwd": "b"},
        ]:
            with self.subTest(extras=extras), self.assertRaises(ReCTMError):
                ExecInvocation.parse({"argv": ["true"], **extras})
        for args in ({"cmd": "true\0"}, {"argv": ["true", "x\0"]}, {"argv": ["true", 1]}):
            with self.assertRaises(ReCTMError):
                ExecInvocation.parse(args)

    def test_shell_literal_operators_quotes_and_nested_shells(self) -> None:
        cases = [
            ("env FOO=1 /opt/one | command /opt/two && /opt/three", ["/opt/one", "/opt/two", "/opt/three"]),
            ("pwd; pwd", ["pwd", "pwd"]),
            ("/opt/one|/opt/two&&/opt/three", ["/opt/one", "/opt/two", "/opt/three"]),
            ("'/opt/one;literal';/opt/two", ["/opt/one;literal", "/opt/two"]),
            ("/opt/one\\;literal;/opt/two", ["/opt/one;literal", "/opt/two"]),
            ("printf '%s' ';' /opt/not-a-command", ["printf"]),
            ("printf '%s' 'literal | /opt/not-command'", ["printf"]),
            ("cat <<'EOF'\n/opt/not-command --payload\nEOF", ["cat"]),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(shell_candidates(source), expected)
        self.assertEqual(ExecInvocation.parse({"argv": ["sh", "-c", "cat a; true"]}).candidates(), ["sh", "cat", "true"])

    def test_loop_queries_do_not_turn_arguments_into_executables(self) -> None:
        source = "pwd; for c in absent; do command -v \"$c\" || true; done; printf result"
        self.assertEqual(shell_candidates(source), ["pwd", "true", "printf"])
        self.assertEqual(shell_candidates("for c in absent; do \"$c\"; done"), ["$c"])
        for source in ("for c in x; missing; done", "for c in x; do true", "command -p true", "printf 'unterminated", "pwd;" * 1025):
            with self.subTest(source=source[:80]), self.assertRaises(ReCTMError):
                shell_candidates(source)


class ExecutableFactsV11Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / "workspace"
        self.private = self.root / "private"
        self.work.mkdir(); self.private.mkdir()
        self.workspace = NativeWorkspace(self.work, private_root=self.private)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def file(self, name: str, mode: int = 0o755) -> Path:
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture")
        path.chmod(mode)
        return path

    def facts(self, args: dict, path: str = "/usr/bin") -> tuple:
        return collect_executable_facts(ExecInvocation.parse(args), self.workspace, sandbox_path=path,
                                        forbidden_paths=(self.private,))

    def test_requested_path_and_relative_workdir_select_exact_candidate(self) -> None:
        self.file("a/program")
        selected = self.file("b/program", 0o4755)
        facts = self.facts({"argv": ["program"], "env": {"PATH": "/workspace/b"}}, "/workspace/a")
        self.assertEqual(facts[-1][0][1], str(selected))
        self.assertTrue(facts[-1][0][4] & 0o4000)
        relative = self.file("sub/bin/program")
        current = self.file("sub/program")
        for path, expected in [("bin", relative), ("", current)]:
            self.assertEqual(self.facts({"argv": ["program"], "workdir": "sub", "env": {"PATH": path}})[-1][0][1], str(expected))

    def test_path_search_skips_nonexecutable_and_direct_path_never_falls_back(self) -> None:
        self.file("a/program", 0o644)
        selected = self.file("b/program")
        facts = self.facts({"argv": ["program"]}, "/workspace/a:/workspace/b")
        self.assertEqual(facts[-1][0][1], str(selected))
        with self.assertRaises(ReCTMError) as caught:
            self.facts({"argv": ["./a/program"]}, "/workspace/b")
        self.assertEqual(caught.exception.code, "NATIVE_EXECUTABLE_NOT_EXECUTABLE")

    def test_shadowing_and_mode_mutation_change_facts(self) -> None:
        selected = self.file("b/program")
        args = {"argv": ["program"]}
        path = "/workspace/a:/workspace/b"
        old = self.facts(args, path)
        selected.chmod(0o4755)
        self.assertNotEqual(old, self.facts(args, path))
        self.file("a/program")
        self.assertNotEqual(old, self.facts(args, path))

    def test_private_symlink_and_relative_path_escape_are_denied(self) -> None:
        secret = self.private / "program"; secret.write_text("secret"); secret.chmod(0o755)
        (self.work / "program").symlink_to(secret)
        for args in [
            {"argv": ["./program"]}, {"argv": ["program"], "env": {"PATH": "../private"}},
            {"argv": [str(secret)]}, {"argv": ["program"], "env": {"PATH": str(self.private)}},
        ]:
            with self.subTest(args=args), self.assertRaises(ReCTMError) as caught:
                self.facts(args)
            self.assertEqual(caught.exception.code, "NATIVE_EXECUTABLE_PATH_DENIED")

    def test_unresolved_error_has_recovery_without_command_or_secret(self) -> None:
        with self.assertRaises(ReCTMError) as caught:
            self.facts({"argv": ["private-name-do-not-print"], "env": {"API_TOKEN": "secret"}})
        payload = caught.exception.to_payload()
        self.assertEqual(payload["code"], "NATIVE_EXECUTABLE_UNRESOLVED")
        self.assertEqual(payload["details"]["unresolved_candidate_indexes"], [0])
        self.assertNotIn("private-name", str(payload))
        self.assertNotIn("secret", str(payload))

    def test_runtime_revalidates_after_building_sandbox_and_never_starts_changed_file(self) -> None:
        selected = self.file("program")
        backend = BubblewrapExecBackend(host_path="/workspace")
        backend.attestation = {"hard_isolation": True, "private_vault_mounted": False}
        runtime = NativeRuntime(self.workspace, NativeMode.DANGEROUS,
                                DebugEventBus(self.root / "debug", self.private), exec_backend=backend)
        def build(**kwargs: object) -> list[str]:
            selected.chmod(0o4755)
            return ["not-launched"]
        try:
            with mock.patch("re_ctm.native._bubblewrap_command", side_effect=build), mock.patch.object(runtime.command_manager, "start") as start:
                with self.assertRaises(ReCTMError) as caught:
                    runtime.exec_command(argv=["program"])
                self.assertEqual(caught.exception.code, "NATIVE_EXECUTABLE_CHANGED")
                start.assert_not_called()
        finally:
            runtime.close()

    def test_external_fallback_default_and_nonzero_outcome(self) -> None:
        class Backend:
            attestation = {"hard_isolation": True, "private_vault_mounted": False}
            received: dict = {}
            def execute(self, **kwargs: object) -> dict:
                self.received = kwargs
                return {"status": "exited", "exit_code": 7, "signal": None, "timed_out": False}
        backend = Backend()
        events = []
        runtime = NativeRuntime(self.workspace, NativeMode.DANGEROUS,
                                DebugEventBus(self.root / "debug", self.private, observer=events.append), exec_backend=backend)
        try:
            result = runtime.exec_command(argv=["true"])
            self.assertEqual(result["operation_outcome"], "exited_nonzero")
            self.assertEqual(backend.received["timeout_ms"], 300000)
            self.assertEqual(sum(event.event_type == "native.command_terminal" for event in events), 1)
            with self.assertRaises(ReCTMError) as caught:
                runtime.exec_command(argv=["true"], env={"PATH": "/usr/bin"})
            self.assertEqual(caught.exception.code, "NATIVE_EXEC_OPTIONS_UNSUPPORTED")
        finally:
            runtime.close()


class WorkflowProtocolConfigTests(unittest.TestCase):
    def test_protocol_defaults_three_and_accepts_only_explicit_two_or_three(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"; work.mkdir()
            settings = Settings(work, root / "data", root / "data/private", root / "data/debug")
            self.assertEqual(settings.workflow_protocol_version, 3)
            settings.validate()
            dataclasses.replace(settings, workflow_protocol_version=2).validate()
            for value in (1, 4, True, "3"):
                with self.assertRaises(ReCTMError) as caught:
                    dataclasses.replace(settings, workflow_protocol_version=value).validate()
                self.assertEqual(caught.exception.code, "INVALID_WORKFLOW_PROTOCOL")
            env = {"RE_CTM_WORKSPACE": str(work), "RE_CTM_DATA_ROOT": str(root / "data"), "RE_CTM_NATIVE_EXEC_BACKEND": "disabled"}
            for value in ("2", "3"):
                with mock.patch.dict("os.environ", {**env, "RE_CTM_WORKFLOW_PROTOCOL_VERSION": value}, clear=True):
                    self.assertEqual(Settings.from_env().workflow_protocol_version, int(value))
            for value in ("1", "4", "", "true", "03"):
                with mock.patch.dict("os.environ", {**env, "RE_CTM_WORKFLOW_PROTOCOL_VERSION": value}, clear=True), self.assertRaises(ReCTMError):
                    Settings.from_env()


if __name__ == "__main__":
    unittest.main()
