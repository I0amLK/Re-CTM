from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from re_ctm.app import build_application
from re_ctm.config import Settings
from re_ctm.enums import LatexPolicy
from re_ctm.native_catalog import NATIVE_TOOL_NAMES
from re_ctm.oauth import OAuthPrincipal
from re_ctm.tools import TOOL_SPECS, _validate_schema_value


class NativeOutputContractV11Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / "workspace"; self.work.mkdir()
        data = self.root / "data"
        self.app = build_application(Settings(
            workspace=self.work, data_root=data, private_root=data / "private", debug_root=data / "debug",
            native_exec_backend="disabled", latex_policy=LatexPolicy.STATIC_ONLY,
            token_secret=b"t" * 32, capability_secret=b"c" * 32,
            oauth_password="fixture-password",
        ))
        self.tools = self.app.tools
        self.native = self.tools.native
        self.principal = OAuthPrincipal("owner", "client", "mcp")
        self.covered: set[str] = set()

    def tearDown(self) -> None:
        self.app.close(); self.temp.cleanup()

    def call(self, name: str, arguments: dict | None = None, *, ok: bool = True) -> dict:
        result = self.tools.call(name, arguments or {}, self.principal)
        content = result["structuredContent"]
        _validate_schema_value(content, TOOL_SPECS[name].output_schema, path=f"{name}.structuredContent")
        self.assertEqual(content["ok"], ok, (name, content))
        self.covered.add(name)
        return content

    def test_all_nineteen_actual_success_payloads_match_specialized_outputs(self) -> None:
        self.call("server_info")
        self.call("check_exec_environment")
        self.call("apply_changes", {"changes": [{"action": "create", "path": "a.txt", "content": "one\ntwo\n"}]})
        read = self.call("read_file", {"path": "a.txt", "max_bytes": 3})
        self.assertTrue(read["truncated"])
        self.call("read_file", read["next_action"]["arguments"])
        noop = self.call("apply_changes", {"changes": [{"action": "write", "path": "a.txt", "content": "one\ntwo\n", "revision": read["revision"]}]})
        self.assertTrue(noop["already_applied"])
        self.call("apply_patch", {"patch": "*** Begin Patch\n*** Update File: a.txt\n@@\n-one\n+first\n*** End Patch\n"})
        self.call("list_dir")
        self.call("list_files")
        self.call("search_text", {"query": "first", "path": "a.txt"})
        nongit = self.call("git_status")
        self.assertFalse(nongit["is_repo"])
        self.assertNotIn("head", nongit)
        self.call("git_diff")
        self.call("git_log")
        self.call("git_show")
        self.call("git_blame", {"path": "a.txt"})
        self.call("request_permissions", {"tool_name": "apply_patch", "permission": "write_generated_or_ignored", "reason": "fixture", "arguments": {}})
        (self.work / "pixel.png").write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZlS8AAAAASUVORK5CYII="))
        image = self.call("view_image", {"path": "pixel.png"})
        self.assertEqual(image["width"], 1)

        class SynchronousFixture:
            attestation = {"hard_isolation": True, "private_vault_mounted": False}
            def execute(self, **arguments: object) -> dict:
                return {"status": "exited", "exit_code": 7, "signal": None, "timed_out": False,
                        "stdout": "fixture", "stderr": "", "elapsed_ms": 1}
        self.native.exec_backend = SynchronousFixture()
        command = self.call("exec_command", {"argv": ["true"]})
        self.assertEqual(command["operation_outcome"], "exited_nonzero")

        # Process-manager fixtures test real output/lifecycle payloads; they are
        # not a public unisolated backend or evidence of Bubblewrap attestation.
        completed = self.native.command_manager.start(
            [sys.executable, "-c", "print('fixture-output')"], env={}, yield_time_ms=1000,
            max_output_bytes=65536, stdin_text="", tty=False, verbosity="full", preview_bytes=4096,
        )
        self.call("write_stdin", {"command_id": completed["command_id"], "yield_time_ms": 0})
        self.call("read_output", {"output_ref": completed["output_refs"]["stdout"]})
        running = self.native.command_manager.start(
            [sys.executable, "-c", "import time; time.sleep(10)"], env={}, yield_time_ms=0,
            max_output_bytes=65536, stdin_text="", tty=False, verbosity="full", preview_bytes=4096,
        )
        self.call("kill_command", {"command_id": running["command_id"], "wait_ms": 1000})
        self.assertEqual(self.covered, set(NATIVE_TOOL_NAMES))

    def test_git_unborn_committed_detached_and_bounded_output_payloads(self) -> None:
        def git(*arguments: str) -> None:
            subprocess.run(["git", "-C", str(self.work), *arguments], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        git("init", "-q")
        unborn = self.call("git_status")
        self.assertEqual(unborn["head"], "")
        (self.work / "a.txt").write_text("one\ntwo\n")
        git("add", "a.txt")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        git("checkout", "--detach", "HEAD")
        self.call("git_status")
        self.call("git_log")
        self.call("git_show", {"max_bytes": 5})
        blame = self.call("git_blame", {"path": "a.txt", "max_lines": 1})
        self.assertTrue(blame["truncated"])
        self.call("git_blame", blame["next_action"]["arguments"])
        (self.work / "a.txt").write_text("changed\ntwo\n")
        (self.work / "new").write_text("untracked\n")
        self.call("git_diff", {"max_bytes": 50})

    def test_all_nineteen_error_payloads_and_runtime_errors_match_outputs(self) -> None:
        for name in NATIVE_TOOL_NAMES:
            with self.subTest(name=name):
                self.call(name, {"not_a_tool_argument": True}, ok=False)
        for name, arguments in [
            ("read_file", {"path": "missing"}), ("apply_changes", {"changes": [{"action": "delete", "path": "missing"}]}),
            ("exec_command", {"argv": ["true"]}), ("write_stdin", {"command_id": "missing"}),
            ("read_output", {"output_ref": "command:missing:stdout"}), ("kill_command", {"command_id": "missing"}),
        ]:
            with self.subTest(name=name):
                self.call(name, arguments, ok=False)


if __name__ == "__main__":
    unittest.main()
