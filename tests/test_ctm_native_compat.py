from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from re_ctm.debug import DebugEventBus
from re_ctm.enums import NativeMode
from re_ctm.native import BubblewrapExecBackend, NativeRuntime, NativeWorkspace
from re_ctm.native_catalog import NATIVE_TOOL_DECLARATIONS, TOOL_CONTRACT_VERSION
from re_ctm.tools import validate_tool_arguments
from re_ctm.errors import ReCTMError
from re_ctm.tools import (
    CTM_NATIVE_TOOL_NAMES,
    LEGACY_RETHLAS_TOOL_NAMES,
    PUBLIC_TOOL_NAMES,
    RETHLAS_TOOL_NAMES,
    TOOL_SPECS,
)


class CTMNativeCompatibilityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.workspace = root / "workspace"
        self.data_root = root / "data"
        self.private = self.data_root / "private"
        self.workspace.mkdir()
        self.private.mkdir(parents=True)
        (self.workspace / "hello.txt").write_text("hello\nworld\n", encoding="utf-8")
        self.debug = DebugEventBus(root / "debug.jsonl", self.private, enabled=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _runtime(self, *, bubblewrap: bool = False) -> NativeRuntime:
        workspace = NativeWorkspace(self.workspace, private_root=self.private)
        if not bubblewrap:
            return NativeRuntime(workspace, NativeMode.DANGEROUS, self.debug)
        if shutil.which("bwrap") is None:
            self.skipTest("bubblewrap is unavailable")
        backend = BubblewrapExecBackend()
        backend.attest(
            workspace=self.workspace,
            forbidden_paths=(self.data_root, self.private),
        )
        return NativeRuntime(workspace, NativeMode.DANGEROUS, self.debug, exec_backend=backend)

    def test_fixed_catalog_is_ctm_superset(self) -> None:
        self.assertEqual(CTM_NATIVE_TOOL_NAMES, (
            "server_info", "check_exec_environment", "read_file", "list_dir", "list_files",
            "search_text", "apply_patch", "apply_changes", "exec_command", "write_stdin", "kill_command",
            "read_output", "git_status", "git_diff", "git_log", "git_show", "git_blame",
            "request_permissions", "view_image",
        ))
        self.assertEqual(RETHLAS_TOOL_NAMES, (
            "rethlas_start", "rethlas_step", "rethlas_inspect", "rethlas_retrieve",
            "rethlas_control", "rethlas_artifact",
        ))
        self.assertEqual(LEGACY_RETHLAS_TOOL_NAMES, (
            "rethlas_start", "rethlas_next", "rethlas_read", "rethlas_write", "rethlas_search",
            "rethlas_retrieve", "rethlas_commit", "rethlas_status", "rethlas_steer",
            "rethlas_resume", "rethlas_cancel", "rethlas_get_artifact", "rethlas_export_final",
        ))
        self.assertEqual(len(CTM_NATIVE_TOOL_NAMES), 19)
        self.assertEqual(len(RETHLAS_TOOL_NAMES), 6)
        self.assertEqual(len(PUBLIC_TOOL_NAMES), 25)
        self.assertEqual(PUBLIC_TOOL_NAMES[:19], CTM_NATIVE_TOOL_NAMES)
        self.assertEqual(len(LEGACY_RETHLAS_TOOL_NAMES), 13)
        retired = set(LEGACY_RETHLAS_TOOL_NAMES) - set(RETHLAS_TOOL_NAMES)
        self.assertTrue(retired.isdisjoint(TOOL_SPECS))
        self.assertEqual(TOOL_CONTRACT_VERSION, "mtm-tools-v11")
        contract = [TOOL_SPECS[name].definition(name) for name in CTM_NATIVE_TOOL_NAMES]
        self.assertEqual(contract, NATIVE_TOOL_DECLARATIONS)
        for definition in contract:
            output = definition["outputSchema"]
            self.assertEqual(output["required"], ["ok"])
            self.assertTrue(output["additionalProperties"])
            self.assertGreater(len(output["properties"]), 2)

        expected_required = {
            "read_file": {"path"},
            "apply_patch": {"patch"},
            "apply_changes": {"changes"},
            "exec_command": set(),
            "write_stdin": {"command_id"},
            "kill_command": {"command_id"},
            "read_output": {"output_ref"},
            "git_blame": {"path"},
            "view_image": {"path"},
        }
        for name, required in expected_required.items():
            self.assertEqual(set(TOOL_SPECS[name].input_schema.get("required", [])), required)

    def test_v11_keeps_workspace_extensions_and_exclusive_command_forms(self) -> None:
        read = TOOL_SPECS["read_file"].input_schema["properties"]
        self.assertEqual(read["line_byte_offset"]["minimum"], 0)
        self.assertEqual(read["max_lines"]["default"], 500)
        for digest in ("a" * 64, "A" * 64):
            validate_tool_arguments("read_file", {"path": "hello.txt", "expected_sha256": digest})
        for name in ("git_status", "git_diff", "git_log", "git_show", "git_blame"):
            self.assertIn("repo_path", TOOL_SPECS[name].input_schema["properties"])
        self.assertIn("paths", TOOL_SPECS["git_log"].input_schema["properties"])
        validate_tool_arguments("exec_command", {"argv": ["printf", ""]})
        validate_tool_arguments("exec_command", {"cmd": "printf ok"})
        for arguments in ({"cmd": "true", "argv": ["true"]}, {"argv": [""]}):
            with self.assertRaises(ReCTMError):
                validate_tool_arguments("exec_command", arguments)
        self.assertEqual(TOOL_SPECS["exec_command"].input_schema["properties"]["timeout_ms"]["default"], 300000)
        self.assertTrue(TOOL_SPECS["git_diff"].input_schema["properties"]["include_untracked"]["default"])

    def test_ctm_file_directory_search_patch_and_git_surfaces(self) -> None:
        runtime = self._runtime()
        listed = runtime.list_dir(path=".", recursive=True, max_depth=2)
        self.assertTrue(any(item["path"] == "hello.txt" for item in listed["entries"]))

        searched = runtime.search_text(
            query=r"h.llo",
            regex=True,
            path=".",
            context_lines=1,
        )
        self.assertEqual(searched["matches"][0]["line"], 1)

        patched = runtime.apply_patch(
            patch="""*** Begin Patch
*** Update File: hello.txt
@@
-hello
+hi
 world
*** End Patch
"""
        )
        self.assertTrue(patched["clean"])
        self.assertEqual((self.workspace / "hello.txt").read_text(encoding="utf-8"), "hi\nworld\n")

        subprocess.run(["git", "init", "-q"], cwd=self.workspace, check=True)
        status = runtime.git_status(path=".")
        self.assertTrue(status["is_repo"])
        self.assertTrue(any(item["path"] == "hello.txt" for item in status["entries"]))

    def test_view_image_returns_mcp_image_payload(self) -> None:
        # 1x1 PNG; only the public image-return shape matters here.
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZlS8AAAAASUVORK5CYII="
        )
        (self.workspace / "pixel.png").write_bytes(png)
        runtime = self._runtime()
        result = runtime.view_image(path="pixel.png")
        self.assertEqual(result["mime_type"], "image/png")
        self.assertEqual(result["width"], 1)
        self.assertTrue(result["_mcp_image_data"])

    def test_bubblewrap_command_lifecycle_poll_read_and_kill(self) -> None:
        runtime = self._runtime(bubblewrap=True)
        try:
            started = runtime.exec_command(
                cmd="python3 -c 'import time; print(\"started\", flush=True); time.sleep(20)'",
                workdir=".",
                yield_time_ms=100,
                timeout_ms=30_000,
            )
            self.assertEqual(started["status"], "running")
            command_id = started["command_id"]
            self.assertIn("stdout", started["output_refs"])

            polled = runtime.write_stdin(command_id=command_id, chars="", yield_time_ms=200)
            self.assertEqual(polled["command_id"], command_id)

            output = runtime.read_output(output_ref=f"command:{command_id}:stdout", offset=0, limit=4096)
            self.assertIn("started", output["content"])

            killed = runtime.kill_command(command_id=command_id, signal="TERM", wait_ms=2000)
            self.assertIn(killed["status"], {"terminated", "killed", "exited"})
        finally:
            runtime.close()

    def test_bubblewrap_tty_write_stdin_interaction(self) -> None:
        runtime = self._runtime(bubblewrap=True)
        try:
            started = runtime.exec_command(
                cmd=(
                    "python3 -c 'import sys,time; print(\"ready\", flush=True); "
                    "x=sys.stdin.readline(); print(\"got:\"+x.strip(), flush=True); time.sleep(1)'"
                ),
                tty=True,
                yield_time_ms=100,
                timeout_ms=10_000,
            )
            command_id = started["command_id"]
            reply = runtime.write_stdin(
                command_id=command_id,
                chars="hello-lifecycle\n",
                yield_time_ms=1000,
                verbosity="full",
            )
            combined = str(reply.get("stdout", "")) + str(reply.get("stderr", ""))
            if "got:hello-lifecycle" not in combined:
                time.sleep(0.2)
                output = runtime.read_output(
                    output_ref=f"command:{command_id}:stdout",
                    offset=0,
                    limit=8192,
                )
                combined += output["content"]
            self.assertIn("got:hello-lifecycle", combined)
        finally:
            runtime.close()

    def test_internal_adapter_modes_remain_distinct_from_public_dangerous_profile(self) -> None:
        workspace = NativeWorkspace(self.workspace, private_root=self.private)
        safe = NativeRuntime(workspace, NativeMode.SAFE, self.debug)
        trusted = NativeRuntime(workspace, NativeMode.TRUSTED, self.debug)
        dangerous = NativeRuntime(workspace, NativeMode.DANGEROUS, self.debug)
        try:
            for cmd, permission in (
                ("curl https://example.com", "network"),
                ("echo $(pwd)", "shell_expansion"),
                ("python3 -c 'print(1)'", "inline_script"),
            ):
                with self.assertRaises(Exception) as denied:
                    safe.exec_command(cmd=cmd)
                self.assertEqual(denied.exception.code, "PERMISSION_REQUIRED")
                self.assertEqual(denied.exception.details["permission"], permission)

            # Trusted mode clears the safe-only network/shell/inline gates and
            # therefore reaches the fail-closed isolation boundary here.
            with self.assertRaises(Exception) as trusted_boundary:
                trusted.exec_command(cmd="python3 -c 'print(1)'")
            self.assertEqual(trusted_boundary.exception.code, "NATIVE_ISOLATION_REQUIRED")

            for runtime in (safe, trusted):
                with self.assertRaises(Exception) as destructive:
                    runtime.exec_command(cmd="git reset --hard HEAD")
                self.assertEqual(destructive.exception.code, "PERMISSION_REQUIRED")
                self.assertEqual(destructive.exception.details["permission"], "destructive_command")

                with self.assertRaises(Exception) as secret_env:
                    runtime.exec_command(cmd="echo ok", env={"API_TOKEN": "secret"})
                self.assertEqual(secret_env.exception.code, "PERMISSION_REQUIRED")
                self.assertEqual(secret_env.exception.details["permission"], "sensitive_env")

            with self.assertRaises(Exception) as dangerous_boundary:
                dangerous.exec_command(cmd="git reset --hard HEAD")
            self.assertEqual(dangerous_boundary.exception.code, "NATIVE_ISOLATION_REQUIRED")
        finally:
            safe.close()
            trusted.close()
            dangerous.close()


if __name__ == "__main__":
    unittest.main()
