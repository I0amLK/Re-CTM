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
from re_ctm.tools import CTM_NATIVE_TOOL_NAMES, RETHLAS_TOOL_NAMES, TOOL_SPECS


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
        self.assertEqual(len(CTM_NATIVE_TOOL_NAMES), 18)
        self.assertEqual(len(RETHLAS_TOOL_NAMES), 13)
        self.assertEqual(tuple(TOOL_SPECS), CTM_NATIVE_TOOL_NAMES + RETHLAS_TOOL_NAMES)
        self.assertEqual(len(TOOL_SPECS), 31)
        contract = [TOOL_SPECS[name].definition(name) for name in CTM_NATIVE_TOOL_NAMES]
        contract_digest = hashlib.sha256(
            json.dumps(
                contract,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            contract_digest,
            "17896146c5c024a2f81174b5869e9861b452419066500ac4e0a0c1b32d442ab4",
        )

        expected_required = {
            "read_file": {"path"},
            "apply_patch": {"patch"},
            "exec_command": {"cmd"},
            "write_stdin": {"command_id"},
            "kill_command": {"command_id"},
            "read_output": {"output_ref"},
            "git_blame": {"path"},
            "view_image": {"path"},
        }
        for name, required in expected_required.items():
            self.assertEqual(set(TOOL_SPECS[name].input_schema.get("required", [])), required)

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

    def test_ctm_permission_modes_keep_safe_trusted_dangerous_distinct(self) -> None:
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
