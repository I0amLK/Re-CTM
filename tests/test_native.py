from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from re_ctm.debug import DebugEventBus
from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.native import NativeRuntime, NativeWorkspace


class NativeRuntimeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.workspace = root / "workspace"
        self.private = root / "private"
        self.workspace.mkdir()
        self.private.mkdir()
        (self.workspace / "hello.txt").write_text("hello\nworld\n", encoding="utf-8")
        (self.private / "secret.json").write_text('{"secret":true}', encoding="utf-8")
        debug = DebugEventBus(root / "debug.jsonl", self.private, enabled=True)
        native_workspace = NativeWorkspace(self.workspace, private_root=self.private)
        self.runtime = NativeRuntime(native_workspace, NativeMode.DANGEROUS, debug)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_dangerous_does_not_change_path_boundary(self) -> None:
        self.assertEqual(self.runtime.read_file(path="hello.txt")["content"], "hello\nworld\n")
        with self.assertRaises(ReCTMError) as absolute:
            self.runtime.read_file(path=str(self.private / "secret.json"))
        self.assertEqual(absolute.exception.code, "ABSOLUTE_PATH_DENIED")
        with self.assertRaises(ReCTMError) as traversal:
            self.runtime.read_file(path="../private/secret.json")
        self.assertEqual(traversal.exception.code, "PATH_OUTSIDE_WORKSPACE")

    def test_dangerous_exec_fails_closed_without_isolation(self) -> None:
        with self.assertRaises(ReCTMError) as denied:
            self.runtime.exec_command(argv=["cat", "hello.txt"])
        self.assertEqual(denied.exception.code, "NATIVE_ISOLATION_REQUIRED")

    def test_atomic_editor_and_baseline(self) -> None:
        original = hashlib.sha256(b"hello\nworld\n").hexdigest()
        result = self.runtime.apply_patch(
            operations=[
                {
                    "op": "update",
                    "path": "hello.txt",
                    "expected_sha256": original,
                    "content": "updated\n",
                },
                {"op": "add", "path": "new.txt", "content": "new\n"},
            ]
        )
        self.assertEqual(len(result["affected_files"]), 2)
        self.assertEqual((self.workspace / "hello.txt").read_text(), "updated\n")
        self.assertEqual((self.workspace / "new.txt").read_text(), "new\n")
        with self.assertRaises(ReCTMError) as conflict:
            self.runtime.apply_patch(
                operations=[
                    {
                        "op": "update",
                        "path": "hello.txt",
                        "expected_sha256": original,
                        "content": "stale\n",
                    }
                ]
            )
        self.assertEqual(conflict.exception.code, "PATCH_CONFLICT")

    def test_automatic_verified_export_is_idempotent_and_non_overwriting(self) -> None:
        content = "\\documentclass{article}\n\\begin{document}ok\\end{document}\n"
        created = self.runtime.ensure_verified_latex(
            path="rethlas-output/run-test/proof_verified.tex",
            content=content,
        )
        self.assertEqual(created["status"], "created")
        repeated = self.runtime.ensure_verified_latex(
            path="rethlas-output/run-test/proof_verified.tex",
            content=content,
        )
        self.assertEqual(repeated["status"], "unchanged")
        target = self.workspace / "rethlas-output" / "run-test" / "proof_verified.tex"
        target.write_text("different\n", encoding="utf-8")
        with self.assertRaises(ReCTMError) as conflict:
            self.runtime.ensure_verified_latex(
                path="rethlas-output/run-test/proof_verified.tex",
                content=content,
            )
        self.assertEqual(conflict.exception.code, "EXPORT_PATH_CONFLICT")


if __name__ == "__main__":
    unittest.main()
