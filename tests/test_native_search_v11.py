from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.debug import DebugEventBus
from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.native import NativeRuntime, NativeWorkspace


class NativeSearchV11Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / "workspace"; self.work.mkdir()
        self.private = self.root / "private"; self.private.mkdir()
        self.workspace = NativeWorkspace(self.work, private_root=self.private)
        self.runtime = NativeRuntime(self.workspace, NativeMode.DANGEROUS,
                                     DebugEventBus(self.root / "debug", self.private))

    def tearDown(self) -> None:
        self.runtime.close(); self.temp.cleanup()

    def test_explicit_file_hidden_selection_and_both_glob_names(self) -> None:
        (self.work / ".hidden").write_text("first\nneedle\nlast\n")
        result = self.runtime.search_text(query="needle", path=".hidden", context_lines=1)
        self.assertEqual(result["matches"][0]["line"], 2)
        self.assertEqual(result["matches"][0]["before"], ["first"])
        self.assertEqual(result["matches"][0]["after"], ["last"])
        self.assertFalse(self.runtime.search_text(query="needle", path=".")["matches"])
        (self.work / "nested").mkdir()
        (self.work / "nested/a.txt").write_text("needle")
        for glob in ("*.txt", "nested/*.txt"):
            self.assertEqual(self.runtime.search_text(query="needle", path="nested/a.txt", glob=glob)["total_matches"], 1)
        self.assertEqual(self.runtime.search_text(query="needle", path="nested/a.txt", exclude_globs=["*.txt"])["total_matches"], 0)

    def test_utf8_preview_and_context_are_byte_bounded_without_replacement(self) -> None:
        (self.work / "a").write_text("你好世界\nneedle世界\n🙂🙂🙂\n")
        match = self.runtime.search_text(query="needle", path="a", context_lines=1, max_preview_bytes=7)["matches"][0]
        self.assertEqual(match["preview"], "needle")
        self.assertEqual(match["before"], ["你好"])
        self.assertEqual(match["after"], ["🙂"])
        self.assertTrue(all(len(text.encode()) <= 7 for text in [match["preview"], *match["before"], *match["after"]]))

    def test_selected_path_parent_swap_cannot_search_private_text(self) -> None:
        (self.work / "dir").mkdir()
        (self.work / "dir/a").write_text("public")
        (self.private / "a").write_text("PRIVATE SECRET")
        original = self.workspace.resolve_existing
        calls = 0
        def resolve(path: str = "."):
            nonlocal calls
            result = original(path)
            calls += 1
            if calls == 2:
                (self.work / "dir").rename(self.work / "saved")
                (self.work / "dir").symlink_to(self.private)
            return result
        with mock.patch.object(self.workspace, "resolve_existing", side_effect=resolve), self.assertRaises(ReCTMError):
            self.runtime.search_text(query="PRIVATE", path="dir/a")


if __name__ == "__main__":
    unittest.main()
