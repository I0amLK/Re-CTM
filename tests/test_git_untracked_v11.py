from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from re_ctm import ctm_compat
from re_ctm.errors import ReCTMError
from re_ctm.native import NativeWorkspace


@unittest.skipUnless(shutil.which("git"), "Git is required for disposable repository fixtures")
class GitUntrackedV11TestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "workspace"
        self.private = self.base / "private"
        self.root.mkdir()
        self.private.mkdir()
        self.workspace = NativeWorkspace(self.root, private_root=self.private)
        self.git("init", "--quiet")
        (self.root / "tracked.txt").write_text("before\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "--quiet", "-m", "disposable fixture")

    def git(self, *args: str) -> None:
        env = {"PATH": os.defpath, "HOME": str(self.base), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        subprocess.run(["git", "--literal-pathspecs", "-C", str(self.root), "-c", "core.hooksPath=/dev/null", *args],
                       check=True, capture_output=True, env=env)

    def diff(self, **args: object) -> dict:
        return ctm_compat.git_diff(self.workspace, args)

    def repository(self):
        return ctm_compat._select_repository(self.workspace, {})

    def test_default_unstaged_only_and_opt_out(self) -> None:
        (self.root / "fresh.txt").write_text("fresh\n", encoding="utf-8")
        result = self.diff(path="fresh.txt")
        self.assertIn("+fresh\n", result["diff"])
        self.assertEqual(result["files"], ["fresh.txt"])
        self.assertFalse(result["truncated"])
        self.assertEqual(self.diff(path="fresh.txt", include_untracked=False)["diff"], "")
        self.assertEqual(self.diff(path="fresh.txt", staged=True, unstaged=False)["diff"], "")
        self.assertEqual(self.diff(path="fresh.txt", staged=False, unstaged=False)["diff"], "")
        self.assertIn("+fresh", self.diff(path="fresh.txt", staged=True)["diff"])

    def test_literal_filters_and_ignored_files(self) -> None:
        for name, text in [("*.txt", "literal"), ("fresh.txt", "sibling"), ("ignored.txt", "secret"), (".gitignore", "ignored.txt\n")]:
            (self.root / name).write_text(text, encoding="utf-8")
        result = self.diff(path="*.txt")
        self.assertEqual(result["files"], ["*.txt"])
        self.assertIn("+literal", result["diff"])
        self.assertNotIn("sibling", result["diff"])
        self.assertEqual(self.diff(path="ignored.txt")["diff"], "")
        self.assertNotIn("secret", self.diff()["diff"])

    def test_exact_names_do_not_depend_on_quoted_headers_or_content(self) -> None:
        for name in ["a b.txt", 'quote".txt', "line\nbreak.txt", "unicode中.txt", "back\\slash.txt"]:
            with self.subTest(name=name):
                (self.root / name).write_text("中🙂\n++ b/fake-name\n-- a/forged\n", encoding="utf-8")
                result = self.diff(path=name)
                self.assertEqual(result["files"], [name])
                for budget in [1, 2, 3, 100]:
                    short = self.diff(path=name, max_bytes=budget)
                    self.assertLessEqual(len(short["diff"].encode("utf-8")), budget)
                    self.assertNotIn("\ufffd", short["diff"])
                    self.assertEqual(short["files"], [name])
                    self.assertTrue(short["truncated"])

    def test_binary_empty_executable_and_missing_final_newline(self) -> None:
        for name, data in [("nul.bin", b"abc\0x"), ("invalid.bin", b"\xff"), ("empty", b""), ("no-newline", b"tail")]:
            (self.root / name).write_bytes(data)
            result = self.diff(path=name)
            self.assertEqual(result["files"], [name])
            self.assertFalse(result["truncated"])
            if name.endswith(".bin"):
                self.assertIn("Binary files /dev/null", result["diff"])
            elif name == "no-newline":
                self.assertIn("+tail\n\\ No newline at end of file\n", result["diff"])
        (self.root / "empty").chmod(0o755)
        self.assertIn("new file mode 100755", self.diff(path="empty")["diff"])

    def test_combined_output_bound_and_exact_budget(self) -> None:
        (self.root / "tracked.txt").write_text("staged\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        (self.root / "tracked.txt").write_text("unstaged\n", encoding="utf-8")
        (self.root / "fresh").write_text("中🙂\n" * 50, encoding="utf-8")
        whole = self.diff(staged=True)
        self.assertIn("+staged", whole["diff"])
        self.assertIn("+unstaged", whole["diff"])
        self.assertIn("+中🙂", whole["diff"])
        self.assertEqual(whole["files"], ["fresh", "tracked.txt"])
        size = len(whole["diff"].encode("utf-8"))
        exact = self.diff(staged=True, max_bytes=size)
        self.assertEqual(exact["diff"], whole["diff"])
        self.assertFalse(exact["truncated"])
        for budget in [1, 100, size - 1]:
            short = self.diff(staged=True, max_bytes=budget)
            self.assertLessEqual(len(short["diff"].encode("utf-8")), budget)
            self.assertTrue(short["truncated"])

    def test_link_and_nonregular_refusals(self) -> None:
        secret = self.private / "secret"
        secret.write_text("not disclosed", encoding="utf-8")
        os.link(secret, self.root / "hard")
        (self.root / "sym").symlink_to(secret)
        (self.root / "internal").symlink_to(self.root / "tracked.txt")
        for name in ["hard", "sym", "internal"]:
            with self.subTest(name=name), self.assertRaises(ReCTMError) as error:
                self.diff(path=name)
            self.assertEqual(error.exception.category, "security")
            self.assertNotIn("not disclosed", str(error.exception.to_payload()))
        os.mkfifo(self.root / "fifo")
        with self.assertRaises(ReCTMError):
            ctm_compat._read_untracked_file(self.workspace, self.repository(), "fifo", time.monotonic() + 15)
        (self.root / "alias").symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(ReCTMError):
            ctm_compat._read_untracked_file(self.workspace, self.repository(), "alias/secret", time.monotonic() + 15)

    def test_file_changes_and_gaining_hardlink_fail_closed(self) -> None:
        source = self.root / "racy"
        source.write_text("before", encoding="utf-8")
        repo = self.repository()
        original_read = os.read
        for change in ["bytes", "hardlink"]:
            source.write_text("before", encoding="utf-8")
            changed = False

            def changing_read(fd: int, size: int) -> bytes:
                nonlocal changed
                data = original_read(fd, size)
                if data and not changed:
                    changed = True
                    if change == "bytes":
                        source.write_text("after!", encoding="utf-8")
                    else:
                        os.link(source, self.private / "new-link")
                return data

            with self.subTest(change=change), patch.object(ctm_compat.os, "read", side_effect=changing_read):
                with self.assertRaises(ReCTMError) as error:
                    ctm_compat._read_untracked_file(self.workspace, repo, "racy", time.monotonic() + 15)
                self.assertEqual(error.exception.code, "GIT_UNTRACKED_CHANGED")

    def test_captured_bytes_survive_later_mutation_without_reread(self) -> None:
        source = self.root / "captured"
        source.write_text("captured\n", encoding="utf-8")
        original = ctm_compat._read_untracked_file

        def capture_then_change(*args):
            result = original(*args)
            source.write_text("later-content\n", encoding="utf-8")
            return result

        with patch.object(ctm_compat, "_read_untracked_file", side_effect=capture_then_change):
            result = self.diff(path="captured")
        self.assertIn("+captured\n", result["diff"])
        self.assertNotIn("later-content", result["diff"])

    def test_complete_listing_required_before_any_read(self) -> None:
        repo = self.repository()
        for listing in [ctm_compat._GitOutput(0, "fragment", ""),
                        ctm_compat._GitOutput(0, "valid\0", "", stdout_truncated=True),
                        ctm_compat._GitOutput(0, "first\0\0", "")]:
            with self.subTest(listing=listing), patch.object(ctm_compat, "_git", return_value=listing):
                with patch.object(ctm_compat, "_read_untracked_file") as read:
                    with self.assertRaises(ReCTMError):
                        ctm_compat._git_untracked_diff(self.workspace, repo, [], 100)
                    read.assert_not_called()

    def test_non_utf8_filename_fails_closed(self) -> None:
        path = os.fsencode(self.root) + b"/bad-\xff"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(descriptor)
        with self.assertRaises(ReCTMError) as error:
            self.diff()
        self.assertEqual(error.exception.code, "BINARY_FILE")

    def test_file_count_pre_read_size_and_processing_window_bounds(self) -> None:
        for number in range(129):
            (self.root / f"entry-{number:03d}").write_bytes(b"x\n")
        result = self.diff()
        self.assertEqual(len(result["files"]), 128)
        self.assertTrue(result["truncated"])
        huge = self.root / "huge"
        with huge.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        result = self.diff(path="huge")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["files"], [])
        self.assertEqual(result["diff"], "")
        with patch.object(ctm_compat, "_UNTRACKED_WINDOW_SECONDS", -1):
            with patch.object(ctm_compat, "_read_untracked_file") as read:
                result = self.diff(path="entry-000")
                read.assert_not_called()
                self.assertTrue(result["truncated"])

    def test_flags_reject_non_boolean_values(self) -> None:
        for flag in ("staged", "unstaged", "include_untracked"):
            with self.subTest(flag=flag), self.assertRaises(ReCTMError):
                self.diff(**{flag: "false"})


if __name__ == "__main__":
    unittest.main()
