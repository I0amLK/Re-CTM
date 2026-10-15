from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.debug import DebugEventBus
from re_ctm.enums import NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.native_changes import MAX_BYTES, edit_lines


def revision(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class NativeChangesV11Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.private = self.root / "private"
        self.workspace.mkdir(); self.private.mkdir()
        self.runtime = NativeRuntime(
            NativeWorkspace(self.workspace, private_root=self.private), NativeMode.DANGEROUS,
            DebugEventBus(self.root / "debug.jsonl", self.private),
        )
        self.editor = self.runtime.editor

    def tearDown(self) -> None:
        self.runtime.close()
        self.temp.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
        return path

    def apply(self, *changes: dict, **kwargs: object) -> dict:
        return self.runtime.apply_changes(changes=list(changes), **kwargs)

    def test_all_six_actions_revision_evidence_and_copy_inode(self) -> None:
        self.apply({"action": "create", "path": "a", "content": "one\ntwo\n"})
        source = self.workspace / "a"
        source.chmod(0o750)
        inode = source.stat().st_ino
        copied = self.apply({"action": "copy", "path": "a", "revision": revision("one\ntwo\n"), "destination": "b"})
        self.assertEqual(source.stat().st_ino, inode)
        self.assertEqual(len(copied["affected_files"]), 1)
        self.assertEqual((self.workspace / "b").stat().st_mode & 0o777, 0o750)
        changed = self.apply({"action": "edit", "path": "b", "revision": revision("one\ntwo\n"),
                              "edits": [{"op": "replace", "start_line": 2, "content": "three"}]})
        self.assertEqual((self.workspace / "b").read_bytes(), b"one\nthree\n")
        self.assertEqual((changed["additions"], changed["removals"]), (1, 1))
        self.assertEqual(changed["affected_files"][0]["revision"], revision("one\nthree\n"))
        moved = self.apply({"action": "move", "path": "b", "revision": revision("one\nthree\n"), "destination": "dir/c"})
        self.assertEqual(len(moved["affected_files"]), 2)
        self.assertFalse((self.workspace / "b").exists())
        self.apply({"action": "write", "path": "dir/c", "revision": revision("one\nthree\n"), "content": "final"})
        self.apply({"action": "delete", "path": "dir/c", "revision": revision("final")})
        self.assertFalse((self.workspace / "dir/c").exists())

    def test_missing_write_creates_but_create_never_overwrites(self) -> None:
        self.apply({"action": "write", "path": "a", "content": "x"})
        with self.assertRaises(ReCTMError) as caught:
            self.apply({"action": "create", "path": "a", "content": "bad"})
        self.assertEqual(caught.exception.code, "PATH_EXISTS")
        self.assertEqual((self.workspace / "a").read_text(), "x")

    def test_stale_missing_revision_and_invalid_batch_make_no_changes(self) -> None:
        self.write("a", "one"); self.write("b", "two")
        cases = [
            [{"action": "write", "path": "a", "revision": revision("stale"), "content": "bad"}],
            [{"action": "delete", "path": "a"}],
            [{"action": "move", "path": "a", "revision": revision("one"), "destination": "b"}],
            [{"action": "write", "path": "a", "revision": revision("one"), "content": "bad"}, {"action": "delete", "path": "./a", "revision": revision("one")}],
            [{"action": "create", "path": "new", "content": "x"}, {"action": "delete", "path": "missing", "revision": revision("x")}],
            [{"action": "write", "path": "missing", "revision": revision("x"), "content": "bad"}],
        ]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ReCTMError):
                self.apply(*changes)
        self.assertEqual((self.workspace / "a").read_text(), "one")
        self.assertEqual((self.workspace / "b").read_text(), "two")
        self.assertFalse((self.workspace / "new").exists())

    def test_dry_run_noop_and_empty_edits_preserve_inodes(self) -> None:
        source = self.write("a", "one")
        inode = source.stat().st_ino
        result = self.apply({"action": "write", "path": "a", "revision": revision("one"), "content": "one"})
        self.assertTrue(result["already_applied"])
        self.assertEqual(result["additions"], 0)
        self.assertEqual(source.stat().st_ino, inode)
        result = self.apply({"action": "create", "path": "dir/new", "content": "x"}, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertFalse((self.workspace / "dir").exists())
        self.assertFalse(list(self.workspace.glob(".re-ctm-*")))

    def test_revision_comes_from_captured_bytes_and_not_post_commit_read(self) -> None:
        source = self.write("a", "one")
        prepared = self.editor.prepare_changes({"changes": [{"action": "write", "path": "a", "revision": revision("one"), "content": "two"}]})
        self.editor.commit(prepared)
        source.write_text("external")
        self.assertEqual(prepared.result["affected_files"][0]["revision"], revision("two"))

    def test_runtime_replay_is_historical_authenticated_and_shared_across_tools(self) -> None:
        scope = {"subject": "owner", "client_id": "client", "scope": "mcp"}
        request = {"changes": [{"action": "create", "path": "a", "content": "one"}], "idempotency_key": "key"}
        with self.assertRaises(ReCTMError) as caught:
            self.runtime.apply_changes(**request)
        self.assertEqual(caught.exception.code, "NATIVE_REPLAY_SCOPE_REQUIRED")
        result = self.runtime.apply_changes(**request, principal_scope=scope)
        self.write("a", "external")
        replay = self.runtime.apply_changes(**request, principal_scope=scope)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["affected_files"], result["affected_files"])
        self.assertEqual((self.workspace / "a").read_text(), "external")
        self.runtime.apply_patch(patch="*** Begin Patch\n*** Add File: b\n+two\n*** End Patch\n", idempotency_key="key", principal_scope=scope)
        self.assertEqual((self.workspace / "b").read_text(), "two\n")
        self.assertEqual(len(self.runtime.replay._entries), 2)
        with self.assertRaises(ReCTMError) as caught:
            self.runtime.apply_changes(**request, principal_scope={**scope, "client_id": "other"})
        self.assertEqual(caught.exception.code, "PATH_EXISTS")

    def test_cleanup_failure_warns_after_success_without_reexecuting(self) -> None:
        self.write("a", "one")
        unlink = os.unlink
        def fail_backup(path: object, *args: object, **kwargs: object) -> None:
            if isinstance(path, str) and path.startswith(".re-ctm-backup-"):
                raise OSError("injected cleanup failure")
            unlink(path, *args, **kwargs)
        with mock.patch("re_ctm.native_changes.os.unlink", side_effect=fail_backup):
            result = self.apply({"action": "write", "path": "a", "revision": revision("one"), "content": "two"})
        self.assertEqual((self.workspace / "a").read_text(), "two")
        self.assertEqual(len(result["warnings"]), 1)
        self.assertTrue(list(self.workspace.glob(".re-ctm-backup-*")))

    def test_patch_move_overwrites_destination_and_reports_source_then_update(self) -> None:
        self.write("a", "context\nnew\n")
        self.write("b", "old target")
        result = self.runtime.apply_patch(patch="*** Begin Patch\n*** Update File: a\n*** Move to: b\n*** End Patch\n")
        self.assertEqual(result["revision_algorithm"], "sha256")
        self.assertFalse(result["already_applied"])
        self.assertEqual(result["affected_files"][0]["operation"], "delete")
        self.assertEqual(result["affected_files"][0]["path"], "a")
        self.assertEqual(result["affected_files"][1]["operation"], "update")
        self.assertEqual(result["affected_files"][1]["old_path"], "a")
        self.assertEqual((self.workspace / "b").read_text(), "context\nnew\n")
        self.assertFalse((self.workspace / "a").exists())

    def test_mode_is_preserved_without_privileged_bits(self) -> None:
        source = self.write("a", "one")
        source.chmod(0o4755)
        self.apply({"action": "write", "path": "a", "revision": revision("one"), "content": "two"})
        self.assertEqual(source.stat().st_mode & 0o7777, 0o755)

    def test_symlink_hardlink_fifo_directory_and_parent_symlink_refused(self) -> None:
        secret = self.private / "secret"; secret.write_text("secret")
        (self.workspace / "sym").symlink_to(secret)
        (self.workspace / "parent").symlink_to(self.private, target_is_directory=True)
        os.link(secret, self.workspace / "hard")
        os.mkfifo(self.workspace / "fifo")
        (self.workspace / "directory").mkdir()
        for path in ["sym", "hard", "fifo", "directory", "parent/secret", "../private/secret"]:
            with self.subTest(path=path), self.assertRaises(ReCTMError):
                self.apply({"action": "copy", "path": path, "revision": revision("secret"), "destination": "copy"})
        self.assertFalse((self.workspace / "copy").exists())
        self.assertEqual(secret.read_text(), "secret")

    def test_parent_capture_is_descriptor_relative_and_never_follows_swapped_symlink(self) -> None:
        self.write("dir/a", "one")
        (self.private / "a").write_text("secret")
        original = self.editor._capture
        swapped = False
        def capture(path: str, **kwargs: object):
            nonlocal swapped
            if not swapped and path == "dir/a" and not kwargs:
                swapped = True
                (self.workspace / "dir").rename(self.workspace / "saved")
                (self.workspace / "dir").symlink_to(self.private, target_is_directory=True)
            return original(path, **kwargs)
        with mock.patch.object(self.editor, "_capture", side_effect=capture):
            with self.assertRaises((OSError, ReCTMError)):
                self.apply({"action": "copy", "path": "dir/a", "revision": revision("one"), "destination": "copy"})
        self.assertFalse((self.workspace / "copy").exists())

    def test_large_sources_and_aggregate_are_bounded_before_mutation(self) -> None:
        source = self.workspace / "large"
        with source.open("wb") as handle:
            handle.truncate(MAX_BYTES + 1)
        with self.assertRaises(ReCTMError):
            self.apply({"action": "delete", "path": "large", "revision": "a" * 64})
        self.assertEqual(source.stat().st_size, MAX_BYTES + 1)

    def test_copy_dependency_and_noop_changed_before_commit_are_rejected(self) -> None:
        for action in ["copy", "write"]:
            self.write("a", "one")
            change = {"action": action, "path": "a", "revision": revision("one")}
            change.update({"destination": "b"} if action == "copy" else {"content": "one"})
            prepared = self.editor.prepare_changes({"changes": [change]})
            with self.assertRaises(ReCTMError):
                self.editor.commit(prepared, before_commit=lambda: self.write("a", "changed"))
            self.assertFalse((self.workspace / "b").exists())

    def test_copy_dependency_hardlink_gain_after_first_write_rolls_back(self) -> None:
        source = self.write("a", "one")
        prepared = self.editor.prepare_changes({"changes": [
            {"action": "copy", "path": "a", "revision": revision("one"), "destination": "b"},
            {"action": "create", "path": "c", "content": "new"},
        ]})
        def hook(index: int) -> None:
            if index == 1:
                os.link(source, self.workspace / "hard")
        with self.assertRaises(ReCTMError):
            self.editor.commit(prepared, before_mutation=hook)
        self.assertFalse((self.workspace / "b").exists())
        self.assertFalse((self.workspace / "c").exists())

    def test_failed_second_write_restores_original_inode_and_cleans(self) -> None:
        first = self.write("a", "one"); self.write("b", "two")
        inode = first.stat().st_ino
        prepared = self.editor.prepare_changes({"changes": [
            {"action": "write", "path": "a", "revision": revision("one"), "content": "new one"},
            {"action": "write", "path": "b", "revision": revision("two"), "content": "new two"},
        ]})
        def hook(index: int) -> None:
            if index == 1:
                raise OSError("injected")
        with self.assertRaises(ReCTMError) as caught:
            self.editor.commit(prepared, before_mutation=hook)
        self.assertEqual(caught.exception.code, "NATIVE_PATCH_IO_ERROR")
        self.assertEqual(first.read_text(), "one")
        self.assertEqual(first.stat().st_ino, inode)
        self.assertEqual((self.workspace / "b").read_text(), "two")
        self.assertFalse(list(self.workspace.glob(".re-ctm-*")))

    def test_drifted_backup_is_preserved_and_never_claimed_restored(self) -> None:
        first = self.write("a", "one"); self.write("b", "two")
        prepared = self.editor.prepare_changes({"changes": [
            {"action": "write", "path": "a", "revision": revision("one"), "content": "new one"},
            {"action": "write", "path": "b", "revision": revision("two"), "content": "new two"},
        ]})
        with first.open("r+b") as held:
            def hook(index: int) -> None:
                if index == 1:
                    held.write(b"BAD"); held.flush()
                    raise OSError("injected")
            with self.assertRaises(ReCTMError) as caught:
                self.editor.commit(prepared, before_mutation=hook)
        self.assertEqual(caught.exception.code, "NATIVE_PATCH_ROLLBACK_FAILED")
        self.assertEqual(first.read_text(), "new one")
        self.assertTrue(caught.exception.details["recovery_files"])
        self.assertTrue(list(self.workspace.glob(".re-ctm-backup-*")))

    def test_external_installed_target_change_is_not_overwritten_by_rollback(self) -> None:
        first = self.write("a", "one")
        prepared = self.editor.prepare_changes({"changes": [
            {"action": "write", "path": "a", "revision": revision("one"), "content": "new one"},
            {"action": "create", "path": "b", "content": "two"},
        ]})
        def hook(index: int) -> None:
            if index == 1:
                first.write_text("external")
        with self.assertRaises(ReCTMError) as caught:
            self.editor.commit(prepared, before_mutation=hook)
        self.assertEqual(caught.exception.code, "NATIVE_PATCH_ROLLBACK_FAILED")
        self.assertEqual(first.read_text(), "external")

    def test_external_install_capture_race_never_acquires_rollback_ownership(self) -> None:
        first = self.write("a", "one")
        original_unlink = os.unlink
        def unlink(path: object, *args: object, **kwargs: object) -> None:
            original_unlink(path, *args, **kwargs)
            if isinstance(path, str) and path.startswith(".re-ctm-patch-"):
                first.write_text("external concurrent edit")
        with mock.patch("re_ctm.native_changes.os.unlink", side_effect=unlink):
            with self.assertRaises(ReCTMError) as caught:
                self.apply({"action": "write", "path": "a", "revision": revision("one"), "content": "ours"})
        self.assertEqual(caught.exception.code, "NATIVE_PATCH_ROLLBACK_FAILED")
        self.assertEqual(first.read_text(), "external concurrent edit")
        self.assertTrue(list(self.workspace.glob(".re-ctm-backup-*")))

    def test_malformed_requests_are_rejected(self) -> None:
        bad = [
            {"changes": []}, {"changes": "x"}, {"changes": [{}]},
            {"changes": [{"action": [], "path": "a"}]},
            {"changes": [{"action": "create", "path": "a", "content": 1}]},
            {"changes": [{"action": "create", "path": "a", "content": "x", "revision": "a" * 64}]},
            {"changes": [{"action": "create", "path": "a", "content": "x", "unknown": 1}]},
            {"changes": [{"action": "create", "path": "a", "content": "x"}], "dry_run": 1},
            {"changes": [{"action": "create", "path": "a", "content": "x"}], "unknown": 1},
            {"changes": [{"action": "create", "path": "a", "content": "x"}] * 101},
        ]
        for request in bad:
            with self.subTest(request=request), self.assertRaises(ReCTMError):
                self.runtime.apply_changes(**request)
        self.assertFalse((self.workspace / "a").exists())

    def test_self_move_and_parent_child_aliases_are_rejected(self) -> None:
        self.write("a", "one")
        for changes in [
            [{"action": "move", "path": "a", "revision": revision("one"), "destination": "./a"}],
            [{"action": "create", "path": "new", "content": "x"}, {"action": "create", "path": "new/child", "content": "y"}],
        ]:
            with self.assertRaises(ReCTMError):
                self.apply(*changes)


class LineEditV11Tests(unittest.TestCase):
    def test_bom_crlf_mixed_eof_and_original_numbering(self) -> None:
        content, ranges, added, removed = edit_lines("\ufeffa\r\nb\r\nc\r\n", [
            {"op": "replace", "start_line": 2, "content": "x\r\ny"},
            {"op": "insert_after", "line": 3, "content": "z"},
        ])
        self.assertEqual(content, "\ufeffa\r\nx\r\ny\r\nc\r\nz\r\n")
        self.assertEqual((added, removed), (3, 1))
        self.assertEqual(ranges[1]["start_line"], 5)
        self.assertEqual(edit_lines("a\rb", [{"op": "replace", "start_line": 1, "content": "x"}])[0], "x")
        self.assertEqual(edit_lines("last", [{"op": "insert_before", "line": 1, "content": "first"}])[0], "first\nlast")
        self.assertEqual(edit_lines("\ufeff", [{"op": "replace", "start_line": 1, "content": "x"}])[0], "\ufeffx")
        self.assertEqual(edit_lines("a", [{"op": "replace", "start_line": 1, "content": "b\n"}])[0], "b\n\n")

    def test_line_numbers_use_only_lf_and_noop_is_byte_exact(self) -> None:
        mixed = "a\r\nb\nc\r\n"
        self.assertEqual(edit_lines(mixed, [{"op": "replace", "start_line": 2, "content": "b"}])[0], mixed)
        self.assertEqual(edit_lines(mixed, [{"op": "replace", "start_line": 2, "content": "x"}])[0], "a\r\nx\r\nc\r\n")
        self.assertEqual(edit_lines("a\u2028b\nc\n", [{"op": "delete", "start_line": 2}])[0], "a\u2028b\n")
        self.assertEqual(edit_lines("\ufeff", [{"op": "delete", "start_line": 1}])[0], "")
        self.assertEqual(edit_lines("", [{"op": "insert_after", "line": 0, "content": "x"}])[0], "x\n")

    def test_invalid_overlap_ranges_and_fields(self) -> None:
        for edits in [
            [{"op": "delete", "start_line": 1, "end_line": 2}, {"op": "insert_after", "line": 1, "content": "x"}],
            [{"op": "replace", "start_line": True, "content": "x"}],
            [{"op": {}, "start_line": 1}],
            [{"op": "delete", "start_line": 0}], [{"op": "delete", "start_line": 3}],
            [{"op": "delete", "start_line": 1, "content": "x"}],
            [{"op": "insert_before", "line": 0, "content": "x"}],
            [{"op": "insert_after", "line": 1, "start_line": 1, "content": "x"}],
            [{"op": "replace", "start_line": 1, "other": "x", "content": "x"}],
        ]:
            with self.subTest(edits=edits), self.assertRaises(ReCTMError):
                edit_lines("a\nb\n", edits)


if __name__ == "__main__":
    unittest.main()
