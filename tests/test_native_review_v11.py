"""Independent boundary/contract regressions for the Native v11 migration."""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.errors import ReCTMError
from re_ctm.native import NativeWorkspace
from re_ctm.native_changes import NativeTransaction
from re_ctm.native_patch import apply_update, parse_patch
from re_ctm.native_replay import CAPACITY, MAX_RESULT_BYTES, NativeReplay


class NativeReplayReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.replay = NativeReplay()
        self.scope = {"subject": "owner", "client_id": "client", "scope": "mcp"}
        self.arguments = {"idempotency_key": "key", "changes": [{"action": "create", "path": "a", "content": "one"}]}

    def execute(self, operation, *, scope=None, tool="apply_changes", arguments=None):
        return self.replay.execute(self.scope if scope is None else scope, tool,
                                   self.arguments if arguments is None else arguments, operation)

    def assert_code(self, code, operation):
        with self.assertRaises(ReCTMError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def test_historical_replay_is_copied_and_canonicalizes_object_order(self) -> None:
        result = {"affected_files": [{"path": "a", "revision": "historical"}]}
        self.execute(lambda: result)
        result["affected_files"][0]["revision"] = "caller changed"
        arguments = {"changes": [{"content": "one", "path": "a", "action": "create"}], "idempotency_key": "key"}
        replayed = self.execute(lambda: self.fail("duplicate executed"), arguments=arguments)
        self.assertEqual(replayed["affected_files"][0]["revision"], "historical")
        replayed["affected_files"][0]["revision"] = "changed replay"
        self.assertEqual(self.execute(lambda: self.fail("duplicate executed"))["affected_files"][0]["revision"], "historical")
        self.assertTrue(replayed["idempotent_replay"])

    def test_each_authenticated_scope_dimension_and_tool_are_isolated(self) -> None:
        self.execute(lambda: {"source": "original"})
        for dimension in self.scope:
            scope = {**self.scope, dimension: "different"}
            self.assertEqual(self.execute(lambda: {"source": dimension}, scope=scope)["source"], dimension)
        self.assertEqual(self.execute(lambda: {"source": "patch"}, tool="apply_patch")["source"], "patch")

    def test_missing_scope_and_changed_arguments_never_execute(self) -> None:
        self.assert_code("NATIVE_REPLAY_SCOPE_REQUIRED", lambda: self.execute(lambda: self.fail("unscoped write"), scope={}))
        self.execute(lambda: {})
        changed = {**self.arguments, "dry_run": False}
        self.assert_code("IDEMPOTENCY_KEY_REUSED", lambda: self.execute(lambda: self.fail("changed write"), arguments=changed))

    def test_pending_duplicate_has_no_second_execution_and_lock_is_not_held(self) -> None:
        entered, release = threading.Event(), threading.Event()
        results, failures = [], []
        def operation():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test operation timed out")
            return {"written": True}
        def worker():
            try:
                results.append(self.execute(operation))
            except BaseException as exc:
                failures.append(exc)
        thread = threading.Thread(target=worker)
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            self.assert_code("NATIVE_WRITE_IN_PROGRESS", lambda: self.execute(lambda: self.fail("second write")))
            other = {**self.arguments, "idempotency_key": "other"}
            self.assertEqual(self.execute(lambda: {"independent": True}, arguments=other), {"independent": True})
        finally:
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(results, [{"written": True}])

    def test_dry_runs_do_not_reserve_success_or_unknown_slots(self) -> None:
        arguments = {**self.arguments, "dry_run": True}
        self.execute(lambda: {}, arguments=arguments)
        self.execute(lambda: {"ok": False}, arguments=arguments)
        self.assertEqual(self.execute(lambda: {"real": True}), {"real": True})

    def test_validation_failure_releases_slot_but_runtime_failure_blocks(self) -> None:
        def rejected():
            raise ReCTMError("BAD_INPUT", "bad input", category="validation")
        self.assert_code("BAD_INPUT", lambda: self.execute(rejected))
        self.assertEqual(self.execute(lambda: {"corrected": True}), {"corrected": True})
        for category in ("runtime", "internal"):
            arguments = {**self.arguments, "idempotency_key": category}
            def failed():
                raise ReCTMError("FAILED", "uncertain", category=category)
            self.assert_code("FAILED", lambda: self.execute(failed, arguments=arguments))
            self.assert_code("NATIVE_WRITE_RESULT_UNKNOWN", lambda: self.execute(lambda: self.fail("uncertain write repeated"), arguments=arguments))

    def test_unknown_slots_survive_capacity_pressure(self) -> None:
        for index in range(CAPACITY):
            arguments = {**self.arguments, "idempotency_key": str(index)}
            self.execute(lambda: {"ok": False}, arguments=arguments)
        self.assert_code("NATIVE_REPLAY_LIMIT", lambda: self.execute(lambda: self.fail("full unknown cache admitted write")))
        first = {**self.arguments, "idempotency_key": "0"}
        self.assert_code("NATIVE_WRITE_RESULT_UNKNOWN", lambda: self.execute(lambda: self.fail("old unknown evicted"), arguments=first))

    def test_success_only_lru_eviction_preserves_recent_replays(self) -> None:
        for index in range(CAPACITY):
            self.execute(lambda: {}, arguments={**self.arguments, "idempotency_key": str(index)})
        first = {**self.arguments, "idempotency_key": "0"}
        self.assertTrue(self.execute(lambda: self.fail("fresh success evicted"), arguments=first)["idempotent_replay"])
        self.execute(lambda: {})
        second = {**self.arguments, "idempotency_key": "1"}
        self.assertEqual(self.execute(lambda: {"evicted": True}, arguments=second), {"evicted": True})
        self.assertTrue(self.execute(lambda: self.fail("recent replay evicted"), arguments=first)["idempotent_replay"])

    def test_oversized_nonobject_and_failed_results_block_reexecution(self) -> None:
        for key, result in (("oversized", {"body": "x" * MAX_RESULT_BYTES}),
                            ("nonobject", []), ("failed", {"ok": False}),
                            ("invalid-json", {"body": float("nan")})):
            arguments = {**self.arguments, "idempotency_key": key}
            self.execute(lambda: result, arguments=arguments)
            self.assert_code("NATIVE_WRITE_RESULT_UNKNOWN", lambda: self.execute(lambda: self.fail("uncertain result repeated"), arguments=arguments))


class CurrentPatchReviewTests(unittest.TestCase):
    def test_forward_anchor_never_falls_back(self) -> None:
        source = "old\nanchor\nold\n"
        result = apply_update(source, [["@@ anchor", "-old", "+new"]], "a")
        self.assertEqual(result.content, "old\nanchor\nnew\n")
        for source, anchor in ((source, "missing"), ("old\nanchor\n", "anchor")):
            with self.assertRaises(ReCTMError) as caught:
                apply_update(source, [["@@ " + anchor, "-old", "+new"]], "a")
            self.assertEqual(caught.exception.code, "PATCH_CONTEXT_NOT_FOUND")

    def test_eof_matching_grades_and_conservative_repetition(self) -> None:
        result = apply_update("x\nx\n", [["@@", "-x", "+y", "*** End of File"]], "a")
        self.assertEqual((result.content, result.additions, result.removals), ("x\ny\n", 1, 1))
        self.assertEqual(apply_update("  x   \n", [["-x", "+y"]], "a").match_quality, "indentation")
        with self.assertRaises(ReCTMError):
            apply_update("new\n", [["-old", "+new"]], "a")
        repeated = apply_update("context\nnew\n", [[" context", "-old", "+new"]], "a")
        self.assertTrue(repeated.already_applied)
        self.assertEqual(repeated.changed_ranges, [])

    def test_append_ambiguity_and_budget_fail_closed(self) -> None:
        appended = apply_update("a\n", [["@@ a", "+b", "+c"]], "a")
        self.assertEqual(appended.content, "a\nb\nc\n")
        self.assertTrue(apply_update(appended.content, [["+b", "+c"]], "a").already_applied)
        with self.assertRaises(ReCTMError) as ambiguous:
            apply_update("x\nx\n", [["-x", "+y"]], "a")
        self.assertEqual(ambiguous.exception.code, "PATCH_CONTEXT_AMBIGUOUS")
        self.assertEqual(ambiguous.exception.details["candidate_lines"], [1, 2])
        with self.assertRaises(ReCTMError) as limited:
            apply_update("same\n" * 20_000, [["-same"] * 1000 + ["-different", "+changed"]], "a")
        self.assertEqual(limited.exception.code, "PATCH_LIMIT")

    def test_parser_preserves_current_eof_marker(self) -> None:
        operations = parse_patch("*** Begin Patch\n*** Update File: a\n@@\n-x\n+y\n*** End of File\n*** End Patch\n")
        self.assertEqual(operations[0].hunks[0][-1], "*** End of File")
        self.assertEqual(len(operations), 1)


class NativeReadIsolationReviewTests(unittest.TestCase):
    def test_swapped_parent_cannot_disclose_private_bytes_after_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, private = root / "workspace", root / "private"
            (workspace / "directory").mkdir(parents=True)
            private.mkdir()
            (workspace / "directory" / "a").write_text("public")
            (private / "a").write_text("private evidence must not be read")
            native = NativeWorkspace(workspace, private_root=private)
            original = native.resolve_existing
            def resolve(path):
                result = original(path)
                (workspace / "directory").rename(workspace / "saved")
                (workspace / "directory").symlink_to(private, target_is_directory=True)
                return result
            with mock.patch.object(native, "resolve_existing", side_effect=resolve):
                with self.assertRaises(ReCTMError):
                    native.read_file("directory/a")

    def test_failed_create_directory_cleanup_cannot_follow_private_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, private = root / "workspace", root / "private"
            workspace.mkdir()
            (private / "child").mkdir(parents=True)
            native = NativeWorkspace(workspace, private_root=private)
            transaction = NativeTransaction(native)
            prepared = transaction.prepare_changes({"changes": [
                {"action": "create", "path": "parent/child/new", "content": "new"},
            ]})
            def swap_parent(index):
                self.assertEqual(index, 0)
                (workspace / "parent").rename(workspace / "saved")
                (workspace / "parent").symlink_to(private, target_is_directory=True)
            with self.assertRaises(ReCTMError):
                transaction.commit(prepared, before_mutation=swap_parent)
            self.assertTrue((private / "child").is_dir(), "cleanup removed an out-of-workspace directory")
            self.assertFalse((private / "child" / "new").exists())


if __name__ == "__main__":
    unittest.main()
