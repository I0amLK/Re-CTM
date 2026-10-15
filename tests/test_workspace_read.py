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
from re_ctm.mcp import MCPDispatcher
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.oauth import OAuthPrincipal
from re_ctm.tools import ToolRuntime, validate_tool_arguments


class WorkspaceReadTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.root = root / "workspace"
        self.private = root / "private"
        self.root.mkdir()
        self.private.mkdir()
        self.path = self.root / "text"
        self.workspace = NativeWorkspace(self.root, private_root=self.private)
        self.runtime = NativeRuntime(
            self.workspace, NativeMode.DANGEROUS,
            DebugEventBus(root / "debug.jsonl", self.private, enabled=True),
        )
        self.addCleanup(self.runtime.close)

    def read(self, **arguments: object) -> dict:
        request = {"path": "text", **arguments}
        validate_tool_arguments("read_file", request)
        return self.runtime.read_file(**request)

    def test_utf8_continuations_are_lossless_and_schema_valid(self) -> None:
        content = "中文🙂abcdef\r\nlast line without newline"
        self.path.write_bytes(content.encode("utf-8"))
        request = {"path": "text", "max_bytes": 7, "max_lines": 1}
        pages = []
        for _ in range(32):
            validate_tool_arguments("read_file", request)
            result = self.runtime.read_file(**request)
            self.assertEqual(result["sha256"], hashlib.sha256(self.path.read_bytes()).hexdigest())
            self.assertEqual(result["revision"], result["sha256"])
            self.assertEqual(result["revision_algorithm"], "sha256")
            self.assertGreater(len(result["content"]), 0)
            self.assertLessEqual(len(result["content"].encode("utf-8")), 7)
            pages.append(result["content"])
            if not result["truncated"]:
                self.assertIsNone(result["next_action"])
                self.assertIsNone(result["next_start_line"])
                self.assertIsNone(result["next_line_byte_offset"])
                break
            next_request = result["next_action"]["arguments"]
            self.assertEqual(result["next_action"]["tool"], "read_file")
            self.assertNotEqual(next_request, request)
            request = next_request
        else:
            self.fail("read_file did not reach the end")
        self.assertEqual("".join(pages), content)

    def test_partial_last_line_and_range_end_are_truthful(self) -> None:
        self.path.write_bytes(b"abcdef\nignored\n")
        first = self.read(max_bytes=3, end_line=1)
        self.assertEqual(first["content"], "abc")
        self.assertTrue(first["truncated"])
        self.assertEqual(first["next_start_line"], 1)
        self.assertEqual(first["next_line_byte_offset"], 3)
        second = self.runtime.read_file(**first["next_action"]["arguments"])
        self.assertEqual(second["content"], "def")
        self.assertTrue(second["truncated"])
        last = self.runtime.read_file(**second["next_action"]["arguments"])
        self.assertEqual(last["content"], "\n")
        self.assertFalse(last["truncated"])

    def test_end_line_and_page_size_are_independent(self) -> None:
        self.path.write_bytes(b"one\ntwo\nthree\nfour\n")
        first = self.read(start_line=2, end_line=3, max_lines=1)
        self.assertEqual(first["content"], "two\n")
        second = self.runtime.read_file(**first["next_action"]["arguments"])
        self.assertEqual(second["content"], "three\n")
        self.assertFalse(second["truncated"])
        self.assertEqual(second["end_line"], 3)

    def test_small_budget_fails_instead_of_skipping_a_character(self) -> None:
        self.path.write_bytes("中🙂".encode("utf-8"))
        with self.assertRaises(ReCTMError) as raised:
            self.read(max_bytes=2)
        self.assertEqual(raised.exception.code, "READ_PAGE_TOO_SMALL")
        first = self.read(max_bytes=3)
        self.assertEqual(first["content"], "中")
        with self.assertRaises(ReCTMError) as continuation:
            self.runtime.read_file(**first["next_action"]["arguments"])
        self.assertEqual(continuation.exception.code, "READ_PAGE_TOO_SMALL")
        self.assertEqual(self.read(max_bytes=4, line_byte_offset=3)["content"], "🙂")

    def test_filled_budget_preserves_next_utf8_line(self) -> None:
        self.path.write_bytes("a\n中\n".encode("utf-8"))
        first = self.read(max_bytes=3)
        self.assertEqual(first["content"], "a\n")
        self.assertEqual(first["next_start_line"], 2)
        self.assertEqual(first["next_line_byte_offset"], 0)

    def test_changed_content_rejects_continuation(self) -> None:
        self.path.write_bytes(b"old\nmore\n")
        first = self.read(max_lines=1)
        self.path.write_bytes(b"new\nmore\n")
        with self.assertRaises(ReCTMError) as raised:
            self.runtime.read_file(**first["next_action"]["arguments"])
        self.assertEqual(raised.exception.code, "READ_FILE_CHANGED")
        self.assertEqual(raised.exception.category, "conflict")

    def test_expected_digest_accepts_upper_and_mixed_case_hex(self) -> None:
        self.path.write_bytes(b"same\nmore\n")
        first = self.read(max_lines=1)
        digest = first["sha256"]
        for expected in (
            digest.upper(),
            "".join(char.upper() if index % 2 else char for index, char in enumerate(digest)),
        ):
            with self.subTest(expected=expected):
                arguments = {**first["next_action"]["arguments"], "expected_sha256": expected}
                validate_tool_arguments("read_file", arguments)
                result = self.runtime.read_file(**arguments)
                self.assertEqual(result["content"], "more\n")
                self.assertEqual(result["sha256"], digest)

    def test_mcp_dispatch_exposes_usable_continuations_and_conflicts(self) -> None:
        # Only Native handlers are exercised; workflow authority is not consulted.
        dispatcher = MCPDispatcher(ToolRuntime(self.runtime, mock.Mock(), self.runtime.debug))
        principal = OAuthPrincipal("client", "client", "mcp")
        self.path.write_bytes("中文🙂\nlast\n".encode("utf-8"))

        def call(arguments: dict) -> dict:
            response = dispatcher.dispatch({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "read_file", "arguments": arguments},
            }, principal)
            self.assertNotIn("error", response)
            return response["result"]

        first = call({"path": "text", "max_bytes": 6, "end_line": 1, "max_lines": 1})
        self.assertFalse(first["isError"])
        self.assertEqual(first["structuredContent"]["content"], "中文")
        next_args = first["structuredContent"]["next_action"]["arguments"]
        second = call(next_args)
        self.assertFalse(second["isError"])
        self.assertEqual(second["structuredContent"]["content"], "🙂\n")
        self.assertFalse(second["structuredContent"]["truncated"])
        self.path.write_bytes(b"changed\n")
        rejected = call(next_args)
        self.assertTrue(rejected["isError"])
        self.assertEqual(rejected["structuredContent"]["error"]["code"], "READ_FILE_CHANGED")

    def test_invalid_range_offsets_and_types_are_rejected(self) -> None:
        self.path.write_bytes("中x".encode("utf-8"))
        for fields in (
            {"start_line": 0}, {"start_line": 2, "end_line": 1}, {"max_lines": 0},
            {"max_bytes": 0}, {"max_bytes": 1_048_577}, {"line_byte_offset": -1},
            {"line_byte_offset": 1}, {"line_byte_offset": 4}, {"line_byte_offset": 5},
            {"start_line": 2, "line_byte_offset": 1}, {"max_lines": "1"},
            {"max_bytes": True}, {"expected_sha256": "bad"}, {"encoding": "latin1"},
        ):
            with self.subTest(fields=fields), self.assertRaises(ReCTMError):
                self.runtime.read_file(path="text", **fields)

    def test_empty_and_beyond_eof_pages_do_not_invent_content(self) -> None:
        for content in (b"", b"hello\n"):
            self.path.write_bytes(content)
            for start in (2, 2**63 - 1):
                result = self.read(start_line=start, max_lines=2**63 - 1)
                self.assertEqual(result["content"], "")
                self.assertFalse(result["truncated"])
                self.assertIsNone(result["next_action"])

    def test_only_lf_separates_lines_and_all_bytes_are_preserved(self) -> None:
        content = "a\rb\v\u2028c\r\nd"
        self.path.write_bytes(content.encode("utf-8"))
        first = self.read(max_lines=1)
        self.assertEqual(first["total_lines"], 2)
        self.assertEqual(first["content"], "a\rb\v\u2028c\r\n")
        second = self.runtime.read_file(**first["next_action"]["arguments"])
        self.assertEqual(first["content"] + second["content"], content)

    def test_large_and_nonregular_files_fail_before_read(self) -> None:
        with self.path.open("wb") as handle:
            handle.truncate(64 * 1024 * 1024 + 1)
        with self.assertRaises(ReCTMError) as large:
            self.read()
        self.assertEqual(large.exception.code, "FILE_TOO_LARGE")
        os.mkfifo(self.root / "pipe")
        with self.assertRaises(ReCTMError) as fifo:
            self.runtime.read_file(path="pipe")
        self.assertEqual(fifo.exception.code, "NOT_A_REGULAR_FILE")
        with self.assertRaises(ReCTMError) as directory:
            self.runtime.read_file(path=".")
        self.assertEqual(directory.exception.code, "IS_DIRECTORY")

    def test_snapshot_reads_have_a_hard_input_bound(self) -> None:
        self.path.write_bytes(b"one\ntwo\n")
        sizes = []
        fdopen = os.fdopen

        class ObservedReader:
            def __init__(self, descriptor: int, mode: str, **kwargs: object) -> None:
                self.handle = fdopen(descriptor, mode, **kwargs)

            def __enter__(self) -> "ObservedReader":
                return self

            def __exit__(self, *args: object) -> None:
                self.handle.close()

            def fileno(self) -> int:
                return self.handle.fileno()

            def read(self, size: int = -1) -> bytes:
                sizes.append(size)
                return self.handle.read(size)

        with mock.patch("re_ctm.native.os.fdopen", ObservedReader):
            self.assertEqual(self.read()["content"], "one\ntwo\n")
        self.assertEqual(sizes, [64 * 1024 * 1024 + 1])

    def test_identity_change_during_read_is_rejected(self) -> None:
        self.path.write_bytes(b"old\n")
        fstat = os.fstat
        calls = 0

        def mutate_after_read(descriptor: int) -> os.stat_result:
            nonlocal calls
            calls += 1
            if calls == 2:
                self.path.write_bytes(b"new and longer\n")
            return fstat(descriptor)

        with mock.patch("re_ctm.native.os.fstat", side_effect=mutate_after_read):
            with self.assertRaises(ReCTMError) as changed:
                self.read()
        self.assertEqual(changed.exception.code, "READ_FILE_CHANGED")

    def test_replaced_descriptor_is_rejected_before_read(self) -> None:
        self.path.write_bytes(b"old\n")
        replacement = self.root / "other"
        replacement.write_bytes(b"replacement\n")
        original_open = os.open

        def open_other(path: Path, flags: int, **kwargs: object) -> int:
            if flags & os.O_DIRECTORY:
                return original_open(path, flags, **kwargs)
            return original_open(replacement, flags)

        with mock.patch("re_ctm.native.os.open", side_effect=open_other):
            with self.assertRaises(ReCTMError) as changed:
                self.read()
        self.assertEqual(changed.exception.code, "READ_FILE_CHANGED")

    def test_binary_and_private_paths_stay_denied(self) -> None:
        self.path.write_bytes(b"\xff")
        with self.assertRaises(ReCTMError) as binary:
            self.read()
        self.assertEqual(binary.exception.code, "BINARY_FILE")
        (self.private / "secret").write_text("secret", encoding="utf-8")
        (self.root / "escape").symlink_to(self.private / "secret")
        with self.assertRaises(ReCTMError) as escaped:
            self.runtime.read_file(path="escape")
        self.assertEqual(escaped.exception.code, "SYMLINK_ESCAPE")


if __name__ == "__main__":
    unittest.main()
