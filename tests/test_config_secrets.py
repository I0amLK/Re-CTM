from __future__ import annotations

import hashlib
import multiprocessing
import os
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest import mock

from re_ctm.config import (
    MAX_PERSISTED_SECRET_BYTES,
    Settings,
    _load_or_create_secret,
    _publish_secret_candidate,
    materialize_secrets,
)
from re_ctm.errors import ReCTMError


def _publish_from_process(path: str, index: int, barrier: Any, output: Any) -> None:
    barrier.wait(timeout=15)
    output.put(_publish_secret_candidate(Path(path), bytes([index]) * 32))


class PersistentSecretTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "oauth-token-secret.hex"

    def test_concurrent_distinct_candidates_return_persisted_winner(self) -> None:
        barrier = threading.Barrier(16)

        def publish(index: int) -> bytes:
            barrier.wait(timeout=10)
            return _publish_secret_candidate(self.path, bytes([index]) * 32)

        with ThreadPoolExecutor(max_workers=16) as workers:
            results = list(workers.map(publish, range(16)))
        persisted = bytes.fromhex(self.path.read_text(encoding="ascii").strip())
        self.assertTrue(all(result == persisted for result in results))
        self.assertEqual(list(self.root.iterdir()), [self.path])
        self.assertEqual(_load_or_create_secret(self.path), persisted)

    def test_concurrent_processes_return_one_persisted_key(self) -> None:
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(8)
        output = context.Queue()
        processes = [context.Process(
            target=_publish_from_process, args=(str(self.path), index, barrier, output)
        ) for index in range(8)]
        try:
            for process in processes:
                process.start()
            results = [output.get(timeout=20) for _ in processes]
            for process in processes:
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)
            persisted = _load_or_create_secret(self.path)
            self.assertTrue(all(result == persisted for result in results))
            self.assertEqual(list(self.root.iterdir()), [self.path])
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            output.close()
            output.join_thread()

    def test_concurrent_first_materialization_and_restart_share_both_secrets(self) -> None:
        workspace = self.root / "workspace"
        workspace.mkdir()
        data = self.root / "data"
        settings = Settings(
            workspace=workspace, data_root=data, private_root=data / "private",
            debug_root=data / "debug",
        )
        barrier = threading.Barrier(12)
        original_random = os.urandom

        def simultaneous_candidate(size: int) -> bytes:
            barrier.wait(timeout=10)
            return original_random(size)

        with mock.patch("re_ctm.config.secrets.token_bytes", side_effect=simultaneous_candidate):
            with ThreadPoolExecutor(max_workers=12) as workers:
                results = list(workers.map(materialize_secrets, [settings] * 12))
        restarted = materialize_secrets(settings)
        expected = hashlib.sha256(restarted.token_secret + b"/capability").digest()
        self.assertEqual(len(restarted.token_secret), 32)
        self.assertEqual(restarted.capability_secret, expected)
        for result in results:
            self.assertEqual(result.token_secret, restarted.token_secret)
            self.assertEqual(result.capability_secret, expected)

    def test_existing_winner_is_never_replaced(self) -> None:
        winner = _load_or_create_secret(self.path)
        original = self.path.read_bytes()
        inode = self.path.stat().st_ino
        self.assertEqual(_publish_secret_candidate(self.path, b"x" * 32), winner)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(self.path.stat().st_ino, inode)
        self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_empty_malformed_or_short_persisted_keys_are_not_replaced(self) -> None:
        for contents in (b"", b"\n", b"not-hex", b"abcd", b"a" * 65, b"aa " * 32, b"\xff" * 64):
            for operation in (
                lambda: _load_or_create_secret(self.path),
                lambda: _publish_secret_candidate(self.path, b"x" * 32),
            ):
                with self.subTest(contents=contents, operation=operation):
                    self.path.write_bytes(contents)
                    with self.assertRaises(ReCTMError) as denied:
                        operation()
                    self.assertEqual(denied.exception.code, "INVALID_SECRET")
                    self.assertEqual(self.path.read_bytes(), contents)
                    self.assertEqual(list(self.root.iterdir()), [self.path])

    def test_directory_is_rejected(self) -> None:
        self.path.mkdir()
        with self.assertRaises(ReCTMError) as denied:
            _load_or_create_secret(self.path)
        self.assertEqual(denied.exception.code, "UNSAFE_SECRET_FILE")
        self.assertEqual(denied.exception.category, "security")
        self.assertTrue(self.path.is_dir())

    def test_oversized_secret_is_rejected_without_replacement(self) -> None:
        contents = b"a" * (MAX_PERSISTED_SECRET_BYTES + 2)
        self.path.write_bytes(contents)
        with self.assertRaises(ReCTMError) as denied:
            _load_or_create_secret(self.path)
        self.assertEqual(denied.exception.code, "INVALID_SECRET")
        self.assertEqual(denied.exception.category, "validation")
        self.assertEqual(self.path.read_bytes(), contents)

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow semantics required")
    def test_removed_or_symlink_replaced_file_during_open_fails_closed(self) -> None:
        original_open = os.open
        target = self.root / "target.hex"
        original = b"01" * 32 + b"\n"
        target.write_bytes(original)
        for replacement in ("missing", "symlink", "file", "fifo"):
            with self.subTest(replacement=replacement):
                self.path.write_bytes(original)

                def replaced_open(path: Path, flags: int) -> int:
                    if replacement == "file":
                        # Keep the old inode allocated so this check is deterministic.
                        path.rename(self.root / "retired.hex")
                    else:
                        path.unlink()
                    if replacement == "symlink":
                        path.symlink_to(target)
                    elif replacement == "file":
                        path.write_bytes(b"02" * 32 + b"\n")
                    elif replacement == "fifo":
                        os.mkfifo(path, 0o600)
                    return original_open(path, flags)

                with mock.patch("re_ctm.config.os.open", side_effect=replaced_open):
                    with self.assertRaises(ReCTMError) as denied:
                        _load_or_create_secret(self.path)
                self.assertEqual(denied.exception.code, "UNSAFE_SECRET_FILE")
                self.assertEqual(target.read_bytes(), original)
                self.path.unlink(missing_ok=True)
                (self.root / "retired.hex").unlink(missing_ok=True)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_regular_and_dangling_symlinks_are_rejected(self) -> None:
        target = self.root / "target.hex"
        original = b"01" * 32 + b"\n"
        for exists in (True, False):
            with self.subTest(target_exists=exists):
                if exists:
                    target.write_bytes(original)
                self.path.symlink_to(target)
                with self.assertRaises(ReCTMError) as denied:
                    _load_or_create_secret(self.path)
                self.assertEqual(denied.exception.code, "UNSAFE_SECRET_FILE")
                self.assertTrue(self.path.is_symlink())
                if exists:
                    self.assertEqual(target.read_bytes(), original)
                    target.unlink()
                else:
                    self.assertFalse(target.exists())
                self.path.unlink()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO unavailable")
    def test_fifo_is_rejected_without_blocking(self) -> None:
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(ReCTMError) as denied:
            _load_or_create_secret(self.path)
        self.assertEqual(denied.exception.code, "UNSAFE_SECRET_FILE")
        self.assertTrue(stat.S_ISFIFO(self.path.lstat().st_mode))

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_publication_happens_after_private_full_write_and_fsync(self) -> None:
        original_fsync = os.fsync
        original_link = os.link
        synced: set[int] = set()

        def sync(descriptor: int) -> None:
            original_fsync(descriptor)
            synced.add(os.fstat(descriptor).st_ino)

        def publish(source: Path, destination: Path) -> None:
            metadata = source.stat()
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(source.read_bytes(), b"61" * 32 + b"\n")
            self.assertIn(metadata.st_ino, synced)
            original_link(source, destination)

        with mock.patch("re_ctm.config.os.fsync", side_effect=sync), mock.patch(
            "re_ctm.config.os.link", side_effect=publish
        ):
            self.assertEqual(_publish_secret_candidate(self.path, b"a" * 32), b"a" * 32)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_write_sync_or_publication_failure_cleans_staging_file(self) -> None:
        for target in ("os.fsync", "os.link"):
            with self.subTest(target=target):
                with mock.patch(f"re_ctm.config.{target}", side_effect=OSError("fixture failure")):
                    with self.assertRaises(OSError):
                        _publish_secret_candidate(self.path, b"a" * 32)
                self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
