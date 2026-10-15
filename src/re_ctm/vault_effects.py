"""Private file evidence and permanent cross-process locks for recovery.

Only hashes and byte lengths leave this module for receipts. Prepared bytes stay
in memory; recovery observes an enrolled effect and never regenerates content.
"""
from __future__ import annotations

import contextvars
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .errors import ReCTMError

MAX_FILE_BYTES = 64 * 1024 * 1024
_capture: contextvars.ContextVar["PreparedFiles | None"] = contextvars.ContextVar("vault_prepared_files", default=None)
_observers: contextvars.ContextVar[list[tuple[Any, Any]] | None] = contextvars.ContextVar("vault_deferred_observers", default=None)
_held: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar("vault_held_locks", default=frozenset())


def conflict(message: str) -> ReCTMError:
    return ReCTMError("VAULT_EFFECT_CONFLICT", message, category="conflict", retryable=False)


def image(data: bytes | None) -> dict[str, Any] | None:
    return None if data is None else {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def read_regular(path: Path) -> bytes | None:
    # Parent directories are private server-created paths, still reject symlink
    # substitution instead of letting evidence refer outside the logical root.
    for parent in path.parents:
        if parent.is_symlink():
            raise conflict("Private file parent is a symlink.")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
            raise conflict("Private evidence requires a bounded, singly linked regular file.")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        named = path.lstat()
        if len(data) > MAX_FILE_BYTES or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino):
            raise conflict("Private file changed while evidence was read.")
        return data
    finally:
        os.close(fd)


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path: Path, data: bytes, *, exact: bool = False) -> None:
    if len(data) > MAX_FILE_BYTES:
        raise conflict("Private file exceeds the bounded evidence limit.")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing = read_regular(path)
    if exact and existing is not None:
        if existing != data:
            raise conflict("Existing private file differs from enrolled initialization.")
        return
    fd, name = tempfile.mkstemp(prefix=".re-ctm-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if exact:
            try:
                os.link(name, path, follow_symlinks=False)
            except FileExistsError:
                if read_regular(path) != data:
                    raise conflict("Concurrent private initialization conflicts.")
        else:
            os.replace(name, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def lock_run(private_root: Path, run_id: str) -> Iterator[None]:
    root = private_root / ".locks"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = hashlib.sha256(run_id.encode()).hexdigest()
    target = root / (key + ".lock")
    identity = str(target)
    held = _held.get()
    if identity in held:
        yield
        return
    fd = os.open(target, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    token = None
    observer_token = _observers.set([]) if _observers.get() is None else None
    queued = _observers.get()
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise conflict("Private lock inode is unsafe.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        named = target.lstat()
        if (named.st_dev, named.st_ino) != (current.st_dev, current.st_ino):
            raise conflict("Private lock inode was replaced.")
        token = _held.set(held | {identity})
        yield
    finally:
        if token is not None:
            _held.reset(token)
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        if observer_token is not None:
            _observers.reset(observer_token)
            for observer, event in queued or []:
                try:
                    observer(event)
                except Exception:
                    pass
        # Deliberately retain the inode: unlinking creates two independent locks.


class PreparedFiles:
    def __init__(self, run_root: Path) -> None:
        self.root = run_root
        self.effects: dict[Path, tuple[bytes | None, bytes]] = {}

    def record(self, path: Path, data: bytes, *, append: bool = False) -> None:
        if not path.is_relative_to(self.root):
            raise conflict("Effect path is outside its run.")
        if path in self.effects:
            before, previous = self.effects[path]
        else:
            before = previous = read_regular(path)
        after = (previous or b"") + data if append else data
        if len(after) > MAX_FILE_BYTES:
            raise conflict("Prepared private file is too large.")
        self.effects[path] = before, after

    @contextmanager
    def capture(self) -> Iterator["PreparedFiles"]:
        if _capture.get() is not None:
            raise conflict("Nested effect preparation is not supported.")
        token = _capture.set(self)
        try:
            yield self
        finally:
            _capture.reset(token)

    def evidence(self, path: Path) -> dict[str, Any]:
        before, after = self.effects[path]
        return {"relative_path": path.relative_to(self.root).as_posix(), "before": image(before), "after": image(after)}

    def apply(self, path: Path) -> None:
        before, after = self.effects[path]
        if read_regular(path) != before:
            raise conflict("Private file changed after effect preparation.")
        publish(path, after)


def capture_write(path: Path, data: bytes, *, append: bool = False) -> bool:
    prepared = _capture.get()
    if prepared is None:
        return False
    prepared.record(path, data, append=append)
    return True


def is_capturing() -> bool:
    return _capture.get() is not None


def defer_observer(observer: Any, event: Any) -> bool:
    queued = _observers.get()
    if queued is None:
        return False
    if len(queued) < 4096:
        queued.append((observer, event))
    return True
