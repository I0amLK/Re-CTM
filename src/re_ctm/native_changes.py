"""Revision-bound Native changes and the single filesystem transaction writer.

Preparation never writes. A process-local lock, descriptor-relative writes,
revalidated dependencies and checked rollback protect normal concurrent edits.
This is not a durable crash journal or a global lock against external writers.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .errors import ReCTMError, invalid_argument
from .native_patch import apply_update, parse_patch
from .native_replay import canonical_bytes, validate_key

MAX_BYTES = 64 * 1024 * 1024
MAX_REQUEST_BYTES = 1_048_576


def _conflict(message: str, path: str = "") -> ReCTMError:
    return ReCTMError("PATCH_CONFLICT", message, category="conflict", retryable=True,
                      details={"path": path} if path else {})


def _directory_identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lines(text: str) -> int:
    return text.count("\n") + int(bool(text) and not text.endswith("\n"))


@dataclass(frozen=True, repr=False)
class Snapshot:
    identity: tuple[int, ...]
    data: bytes

    @property
    def revision(self) -> str:
        return _digest(self.data)

    @property
    def mode(self) -> int:
        return self.identity[2] & 0o777


@dataclass(repr=False)
class PathChange:
    path: str
    baseline: Snapshot | None
    content: bytes | None
    mode: int | None = None
    dependency: bool = False


@dataclass(repr=False)
class PreparedChanges:
    changes: list[PathChange]
    directories: dict[str, tuple[int, int, int] | None]
    result: dict[str, Any]


@dataclass(repr=False)
class _Pending:
    change: PathChange
    parent_fd: int
    name: str
    staged: str | None = None
    staged_snapshot: Snapshot | None = None
    backup: str | None = None
    backup_snapshot: Snapshot | None = None
    installed: Snapshot | None = None
    touched: bool = False


class NativeTransaction:
    def __init__(self, workspace: Any) -> None:
        self.workspace = workspace
        self._lock = threading.Lock()

    def _path(self, raw: str, directories: dict[str, tuple[int, int, int] | None]) -> str:
        pure = self.workspace._validate_text(raw)
        if not pure.parts:
            raise invalid_argument("A file path is required")
        display = pure.as_posix()
        current = self.workspace.root
        for index, part in enumerate(("", *pure.parts)):
            if part:
                current = current / part
            relative = current.relative_to(self.workspace.root).as_posix()
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                metadata = None
            if metadata is not None and stat.S_ISLNK(metadata.st_mode):
                raise ReCTMError("SYMLINK_WRITE_DENIED", "Native writes reject symlink path components.", category="security")
            if index < len(pure.parts):
                if metadata is not None and not stat.S_ISDIR(metadata.st_mode):
                    raise invalid_argument("A file parent is not a directory", path=display)
                identity = _directory_identity(metadata) if metadata is not None else None
                if relative in directories and directories[relative] != identity:
                    raise _conflict("A parent directory changed during preparation", display)
                directories[relative] = identity
        # Keep NativeWorkspace's private-root boundary as a separate authority.
        resolved = self.workspace.resolve_for_write(display)
        if resolved.path != self.workspace.root.joinpath(*pure.parts):
            raise _conflict("Native path resolution changed", display)
        return display

    def _capture(self, path: str, *, parent_fd: int | None = None) -> Snapshot | None:
        if parent_fd is None:
            # O_NOFOLLOW on the leaf alone does not prevent an intermediate
            # symlink from reaching private files. Traverse every parent by fd.
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            fd = os.open(self.workspace.root, flags)
            try:
                for part in Path(path).parts[:-1]:
                    try:
                        child = os.open(part, flags, dir_fd=fd)
                    except FileNotFoundError:
                        return None
                    os.close(fd)
                    fd = child
                return self._capture(Path(path).name, parent_fd=fd)
            finally:
                os.close(fd)
        target = path
        try:
            before = os.stat(target, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReCTMError("UNSAFE_CHANGE_SOURCE", "Native changes require regular, non-hardlinked files.", category="security")
        if before.st_size > MAX_BYTES:
            raise invalid_argument("Native source exceeds 64 MiB")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(target, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            if _identity(before) != _identity(opened):
                raise _conflict("File changed before capture", path)
            chunks: list[bytes] = []
            size = 0
            while True:
                block = os.read(fd, min(1_048_576, MAX_BYTES + 1 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
                if size > MAX_BYTES:
                    raise invalid_argument("Captured Native source exceeds 64 MiB")
            after = os.fstat(fd)
            current = os.stat(target, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(opened) != _identity(after) or _identity(after) != _identity(current):
                raise _conflict("File changed during capture", path)
            return Snapshot(_identity(after), b"".join(chunks))
        finally:
            os.close(fd)

    def _capture_sources(self, paths: Iterable[str]) -> tuple[dict[str, Snapshot | None], dict[str, tuple[int, int, int] | None]]:
        directories: dict[str, tuple[int, int, int] | None] = {}
        normalized: list[str] = []
        for raw in paths:
            path = self._path(raw, directories)
            if path in normalized or any(path.startswith(old + "/") or old.startswith(path + "/") for old in normalized):
                raise invalid_argument("Resolved paths may appear only once and cannot contain one another")
            normalized.append(path)
        captured: dict[str, Snapshot | None] = {}
        total = 0
        for path in normalized:
            snapshot = self._capture(path)
            if snapshot is not None:
                total += len(snapshot.data)
                if total > MAX_BYTES:
                    raise invalid_argument("Aggregate captured Native sources exceed 64 MiB")
                try:
                    snapshot.data.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ReCTMError("UNSUPPORTED_ENCODING", "Native changes require UTF-8 text.", category="validation") from exc
            captured[path] = snapshot
        self._revalidate_directories(directories)
        return captured, directories

    def _revalidate_directories(self, directories: Mapping[str, tuple[int, int, int] | None]) -> None:
        for path, expected in directories.items():
            try:
                metadata = (self.workspace.root / path).lstat()
            except FileNotFoundError:
                current = None
            else:
                if not stat.S_ISDIR(metadata.st_mode):
                    raise _conflict("Native parent is no longer a directory", path)
                current = _directory_identity(metadata)
            if current != expected:
                raise _conflict("Native parent directory binding changed", path)

    def _revalidate(self, prepared: PreparedChanges, pending: list[_Pending] | None = None) -> None:
        self._revalidate_directories(prepared.directories)
        by_path = {item.change.path: item for item in (pending or [])}
        for change in prepared.changes:
            item = by_path.get(change.path)
            expected = item.installed if item is not None and item.touched else change.baseline
            actual = self._capture(change.path)
            if actual != expected:
                raise _conflict("A Native transaction dependency changed", change.path)
            if item is not None and item.backup is not None:
                if self._capture(item.backup, parent_fd=item.parent_fd) != item.backup_snapshot:
                    raise _conflict("Native rollback backup changed", change.path)

    def _result(self, changes: list[PathChange], directories: dict[str, tuple[int, int, int] | None],
                affected: list[dict[str, Any]], summary: list[str], additions: int,
                removals: int, dry_run: bool) -> PreparedChanges:
        result = {"clean": True, "dry_run": dry_run, "affected_files": affected,
                  "summary": "\n".join(summary), "additions": additions, "removals": removals,
                  "already_applied": all(item.dependency for item in changes),
                  "revision_algorithm": "sha256", "warnings": []}
        prepared = PreparedChanges(changes, directories, result)
        self._revalidate(prepared)
        return prepared

    def prepare_changes(self, arguments: Mapping[str, Any]) -> PreparedChanges:
        request = _validate_request(arguments, "changes")
        entries = request["changes"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
            raise invalid_argument("changes must contain 1..100 entries")
        paths: list[str] = []
        for entry in entries:
            _validate_change(entry)
            paths.append(entry["path"])
            if "destination" in entry:
                paths.append(entry["destination"])
        captured, directories = self._capture_sources(paths)
        changes: list[PathChange] = []
        affected: list[dict[str, Any]] = []
        summary: list[str] = []
        additions = removals = 0
        for entry in entries:
            action = entry["action"]
            path = self.workspace._validate_text(entry["path"]).as_posix()
            baseline = captured[path]
            if baseline is not None:
                if action == "create":
                    raise ReCTMError("PATH_EXISTS", "create requires an absent path", category="validation")
                if "revision" not in entry:
                    raise ReCTMError("REVISION_REQUIRED", "Read the file and supply its revision", category="validation")
                if entry["revision"] != baseline.revision:
                    raise ReCTMError("REVISION_MISMATCH", "File revision changed; read it again before editing", category="conflict", retryable=True)
            elif action not in {"create", "write"}:
                raise ReCTMError("NOT_FOUND", "Change source does not exist", category="not_found")
            elif "revision" in entry:
                raise ReCTMError("REVISION_MISMATCH", "Missing path has no revision", category="conflict")
            old = baseline.data.decode("utf-8") if baseline is not None else ""
            mode = baseline.mode if baseline is not None else None
            if action in {"create", "write", "edit"}:
                content = entry.get("content", "")
                edit_evidence = None
                if action == "edit":
                    content, ranges, added, removed = edit_lines(old, entry["edits"])
                    edit_evidence = ranges, added, removed
                unchanged = baseline is not None and content.encode("utf-8") == baseline.data
                operation = "unchanged" if unchanged else "write" if baseline is not None else "create"
                detail = _evidence(content, old, unchanged)
                if edit_evidence is not None:
                    detail["changed_ranges"] = edit_evidence[0]
                affected.append({"operation": operation, "path": path, **detail})
                summary.append(f"{'=' if unchanged else 'M'} {path}")
                if not unchanged:
                    additions += edit_evidence[1] if edit_evidence else _lines(content)
                    removals += edit_evidence[2] if edit_evidence else _lines(old)
                changes.append(PathChange(path, baseline, content.encode("utf-8"), mode, unchanged))
            elif action == "delete":
                removals += _lines(old)
                affected.append({"operation": "delete", "path": path, "total_lines": 0, "changed_ranges": []})
                summary.append(f"D {path}")
                changes.append(PathChange(path, baseline, None))
            else:
                target = self.workspace._validate_text(entry["destination"]).as_posix()
                if captured[target] is not None:
                    raise ReCTMError("PATH_EXISTS", "move/copy destination must not exist", category="validation")
                affected.append({"operation": action, "path": target, "old_path": path, **_evidence(old, "", False)})
                additions += _lines(old)
                summary.append(f"{action} {path} -> {target}")
                changes.append(PathChange(target, None, old.encode("utf-8"), mode))
                changes.append(PathChange(path, baseline, None, dependency=action == "copy"))
                if action == "move":
                    removals += _lines(old)
                    affected.append({"operation": "delete", "path": path, "total_lines": 0, "changed_ranges": []})
        return self._result(changes, directories, affected, summary, additions, removals, request.get("dry_run", False))

    def prepare_patch(self, arguments: Mapping[str, Any]) -> PreparedChanges:
        request = _validate_request(arguments, "patch")
        operations = parse_patch(request["patch"])
        paths = [path for op in operations for path in ([op.path, op.move_to] if op.move_to else [op.path])]
        captured, directories = self._capture_sources(paths)
        changes: list[PathChange] = []
        affected: list[dict[str, Any]] = []
        summary: list[str] = []
        additions = removals = 0
        for operation in operations:
            path = self.workspace._validate_text(operation.path).as_posix()
            baseline = captured[path]
            old = baseline.data.decode("utf-8") if baseline else ""
            if operation.kind == "add":
                if baseline is not None:
                    raise _conflict("Add target already exists", path)
                content = operation.add_content or ""
                changes.append(PathChange(path, None, content.encode("utf-8")))
                affected.append({"operation": "add", "path": path, **_evidence(content, "", False)})
                additions += _lines(content)
                summary.append(f"A {path}")
                continue
            if baseline is None:
                raise ReCTMError("NOT_FOUND", "Patch source does not exist", category="not_found")
            if operation.kind == "delete":
                changes.append(PathChange(path, baseline, None))
                affected.append({"operation": "delete", "path": path, "total_lines": 0, "changed_ranges": []})
                removals += _lines(old)
                summary.append(f"D {path}")
                continue
            update = apply_update(old, operation.hunks, path)
            detail = {**_evidence(update.content, old, update.already_applied),
                      "changed_ranges": update.changed_ranges, "match_quality": update.match_quality}
            additions += update.additions
            removals += update.removals
            if operation.move_to:
                target = self.workspace._validate_text(operation.move_to).as_posix()
                changes.append(PathChange(path, baseline, None))
                changes.append(PathChange(target, captured[target], update.content.encode("utf-8"), baseline.mode))
                affected.append({"operation": "delete", "path": path, "total_lines": 0, "changed_ranges": []})
                affected.append({"operation": "update", "path": target, "old_path": path, **detail})
                summary.append(f"R {path} -> {target}")
            else:
                changes.append(PathChange(path, baseline, update.content.encode("utf-8"), baseline.mode, update.already_applied))
                affected.append({"operation": "unchanged" if update.already_applied else "update", "path": path, **detail})
                summary.append(f"{'=' if update.already_applied else 'M'} {path}")
        return self._result(changes, directories, affected, summary, additions, removals, request.get("dry_run", False))

    def apply_changes(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return self.commit(self.prepare_changes(arguments))

    def apply_patch(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return self.commit(self.prepare_patch(arguments))

    def apply(self, operations: Iterable[Mapping[str, Any]], *, dry_run: bool = False) -> dict[str, Any]:
        """Internal export/legacy embedding API, using the same transaction authority."""
        entries = list(operations)
        if type(dry_run) is not bool or not 1 <= len(entries) <= 100:
            raise invalid_argument("Invalid internal Native edit request")
        for entry in entries:
            if (not isinstance(entry, Mapping) or not isinstance(entry.get("op"), str)
                    or entry["op"] not in {"add", "update", "delete"}):
                raise invalid_argument("op must be add, update, or delete")
            if set(entry) - {"op", "path", "content", "expected_sha256"}:
                raise invalid_argument("Unknown internal Native edit field")
        captured, directories = self._capture_sources(entry.get("path", "") for entry in entries)
        changes: list[PathChange] = []
        affected = []
        for entry in entries:
            path = self.workspace._validate_text(entry["path"]).as_posix()
            baseline = captured[path]
            if "expected_sha256" in entry and entry["expected_sha256"] != (baseline.revision if baseline else None):
                raise _conflict("File changed since the caller's baseline", path)
            if entry["op"] == "add" and baseline is not None:
                raise _conflict("Add target already exists", path)
            if entry["op"] != "add" and baseline is None:
                raise ReCTMError("NOT_FOUND", "Native edit source does not exist", category="not_found")
            content = None if entry["op"] == "delete" else entry.get("content", "")
            if content is not None and not isinstance(content, str):
                raise invalid_argument("content must be a string")
            encoded = content.encode("utf-8") if content is not None else None
            if encoded is not None and len(encoded) > MAX_BYTES:
                raise invalid_argument("Changed file exceeds 64 MiB")
            unchanged = baseline is not None and encoded == baseline.data
            changes.append(PathChange(path, baseline, encoded, baseline.mode if baseline else None, unchanged))
            affected.append({"operation": entry["op"], "path": path})
        prepared = self._result(changes, directories, affected, [], 0, 0, dry_run)
        return self.commit(prepared)

    def _open_parent(self, path: str, prepared: PreparedChanges, created: list[str]) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(self.workspace.root, flags)
        try:
            if _directory_identity(os.fstat(fd)) != prepared.directories["."]:
                raise _conflict("Native workspace changed")
            relative = Path()
            for part in Path(path).parts[:-1]:
                relative /= part
                key = relative.as_posix()
                expected = prepared.directories[key]
                if expected is None:
                    os.mkdir(part, 0o755, dir_fd=fd)
                    child = os.open(part, flags, dir_fd=fd)
                    prepared.directories[key] = _directory_identity(os.fstat(child))
                    created.append(key)
                else:
                    child = os.open(part, flags, dir_fd=fd)
                    if _directory_identity(os.fstat(child)) != expected:
                        os.close(child)
                        raise _conflict("Native parent directory changed", path)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _stage(self, item: _Pending) -> None:
        if item.change.content is None:
            return
        if len(item.change.content) > MAX_BYTES:
            raise invalid_argument("Changed file exceeds 64 MiB")
        item.staged = ".re-ctm-patch-" + secrets.token_hex(16)
        fd = os.open(item.staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=item.parent_fd)
        try:
            data = memoryview(item.change.content)
            while data:
                written = os.write(fd, data)
                if written <= 0:
                    raise OSError("Could not write Native staging file")
                data = data[written:]
            os.fchmod(fd, item.change.mode if item.change.mode is not None else 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        item.staged_snapshot = self._capture(item.staged, parent_fd=item.parent_fd)

    def _mutate(self, item: _Pending) -> None:
        if item.change.baseline is not None:
            item.backup = ".re-ctm-backup-" + secrets.token_hex(16)
            os.rename(item.name, item.backup, src_dir_fd=item.parent_fd, dst_dir_fd=item.parent_fd)
            item.touched = True
            item.backup_snapshot = self._capture(item.backup, parent_fd=item.parent_fd)
            baseline = item.change.baseline
            if item.backup_snapshot is None or item.backup_snapshot.data != baseline.data or item.backup_snapshot.identity[:-1] != baseline.identity[:-1]:
                raise _conflict("Source changed during backup", item.change.path)
        if item.staged is not None:
            if self._capture(item.staged, parent_fd=item.parent_fd) != item.staged_snapshot:
                raise _conflict("Native staged bytes changed", item.change.path)
            # The destination must still be absent. link is atomic no-overwrite,
            # unlike rename, which could overwrite an external concurrent write.
            os.link(item.staged, item.name, src_dir_fd=item.parent_fd, dst_dir_fd=item.parent_fd, follow_symlinks=False)
            item.touched = True
            os.unlink(item.staged, dir_fd=item.parent_fd)
            item.staged = None
            installed = self._capture(item.name, parent_fd=item.parent_fd)
            if (installed is None or item.staged_snapshot is None
                    or installed.data != item.change.content
                    or installed.identity[:-1] != item.staged_snapshot.identity[:-1]):
                raise _conflict("Installed Native bytes changed", item.change.path)
            # Only validated staged bytes/inode establish rollback ownership.
            # Capturing an external replacement must never authorize deleting it.
            item.installed = installed

    def _rollback(self, pending: list[_Pending]) -> list[str]:
        failures: list[str] = []
        for item in reversed(pending):
            if not item.touched:
                continue
            try:
                current = self._capture(item.name, parent_fd=item.parent_fd)
                if current != item.installed:
                    raise _conflict("Rollback target was externally changed", item.change.path)
                if item.backup is not None:
                    backup = self._capture(item.backup, parent_fd=item.parent_fd)
                    if backup != item.backup_snapshot:
                        raise _conflict("Rollback backup was externally changed", item.change.path)
                    baseline = item.change.baseline
                    if backup is None or baseline is None or backup.data != baseline.data or backup.identity[:-1] != baseline.identity[:-1]:
                        raise _conflict("Rollback backup does not match original bytes", item.change.path)
                if current is not None:
                    os.unlink(item.name, dir_fd=item.parent_fd)
                if item.backup is not None:
                    os.link(item.backup, item.name, src_dir_fd=item.parent_fd, dst_dir_fd=item.parent_fd, follow_symlinks=False)
                    os.unlink(item.backup, dir_fd=item.parent_fd)
                    item.backup = None
                item.touched = False
            except (OSError, ReCTMError):
                failures.append(item.change.path)
        return failures

    def _remove_created_directory(self, path: str, prepared: PreparedChanges) -> None:
        """Best-effort cleanup obeys the same no-follow boundary as writes."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(self.workspace.root, flags)
        try:
            if _directory_identity(os.fstat(descriptor)) != prepared.directories["."]:
                return
            relative = Path()
            parts = Path(path).parts
            for part in parts[:-1]:
                relative /= part
                child = os.open(part, flags, dir_fd=descriptor)
                if _directory_identity(os.fstat(child)) != prepared.directories[relative.as_posix()]:
                    os.close(child)
                    return
                os.close(descriptor)
                descriptor = child
            metadata = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            if _directory_identity(metadata) == prepared.directories[path]:
                os.rmdir(parts[-1], dir_fd=descriptor)
        finally:
            os.close(descriptor)

    def commit(self, prepared: PreparedChanges, *, before_commit: Callable[[], None] | None = None,
               before_mutation: Callable[[int], None] | None = None) -> dict[str, Any]:
        """Hooks support deterministic fault tests; no tool argument can set them."""
        pending: list[_Pending] = []
        created: list[str] = []
        preserve = False
        succeeded = False
        with self._lock:
            try:
                if before_commit is not None:
                    before_commit()
                self._revalidate(prepared)
                if prepared.result["dry_run"]:
                    return prepared.result
                for change in prepared.changes:
                    if change.dependency:
                        continue
                    parent_fd = self._open_parent(change.path, prepared, created)
                    item = _Pending(change, parent_fd, Path(change.path).name)
                    pending.append(item)
                    self._stage(item)
                self._revalidate(prepared)
                for index, item in enumerate(pending):
                    if before_mutation is not None:
                        before_mutation(index)
                    self._revalidate(prepared, pending)
                    self._mutate(item)
                self._revalidate(prepared, pending)
                succeeded = True
                return prepared.result
            except BaseException as exc:
                failures = self._rollback(pending)
                if failures:
                    preserve = True
                    recovery = [str(Path(item.change.path).parent / item.backup)
                                for item in pending if item.backup is not None]
                    raise ReCTMError(
                        "NATIVE_PATCH_ROLLBACK_FAILED",
                        "Rollback could not be verified. Preserved recovery evidence; inspect files before retrying.",
                        category="internal", details={"paths": failures, "recovery_files": recovery},
                    ) from exc
                if isinstance(exc, ReCTMError):
                    raise
                if isinstance(exc, OSError):
                    raise ReCTMError("NATIVE_PATCH_IO_ERROR", "Native filesystem transaction failed and was rolled back.", category="runtime") from exc
                raise
            finally:
                cleanup_failures = 0
                for item in pending:
                    try:
                        if not preserve:
                            for name in (item.staged, item.backup):
                                if name is not None:
                                    try:
                                        os.unlink(name, dir_fd=item.parent_fd)
                                    except FileNotFoundError:
                                        pass
                                    except OSError:
                                        cleanup_failures += 1
                    finally:
                        os.close(item.parent_fd)
                if succeeded and cleanup_failures:
                    prepared.result["warnings"].append("Patch committed, but temporary-file cleanup was incomplete.")
                if not succeeded and not preserve:
                    for path in reversed(created):
                        try:
                            self._remove_created_directory(path, prepared)
                        except OSError:
                            pass


def _validate_request(arguments: Mapping[str, Any], field: str) -> dict[str, Any]:
    if not isinstance(arguments, Mapping) or set(arguments) - {field, "dry_run", "idempotency_key"}:
        raise invalid_argument("Unknown Native write request field")
    if field not in arguments or type(arguments.get("dry_run", False)) is not bool:
        raise invalid_argument("Invalid Native write request")
    if len(canonical_bytes(dict(arguments))) > MAX_REQUEST_BYTES:
        raise invalid_argument("Native write request exceeds 1 MiB")
    if "idempotency_key" in arguments:
        validate_key(arguments["idempotency_key"])
    return dict(arguments)


def _validate_change(entry: Any) -> None:
    if not isinstance(entry, dict) or set(entry) - {"action", "path", "revision", "content", "destination", "edits"}:
        raise invalid_argument("Malformed structured change or unknown field")
    if not isinstance(entry.get("action"), str) or entry["action"] not in {"create", "write", "edit", "delete", "move", "copy"}:
        raise invalid_argument("Unknown structured action")
    for name in ("path", "destination", "content", "revision"):
        if name in entry and not isinstance(entry[name], str):
            raise invalid_argument(f"{name} must be a string")
    if not entry.get("path"):
        raise invalid_argument("path is required")
    revision = entry.get("revision")
    if revision is not None and (len(revision) != 64 or any(c not in "0123456789abcdefABCDEF" for c in revision)):
        raise invalid_argument("revision must be a SHA-256 hex digest")
    action = entry["action"]
    if action in {"create", "write"}:
        valid = "content" in entry and not {"destination", "edits"}.intersection(entry)
        valid = valid and (action != "create" or "revision" not in entry)
    elif action == "edit":
        edits = entry.get("edits")
        valid = isinstance(edits, list) and 1 <= len(edits) <= 200 and not {"content", "destination"}.intersection(entry)
    elif action == "delete":
        valid = not {"content", "destination", "edits"}.intersection(entry)
    else:
        valid = bool(entry.get("destination")) and not {"content", "edits"}.intersection(entry)
    if not valid:
        raise invalid_argument("Invalid field combination for structured action")


def _evidence(content: str, old: str, unchanged: bool) -> dict[str, Any]:
    return {"revision": _digest(content.encode("utf-8")), "revision_algorithm": "sha256",
            "total_lines": _lines(content), "match_quality": "exact", "changed_ranges": [] if unchanged else [
                {"start_line": 1, "end_line": _lines(content), "added_lines": _lines(content), "removed_lines": _lines(old)}]}


def edit_lines(original: str, edits: list[dict[str, Any]]) -> tuple[str, list[dict[str, int]], int, int]:
    bom, text = ("\ufeff", original[1:]) if original.startswith("\ufeff") else ("", original)
    first_lf = text.find("\n")
    ending = "\r\n" if first_lf > 0 and text[first_lf - 1] == "\r" else "\n"
    trailing = text.endswith("\n")
    raw_lines = _lf_lines(text)
    if not raw_lines and bom:
        raw_lines = [""]
    lines = [line[:-2] if line.endswith("\r\n") else line[:-1] if line.endswith("\n") else line for line in raw_lines]
    replacements = []
    for edit in edits:
        if not isinstance(edit, dict) or set(edit) - {"op", "start_line", "end_line", "line", "content"}:
            raise invalid_argument("Malformed line edit or unknown field")
        for key in ("start_line", "end_line", "line"):
            if key in edit and (type(edit[key]) is not int or edit[key] < 0):
                raise invalid_argument("Line indices must be nonnegative integers")
        op = edit.get("op")
        if not isinstance(op, str):
            raise invalid_argument("Line edit operation must be a string")
        if op in {"replace", "delete"}:
            start = edit.get("start_line", 0)
            end = edit.get("end_line", start)
            if start <= 0 or end < start or "line" in edit:
                raise invalid_argument("Invalid line range")
            start -= 1
        elif op in {"insert_before", "insert_after"}:
            if {"start_line", "end_line"}.intersection(edit) or "line" not in edit:
                raise invalid_argument("Insertion uses line only")
            start = end = edit["line"] - int(op == "insert_before")
            if start < 0:
                raise invalid_argument("insert_before starts at 1")
        else:
            raise invalid_argument("Unknown line edit operation")
        if start > len(lines) or end > len(lines):
            raise invalid_argument("Edit addresses past the last line")
        if op == "delete":
            if "content" in edit:
                raise invalid_argument("delete edit rejects content")
            new = []
        else:
            content = edit.get("content")
            if not isinstance(content, str):
                raise invalid_argument("Edit content is required")
            new = content.replace("\r\n", "\n").replace("\r", "\n").split("\n") if content else []
        replacements.append((start, end, new))
    replacements.sort(key=lambda item: (item[0], item[1]))
    for left, right in zip(replacements, replacements[1:]):
        if right[0] < left[1] or (left[0] == left[1] == right[0] == right[1]):
            raise invalid_argument("Line edits overlap")
    ranges = []
    added = removed = 0
    for start, end, new in replacements:
        if lines[start:end] != new:
            first = start + added + 1 - removed
            ranges.append({"start_line": first, "end_line": first + len(new) - 1,
                           "added_lines": len(new), "removed_lines": end - start})
            added += len(new)
            removed += end - start
    for start, end, new in reversed(replacements):
        if lines[start:end] != new:
            raw_lines[start:end] = [line + ending for line in new]
    for index, line in enumerate(raw_lines):
        if index < len(raw_lines) - 1 and not line.endswith("\n"):
            raw_lines[index] = line + ending
        if index == len(raw_lines) - 1 and not trailing and lines and line.endswith("\n") and line != ending:
            raw_lines[index] = line[:-2] if line.endswith("\r\n") else line[:-1]
    return (bom + "".join(raw_lines) if raw_lines else ""), ranges, added, removed


def _lf_lines(text: str) -> list[str]:
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines
