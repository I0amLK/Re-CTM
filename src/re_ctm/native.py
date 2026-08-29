from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Protocol

from . import ctm_compat
from .debug import DebugEventBus, new_trace_id
from .enums import NativeMode
from .errors import ReCTMError, invalid_argument
from .native_helper_bwrap import _bubblewrap_command, _helper_child_env
from .processes import CommandManager, MAX_ACTIVE_COMMANDS
from .toolchains import ToolchainExposurePlan, build_toolchain_exposure_plan


DEFAULT_EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

NATIVE_HELPER_PROTOCOL = "re-ctm-native-helper-v1"
_REQUIRED_ATTESTATION_TRUE = {
    "hard_isolation",
    "workspace_mounted",
    "forbidden_paths_hidden",
    "no_privilege_escalation",
    "mount_namespace",
    "user_namespace",
    "pid_namespace",
}


@dataclass(frozen=True)
class NativePath:
    display: str
    path: Path
    existed: bool


class NativeWorkspace:
    """Workspace-confined native file access. Dangerous mode does not alter paths."""

    def __init__(self, root: Path, *, private_root: Path) -> None:
        self.root = root.expanduser().resolve(strict=True)
        self.private_root = private_root.expanduser().resolve(strict=False)
        if not self.root.is_dir():
            raise ReCTMError(
                "INVALID_WORKSPACE",
                "Native workspace must be a directory.",
                category="validation",
            )
        if self.root in {Path("/").resolve(), Path.home().resolve()}:
            raise ReCTMError(
                "UNSAFE_WORKSPACE",
                "Filesystem root and home directory cannot be native workspaces.",
                category="security",
            )
        if self.private_root.is_relative_to(self.root) or self.root.is_relative_to(
            self.private_root
        ):
            raise ReCTMError(
                "TRUST_DOMAIN_OVERLAP",
                "Native workspace and workflow-private root must not overlap.",
                category="security",
            )

    def resolve_existing(self, raw_path: str = ".") -> NativePath:
        pure = self._validate_text(raw_path or ".")
        candidate = self.root.joinpath(*pure.parts)
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ReCTMError(
                "NOT_FOUND",
                f"Path not found: {raw_path}",
                category="not_found",
            ) from exc
        self._assert_inside(resolved, candidate)
        return NativePath(_display(resolved, self.root), resolved, True)

    def resolve_for_write(self, raw_path: str) -> NativePath:
        pure = self._validate_text(raw_path)
        if pure.name in {"", ".", ".."}:
            raise invalid_argument("Invalid write target.", path=raw_path)
        candidate = self.root.joinpath(*pure.parts)
        if candidate.exists() or candidate.is_symlink():
            resolved = candidate.resolve(strict=True)
            self._assert_inside(resolved, candidate)
            if candidate.is_symlink():
                raise ReCTMError(
                    "SYMLINK_WRITE_DENIED",
                    "Writing through symlinks is denied.",
                    category="security",
                )
            return NativePath(_display(resolved, self.root), resolved, True)
        parent = candidate.parent
        missing: list[Path] = []
        while not parent.exists():
            missing.append(parent)
            if parent == self.root or parent.parent == parent:
                break
            parent = parent.parent
        try:
            resolved_parent = parent.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ReCTMError(
                "NOT_FOUND",
                f"Parent directory not found: {raw_path}",
                category="not_found",
            ) from exc
        self._assert_inside(resolved_parent, parent)
        target = resolved_parent.joinpath(
            *reversed([item.name for item in missing]),
            candidate.name,
        )
        return NativePath(_display(target, self.root), target, False)

    def read_file(
        self,
        raw_path: str,
        *,
        start_line: int = 1,
        max_lines: int = 500,
        max_bytes: int = 131_072,
    ) -> dict[str, Any]:
        resolved = self.resolve_existing(raw_path)
        if resolved.path.is_dir():
            raise ReCTMError("IS_DIRECTORY", "Path is a directory.", category="validation")
        data = resolved.path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReCTMError(
                "BINARY_FILE",
                "Native read_file supports UTF-8 text only.",
                category="validation",
            ) from exc
        lines = text.splitlines(keepends=True)
        if start_line < 1:
            raise invalid_argument("start_line must be >= 1")
        selected: list[str] = []
        bytes_used = 0
        index = start_line - 1
        while index < len(lines) and len(selected) < max_lines:
            encoded = lines[index].encode("utf-8")
            if selected and bytes_used + len(encoded) > max_bytes:
                break
            if not selected and len(encoded) > max_bytes:
                selected.append(encoded[:max_bytes].decode("utf-8", errors="ignore"))
                bytes_used = max_bytes
                break
            selected.append(lines[index])
            bytes_used += len(encoded)
            index += 1
        content = "".join(selected)
        end_line = start_line + max(len(selected) - 1, 0)
        truncated = index < len(lines) or len(data) > max_bytes and not selected
        return {
            "path": resolved.display,
            "content": content,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": len(lines),
            "total_bytes": len(data),
            "truncated": truncated,
            "next_start_line": index + 1 if index < len(lines) else None,
        }

    def list_files(
        self,
        raw_path: str = ".",
        *,
        include_hidden: bool = False,
        include_ignored: bool = False,
        max_results: int = 1000,
    ) -> dict[str, Any]:
        resolved = self.resolve_existing(raw_path)
        if not resolved.path.is_dir():
            raise ReCTMError("NOT_A_DIRECTORY", "Path is not a directory.", category="validation")
        files: list[dict[str, Any]] = []
        truncated = False
        for current, dirs, names in os.walk(resolved.path, followlinks=False):
            current_path = Path(current)
            dirs[:] = sorted(
                name
                for name in dirs
                if not self._ignored_component(name, include_hidden, include_ignored)
                and not (current_path / name).is_symlink()
            )
            for name in sorted(names):
                if self._ignored_component(name, include_hidden, include_ignored):
                    continue
                path = current_path / name
                if path.is_symlink():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                files.append(
                    {
                        "path": _display(path, self.root),
                        "type": "file",
                        "size_bytes": stat.st_size,
                    }
                )
                if len(files) >= max_results:
                    truncated = True
                    break
            if truncated:
                break
        return {"files": files, "truncated": truncated, "count": len(files)}

    def search_text(
        self,
        query: str,
        *,
        raw_path: str = ".",
        case_sensitive: bool = False,
        max_results: int = 1000,
    ) -> dict[str, Any]:
        if not query:
            raise invalid_argument("query is required")
        listed = self.list_files(raw_path, max_results=10_000)
        needle = query if case_sensitive else query.lower()
        matches: list[dict[str, Any]] = []
        for item in listed["files"]:
            path = self.resolve_existing(item["path"]).path
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                haystack = line if case_sensitive else line.lower()
                position = haystack.find(needle)
                if position < 0:
                    continue
                matches.append(
                    {
                        "path": item["path"],
                        "line": line_number,
                        "column": position + 1,
                        "preview": line[:500],
                    }
                )
                if len(matches) >= max_results:
                    return {"matches": matches, "truncated": True, "count": len(matches)}
        return {"matches": matches, "truncated": False, "count": len(matches)}

    def _validate_text(self, raw_path: str) -> PurePosixPath:
        if not isinstance(raw_path, str) or not raw_path:
            raise invalid_argument("Path must be a non-empty string.")
        if "\x00" in raw_path:
            raise invalid_argument("Path contains a NUL byte.")
        if raw_path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", raw_path):
            raise ReCTMError(
                "ABSOLUTE_PATH_DENIED",
                "Absolute paths are denied.",
                category="security",
            )
        pure = PurePosixPath(raw_path)
        if any(part == ".." for part in pure.parts):
            raise ReCTMError(
                "PATH_OUTSIDE_WORKSPACE",
                "Path escapes the native workspace.",
                category="security",
            )
        return pure

    def _assert_inside(self, resolved: Path, candidate: Path) -> None:
        if not resolved.is_relative_to(self.root):
            code = "SYMLINK_ESCAPE" if candidate.is_symlink() else "PATH_OUTSIDE_WORKSPACE"
            raise ReCTMError(code, "Path escapes the native workspace.", category="security")
        if resolved.is_relative_to(self.private_root):
            raise ReCTMError(
                "PRIVATE_VAULT_DENIED",
                "Native tools cannot access the Rethlas private vault.",
                category="security",
            )

    @staticmethod
    def _ignored_component(name: str, include_hidden: bool, include_ignored: bool) -> bool:
        if not include_hidden and name.startswith("."):
            return True
        return not include_ignored and name in DEFAULT_EXCLUDED


class NativeExecBackend(Protocol):
    def execute(
        self,
        *,
        workspace: Path,
        argv: list[str],
        workdir: str,
        timeout_ms: int,
        mode: NativeMode,
    ) -> dict[str, Any]: ...


class DisabledExecBackend:
    def execute(
        self,
        *,
        workspace: Path,
        argv: list[str],
        workdir: str,
        timeout_ms: int,
        mode: NativeMode,
    ) -> dict[str, Any]:
        raise ReCTMError(
            "NATIVE_ISOLATION_REQUIRED",
            "Native command execution is disabled until an external hard-isolation backend is configured and manually validated.",
            category="security",
            details={"mode": mode.value, "manual_validation_required": True},
        )


class ExternalHelperExecBackend:
    """JSON helper protocol; the helper owns the OS-level isolation boundary.

    The helper is trusted, but every reply is still nonce-bound and checked
    for the minimum properties required by the Re-CTM authorization axioms.
    A Python helper is launched with the active interpreter so wheel installs
    do not depend on executable-bit preservation.
    """

    def __init__(
        self,
        helper: Path | list[str] | tuple[str, ...],
        *,
        output_limit: int = 1_048_576,
    ) -> None:
        self.command = _helper_command(helper)
        self.output_limit = output_limit
        self.attestation: dict[str, Any] | None = None

    def attest(
        self,
        *,
        workspace: Path,
        forbidden_paths: Iterable[Path],
    ) -> dict[str, Any]:
        request = {
            "protocol": NATIVE_HELPER_PROTOCOL,
            "operation": "attest",
            "request_id": secrets.token_urlsafe(18),
            "workspace": str(workspace.expanduser().resolve(strict=True)),
            "forbidden_paths": [
                str(path.expanduser().resolve(strict=False)) for path in forbidden_paths
            ],
            "mode": NativeMode.SAFE.value,
        }
        payload = self._invoke(request, timeout_seconds=20.0)
        attestation = self._validate_response(
            payload,
            request=request,
            require_safe_network=True,
        )
        self.attestation = attestation
        return dict(attestation)

    def execute(
        self,
        *,
        workspace: Path,
        argv: list[str],
        workdir: str,
        timeout_ms: int,
        mode: NativeMode,
    ) -> dict[str, Any]:
        request = {
            "protocol": NATIVE_HELPER_PROTOCOL,
            "operation": "execute",
            "request_id": secrets.token_urlsafe(18),
            "workspace": str(workspace),
            "argv": argv,
            "workdir": workdir,
            "timeout_ms": timeout_ms,
            "mode": mode.value,
            "required_isolation": {
                "private_vault_not_mounted": True,
                "no_privilege_escalation": True,
            },
        }
        payload = self._invoke(
            request,
            timeout_seconds=max(1.0, timeout_ms / 1000 + 5.0),
        )
        self._validate_response(
            payload,
            request=request,
            require_safe_network=mode is NativeMode.SAFE,
        )
        return payload

    def _invoke(self, request: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        helper_env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR"}
        }
        helper_env["PYTHONUNBUFFERED"] = "1"
        completed = subprocess.run(
            self.command,
            input=json.dumps(request),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=helper_env,
        )
        if len(completed.stdout.encode("utf-8")) > self.output_limit:
            raise ReCTMError(
                "NATIVE_HELPER_OUTPUT_TOO_LARGE",
                "Native helper response exceeded the configured limit.",
                category="runtime",
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ReCTMError(
                "NATIVE_HELPER_PROTOCOL_ERROR",
                "Native helper did not return valid JSON.",
                category="runtime",
                details={"exit_code": completed.returncode, "stderr": completed.stderr[-4000:]},
            ) from exc
        if not isinstance(payload, dict) or payload.get("protocol") != NATIVE_HELPER_PROTOCOL:
            raise ReCTMError(
                "NATIVE_HELPER_PROTOCOL_ERROR",
                "Native helper returned an unsupported response.",
                category="runtime",
            )
        if completed.returncode != 0 and payload.get("ok") is not False:
            raise ReCTMError(
                "NATIVE_HELPER_PROTOCOL_ERROR",
                "Native helper exited unsuccessfully without a structured denial.",
                category="runtime",
                details={"exit_code": completed.returncode, "stderr": completed.stderr[-4000:]},
            )
        return payload

    def _validate_response(
        self,
        payload: dict[str, Any],
        *,
        request: Mapping[str, Any],
        require_safe_network: bool,
    ) -> dict[str, Any]:
        if payload.get("request_id") != request.get("request_id"):
            raise ReCTMError(
                "NATIVE_HELPER_PROTOCOL_ERROR",
                "Native helper response nonce did not match the request.",
                category="security",
            )
        if payload.get("operation") != request.get("operation"):
            raise ReCTMError(
                "NATIVE_HELPER_PROTOCOL_ERROR",
                "Native helper response operation did not match the request.",
                category="security",
            )
        if payload.get("ok") is not True:
            raw_error = payload.get("error")
            error = raw_error if isinstance(raw_error, Mapping) else {}
            helper_details = error.get("details")
            raise ReCTMError(
                str(error.get("code") or "NATIVE_HELPER_DENIED"),
                str(error.get("message") or "Native isolation helper denied the request."),
                category=str(error.get("category") or "security"),
                details={
                    "helper_details": dict(helper_details)
                    if isinstance(helper_details, Mapping)
                    else {}
                },
            )
        raw_attestation = payload.get("attestation")
        if not isinstance(raw_attestation, Mapping):
            raise ReCTMError(
                "NATIVE_HELPER_ATTESTATION_INVALID",
                "Native helper response did not include an attestation object.",
                category="security",
            )
        attestation = dict(raw_attestation)
        missing = sorted(
            key for key in _REQUIRED_ATTESTATION_TRUE if attestation.get(key) is not True
        )
        if missing or attestation.get("private_vault_mounted") is not False:
            raise ReCTMError(
                "NATIVE_HELPER_ATTESTATION_INVALID",
                "Native helper did not attest every required isolation property.",
                category="security",
                details={
                    "missing_true_properties": missing,
                    "private_vault_mounted": attestation.get("private_vault_mounted"),
                },
            )
        if require_safe_network and attestation.get("network_isolated") is not True:
            raise ReCTMError(
                "NATIVE_HELPER_ATTESTATION_INVALID",
                "Safe mode requires an isolated network namespace.",
                category="security",
            )
        return attestation


class BubblewrapExecBackend(ExternalHelperExecBackend):
    """Built-in Linux helper transported through a separate Python process."""

    def __init__(
        self,
        *,
        output_limit: int = 1_048_576,
        host_path: str | None = None,
        extra_read_roots: Iterable[Path] = (),
        exposure_plan: ToolchainExposurePlan | None = None,
    ) -> None:
        super().__init__(
            Path(__file__).with_name("native_helper_bwrap.py"),
            output_limit=output_limit,
        )
        self.exposure_plan = exposure_plan
        self.host_path = exposure_plan.sandbox_path if exposure_plan is not None else host_path
        self.extra_read_roots = (
            exposure_plan.read_only_roots
            if exposure_plan is not None
            else tuple(extra_read_roots)
        )
        self.forbidden_paths: tuple[Path, ...] = ()

    def attest(
        self,
        *,
        workspace: Path,
        forbidden_paths: Iterable[Path],
    ) -> dict[str, Any]:
        self.forbidden_paths = tuple(
            path.expanduser().resolve(strict=False) for path in forbidden_paths
        )
        request = {
            "protocol": NATIVE_HELPER_PROTOCOL,
            "operation": "attest",
            "request_id": secrets.token_urlsafe(18),
            "workspace": str(workspace.expanduser().resolve(strict=True)),
            "forbidden_paths": [str(path) for path in self.forbidden_paths],
            "mode": NativeMode.SAFE.value,
            "host_path": self.host_path or "",
            "extra_read_roots": [str(path) for path in self.extra_read_roots],
        }
        payload = self._invoke(request, timeout_seconds=30.0)
        attestation = self._validate_response(
            payload,
            request=request,
            require_safe_network=True,
        )
        expected_root_count = len(self.extra_read_roots)
        if (
            attestation.get("toolchain_roots_validated") is not True
            or attestation.get("toolchain_read_only_root_count") != expected_root_count
        ):
            raise ReCTMError(
                "NATIVE_HELPER_ATTESTATION_INVALID",
                "Bubblewrap startup attestation did not validate the complete read-only toolchain plan.",
                category="security",
                details={
                    "expected_root_count": expected_root_count,
                    "reported_root_count": attestation.get(
                        "toolchain_read_only_root_count"
                    ),
                },
            )
        attestation["toolchain_host_path_inherited"] = bool(
            self.exposure_plan is not None
            and self.exposure_plan.host_path_inherited
        )
        self.attestation = dict(attestation)
        return dict(attestation)

    def execute(
        self,
        *,
        workspace: Path,
        argv: list[str],
        workdir: str,
        timeout_ms: int,
        mode: NativeMode,
    ) -> dict[str, Any]:
        request = {
            "protocol": NATIVE_HELPER_PROTOCOL,
            "operation": "execute",
            "request_id": secrets.token_urlsafe(18),
            "workspace": str(workspace),
            "argv": argv,
            "workdir": workdir,
            "timeout_ms": timeout_ms,
            "mode": mode.value,
            "host_path": self.host_path or "",
            "extra_read_roots": [str(path) for path in self.extra_read_roots],
            "forbidden_paths": [str(path) for path in self.forbidden_paths],
            "required_isolation": {
                "private_vault_not_mounted": True,
                "no_privilege_escalation": True,
                "toolchain_roots_read_only": True,
            },
        }
        payload = self._invoke(
            request,
            timeout_seconds=max(1.0, timeout_ms / 1000 + 5.0),
        )
        attestation = self._validate_response(
            payload,
            request=request,
            require_safe_network=mode is NativeMode.SAFE,
        )
        if (
            attestation.get("toolchain_roots_validated") is not True
            or attestation.get("toolchain_read_only_root_count")
            != len(self.extra_read_roots)
        ):
            raise ReCTMError(
                "NATIVE_HELPER_ATTESTATION_INVALID",
                "Bubblewrap execution response did not validate the complete read-only toolchain plan.",
                category="security",
            )
        return payload


def discover_dangerous_toolchain_roots(
    *,
    workspace: Path,
    forbidden_paths: Iterable[Path],
    host_path: str | None = None,
) -> tuple[Path, ...]:
    """Compatibility wrapper around the generic exposure-plan builder."""

    return build_toolchain_exposure_plan(
        mode=NativeMode.DANGEROUS,
        workspace=workspace,
        forbidden_paths=forbidden_paths,
        host_path=host_path,
    ).discovered_roots


class AtomicNativeEditor:
    def __init__(self, workspace: NativeWorkspace) -> None:
        self.workspace = workspace
        self._lock = threading.Lock()

    def apply(self, operations: Iterable[Mapping[str, Any]], *, dry_run: bool = False) -> dict[str, Any]:
        normalized = [dict(operation) for operation in operations]
        if not normalized:
            raise invalid_argument("operations must be a non-empty array")
        with self._lock:
            staged: list[tuple[str, NativePath, str | None, str | None]] = []
            seen: set[Path] = set()
            for operation in normalized:
                kind = str(operation.get("op") or "")
                path = str(operation.get("path") or "")
                if kind not in {"add", "update", "delete"}:
                    raise invalid_argument("op must be add, update, or delete", op=kind)
                resolved = (
                    self.workspace.resolve_for_write(path)
                    if kind == "add"
                    else self.workspace.resolve_existing(path)
                )
                if resolved.path in seen:
                    raise invalid_argument("the same path cannot be staged twice", path=path)
                seen.add(resolved.path)
                if resolved.path.is_dir():
                    raise ReCTMError("IS_DIRECTORY", "Patch target is a directory.", category="validation")
                existing_hash = _sha256_file(resolved.path) if resolved.existed else None
                expected = operation.get("expected_sha256")
                if expected is not None and expected != existing_hash:
                    raise ReCTMError(
                        "PATCH_CONFLICT",
                        "File changed since the caller's baseline.",
                        category="conflict",
                        retryable=True,
                        details={"path": resolved.display, "expected": expected, "actual": existing_hash},
                    )
                if kind == "add" and resolved.existed:
                    raise ReCTMError("PATCH_CONFLICT", "Add target already exists.", category="conflict")
                content = None if kind == "delete" else str(operation.get("content") or "")
                staged.append((kind, resolved, content, existing_hash))
            if not dry_run:
                self._commit(staged)
        return {
            "dry_run": dry_run,
            "affected_files": [
                {"operation": kind, "path": resolved.display}
                for kind, resolved, _content, _hash in staged
            ],
        }

    def _commit(self, staged: list[tuple[str, NativePath, str | None, str | None]]) -> None:
        prepared: dict[Path, Path] = {}
        backups: dict[Path, Path] = {}
        installed: set[Path] = set()
        try:
            for kind, resolved, content, _baseline in staged:
                if kind != "delete":
                    resolved.path.parent.mkdir(parents=True, exist_ok=True)
                    fd, raw = tempfile.mkstemp(prefix=".re-ctm-patch-", dir=resolved.path.parent)
                    temp = Path(raw)
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        handle.write(content or "")
                        handle.flush()
                        os.fsync(handle.fileno())
                    prepared[resolved.path] = temp
            for _kind, resolved, _content, baseline in staged:
                current = _sha256_file(resolved.path) if resolved.path.exists() else None
                if current != baseline:
                    raise ReCTMError(
                        "PATCH_CONFLICT",
                        "File changed while the patch was being prepared.",
                        category="conflict",
                        retryable=True,
                        details={"path": resolved.display},
                    )
            for _kind, resolved, _content, _baseline in staged:
                if resolved.path.exists():
                    fd, raw = tempfile.mkstemp(prefix=".re-ctm-backup-", dir=resolved.path.parent)
                    os.close(fd)
                    backup = Path(raw)
                    backup.unlink()
                    os.replace(resolved.path, backup)
                    backups[resolved.path] = backup
            for kind, resolved, _content, _baseline in staged:
                if kind != "delete":
                    os.replace(prepared[resolved.path], resolved.path)
                    installed.add(resolved.path)
        except Exception:
            for _kind, resolved, _content, _baseline in reversed(staged):
                try:
                    if resolved.path in installed and resolved.path.exists():
                        resolved.path.unlink()
                    backup = backups.get(resolved.path)
                    if backup is not None and backup.exists():
                        os.replace(backup, resolved.path)
                except OSError:
                    pass
            raise
        finally:
            for path in prepared.values():
                path.unlink(missing_ok=True)
            for path in backups.values():
                path.unlink(missing_ok=True)


class NativeRuntime:
    def __init__(
        self,
        workspace: NativeWorkspace,
        mode: NativeMode,
        debug: DebugEventBus,
        *,
        exec_backend: NativeExecBackend | None = None,
    ) -> None:
        self.workspace = workspace
        self.mode = mode
        self.debug = debug
        self.exec_backend = exec_backend or DisabledExecBackend()
        self.editor = AtomicNativeEditor(workspace)
        self.command_manager = CommandManager()

    def server_info(self) -> dict[str, Any]:
        raw_attestation = getattr(self.exec_backend, "attestation", None)
        exposure_plan = getattr(self.exec_backend, "exposure_plan", None)
        attestation = (
            {
                key: raw_attestation.get(key)
                for key in (
                    "backend",
                    "backend_version",
                    "hard_isolation",
                    "workspace_mounted",
                    "forbidden_paths_hidden",
                    "private_vault_mounted",
                    "network_isolated",
                    "no_privilege_escalation",
                    "mount_namespace",
                    "user_namespace",
                    "pid_namespace",
                )
                if key in raw_attestation
            }
            if isinstance(raw_attestation, Mapping)
            else None
        )
        return {
            "workspace": str(self.workspace.root),
            "native_mode": self.mode.value,
            "workflow_authority_inherited": False,
            "private_vault_visible": False,
            "native_exec_backend": type(self.exec_backend).__name__,
            "native_exec_attestation": attestation,
            "toolchain_exposure": (
                exposure_plan.summary(include_paths=False)
                if isinstance(exposure_plan, ToolchainExposurePlan)
                else {
                    "policy": "unavailable",
                    "resolved_read_only_root_count": 0,
                }
            ),
            "ctm_native_tool_compatibility": "18_of_18_surface",
            "command_lifecycle": {
                "max_active_commands": MAX_ACTIVE_COMMANDS,
                "write_stdin": True,
                "read_output": True,
                "kill_command": True,
            },
        }

    def close(self) -> None:
        self.command_manager.close()

    def check_exec_environment(self, **arguments: Any) -> dict[str, Any]:
        _ = arguments
        raw_attestation = getattr(self.exec_backend, "attestation", None)
        exposure_plan = getattr(self.exec_backend, "exposure_plan", None)
        global_tmp = {
            NativeMode.SAFE: "blocked",
            NativeMode.TRUSTED: "tmp-prefix",
            NativeMode.DANGEROUS: "allowed",
        }[self.mode]
        warnings: list[str] = []
        if self.mode is NativeMode.DANGEROUS:
            warnings.append("permission_mode=dangerous disables MCP safety gates")
        if not isinstance(self.exec_backend, BubblewrapExecBackend):
            warnings.append(
                "Full interactive command lifecycle requires the built-in bubblewrap backend; disabled/external helpers may execute synchronously only."
            )
        return {
            "ok": True,
            "native_mode": self.mode.value,
            "permission_mode": self.mode.value,
            "workspace": str(self.workspace.root),
            "network_allowed": self.mode is not NativeMode.SAFE,
            "runtime_dir": "/tmp",
            "home": "/home/re-ctm",
            "tmpdir": "/tmp",
            "cache_dir": "/tmp/cache",
            "native_exec_backend": type(self.exec_backend).__name__,
            "hard_isolation_attested": bool(
                isinstance(raw_attestation, Mapping)
                and raw_attestation.get("hard_isolation") is True
                and raw_attestation.get("private_vault_mounted") is False
            ),
            "command_lifecycle_supported": isinstance(self.exec_backend, BubblewrapExecBackend),
            "max_active_commands": MAX_ACTIVE_COMMANDS,
            "private_vault_visible": False,
            "landlock_enabled": False,
            "landlock_abi": None,
            "global_tmp_write": global_tmp,
            "toolchain_exposure": (
                exposure_plan.summary(include_paths=True)
                if isinstance(exposure_plan, ToolchainExposurePlan)
                else {
                    "policy": "unavailable",
                    "mount_mode": "none",
                    "resolved_read_only_root_count": 0,
                }
            ),
            "warnings": warnings,
        }

    def read_file(self, **arguments: Any) -> dict[str, Any]:
        encoding = str(arguments.get("encoding", "utf-8"))
        if encoding != "utf-8":
            raise ReCTMError("UNSUPPORTED_ENCODING", "Only utf-8 is supported.", category="validation")
        start_line = int(arguments.get("start_line", 1))
        end_line = arguments.get("end_line")
        max_lines = arguments.get("max_lines")
        if end_line is not None and max_lines is not None:
            expected_end = start_line + int(max_lines) - 1
            if int(end_line) != expected_end:
                raise invalid_argument("end_line and max_lines select different ranges")
        if end_line is not None:
            max_lines = max(1, int(end_line) - start_line + 1)
        return self.workspace.read_file(
            str(arguments.get("path") or ""),
            start_line=start_line,
            max_lines=int(max_lines or 500),
            max_bytes=int(arguments.get("max_bytes", 131_072)),
        )

    def list_dir(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.list_dir(self.workspace, arguments)

    def list_files(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.list_files(self.workspace, arguments)

    def search_text(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.search_text(self.workspace, arguments)

    def apply_patch(self, **arguments: Any) -> dict[str, Any]:
        if isinstance(arguments.get("patch"), str):
            editor_ops, metadata = ctm_compat.patch_to_editor_operations(
                self.workspace,
                str(arguments["patch"]),
            )
            result = self.editor.apply(editor_ops, dry_run=bool(arguments.get("dry_run", False)))
            return {"clean": True, **metadata, **result, "warnings": []}
        operations = arguments.get("operations")
        if not isinstance(operations, list):
            raise invalid_argument("patch must be a patch envelope")
        return self.editor.apply(operations, dry_run=bool(arguments.get("dry_run", False)))

    def git_status(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.git_status(self.workspace, arguments)

    def git_diff(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.git_diff(self.workspace, arguments)

    def git_log(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.git_log(self.workspace, arguments)

    def git_show(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.git_show(self.workspace, arguments)

    def git_blame(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.git_blame(self.workspace, arguments)

    def request_permissions(self, **arguments: Any) -> dict[str, Any]:
        if self.mode is NativeMode.DANGEROUS:
            return {
                "ok": True,
                "status": "granted",
                "grant_id": "dangerously-skip-all-permissions",
                "expires_at": None,
                "constraints": {
                    "mode": "dangerously_skip_all_permissions",
                    "workspace": str(self.workspace.root),
                    "requested": dict(arguments),
                },
                "warnings": [
                    "dangerously-skip-all-permissions is enabled; permission-gated operations are auto-granted"
                ],
            }
        return {
            "ok": False,
            "status": "unsupported",
            "grant_id": None,
            "expires_at": None,
            "error": {
                "code": "ELICITATION_UNSUPPORTED",
                "message": "Permission elicitation is not available for this client.",
                "category": "permission",
                "retryable": False,
                "details": {"requested": dict(arguments)},
            },
        }

    def view_image(self, **arguments: Any) -> dict[str, Any]:
        return ctm_compat.view_image(self.workspace, arguments)

    def export_verified_latex(
        self,
        *,
        path: str,
        content: str,
        expected_sha256: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        if not path.lower().endswith(".tex"):
            raise invalid_argument("verified LaTeX export path must end in .tex", path=path)
        resolved = self.workspace.resolve_for_write(path)
        existing_sha256 = _sha256_file(resolved.path) if resolved.existed else None
        if resolved.existed and not expected_sha256:
            raise ReCTMError(
                "EXPORT_BASELINE_REQUIRED",
                "Overwriting an existing export requires expected_sha256.",
                category="conflict",
                retryable=True,
                details={"path": resolved.display, "actual_sha256": existing_sha256},
            )
        operation: dict[str, Any] = {
            "op": "update" if resolved.existed else "add",
            "path": resolved.display,
            "content": content,
        }
        if expected_sha256 is not None:
            operation["expected_sha256"] = expected_sha256
        result = self.editor.apply([operation])
        content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.debug.emit(
            "native.verified_latex_exported",
            "native_runtime",
            trace_id=trace_id or new_trace_id(),
            decision="allow",
            reason="mechanically_finalized_artifact_bridge",
            details={
                "path": resolved.display,
                "content_sha256": content_sha256,
                "content_bytes": len(content.encode("utf-8")),
                "native_mode": self.mode.value,
                "workflow_authority_inherited": False,
            },
        )
        return {
            **result,
            "path": resolved.display,
            "sha256": content_sha256,
            "bytes": len(content.encode("utf-8")),
        }

    def ensure_verified_latex(
        self,
        *,
        path: str,
        content: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        """Create the default verified export once and make retries idempotent.

        This is the automatic finalization bridge used by the MCP workflow. It
        never overwrites different workspace content. Explicit replacement
        remains available through export_verified_latex with an expected hash.
        """

        if not path.lower().endswith(".tex"):
            raise invalid_argument("verified LaTeX export path must end in .tex", path=path)
        resolved = self.workspace.resolve_for_write(path)
        content_bytes = content.encode("utf-8")
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()
        if resolved.existed:
            if not resolved.path.is_file():
                raise ReCTMError(
                    "EXPORT_PATH_CONFLICT",
                    "Automatic verified export target is not a regular file.",
                    category="conflict",
                    details={"path": resolved.display},
                )
            existing_sha256 = _sha256_file(resolved.path)
            if existing_sha256 != content_sha256:
                raise ReCTMError(
                    "EXPORT_PATH_CONFLICT",
                    "Automatic verified export will not overwrite different workspace content.",
                    category="conflict",
                    retryable=True,
                    details={
                        "path": resolved.display,
                        "actual_sha256": existing_sha256,
                        "verified_sha256": content_sha256,
                    },
                )
            self.debug.emit(
                "native.verified_latex_export_confirmed",
                "native_runtime",
                trace_id=trace_id or new_trace_id(),
                decision="allow",
                reason="automatic_export_already_matches",
                details={
                    "path": resolved.display,
                    "content_sha256": content_sha256,
                    "content_bytes": len(content_bytes),
                    "workflow_authority_inherited": False,
                },
            )
            return {
                "ok": True,
                "status": "unchanged",
                "path": resolved.display,
                "sha256": content_sha256,
                "bytes": len(content_bytes),
            }
        result = self.export_verified_latex(
            path=resolved.display,
            content=content,
            trace_id=trace_id,
        )
        return {"ok": True, **result, "status": "created"}

    def exec_command(self, **arguments: Any) -> dict[str, Any]:
        trace_id = str(arguments.get("trace_id") or new_trace_id())
        cmd = str(arguments.get("cmd") or "")
        argv = arguments.get("argv")
        if cmd:
            child_argv = ["/bin/sh", "-lc", cmd]
        elif isinstance(argv, list) and argv and all(isinstance(item, str) for item in argv):
            child_argv = list(argv)
            cmd = " ".join(child_argv)
        else:
            raise invalid_argument("cmd is required")
        workdir_arg = arguments.get("workdir", arguments.get("cwd", "."))
        if "workdir" in arguments and "cwd" in arguments and str(arguments["workdir"]) != str(arguments["cwd"]):
            raise invalid_argument("workdir and cwd refer to different directories")
        workdir = str(workdir_arg or ".")
        resolved = self.workspace.resolve_existing(workdir)
        if not resolved.path.is_dir():
            raise ReCTMError("NOT_A_DIRECTORY", "workdir is not a directory.", category="validation")
        timeout_ms = int(arguments.get("timeout_ms", 30_000))
        yield_time_ms = int(arguments.get("yield_time_ms", 10_000))
        max_output_bytes = int(arguments.get("max_output_bytes", 65_536))
        preview_bytes = int(arguments.get("preview_bytes", 4096))
        verbosity = arguments.get("verbosity")
        stdin_text = str(arguments.get("stdin", ""))
        tty = bool(arguments.get("tty", False))
        extra_env = arguments.get("env", {})
        if not isinstance(extra_env, Mapping) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in extra_env.items()
        ):
            raise invalid_argument("env must be an object whose values are strings")
        if not isinstance(self.exec_backend, DisabledExecBackend):
            attestation = getattr(self.exec_backend, "attestation", None)
            if not (
                isinstance(attestation, Mapping)
                and attestation.get("hard_isolation") is True
                and attestation.get("private_vault_mounted") is False
            ):
                raise ReCTMError(
                    "NATIVE_ISOLATION_REQUIRED",
                    "Native execution backend has not completed a valid hard-isolation attestation.",
                    category="security",
                    details={"backend": type(self.exec_backend).__name__},
                )
        ctm_compat.check_command_policy(
            self.mode.value,
            cmd,
            {str(key): str(value) for key, value in extra_env.items()},
        )
        self.debug.emit(
            "native.exec_requested",
            "native_runtime",
            trace_id=trace_id,
            decision="allow",
            reason="delegating_to_hard_isolation_backend",
            details={
                "mode": self.mode.value,
                "command_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(),
                "argv_sha256": hashlib.sha256(
                    json.dumps(child_argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "workdir": resolved.display,
                "timeout_ms": timeout_ms,
                "tty": tty,
            },
        )
        if isinstance(self.exec_backend, BubblewrapExecBackend):
            command_argv = _bubblewrap_command(
                workspace=self.workspace.root,
                workdir=resolved.display,
                mode=self.mode.value,
                argv=child_argv,
                extra_env={str(key): str(value) for key, value in extra_env.items()},
                host_path=self.exec_backend.host_path,
                extra_read_roots=self.exec_backend.extra_read_roots,
                forbidden_paths=self.exec_backend.forbidden_paths,
            )
            return self.command_manager.start(
                command_argv,
                env=_helper_child_env(),
                timeout_ms=timeout_ms,
                yield_time_ms=yield_time_ms,
                max_output_bytes=max_output_bytes,
                stdin_text=stdin_text,
                tty=tty,
                verbosity=str(verbosity) if verbosity is not None else None,
                preview_bytes=preview_bytes,
            )
        return self.exec_backend.execute(
            workspace=self.workspace.root,
            argv=child_argv,
            workdir=resolved.display,
            timeout_ms=timeout_ms,
            mode=self.mode,
        )

    def write_stdin(self, **arguments: Any) -> dict[str, Any]:
        return self.command_manager.poll(
            str(arguments.get("command_id") or ""),
            chars=str(arguments.get("chars", "")),
            yield_time_ms=int(arguments.get("yield_time_ms", 10_000)),
            max_output_bytes=int(arguments.get("max_output_bytes", 65_536)),
            verbosity=str(arguments["verbosity"]) if arguments.get("verbosity") is not None else None,
            preview_bytes=int(arguments.get("preview_bytes", 4096)),
        )

    def kill_command(self, **arguments: Any) -> dict[str, Any]:
        return self.command_manager.kill(
            str(arguments.get("command_id") or ""),
            signal_name=str(arguments.get("signal", "TERM")),
            wait_ms=int(arguments.get("wait_ms", 5000)),
            kill_wait_ms=int(arguments.get("kill_wait_ms", 2000)),
            max_output_bytes=int(arguments.get("max_output_bytes", 65_536)),
            verbosity=str(arguments["verbosity"]) if arguments.get("verbosity") is not None else None,
            preview_bytes=int(arguments.get("preview_bytes", 4096)),
        )

    def read_output(self, **arguments: Any) -> dict[str, Any]:
        stream = arguments.get("stream")
        return self.command_manager.read_output(
            str(arguments.get("output_ref") or ""),
            stream=str(stream) if stream is not None else None,
            offset=int(arguments.get("offset", 0)),
            limit=int(arguments.get("limit", 4096)),
        )


def _helper_command(helper: Path | list[str] | tuple[str, ...]) -> list[str]:
    if isinstance(helper, Path):
        resolved = helper.expanduser().resolve(strict=True)
        if not resolved.is_file():
            raise ReCTMError(
                "INVALID_NATIVE_HELPER",
                "Native isolation helper must be a file.",
                category="validation",
            )
        if resolved.suffix.lower() == ".py":
            return [sys.executable, str(resolved)]
        if not os.access(resolved, os.X_OK):
            raise ReCTMError(
                "INVALID_NATIVE_HELPER",
                "Native isolation helper must be executable.",
                category="validation",
            )
        return [str(resolved)]
    command = [str(item) for item in helper]
    if not command or any(not item for item in command):
        raise ReCTMError(
            "INVALID_NATIVE_HELPER",
            "Native isolation helper command must be non-empty.",
            category="validation",
        )
    return command


def _display(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    return relative.as_posix() or "."


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
