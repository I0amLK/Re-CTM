from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Iterable

from .enums import NativeMode
from .errors import ReCTMError


DEFAULT_SANDBOX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

_SYSTEM_PREFIXES = tuple(
    Path(value).resolve(strict=False)
    for value in ("/usr", "/bin", "/sbin", "/lib", "/lib64")
)
_UNSAFE_EXACT_ROOTS = tuple(
    Path(value).resolve(strict=False)
    for value in (
        "/",
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/home",
        "/root",
        "/var",
        "/srv",
        "/opt",
        "/mnt",
        "/media",
    )
)
_EXECUTABLE_DIRECTORY_NAMES = frozenset({"bin", "sbin", "executables"})


@dataclass(frozen=True)
class ToolchainExposurePlan:
    """Validated read-only toolchain view for one Bubblewrap runtime."""

    mode: NativeMode
    sandbox_path: str
    host_path_inherited: bool
    auto_discovery_enabled: bool
    explicit_roots: tuple[Path, ...]
    discovered_roots: tuple[Path, ...]
    read_only_roots: tuple[Path, ...]

    def summary(self, *, include_paths: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "policy": "system_plus_path_discovery_plus_explicit_roots",
            "mount_mode": "read_only",
            "host_path_inherited": self.host_path_inherited,
            "auto_discovery_enabled": self.auto_discovery_enabled,
            "explicit_root_count": len(self.explicit_roots),
            "discovered_root_count": len(self.discovered_roots),
            "resolved_read_only_root_count": len(self.read_only_roots),
            "root_fingerprints": [
                hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16]
                for path in self.read_only_roots
            ],
        }
        if include_paths:
            payload.update(
                {
                    "explicit_roots": [str(path) for path in self.explicit_roots],
                    "discovered_roots": [str(path) for path in self.discovered_roots],
                    "resolved_read_only_roots": [
                        str(path) for path in self.read_only_roots
                    ],
                    "sandbox_path": self.sandbox_path,
                }
            )
        return payload


def parse_native_exec_allow_roots(raw: str | None) -> tuple[Path, ...]:
    """Parse an os.pathsep-delimited list without depending on the current cwd."""

    roots: list[Path] = []
    for item in (raw or "").split(os.pathsep):
        value = item.strip()
        if not value:
            continue
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ReCTMError(
                "INVALID_NATIVE_EXEC_ALLOW_ROOT",
                "RE_CTM_NATIVE_EXEC_ALLOW_ROOTS entries must be absolute paths.",
                category="validation",
                details={"root": value},
            )
        roots.append(path.resolve(strict=False))
    return tuple(roots)


def validate_explicit_toolchain_roots(
    roots: Iterable[Path],
    *,
    workspace: Path,
    forbidden_paths: Iterable[Path],
) -> tuple[Path, ...]:
    """Validate operator-declared roots using the same gate as auto-discovery."""

    policy = _RootPolicy(workspace=workspace, forbidden_paths=forbidden_paths)
    validated: list[Path] = []
    for raw_root in roots:
        root = policy.validate(raw_root, source="explicit", strict=True)
        if root is not None:
            validated.append(root)
    return _collapse_roots(validated)


def build_toolchain_exposure_plan(
    *,
    mode: NativeMode,
    workspace: Path,
    forbidden_paths: Iterable[Path],
    explicit_roots: Iterable[Path] = (),
    host_path: str | None = None,
) -> ToolchainExposurePlan:
    """Build one generic toolchain policy; no application names are inspected."""

    policy = _RootPolicy(workspace=workspace, forbidden_paths=forbidden_paths)
    explicit = validate_explicit_toolchain_roots(
        explicit_roots,
        workspace=workspace,
        forbidden_paths=forbidden_paths,
    )
    auto_discovery = mode in {NativeMode.TRUSTED, NativeMode.DANGEROUS}
    inherited_path = (host_path if host_path is not None else os.environ.get("PATH", ""))
    if auto_discovery:
        discovered, inherited_path_entries = _discover_path_view(
            inherited_path,
            policy=policy,
        )
    else:
        discovered, inherited_path_entries = (), ()
    read_only_roots = _collapse_roots((*discovered, *explicit))
    base_path = (
        os.pathsep.join(inherited_path_entries) or DEFAULT_SANDBOX_PATH
        if auto_discovery
        else DEFAULT_SANDBOX_PATH
    )
    sandbox_path = _extend_path_for_explicit_roots(base_path, explicit)
    return ToolchainExposurePlan(
        mode=mode,
        sandbox_path=sandbox_path,
        host_path_inherited=auto_discovery,
        auto_discovery_enabled=auto_discovery,
        explicit_roots=explicit,
        discovered_roots=discovered,
        read_only_roots=read_only_roots,
    )


@dataclass(frozen=True)
class _RootPolicy:
    workspace: Path
    forbidden_paths: tuple[Path, ...]
    home: Path

    def __init__(self, *, workspace: Path, forbidden_paths: Iterable[Path]) -> None:
        object.__setattr__(self, "workspace", workspace.expanduser().resolve(strict=True))
        object.__setattr__(
            self,
            "forbidden_paths",
            tuple(path.expanduser().resolve(strict=False) for path in forbidden_paths),
        )
        object.__setattr__(self, "home", Path.home().resolve(strict=False))

    def validate(
        self,
        raw_path: Path,
        *,
        source: str,
        strict: bool,
    ) -> Path | None:
        try:
            path = raw_path.expanduser().resolve(strict=True)
        except OSError as exc:
            if strict:
                raise ReCTMError(
                    "INVALID_NATIVE_EXEC_ALLOW_ROOT",
                    "Declared native toolchain root does not exist.",
                    category="validation",
                    details={"root": str(raw_path)},
                ) from exc
            return None
        if not path.is_dir():
            if strict:
                raise ReCTMError(
                    "INVALID_NATIVE_EXEC_ALLOW_ROOT",
                    "Declared native toolchain root must be a directory.",
                    category="validation",
                    details={"root": str(path)},
                )
            return None
        if any(path == unsafe for unsafe in _UNSAFE_EXACT_ROOTS):
            return self._deny(path, source, strict, "unsafe broad or virtual filesystem root")
        if path == self.home:
            return self._deny(path, source, strict, "the complete user home is too broad")
        if _overlaps(path, self.workspace):
            return self._deny(path, source, strict, "root overlaps the writable workspace")
        if any(_overlaps(path, forbidden) for forbidden in self.forbidden_paths):
            return self._deny(path, source, strict, "root overlaps Re-CTM data/private state")
        if self.is_system_path(path):
            return None
        return path

    @staticmethod
    def is_system_path(path: Path) -> bool:
        return any(path == root or path.is_relative_to(root) for root in _SYSTEM_PREFIXES)

    @staticmethod
    def _deny(path: Path, source: str, strict: bool, reason: str) -> None:
        if strict:
            raise ReCTMError(
                "NATIVE_TOOLCHAIN_ROOT_DENIED",
                "Native toolchain root violates the isolation policy.",
                category="security",
                details={"root": str(path), "source": source, "reason": reason},
            )
        return None


def _discover_path_view(
    host_path: str,
    *,
    policy: _RootPolicy,
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    candidates: list[Path] = []
    path_entries: list[str] = []
    seen_path_entries: set[str] = set()

    def add(raw_path: Path, *, fallback: Path | None = None) -> Path | None:
        root = policy.validate(raw_path, source="path_discovery", strict=False)
        if root is None and fallback is not None:
            root = policy.validate(fallback, source="path_discovery", strict=False)
        if root is not None:
            candidates.append(root)
        return root

    def add_path_entry(path: Path) -> None:
        value = str(path)
        if value not in seen_path_entries:
            seen_path_entries.add(value)
            path_entries.append(value)

    for raw_entry in host_path.split(os.pathsep):
        if not raw_entry:
            continue
        entry = Path(raw_entry).expanduser()
        if not entry.is_absolute():
            continue
        try:
            resolved_entry = entry.resolve(strict=True)
        except OSError:
            continue
        if not resolved_entry.is_dir():
            continue
        if policy.is_system_path(resolved_entry):
            add_path_entry(resolved_entry)
            continue
        inferred_prefix = _prefix_for_executable_directory(resolved_entry)
        if add(inferred_prefix, fallback=resolved_entry) is None:
            continue
        add_path_entry(resolved_entry)

        try:
            entries = sorted(
                islice(resolved_entry.iterdir(), 4096),
                key=lambda item: item.name,
            )
        except OSError:
            entries = []
        for executable in entries:
            if not executable.is_symlink():
                continue
            try:
                target = executable.resolve(strict=True)
            except OSError:
                continue
            if not target.is_file():
                continue
            target_directory = target.parent
            inferred_target_prefix = _prefix_for_executable_directory(target_directory)
            add(inferred_target_prefix, fallback=target_directory)

    return _collapse_roots(candidates), tuple(path_entries)


def _prefix_for_executable_directory(path: Path) -> Path:
    if path.name.casefold() in _EXECUTABLE_DIRECTORY_NAMES:
        return path.parent
    return path


def _extend_path_for_explicit_roots(base_path: str, roots: Iterable[Path]) -> str:
    entries = [item for item in base_path.split(os.pathsep) if item]
    seen = set(entries)
    for root in roots:
        candidates = [root]
        try:
            children = {child.name.casefold(): child for child in root.iterdir() if child.is_dir()}
        except OSError:
            children = {}
        for name in sorted(_EXECUTABLE_DIRECTORY_NAMES):
            candidate = children.get(name)
            if candidate is not None:
                candidates.append(candidate)
        for candidate in candidates:
            value = str(candidate)
            if value not in seen:
                entries.append(value)
                seen.add(value)
    return os.pathsep.join(entries)


def _collapse_roots(roots: Iterable[Path]) -> tuple[Path, ...]:
    result: list[Path] = []
    for root in sorted(set(roots), key=lambda item: (len(item.parts), str(item))):
        if any(root == existing or root.is_relative_to(existing) for existing in result):
            continue
        result = [existing for existing in result if not existing.is_relative_to(root)]
        result.append(root)
    return tuple(sorted(result, key=str))


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)
