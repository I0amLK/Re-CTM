from __future__ import annotations

import errno
import hashlib
import ipaddress
import os
import secrets
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from .enums import LatexPolicy, NativeMode
from .errors import ReCTMError
from .toolchains import (
    parse_native_exec_allow_roots,
    validate_explicit_toolchain_roots,
)


MAX_PERSISTED_SECRET_BYTES = 65_536


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def is_loopback_host(value: str) -> bool:
    """Return whether a bind/peer host is loopback-only.

    Dynamic OAuth issuer discovery is allowed only when the HTTP server itself
    is loopback-bound. Keep this helper in configuration code so CLI, server,
    and tests share one definition of that security boundary.
    """

    host = (value or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Settings:
    workspace: Path
    data_root: Path
    private_root: Path
    debug_root: Path
    native_mode: NativeMode = NativeMode.DANGEROUS
    native_exec_backend: str = "disabled"
    native_exec_helper: Path | None = None
    native_isolation_attested: bool = False
    native_exec_allow_roots: tuple[Path, ...] = ()
    latex_policy: LatexPolicy = LatexPolicy.REQUIRED
    debug_enabled: bool = False
    trace_payloads: bool = False
    oauth_server_url: str = ""
    oauth_password: str = ""
    allowed_origins: tuple[str, ...] = ()
    theorem_search_url: str = "https://leansearch.net/thm/search"
    theorem_search_timeout_seconds: int = 30
    token_secret: bytes = b""
    capability_secret: bytes = b""
    workflow_protocol_version: int = 3

    @classmethod
    def from_env(cls) -> "Settings":
        workspace = Path(os.environ.get("RE_CTM_WORKSPACE") or os.getcwd()).expanduser().resolve()
        data_root = Path(os.environ.get("RE_CTM_DATA_ROOT") or "~/.re-ctm").expanduser().resolve()
        private_root = Path(
            os.environ.get("RE_CTM_PRIVATE_ROOT") or str(data_root / "private")
        ).expanduser().resolve()
        debug_root = Path(
            os.environ.get("RE_CTM_DEBUG_ROOT") or str(data_root / "debug")
        ).expanduser().resolve()
        raw_native_mode = os.environ.get("RE_CTM_NATIVE_MODE") or NativeMode.DANGEROUS.value
        if raw_native_mode != NativeMode.DANGEROUS.value:
            raise _invalid_native_mode()
        native_mode = NativeMode.DANGEROUS
        raw_protocol = os.environ.get("RE_CTM_WORKFLOW_PROTOCOL_VERSION", "3")
        if raw_protocol not in {"2", "3"}:
            raise ReCTMError("INVALID_WORKFLOW_PROTOCOL", "RE_CTM_WORKFLOW_PROTOCOL_VERSION must be 2 or 3.", category="validation")
        configured_backend = (os.environ.get("RE_CTM_NATIVE_EXEC_BACKEND") or "").strip()
        native_exec_backend = configured_backend or (
            "bubblewrap"
            if sys.platform.startswith("linux") and shutil.which("bwrap") is not None
            else "disabled"
        )
        latex_policy = LatexPolicy(
            os.environ.get("RE_CTM_LATEX_POLICY") or LatexPolicy.REQUIRED
        )
        token_secret_raw = os.environ.get("RE_CTM_TOKEN_SECRET", "")
        capability_secret_raw = os.environ.get("RE_CTM_CAPABILITY_SECRET", "")
        token_secret = _decode_secret(token_secret_raw, "RE_CTM_TOKEN_SECRET")
        capability_secret = _decode_secret(
            capability_secret_raw,
            "RE_CTM_CAPABILITY_SECRET",
        )
        if not capability_secret and token_secret:
            capability_secret = hashlib.sha256(token_secret + b"/capability").digest()
        settings = cls(
            workspace=workspace,
            data_root=data_root,
            private_root=private_root,
            debug_root=debug_root,
            native_mode=native_mode,
            native_exec_backend=native_exec_backend,
            native_exec_helper=(
                Path(os.environ["RE_CTM_NATIVE_EXEC_HELPER"]).expanduser().resolve()
                if os.environ.get("RE_CTM_NATIVE_EXEC_HELPER")
                else None
            ),
            native_isolation_attested=_truthy(
                os.environ.get("RE_CTM_NATIVE_ISOLATION_ATTESTED")
            ),
            native_exec_allow_roots=parse_native_exec_allow_roots(
                os.environ.get("RE_CTM_NATIVE_EXEC_ALLOW_ROOTS")
            ),
            latex_policy=latex_policy,
            debug_enabled=_truthy(os.environ.get("RE_CTM_DEBUG")),
            trace_payloads=_truthy(os.environ.get("RE_CTM_TRACE_PAYLOADS")),
            oauth_server_url=(os.environ.get("RE_CTM_SERVER_URL") or "").rstrip("/"),
            oauth_password=os.environ.get("RE_CTM_OAUTH_PASSWORD", ""),
            allowed_origins=tuple(
                item.strip().rstrip("/")
                for item in os.environ.get("RE_CTM_ALLOWED_ORIGINS", "").split(",")
                if item.strip()
            ),
            theorem_search_url=(
                os.environ.get("RE_CTM_THEOREM_SEARCH_URL")
                or "https://leansearch.net/thm/search"
            ).strip(),
            theorem_search_timeout_seconds=int(
                os.environ.get("RE_CTM_THEOREM_SEARCH_TIMEOUT_SECONDS") or "30"
            ),
            token_secret=token_secret,
            capability_secret=capability_secret,
            workflow_protocol_version=int(raw_protocol),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if type(self.workflow_protocol_version) is not int or self.workflow_protocol_version not in {2, 3}:
            raise ReCTMError("INVALID_WORKFLOW_PROTOCOL", "workflow_protocol_version must be 2 or 3.", category="validation")
        if self.native_mode is not NativeMode.DANGEROUS:
            raise _invalid_native_mode()
        if not self.workspace.is_dir():
            raise ReCTMError(
                "INVALID_WORKSPACE",
                "RE_CTM_WORKSPACE must be an existing directory.",
                category="validation",
                details={"workspace": str(self.workspace)},
            )
        unsafe_roots = {Path("/").resolve(), Path.home().resolve()}
        if self.workspace in unsafe_roots:
            raise ReCTMError(
                "UNSAFE_WORKSPACE",
                "The filesystem root and home directory cannot be the native workspace.",
                category="security",
            )
        overlaps = any(
            _is_relative_to(candidate, self.workspace)
            or _is_relative_to(self.workspace, candidate)
            for candidate in (self.data_root, self.private_root)
        )
        if overlaps:
            raise ReCTMError(
                "TRUST_DOMAIN_OVERLAP",
                "The server data/private roots and native workspace must not overlap.",
                category="security",
                details={
                    "workspace": str(self.workspace),
                    "data_root": str(self.data_root),
                    "private_root": str(self.private_root),
                },
            )
        if self.native_exec_backend not in {"disabled", "external", "bubblewrap"}:
            raise ReCTMError(
                "INVALID_NATIVE_EXEC_BACKEND",
                "RE_CTM_NATIVE_EXEC_BACKEND must be disabled, external, or bubblewrap.",
                category="validation",
                details={"backend": self.native_exec_backend},
            )
        if self.native_exec_backend == "external" and not self.native_isolation_attested:
            raise ReCTMError(
                "NATIVE_ISOLATION_REQUIRED",
                "External native command execution requires an explicitly attested hard-isolation backend.",
                category="security",
                details={"backend": self.native_exec_backend},
            )
        if self.native_exec_backend == "external" and self.native_exec_helper is None:
            raise ReCTMError(
                "NATIVE_HELPER_REQUIRED",
                "RE_CTM_NATIVE_EXEC_HELPER is required for the external backend.",
                category="validation",
            )
        if self.native_exec_allow_roots and self.native_exec_backend != "bubblewrap":
            raise ReCTMError(
                "NATIVE_TOOLCHAIN_ROOTS_UNSUPPORTED",
                "RE_CTM_NATIVE_EXEC_ALLOW_ROOTS currently requires the built-in Bubblewrap backend.",
                category="validation",
                details={"backend": self.native_exec_backend},
            )
        if self.native_exec_allow_roots:
            validate_explicit_toolchain_roots(
                self.native_exec_allow_roots,
                workspace=self.workspace,
                forbidden_paths=(self.data_root, self.private_root),
            )
        if not 1 <= self.theorem_search_timeout_seconds <= 300:
            raise ReCTMError(
                "INVALID_RESEARCH_TIMEOUT",
                "RE_CTM_THEOREM_SEARCH_TIMEOUT_SECONDS must be between 1 and 300.",
                category="validation",
            )

    def ensure_directories(self) -> None:
        for path in (self.data_root, self.private_root, self.debug_root):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                path.chmod(0o700)
            except OSError:
                pass


def _invalid_native_mode() -> ReCTMError:
    return ReCTMError(
        "INVALID_NATIVE_MODE",
        "RE_CTM_NATIVE_MODE must be dangerous; safe and trusted public profiles are retired.",
        category="validation",
    )


def _decode_secret(raw: str, name: str) -> bytes:
    value = raw.strip()
    if not value:
        return b""
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise ReCTMError(
            "INVALID_SECRET",
            f"{name} must be hex-encoded bytes.",
            category="validation",
        ) from exc
    if len(decoded) < 32:
        raise ReCTMError(
            "INVALID_SECRET",
            f"{name} must contain at least 32 bytes.",
            category="validation",
        )
    return decoded


def materialize_secrets(settings: Settings) -> Settings:
    """Load or create server-owned secrets without printing them."""

    settings.ensure_directories()
    token_secret = settings.token_secret or _load_or_create_secret(
        settings.data_root / "oauth-token-secret.hex"
    )
    capability_secret = settings.capability_secret or hashlib.sha256(
        token_secret + b"/capability"
    ).digest()
    return replace(
        settings,
        token_secret=token_secret,
        capability_secret=capability_secret,
    )


def _load_or_create_secret(path: Path) -> bytes:
    persisted = _read_persisted_secret(path)
    if persisted is not None:
        return persisted
    secret = secrets.token_bytes(32)
    return _publish_secret_candidate(path, secret)


def _publish_secret_candidate(path: Path, secret: bytes) -> bytes:
    # The parent directory is server-owned. Publish a fully written inode without
    # replacing a concurrent winner, and always return the persisted winning key.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        # mkstemp uses exclusive creation and mode 0600, before any bytes exist.
        with os.fdopen(descriptor, "w", encoding="ascii") as staged:
            staged.write(secret.hex() + "\n")
            staged.flush()
            os.fsync(staged.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
    finally:
        temporary.unlink()
    if os.name == "posix":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    persisted = _read_persisted_secret(path)
    if persisted is None:
        raise ReCTMError(
            "UNSAFE_SECRET_FILE",
            "Persisted secret disappeared during initialization.",
            category="security",
        )
    return persisted


def _read_persisted_secret(path: Path) -> bytes | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        raise ReCTMError(
            "UNSAFE_SECRET_FILE", "Persisted secret must be a regular file.", category="security"
        )
    # Reject links and nonregular files before reading; O_NONBLOCK also prevents
    # a replacement FIFO from blocking startup. Private-directory ownership is
    # still required; this does not reconcile keys in already-running processes.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno not in {errno.ENOENT, errno.ELOOP}:
            raise
        raise ReCTMError(
            "UNSAFE_SECRET_FILE", "Persisted secret changed while opening.", category="security"
        ) from exc
    with os.fdopen(descriptor, "r", encoding="ascii") as persisted:
        opened = os.fstat(persisted.fileno())
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev, opened.st_ino
        ) != (metadata.st_dev, metadata.st_ino):
            raise ReCTMError(
                "UNSAFE_SECRET_FILE", "Persisted secret changed while opening.", category="security"
            )
        try:
            raw = persisted.read(MAX_PERSISTED_SECRET_BYTES + 1)
        except UnicodeDecodeError as exc:
            raise ReCTMError(
                "INVALID_SECRET", "Persisted secret must contain ASCII hex.", category="validation"
            ) from exc
    if len(raw) > MAX_PERSISTED_SECRET_BYTES:
        raise ReCTMError(
            "INVALID_SECRET", "Persisted secret exceeds the supported file size.", category="validation"
        )
    raw = raw.strip()
    if not raw or any(character not in "0123456789abcdefABCDEF" for character in raw):
        raise ReCTMError(
            "INVALID_SECRET", "Persisted secret must contain nonempty hex.", category="validation"
        )
    return _decode_secret(raw, "Persisted OAuth secret")
