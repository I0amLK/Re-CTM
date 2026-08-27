from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
from dataclasses import dataclass, replace
from pathlib import Path

from .enums import LatexPolicy, NativeMode
from .errors import ReCTMError


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
    native_mode: NativeMode = NativeMode.SAFE
    native_exec_backend: str = "disabled"
    native_exec_helper: Path | None = None
    native_isolation_attested: bool = False
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
        native_mode = NativeMode(os.environ.get("RE_CTM_NATIVE_MODE") or NativeMode.SAFE)
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
            native_exec_backend=os.environ.get("RE_CTM_NATIVE_EXEC_BACKEND", "disabled"),
            native_exec_helper=(
                Path(os.environ["RE_CTM_NATIVE_EXEC_HELPER"]).expanduser().resolve()
                if os.environ.get("RE_CTM_NATIVE_EXEC_HELPER")
                else None
            ),
            native_isolation_attested=_truthy(
                os.environ.get("RE_CTM_NATIVE_ISOLATION_ATTESTED")
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
        )
        settings.validate()
        return settings

    def validate(self) -> None:
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
        if self.native_exec_backend != "disabled" and not self.native_isolation_attested:
            raise ReCTMError(
                "NATIVE_ISOLATION_REQUIRED",
                "Native command execution requires an attested hard-isolation backend.",
                category="security",
                details={"backend": self.native_exec_backend},
            )
        if self.native_exec_backend == "external" and self.native_exec_helper is None:
            raise ReCTMError(
                "NATIVE_HELPER_REQUIRED",
                "RE_CTM_NATIVE_EXEC_HELPER is required for the external backend.",
                category="validation",
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
    if path.exists():
        raw = path.read_text(encoding="ascii").strip()
        return _decode_secret(raw, str(path))
    secret = secrets.token_bytes(32)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(secret.hex() + "\n", encoding="ascii")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return secret
