from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .debug import DebugEventBus, token_fingerprint, utc_now
from .errors import ReCTMError, invalid_argument


AUTH_CODE_TTL_SECONDS = 300
ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60
MAX_REDIRECT_URIS = 10
MAX_CLIENTS = 1024
SUPPORTED_AUTH_METHODS = {"none", "client_secret_post", "client_secret_basic"}


@dataclass(frozen=True)
class OAuthPrincipal:
    client_id: str
    subject: str
    scope: str


class OAuthStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    redirect_uris_json TEXT NOT NULL,
                    token_endpoint_auth_method TEXT NOT NULL,
                    client_name TEXT,
                    secret_digest TEXT,
                    issued_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS oauth_codes (
                    code_digest TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
                    redirect_uri TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def register_client(
        self,
        *,
        redirect_uris: tuple[str, ...],
        auth_method: str,
        client_name: str | None,
    ) -> dict[str, Any]:
        with self._lock:
            count = int(
                self._connection.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0]
            )
            if count >= MAX_CLIENTS:
                raise ReCTMError(
                    "OAUTH_CLIENT_LIMIT",
                    "Dynamic client registration limit reached.",
                    category="runtime",
                )
            client_id = secrets.token_urlsafe(24)
            client_secret = secrets.token_urlsafe(32) if auth_method != "none" else None
            issued_at = int(time.time())
            self._connection.execute(
                """
                INSERT INTO oauth_clients (
                    client_id, redirect_uris_json, token_endpoint_auth_method,
                    client_name, secret_digest, issued_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    json.dumps(list(redirect_uris), separators=(",", ":")),
                    auth_method,
                    client_name,
                    _secret_digest(client_secret) if client_secret else None,
                    issued_at,
                ),
            )
        result: dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": issued_at,
            "redirect_uris": list(redirect_uris),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": auth_method,
        }
        if client_name:
            result["client_name"] = client_name
        if client_secret:
            result["client_secret"] = client_secret
            result["client_secret_expires_at"] = 0
        return result

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["redirect_uris"] = json.loads(result.pop("redirect_uris_json"))
        return result

    def save_code(
        self,
        *,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        resource: str,
        expires_at: int,
    ) -> None:
        digest = _secret_digest(code)
        with self._lock:
            self._connection.execute(
                "DELETE FROM oauth_codes WHERE expires_at < ?",
                (int(time.time()),),
            )
            self._connection.execute(
                """
                INSERT INTO oauth_codes (
                    code_digest, client_id, redirect_uri, code_challenge,
                    resource, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    digest,
                    client_id,
                    redirect_uri,
                    code_challenge,
                    resource,
                    expires_at,
                    utc_now(),
                ),
            )

    def consume_code(self, code: str) -> dict[str, Any] | None:
        digest = _secret_digest(code)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM oauth_codes WHERE code_digest = ?",
                    (digest,),
                ).fetchone()
                if row is not None:
                    self._connection.execute(
                        "DELETE FROM oauth_codes WHERE code_digest = ?",
                        (digest,),
                    )
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")
        return None if row is None else dict(row)


class OAuthService:
    """OAuth-only gateway service: Authorization Code + PKCE + DCR."""

    def __init__(
        self,
        *,
        server_url: str,
        password: str,
        token_secret: bytes,
        store: OAuthStore,
        debug: DebugEventBus,
        token_ttl: int = ACCESS_TOKEN_TTL_SECONDS,
    ) -> None:
        if server_url:
            _validate_server_url(server_url)
        if not password:
            raise ReCTMError(
                "OAUTH_PASSWORD_REQUIRED",
                "RE_CTM_OAUTH_PASSWORD is required.",
                category="security",
            )
        if len(token_secret) < 32:
            raise ReCTMError(
                "OAUTH_TOKEN_SECRET_REQUIRED",
                "OAuth signing requires at least 32 secret bytes.",
                category="security",
            )
        self.server_url = server_url.rstrip("/")
        self.password = password
        self.token_secret = token_secret
        self.store = store
        self.debug = debug
        self.token_ttl = token_ttl

    def authorization_server_metadata(self, *, base_url: str | None = None) -> dict[str, Any]:
        base = self._base_url(base_url)
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "registration_endpoint": f"{base}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": sorted(SUPPORTED_AUTH_METHODS),
        }

    def protected_resource_metadata(self, *, base_url: str | None = None) -> dict[str, Any]:
        base = self._base_url(base_url)
        return {
            "resource": base,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
        }

    def register(self, metadata: Mapping[str, Any], *, trace_id: str) -> dict[str, Any]:
        redirects = validate_redirect_uris(metadata.get("redirect_uris"))
        grant_types = metadata.get("grant_types", ["authorization_code"])
        response_types = metadata.get("response_types", ["code"])
        if not isinstance(grant_types, list) or "authorization_code" not in grant_types:
            raise invalid_argument("grant_types must include authorization_code")
        if not isinstance(response_types, list) or "code" not in response_types:
            raise invalid_argument("response_types must include code")
        auth_method = str(metadata.get("token_endpoint_auth_method") or "none")
        if auth_method not in SUPPORTED_AUTH_METHODS:
            raise invalid_argument("unsupported token_endpoint_auth_method")
        client_name = _optional_text(metadata.get("client_name"), 200)
        result = self.store.register_client(
            redirect_uris=redirects,
            auth_method=auth_method,
            client_name=client_name,
        )
        self.debug.emit(
            "oauth.client_registered",
            "oauth_authority",
            trace_id=trace_id,
            decision="allow",
            reason="valid_dynamic_client_registration",
            details={
                "client_id_fingerprint": token_fingerprint(result["client_id"]),
                "redirect_count": len(redirects),
                "auth_method": auth_method,
            },
        )
        return result

    def validate_authorization_request(
        self,
        params: Mapping[str, str],
        *,
        base_url: str | None = None,
    ) -> dict[str, str]:
        base = self._base_url(base_url)
        client_id = str(params.get("client_id") or "")
        redirect_uri = str(params.get("redirect_uri") or "")
        response_type = str(params.get("response_type") or "")
        code_challenge = str(params.get("code_challenge") or "")
        method = str(params.get("code_challenge_method") or "")
        resource = str(params.get("resource") or "").rstrip("/")
        state = str(params.get("state") or "")
        client = self.store.get_client(client_id)
        if client is None:
            raise ReCTMError("OAUTH_INVALID_CLIENT", "Unknown client_id.", category="permission")
        if redirect_uri not in client["redirect_uris"]:
            raise ReCTMError("OAUTH_INVALID_REDIRECT", "redirect_uri is not registered.", category="permission")
        if response_type != "code":
            raise invalid_argument("response_type must be code")
        if method != "S256" or not valid_pkce_challenge(code_challenge):
            raise invalid_argument("code_challenge_method must be S256 with a valid challenge")
        if resource != base:
            raise ReCTMError("OAUTH_INVALID_TARGET", "resource must identify this server.", category="permission")
        return {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "resource": resource,
            "state": state,
        }

    def authorize(
        self,
        params: Mapping[str, str],
        *,
        password: str,
        trace_id: str,
        base_url: str | None = None,
    ) -> str:
        validated = self.validate_authorization_request(params, base_url=base_url)
        if not secrets.compare_digest(password, self.password):
            self.debug.emit(
                "oauth.authorization_denied",
                "oauth_authority",
                trace_id=trace_id,
                decision="deny",
                reason="invalid_authorization_password",
                details={"client_id_fingerprint": token_fingerprint(validated["client_id"])},
            )
            raise ReCTMError(
                "OAUTH_ACCESS_DENIED",
                "Invalid authorization password.",
                category="permission",
            )
        code = secrets.token_urlsafe(32)
        self.store.save_code(
            code=code,
            client_id=validated["client_id"],
            redirect_uri=validated["redirect_uri"],
            code_challenge=validated["code_challenge"],
            resource=validated["resource"],
            expires_at=int(time.time()) + AUTH_CODE_TTL_SECONDS,
        )
        query: dict[str, str] = {"code": code}
        if validated["state"]:
            query["state"] = validated["state"]
        separator = "&" if "?" in validated["redirect_uri"] else "?"
        redirect = validated["redirect_uri"] + separator + urllib.parse.urlencode(query)
        self.debug.emit(
            "oauth.authorization_code_issued",
            "oauth_authority",
            trace_id=trace_id,
            decision="allow",
            reason="authorization_password_and_pkce_request_valid",
            details={
                "client_id_fingerprint": token_fingerprint(validated["client_id"]),
                "code_fingerprint": token_fingerprint(code),
            },
        )
        return redirect

    def exchange_code(
        self,
        params: Mapping[str, str],
        *,
        basic_client_id: str = "",
        basic_client_secret: str = "",
        trace_id: str,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        base = self._base_url(base_url)
        if params.get("grant_type") != "authorization_code":
            raise invalid_argument("Only authorization_code is supported.")
        code = str(params.get("code") or "")
        redirect_uri = str(params.get("redirect_uri") or "")
        verifier = str(params.get("code_verifier") or "")
        resource = str(params.get("resource") or "").rstrip("/")
        client_id = str(params.get("client_id") or basic_client_id or "")
        client_secret = str(params.get("client_secret") or basic_client_secret or "")
        presented_method = "client_secret_basic" if basic_client_id else (
            "client_secret_post" if client_secret else "none"
        )
        client = self.store.get_client(client_id)
        if client is None or not _authenticate_client(client, client_secret, presented_method):
            raise ReCTMError("OAUTH_INVALID_CLIENT", "Client authentication failed.", category="permission")
        if not code or not valid_pkce_verifier(verifier):
            raise ReCTMError("OAUTH_INVALID_GRANT", "Invalid code or code_verifier.", category="permission")
        record = self.store.consume_code(code)
        if record is None:
            raise ReCTMError(
                "OAUTH_INVALID_GRANT",
                "Authorization code is unknown or already used.",
                category="permission",
            )
        if int(record["expires_at"]) < int(time.time()):
            raise ReCTMError("OAUTH_INVALID_GRANT", "Authorization code expired.", category="permission")
        facts = (
            secrets.compare_digest(record["client_id"], client_id),
            secrets.compare_digest(record["redirect_uri"], redirect_uri),
            secrets.compare_digest(record["resource"], resource),
            secrets.compare_digest(resource, base),
            verify_pkce(verifier, record["code_challenge"]),
        )
        if not all(facts):
            raise ReCTMError(
                "OAUTH_INVALID_GRANT",
                "Authorization code binding or PKCE verification failed.",
                category="permission",
            )
        token = self._create_access_token(client_id, base_url=base)
        self.debug.emit(
            "oauth.access_token_issued",
            "oauth_authority",
            trace_id=trace_id,
            decision="allow",
            reason="authorization_code_and_pkce_valid",
            details={
                "client_id_fingerprint": token_fingerprint(client_id),
                "token_fingerprint": token_fingerprint(token),
            },
        )
        return {"access_token": token, "token_type": "Bearer", "expires_in": self.token_ttl}

    def validate_authorization_header(
        self,
        header: str,
        *,
        trace_id: str,
        base_url: str | None = None,
    ) -> OAuthPrincipal:
        base = self._base_url(base_url)
        if not header.startswith("Bearer "):
            raise ReCTMError("OAUTH_UNAUTHORIZED", "OAuth Bearer token is required.", category="permission")
        token = header[len("Bearer ") :].strip()
        try:
            payload = _decode_signed_token(token, self.token_secret)
            now = int(time.time())
            if payload.get("iss") != base or payload.get("aud") != base:
                raise ValueError("issuer or audience")
            if int(payload.get("exp", 0)) < now:
                raise ValueError("expired")
            client_id = str(payload.get("client_id") or "")
            if not client_id or self.store.get_client(client_id) is None:
                raise ValueError("unknown client")
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.debug.emit(
                "oauth.access_token_denied",
                "oauth_authority",
                trace_id=trace_id,
                decision="deny",
                reason="invalid_access_token",
                details={"token_fingerprint": token_fingerprint(token)},
            )
            raise ReCTMError(
                "OAUTH_UNAUTHORIZED",
                "OAuth access token is invalid or expired.",
                category="permission",
            ) from exc
        principal = OAuthPrincipal(
            client_id=client_id,
            subject=str(payload.get("sub") or client_id),
            scope=str(payload.get("scope") or ""),
        )
        self.debug.emit(
            "oauth.access_token_accepted",
            "oauth_authority",
            trace_id=trace_id,
            decision="allow",
            reason="signed_access_token_valid",
            details={"client_id_fingerprint": token_fingerprint(client_id)},
        )
        return principal

    def _create_access_token(self, client_id: str, *, base_url: str | None = None) -> str:
        base = self._base_url(base_url)
        now = int(time.time())
        return _encode_signed_token(
            {
                "v": 1,
                "iss": base,
                "aud": base,
                "sub": client_id,
                "client_id": client_id,
                "iat": now,
                "exp": now + self.token_ttl,
                "scope": "mcp",
            },
            self.token_secret,
        )

    def _base_url(self, override: str | None) -> str:
        base = (self.server_url or override or "").rstrip("/")
        if not base:
            raise ReCTMError(
                "OAUTH_SERVER_URL_REQUIRED",
                "OAuth request base URL is unavailable.",
                category="validation",
            )
        _validate_server_url(base)
        return base


def _validate_server_url(value: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ReCTMError(
            "OAUTH_SERVER_URL_INVALID",
            "OAuth server URL is malformed.",
            category="validation",
        ) from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ReCTMError(
            "OAUTH_SERVER_URL_INVALID",
            "OAuth server URL must be an origin URL without user info, path, query, or fragment.",
            category="validation",
        )
    hostname = parsed.hostname.lower()
    if parsed.scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ReCTMError(
            "OAUTH_SERVER_URL_INVALID",
            "OAuth server URL must be HTTPS or a loopback HTTP URL.",
            category="validation",
        )


def validate_redirect_uris(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_REDIRECT_URIS:
        raise invalid_argument(
            f"redirect_uris must contain between 1 and {MAX_REDIRECT_URIS} entries"
        )
    redirects: list[str] = []
    for item in value:
        if not isinstance(item, str) or len(item) > 2048:
            raise invalid_argument("redirect_uri must be a string of at most 2048 characters")
        parsed = urllib.parse.urlsplit(item)
        if parsed.fragment or not parsed.scheme or not parsed.netloc or not parsed.hostname:
            raise invalid_argument("redirect_uri must be absolute and have no fragment")
        if parsed.username is not None or parsed.password is not None:
            raise invalid_argument("redirect_uri must not contain user information")
        hostname = parsed.hostname.lower()
        if parsed.scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise invalid_argument("HTTP redirect_uri is allowed only for loopback hosts")
        if parsed.scheme not in {"http", "https"}:
            raise invalid_argument("redirect_uri must use HTTPS or loopback HTTP")
        redirects.append(item)
    if len(set(redirects)) != len(redirects):
        raise invalid_argument("redirect_uris must be unique")
    return tuple(redirects)


def valid_pkce_challenge(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is not None


def valid_pkce_verifier(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9\-._~]{43,128}", value) is not None


def verify_pkce(verifier: str, challenge: str) -> bool:
    if not valid_pkce_verifier(verifier):
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = _b64url(digest)
    return secrets.compare_digest(expected, challenge)


def parse_basic_authorization(header: str) -> tuple[str, str]:
    if not header.startswith("Basic "):
        return "", ""
    try:
        decoded = base64.b64decode(header[6:]).decode("utf-8")
        client_id, separator, client_secret = decoded.partition(":")
        if not separator:
            return "", ""
        return urllib.parse.unquote(client_id), urllib.parse.unquote(client_secret)
    except (ValueError, UnicodeDecodeError):
        return "", ""


def _authenticate_client(client: Mapping[str, Any], secret: str, presented_method: str) -> bool:
    required = str(client["token_endpoint_auth_method"])
    if required != presented_method:
        return False
    if required == "none":
        return not secret
    digest = str(client.get("secret_digest") or "")
    return bool(secret and digest and secrets.compare_digest(digest, _secret_digest(secret)))


def _secret_digest(value: str | None) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _optional_text(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:maximum]


def _encode_signed_token(payload: Mapping[str, Any], secret: bytes) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode("ascii")
    signature = _b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return f"{header}.{body}.{signature}"


def _decode_signed_token(token: str, secret: bytes) -> dict[str, Any]:
    header, body, signature = token.split(".", 2)
    signing_input = f"{header}.{body}".encode("ascii")
    expected = _b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise ValueError("signature")
    decoded_header = json.loads(_unb64url(header))
    if decoded_header.get("alg") != "HS256":
        raise ValueError("algorithm")
    payload = json.loads(_unb64url(body))
    if not isinstance(payload, dict):
        raise ValueError("payload")
    return payload


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> str:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
