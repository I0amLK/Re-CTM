from __future__ import annotations

import html
import http.server
import json
import posixpath
import sys
import urllib.parse
from typing import Any, Mapping, cast

from .app import ReCTMApplication
from .config import is_loopback_host
from .debug import new_trace_id
from .errors import ReCTMError
from .mcp import (
    HEADER_MISMATCH,
    JSONRPCError,
    MODERN_ERA,
    jsonrpc_error,
    modern_http_status,
    request_era_from_envelope,
    response_id,
    validate_http_mirror_headers,
)
from .oauth import parse_basic_authorization


MAX_REQUEST_BYTES = 1_048_576
MCP_PATH = "/mcp"


def _first_header_value(value: str | None) -> str:
    return (value or "").split(",", 1)[0].strip()


def _forwarded_header_param(value: str | None, name: str) -> str:
    first = _first_header_value(value)
    for part in first.split(";"):
        key, sep, raw = part.strip().partition("=")
        if sep and key.lower() == name:
            return raw.strip().strip('"')
    return ""


def _safe_external_host(host: str) -> str:
    host = host.strip()
    if not host or any(ch.isspace() or ch in "/\\@?#" for ch in host):
        return ""
    try:
        parsed = urllib.parse.urlsplit(f"//{host}")
        _ = parsed.port
    except ValueError:
        return ""
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        return ""
    return host


def _host_name(host: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(f"//{host}")
    except ValueError:
        return ""
    return (parsed.hostname or "").lower()


def _host_with_port(host: str, port: int) -> str:
    display = host
    if ":" in display and not display.startswith("["):
        display = f"[{display}]"
    return f"{display}:{port}"


class ReCTMHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        application: ReCTMApplication,
    ) -> None:
        if not application.settings.oauth_server_url and not is_loopback_host(address[0]):
            raise ReCTMError(
                "OAUTH_DYNAMIC_ISSUER_REQUIRES_LOOPBACK",
                "Without RE_CTM_SERVER_URL, Re-CTM must bind to a loopback host so reverse-proxy OAuth discovery cannot trust public request headers directly.",
                category="security",
                details={"host": address[0]},
            )
        self.application = application
        super().__init__(address, ReCTMHandler)

    def server_close(self) -> None:
        try:
            self.application.close()
        finally:
            super().server_close()


class ReCTMHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ReCTM/0.1"

    @property
    def app(self) -> ReCTMApplication:
        return cast(ReCTMHTTPServer, self.server).application

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        trace = new_trace_id()
        if not self._origin_allowed():
            self._json_error(403, "ORIGIN_DENIED", "Browser Origin is not allowed.", trace)
            return
        self.send_response(204)
        self._cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name",
        )
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        trace = new_trace_id()
        if not self._origin_allowed():
            self._json_error(403, "ORIGIN_DENIED", "Browser Origin is not allowed.", trace)
            return
        parsed = urllib.parse.urlsplit(self.path)
        path = posixpath.normpath(parsed.path)
        try:
            if path == "/health":
                self._send_json(
                    {
                        "ok": True,
                        "service": "re-ctm",
                        "oauth_only": True,
                        "complete_flow_locally_validated": False,
                        "trace_id": trace,
                    }
                )
                return
            if path == "/.well-known/oauth-authorization-server":
                base = self._oauth_base_url(trace_id=trace)
                self._send_json(self.app.oauth.authorization_server_metadata(base_url=base))
                return
            if path == "/.well-known/oauth-protected-resource":
                base = self._oauth_base_url(trace_id=trace)
                self._send_json(self.app.oauth.protected_resource_metadata(base_url=base))
                return
            if path == "/.well-known/mcp.json":
                base = self._oauth_base_url(trace_id=trace)
                self._send_json(
                    {
                        "name": "re-ctm",
                        "title": "Re-CTM",
                        "endpoint": base + MCP_PATH,
                        "oauth": self.app.oauth.protected_resource_metadata(base_url=base),
                        "tool_count": len(self.app.tools.list_tools()),
                        "tool_catalog_stable": True,
                        "manual_validation_required": True,
                    }
                )
                return
            if path == "/oauth/authorize":
                params = _single_query_values(parsed.query)
                validated = self.app.oauth.validate_authorization_request(
                    params,
                    base_url=self._oauth_base_url(trace_id=trace),
                )
                self._send_authorization_page(validated, params, trace)
                return
            self._json_error(404, "NOT_FOUND", "Unknown endpoint.", trace)
        except ReCTMError as exc:
            self._handle_error(exc, trace)
        except Exception as exc:  # noqa: BLE001 - HTTP boundary must always answer
            self.app.debug.emit(
                "http.unhandled_error",
                "mcp_gateway",
                trace_id=trace,
                decision="error",
                reason="INTERNAL_ERROR",
                details={"exception_type": type(exc).__name__, "message": str(exc)},
            )
            self._json_error(500, "INTERNAL_ERROR", "Unhandled server error.", trace)

    def do_POST(self) -> None:  # noqa: N802
        trace = new_trace_id()
        if not self._origin_allowed():
            self._json_error(403, "ORIGIN_DENIED", "Browser Origin is not allowed.", trace)
            return
        path = posixpath.normpath(urllib.parse.urlsplit(self.path).path)
        try:
            if path == "/oauth/register":
                payload = self._read_json_body()
                result = self.app.oauth.register(payload, trace_id=trace)
                self._send_json(result, status=201)
                return
            if path == "/oauth/authorize":
                params = self._read_form_body()
                password = params.pop("password", "")
                redirect = self.app.oauth.authorize(
                    params,
                    password=password,
                    trace_id=trace,
                    base_url=self._oauth_base_url(trace_id=trace),
                )
                self.send_response(302)
                self.send_header("Location", redirect)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/oauth/token":
                params = self._read_form_body()
                basic_id, basic_secret = parse_basic_authorization(
                    self.headers.get("Authorization", "")
                )
                result = self.app.oauth.exchange_code(
                    params,
                    basic_client_id=basic_id,
                    basic_client_secret=basic_secret,
                    trace_id=trace,
                    base_url=self._oauth_base_url(trace_id=trace),
                )
                self._send_json(result)
                return
            if path == MCP_PATH:
                principal = self.app.oauth.validate_authorization_header(
                    self.headers.get("Authorization", ""),
                    trace_id=trace,
                    base_url=self._oauth_base_url(trace_id=trace),
                )
                request = self._read_json_body()
                era = request_era_from_envelope(request)
                if era == MODERN_ERA:
                    duplicate = self._duplicated_mirror_header()
                    if duplicate is not None:
                        response = jsonrpc_error(
                            response_id(request),
                            HEADER_MISMATCH,
                            f"{duplicate} must appear exactly once",
                            {"header": duplicate, "reason": "duplicate"},
                        )
                        self._send_json(response, status=400)
                        return
                try:
                    validate_http_mirror_headers(
                        request,
                        version_header=self.headers.get("MCP-Protocol-Version"),
                        method_header=self.headers.get("Mcp-Method"),
                        name_header=self.headers.get("Mcp-Name"),
                    )
                except JSONRPCError as exc:
                    response = jsonrpc_error(
                        response_id(request),
                        exc.code,
                        exc.message,
                        exc.data,
                    )
                    self._send_json(
                        response,
                        status=modern_http_status(request, response),
                    )
                    return
                response = self.app.mcp.dispatch(
                    request,
                    principal,
                    trace_id=trace,
                    transport_protocol_version=self.headers.get(
                        "MCP-Protocol-Version"
                    ),
                )
                if response is None:
                    self.send_response(202)
                    self._cors_headers()
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self._send_json(
                        response,
                        status=modern_http_status(request, response),
                    )
                return
            self._json_error(404, "NOT_FOUND", "Unknown endpoint.", trace)
        except ReCTMError as exc:
            self._handle_error(exc, trace)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._json_error(400, "INVALID_BODY", str(exc), trace)
        except Exception as exc:  # noqa: BLE001 - HTTP boundary must always answer
            self.app.debug.emit(
                "http.unhandled_error",
                "mcp_gateway",
                trace_id=trace,
                decision="error",
                reason="INTERNAL_ERROR",
                details={"exception_type": type(exc).__name__, "message": str(exc)},
            )
            self._json_error(500, "INTERNAL_ERROR", "Unhandled server error.", trace)

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ReCTMError(
                "CONTENT_LENGTH_REQUIRED",
                "Content-Length is required.",
                category="validation",
            )
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ReCTMError(
                "CONTENT_LENGTH_INVALID",
                "Content-Length must be an integer.",
                category="validation",
            ) from exc
        if not 0 <= length <= MAX_REQUEST_BYTES:
            raise ReCTMError(
                "REQUEST_TOO_LARGE",
                "Request body exceeds the 1 MiB limit.",
                category="validation",
            )
        return self.rfile.read(length)

    def _read_json_body(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ReCTMError(
                "CONTENT_TYPE_INVALID",
                "Content-Type must be application/json.",
                category="validation",
            )
        payload = json.loads(self._read_body().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ReCTMError(
                "INVALID_BODY",
                "JSON request body must be an object.",
                category="validation",
            )
        return payload

    def _read_form_body(self) -> dict[str, str]:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            raise ReCTMError(
                "CONTENT_TYPE_INVALID",
                "Content-Type must be application/x-www-form-urlencoded.",
                category="validation",
            )
        body = self._read_body().decode("utf-8", errors="strict")
        return {
            key: values[0] if values else ""
            for key, values in urllib.parse.parse_qs(body, keep_blank_values=True).items()
        }

    def _send_authorization_page(
        self,
        validated: Mapping[str, str],
        original: Mapping[str, str],
        trace_id: str,
    ) -> None:
        hidden = {
            "client_id": validated["client_id"],
            "redirect_uri": validated["redirect_uri"],
            "response_type": "code",
            "code_challenge": validated["code_challenge"],
            "code_challenge_method": "S256",
            "resource": validated["resource"],
            "state": validated["state"],
        }
        hidden_html = "".join(
            f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(value, quote=True)}">'
            for name, value in hidden.items()
        )
        body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize Re-CTM</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{{font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:1rem}}input,button{{width:100%;padding:.7rem;margin:.4rem 0;box-sizing:border-box}}code{{overflow-wrap:anywhere}}</style>
</head><body><h1>Authorize Re-CTM</h1>
<p>Client: <code>{html.escape(validated['client_id'])}</code></p>
<p>Redirect: <code>{html.escape(validated['redirect_uri'])}</code></p>
<form method="post" action="/oauth/authorize">{hidden_html}
<label>Operator password<input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Authorize</button></form>
<p>Trace: <code>{html.escape(trace_id)}</code></p></body></html>"""
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(data)

    def _duplicated_mirror_header(self) -> str | None:
        for name in ("MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"):
            if len(self.headers.get_all(name) or ()) > 1:
                return name
        return None

    def _oauth_base_url(self, *, trace_id: str | None = None) -> str:
        configured = self.app.settings.oauth_server_url.rstrip("/")
        if configured:
            self.app.debug.emit(
                "oauth.external_origin_resolved",
                "mcp_gateway",
                trace_id=trace_id or new_trace_id(),
                decision="allow",
                reason="fixed_server_url",
                details={"base_url": configured, "proxy_headers_trusted": False},
            )
            return configured

        server_address = cast(tuple[Any, ...], self.server.server_address)
        bind_host = str(server_address[0])
        bind_port = int(server_address[1])
        if not is_loopback_host(bind_host):
            raise ReCTMError(
                "OAUTH_DYNAMIC_ISSUER_REQUIRES_LOOPBACK",
                "Dynamic OAuth issuer discovery is allowed only on a loopback-bound Re-CTM server.",
                category="security",
                details={"host": bind_host},
            )

        peer_host = str(self.client_address[0]) if self.client_address else ""
        trust_proxy_headers = is_loopback_host(peer_host)
        proto = ""
        host = ""
        if trust_proxy_headers:
            proto = _first_header_value(self.headers.get("X-Forwarded-Proto"))
            if not proto:
                proto = _forwarded_header_param(self.headers.get("Forwarded"), "proto")
            host = _safe_external_host(_first_header_value(self.headers.get("X-Forwarded-Host")))
            if not host:
                host = _safe_external_host(_forwarded_header_param(self.headers.get("Forwarded"), "host"))

        raw_host = self.headers.get("Host", "")
        if not host:
            host = _safe_external_host(raw_host)
            if raw_host and not host:
                raise ReCTMError(
                    "OAUTH_EXTERNAL_URL_INVALID",
                    "Request Host header is not a valid OAuth origin host.",
                    category="validation",
                )
        if not host:
            host = _host_with_port(bind_host, bind_port)

        if proto not in {"http", "https"}:
            hostname = _host_name(host)
            proto = "http" if is_loopback_host(hostname) else "https"
        base = f"{proto}://{host}".rstrip("/")
        self.app.debug.emit(
            "oauth.external_origin_resolved",
            "mcp_gateway",
            trace_id=trace_id or new_trace_id(),
            decision="allow",
            reason="loopback_dynamic_origin",
            details={
                "base_url": base,
                "proxy_headers_trusted": trust_proxy_headers,
                "peer_loopback": is_loopback_host(peer_host),
            },
        )
        return base

    def _handle_error(self, error: ReCTMError, trace_id: str) -> None:
        if error.code == "OAUTH_UNAUTHORIZED":
            base = self._oauth_base_url(trace_id=trace_id)
            self._send_json(
                {"error": error.to_payload(), "trace_id": trace_id},
                status=401,
                extra_headers={
                    "WWW-Authenticate": (
                        f'Bearer realm="re-ctm", resource_metadata="{base}/.well-known/oauth-protected-resource"'
                    )
                },
            )
            return
        if error.category in {"permission", "security"}:
            status = 403
        elif error.category == "not_found":
            status = 404
        elif error.category in {"validation", "conflict"}:
            status = 400 if error.category == "validation" else 409
        else:
            status = 500
        self._send_json({"error": error.to_payload(), "trace_id": trace_id}, status=status)

    def _json_error(self, status: int, code: str, message: str, trace_id: str) -> None:
        self._send_json(
            {
                "error": {
                    "code": code,
                    "message": message,
                    "category": "http",
                    "retryable": False,
                    "details": {},
                },
                "trace_id": trace_id,
            },
            status=status,
        )

    def _send_json(
        self,
        payload: Any,
        *,
        status: int = 200,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._cors_headers()
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            parsed = urllib.parse.urlsplit(origin)
            if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                return False
            hostname = (parsed.hostname or "").lower()
            if parsed.scheme in {"http", "https"} and hostname in {"localhost", "127.0.0.1", "::1"}:
                return True
        except ValueError:
            return False
        return origin.rstrip("/") in self.app.settings.allowed_origins

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and self._origin_allowed():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def log_message(self, format: str, *args: object) -> None:
        print(
            f"{self.address_string()} - [{self.log_date_time_string()}] {format % args}",
            file=sys.stderr,
        )


def run_server(
    application: ReCTMApplication,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> int:
    server = ReCTMHTTPServer((host, port), application)
    oauth_mode = (
        f"fixed OAuth origin {application.settings.oauth_server_url}"
        if application.settings.oauth_server_url
        else "dynamic OAuth origin from loopback tunnel/request headers"
    )
    print(
        f"Re-CTM OAuth MCP listening on http://{host}:{port}{MCP_PATH}; "
        f"{oauth_mode}; complete browser workflow requires post-push manual validation.",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
    return 0


def _single_query_values(query: str) -> dict[str, str]:
    return {
        key: values[0] if values else ""
        for key, values in urllib.parse.parse_qs(query, keep_blank_values=True).items()
    }
