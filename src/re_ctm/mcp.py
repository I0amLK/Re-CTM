from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Mapping

from . import __version__
from .debug import new_trace_id
from .errors import ReCTMError
from .oauth import OAuthPrincipal
from .tools import TOOL_SPECS, ToolRuntime, validate_tool_arguments


LEGACY_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18")
MODERN_PROTOCOL_VERSIONS = ("2026-07-28",)
SUPPORTED_PROTOCOL_VERSIONS = (*MODERN_PROTOCOL_VERSIONS, *LEGACY_PROTOCOL_VERSIONS)
LATEST_LEGACY_PROTOCOL_VERSION = LEGACY_PROTOCOL_VERSIONS[0]
LEGACY_ERA = "legacy"
MODERN_ERA = "modern"

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
MODERN_RESULT_TYPE = "complete"

HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022
MODERN_ERROR_HTTP_STATUSES = {
    -32601: 404,
    -32602: 400,
    HEADER_MISMATCH: 400,
    UNSUPPORTED_PROTOCOL_VERSION: 400,
}
MODERN_METHODS = frozenset(
    {
        "server/discover",
        "notifications/cancelled",
        "ping",
        "tools/list",
        "tools/call",
    }
)
MODERN_CACHEABLE_METHODS = frozenset({"server/discover", "tools/list"})
MIRRORED_NAME_METHODS = {"tools/call": "name"}
BASE64_SENTINEL_PREFIX = "=?base64?"
BASE64_SENTINEL_SUFFIX = "?="
BASE64_SENTINEL_MAX_PAYLOAD = 8192


@dataclass(frozen=True)
class RequestContext:
    era: str
    protocol_version: str
    client_info: dict[str, str] | None = None


class MCPDispatcher:
    def __init__(self, tools: ToolRuntime) -> None:
        self.tools = tools

    def dispatch(
        self,
        request: Mapping[str, Any],
        principal: OAuthPrincipal,
        *,
        trace_id: str | None = None,
        transport_protocol_version: str | None = None,
    ) -> dict[str, Any] | None:
        trace = trace_id or new_trace_id()
        request_id = response_id(request)
        is_notification = "id" not in request
        try:
            validate_rpc_envelope(request)
            method = str(request["method"])
            params = rpc_params(request)
            era = request_era(method, params)
            if era == MODERN_ERA:
                context = modern_request_context(params)
                result = self._dispatch_modern(method, params, principal, trace)
            else:
                context = RequestContext(
                    era=LEGACY_ERA,
                    protocol_version=(
                        transport_protocol_version
                        if transport_protocol_version in LEGACY_PROTOCOL_VERSIONS
                        else LATEST_LEGACY_PROTOCOL_VERSION
                    ),
                )
                result = self._dispatch_legacy(method, params, principal, trace)
        except JSONRPCError as exc:
            if is_notification:
                return None
            return jsonrpc_error(request_id, exc.code, exc.message, exc.data)
        except ReCTMError as exc:
            if is_notification:
                return None
            return jsonrpc_error(
                request_id,
                -32603,
                exc.message,
                {"re_ctm_error": exc.to_payload(), "trace_id": trace},
            )
        if is_notification or result is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": shape_result(context, method, result),
        }

    def _dispatch_modern(
        self,
        method: str,
        params: dict[str, Any],
        principal: OAuthPrincipal,
        trace_id: str,
    ) -> dict[str, Any] | None:
        if method not in MODERN_METHODS:
            raise JSONRPCError(-32601, f"Method not found: {method}")
        if method == "notifications/cancelled":
            return None
        if method == "ping":
            return {}
        if method == "server/discover":
            return self._discover_payload()
        if method == "tools/list":
            return {"tools": self.tools.list_tools()}
        return self._call_tool(params, principal, trace_id)

    def _dispatch_legacy(
        self,
        method: str,
        params: dict[str, Any],
        principal: OAuthPrincipal,
        trace_id: str,
    ) -> dict[str, Any] | None:
        if method == "initialize":
            requested = params.get("protocolVersion")
            negotiated = (
                str(requested)
                if isinstance(requested, str) and requested in LEGACY_PROTOCOL_VERSIONS
                else LATEST_LEGACY_PROTOCOL_VERSION
            )
            return {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": server_identity(),
                "instructions": server_instructions(),
            }
        if method in {"notifications/initialized", "notifications/cancelled"}:
            return None
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self.tools.list_tools()}
        if method == "tools/call":
            return self._call_tool(params, principal, trace_id)
        raise JSONRPCError(-32601, f"Method not found: {method}")

    def _call_tool(
        self,
        params: dict[str, Any],
        principal: OAuthPrincipal,
        trace_id: str,
    ) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not name:
            raise JSONRPCError(-32602, "tools/call requires a tool name")
        if not isinstance(arguments, Mapping):
            raise JSONRPCError(-32602, "tools/call arguments must be an object")
        if name not in TOOL_SPECS:
            raise JSONRPCError(-32602, f"Unknown tool: {name}", {"reason": "unknown_tool"})
        try:
            validate_tool_arguments(name, arguments)
        except ReCTMError as exc:
            raise JSONRPCError(
                -32602,
                exc.message,
                {"reason": "invalid_arguments", "code": exc.code},
            ) from exc
        return self.tools.call(
            name,
            dict(arguments),
            principal,
            trace_id=trace_id,
        )

    @staticmethod
    def _discover_payload() -> dict[str, Any]:
        return {
            "supportedVersions": list(MODERN_PROTOCOL_VERSIONS),
            "capabilities": {"tools": {"listChanged": False}},
            "oauthOnly": True,
            "instructions": server_instructions(),
        }


class JSONRPCError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message)


def server_identity() -> dict[str, str]:
    return {"name": "re-ctm", "title": "Re-CTM", "version": __version__}


def server_instructions() -> str:
    return (
        "Use native tools for ordinary workspace and computer operations under the configured native authority. "
        "For every concrete mathematical proof, derivation, proof repair, or rigorous verification task, start with rethlas_start and continue with rethlas_next plus the capability-authorized rethlas_* tools until the run reaches done, unless the user explicitly requests a direct informal answer. "
        "Do not replace a required Rethlas branch, join, LaTeX, verifier, repair, or finalization stage with an unverified answer in chat. "
        "When rethlas_next reports done, report the workspace_export_path where proof_verified.tex was automatically written. "
        "The rethlas_* workflow is a separate capability-gated authority; native dangerous mode never grants workflow authority."
    )


def response_id(request: Mapping[str, Any]) -> str | int | None:
    value = request.get("id")
    if isinstance(value, str) or (
        isinstance(value, int) and not isinstance(value, bool)
    ):
        return value
    return None


def validate_rpc_envelope(request: Mapping[str, Any]) -> None:
    if request.get("jsonrpc") != "2.0":
        raise JSONRPCError(-32600, "Invalid Request: jsonrpc must be 2.0")
    method = request.get("method")
    if not isinstance(method, str) or not method:
        raise JSONRPCError(-32600, "Invalid Request: method must be a non-empty string")
    if "id" in request and not (
        request["id"] is None
        or isinstance(request["id"], str)
        or (
            isinstance(request["id"], int)
            and not isinstance(request["id"], bool)
        )
    ):
        raise JSONRPCError(-32600, "Invalid Request: id must be string, integer, or null")


def rpc_params(request: Mapping[str, Any]) -> dict[str, Any]:
    params = request.get("params", {})
    if params is None:
        return {}
    if not isinstance(params, Mapping):
        raise JSONRPCError(-32602, "MCP method params must be an object")
    return dict(params)


def request_era(method: str, params: Mapping[str, Any]) -> str:
    if method == "initialize":
        return LEGACY_ERA
    meta = params.get("_meta")
    if isinstance(meta, Mapping) and META_PROTOCOL_VERSION in meta:
        return MODERN_ERA
    return LEGACY_ERA


def request_era_from_envelope(request: Mapping[str, Any]) -> str:
    method = request.get("method")
    raw_params = request.get("params")
    params = raw_params if isinstance(raw_params, Mapping) else {}
    return request_era(str(method or ""), params)


def modern_request_context(params: Mapping[str, Any]) -> RequestContext:
    meta = params.get("_meta")
    if not isinstance(meta, Mapping):
        raise JSONRPCError(-32602, "Modern request _meta must be an object")
    version = meta.get(META_PROTOCOL_VERSION)
    if not isinstance(version, str):
        raise JSONRPCError(
            -32602,
            f"{META_PROTOCOL_VERSION} must be a string",
            {"reason": "protocol_version"},
        )
    if version not in MODERN_PROTOCOL_VERSIONS:
        raise JSONRPCError(
            UNSUPPORTED_PROTOCOL_VERSION,
            f"Unsupported MCP protocol version in _meta: {version}",
            {"supported": list(MODERN_PROTOCOL_VERSIONS), "received": version},
        )
    capabilities = meta.get(META_CLIENT_CAPABILITIES)
    if not isinstance(capabilities, Mapping):
        raise JSONRPCError(
            -32602,
            f"{META_CLIENT_CAPABILITIES} is required and must be an object",
            {"reason": "client_capabilities"},
        )
    declared = meta.get(META_CLIENT_INFO)
    if declared is not None and not isinstance(declared, Mapping):
        raise JSONRPCError(
            -32602,
            f"{META_CLIENT_INFO} must be an object when present",
            {"reason": "client_info"},
        )
    client_info: dict[str, str] | None = None
    if isinstance(declared, Mapping):
        bounded: dict[str, str] = {}
        for key in ("name", "version"):
            value = declared.get(key)
            if isinstance(value, str):
                bounded[key] = value[:200]
        client_info = bounded
    return RequestContext(MODERN_ERA, version, client_info)


def shape_result(
    context: RequestContext,
    method: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    if context.era != MODERN_ERA:
        return result
    shaped = dict(result)
    shaped["resultType"] = MODERN_RESULT_TYPE
    carried = shaped.get("_meta")
    meta = dict(carried) if isinstance(carried, Mapping) else {}
    meta[META_SERVER_INFO] = server_identity()
    shaped["_meta"] = meta
    if method in MODERN_CACHEABLE_METHODS:
        shaped["ttlMs"] = 0
        shaped["cacheScope"] = "private"
    return shaped


def validate_http_mirror_headers(
    request: Mapping[str, Any],
    *,
    version_header: str | None,
    method_header: str | None,
    name_header: str | None,
) -> None:
    validate_rpc_envelope(request)
    method = str(request["method"])
    params = rpc_params(request)
    era = request_era(method, params)
    if era != MODERN_ERA:
        if version_header in MODERN_PROTOCOL_VERSIONS:
            raise JSONRPCError(
                HEADER_MISMATCH,
                "MCP-Protocol-Version names the modern era but params._meta does not",
                {"header": "MCP-Protocol-Version", "reason": "body_is_not_modern"},
            )
        if version_header and version_header not in SUPPORTED_PROTOCOL_VERSIONS:
            raise JSONRPCError(
                -32600,
                "Unsupported MCP protocol version",
                {"supported": list(SUPPORTED_PROTOCOL_VERSIONS), "received": version_header},
            )
        return

    modern_request_context(params)
    meta = _require_mapping(params["_meta"])
    meta_version = meta[META_PROTOCOL_VERSION]
    if version_header is None:
        raise _mirror_error(
            "MCP-Protocol-Version",
            "MCP-Protocol-Version is required for a modern request",
            "missing",
        )
    if version_header != meta_version:
        raise _mirror_error(
            "MCP-Protocol-Version",
            "MCP-Protocol-Version does not match params._meta",
            "mismatch",
        )
    if method_header is None:
        raise _mirror_error("Mcp-Method", "Mcp-Method is required", "missing")
    if method_header != method:
        raise _mirror_error("Mcp-Method", "Mcp-Method does not match request method", "mismatch")
    subject_field = MIRRORED_NAME_METHODS.get(method)
    if subject_field is None:
        return
    if name_header is None:
        raise _mirror_error("Mcp-Name", f"Mcp-Name is required for {method}", "missing")
    if decode_mirror_header(name_header) != params.get(subject_field):
        raise _mirror_error(
            "Mcp-Name",
            f"Mcp-Name does not match params.{subject_field}",
            "mismatch",
        )


def decode_mirror_header(value: str) -> str:
    if not (
        value.startswith(BASE64_SENTINEL_PREFIX)
        and value.endswith(BASE64_SENTINEL_SUFFIX)
    ):
        return value
    payload = value[len(BASE64_SENTINEL_PREFIX) : -len(BASE64_SENTINEL_SUFFIX)]
    if len(payload) > BASE64_SENTINEL_MAX_PAYLOAD:
        raise _mirror_error("Mcp-Name", "Base64 mirror value is too long", "oversized")
    try:
        return base64.b64decode(payload, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise _mirror_error("Mcp-Name", "Base64 mirror value is not valid UTF-8", "invalid_base64") from exc


def modern_http_status(request: Mapping[str, Any], response: Mapping[str, Any]) -> int:
    if request_era_from_envelope(request) != MODERN_ERA:
        return 200
    error = response.get("error")
    if not isinstance(error, Mapping):
        return 200
    return MODERN_ERROR_HTTP_STATUSES.get(error.get("code"), 200)


def jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    data: Any = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _mirror_error(header: str, message: str, reason: str) -> JSONRPCError:
    return JSONRPCError(
        HEADER_MISMATCH,
        message,
        {"header": header, "reason": reason},
    )


def _require_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("value is not a mapping")
    return value
