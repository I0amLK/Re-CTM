#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Redacted OAuth DCR/PKCE to legacy+modern MCP smoke for a running Re-CTM server."
    )
    parser.add_argument("--base-url", required=True, help="Public Re-CTM issuer/base URL.")
    parser.add_argument(
        "--password-env",
        default="RE_CTM_OAUTH_PASSWORD",
        help="Environment variable containing the OAuth authorization password; hidden input is used when unset.",
    )
    parser.add_argument("--callback", default="http://127.0.0.1/callback")
    parser.add_argument("--output", default="oauth-mcp-smoke.json")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args(argv)

    base = args.base_url.rstrip("/")
    parsed_base = urllib.parse.urlsplit(base)
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
        parser.error("--base-url must be an absolute HTTP(S) URL")
    if parsed_base.scheme == "http" and parsed_base.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        parser.error("non-loopback smoke must use HTTPS")
    password = os.environ.get(args.password_env) or getpass.getpass(
        f"OAuth authorization password ({args.password_env} is unset): "
    )
    if not password:
        parser.error("OAuth authorization password is required")

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "base_url": base,
        "callback": args.callback,
        "checks": [],
        "passed": False,
        "redaction": "OAuth password, authorization code, client secret, and access token are never written.",
    }
    access_token = ""
    try:
        metadata = _json_request(
            f"{base}/.well-known/oauth-authorization-server",
            timeout=args.timeout,
        )
        _record(
            report,
            "authorization_server_metadata",
            metadata.get("issuer") == base
            and metadata.get("authorization_endpoint") == f"{base}/oauth/authorize"
            and metadata.get("token_endpoint") == f"{base}/oauth/token",
            issuer=metadata.get("issuer"),
        )

        protected = _json_request(
            f"{base}/.well-known/oauth-protected-resource",
            timeout=args.timeout,
        )
        _record(
            report,
            "protected_resource_metadata",
            protected.get("resource") == base,
            resource=protected.get("resource"),
        )

        client = _json_request(
            f"{base}/oauth/register",
            method="POST",
            json_body={
                "client_name": "Re-CTM manual smoke",
                "redirect_uris": [args.callback],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
            timeout=args.timeout,
        )
        client_id = _required_text(client, "client_id")
        _record(
            report,
            "dynamic_client_registration",
            client.get("token_endpoint_auth_method") == "none",
            client_id_sha256=_sha256(client_id),
            token_endpoint_auth_method=client.get("token_endpoint_auth_method"),
        )

        verifier = secrets.token_urlsafe(64)[:96]
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        state = secrets.token_urlsafe(24)
        authorize_fields = {
            "client_id": client_id,
            "redirect_uri": args.callback,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "resource": base,
            "password": password,
        }
        location = _form_redirect(
            f"{base}/oauth/authorize",
            authorize_fields,
            timeout=args.timeout,
        )
        redirect = urllib.parse.urlsplit(location)
        redirect_params = urllib.parse.parse_qs(redirect.query)
        code = (redirect_params.get("code") or [""])[0]
        returned_state = (redirect_params.get("state") or [""])[0]
        _record(
            report,
            "authorization_code_pkce",
            bool(code) and returned_state == state,
            redirect_origin=f"{redirect.scheme}://{redirect.netloc}",
            state_matched=returned_state == state,
        )

        token = _form_json(
            f"{base}/oauth/token",
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": args.callback,
                "code_verifier": verifier,
                "client_id": client_id,
                "resource": base,
            },
            timeout=args.timeout,
        )
        access_token = _required_text(token, "access_token")
        _record(
            report,
            "access_token",
            token.get("token_type") == "Bearer",
            token_type=token.get("token_type"),
            token_sha256=_sha256(access_token),
            expires_in=token.get("expires_in"),
        )

        legacy_initialize = _mcp(
            base,
            access_token,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "clientInfo": {"name": "manual-smoke", "version": "1"},
                    "capabilities": {},
                },
            },
            timeout=args.timeout,
        )
        legacy_version = legacy_initialize.get("result", {}).get("protocolVersion")
        _record(
            report,
            "legacy_initialize",
            legacy_version == "2025-11-25",
            protocol_version=legacy_version,
        )

        tools_response = _mcp(
            base,
            access_token,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            timeout=args.timeout,
        )
        tools = tools_response.get("result", {}).get("tools")
        names = [str(item.get("name")) for item in tools] if isinstance(tools, list) else []
        _record(
            report,
            "fixed_tool_catalog",
            len(names) == 24
            and all(
                tool in names
                for tool in (
                    "check_exec_environment",
                    "list_dir",
                    "write_stdin",
                    "kill_command",
                    "read_output",
                    "git_status",
                    "git_diff",
                    "git_log",
                    "git_show",
                    "git_blame",
                    "request_permissions",
                    "view_image",
                )
            )
            and "exec_command" in names
            and "rethlas_retrieve" in names
            and "rethlas_step" in names
            and "rethlas_inspect" in names
            and "rethlas_control" in names
            and "rethlas_artifact" in names
            and "rethlas_export_final" not in names,
            tool_count=len(names),
            tool_names=names,
        )

        legacy_alias = _mcp(
            base,
            access_token,
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "rethlas_status",
                    "arguments": {"run_id": "smoke-nonexistent-run"},
                },
            },
            timeout=args.timeout,
        )
        legacy_structured = legacy_alias.get("result", {}).get("structuredContent", {})
        _record(
            report,
            "hidden_legacy_rethlas_alias",
            "rethlas_status" not in names
            and isinstance(legacy_structured, dict)
            and legacy_structured.get("error", {}).get("code") == "RUN_NOT_FOUND",
            advertised=False,
            accepted_as_tool=isinstance(legacy_alias.get("result"), dict),
        )

        meta = {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "manual-smoke", "version": "1"},
        }
        modern = _mcp(
            base,
            access_token,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "server_info", "arguments": {}, "_meta": meta},
            },
            timeout=args.timeout,
            extra_headers={
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": "server_info",
            },
        )
        modern_result = modern.get("result") or {}
        structured = modern_result.get("structuredContent") or {}
        native_info = structured.get("native") or {}
        axioms = structured.get("authorization_axioms") or {}
        non_inheritance = (
            native_info.get("workflow_authority_inherited") is False
            and "never implies workflow authority" in str(axioms.get("non_inheritance") or "")
        )
        _record(
            report,
            "modern_mcp_and_non_inheritance",
            modern_result.get("resultType") == "complete"
            and non_inheritance,
            result_type=modern_result.get("resultType"),
            workflow_authority_inherited=native_info.get("workflow_authority_inherited"),
            non_inheritance_axiom=axioms.get("non_inheritance"),
            native_exec_backend=native_info.get("native_exec_backend"),
        )
    except Exception as exc:  # noqa: BLE001 - manual report must preserve failure evidence
        _record(
            report,
            "unhandled_smoke_failure",
            False,
            exception_type=type(exc).__name__,
            message=str(exc),
        )
    finally:
        access_token = ""
        password = ""

    report["passed"] = bool(report["checks"]) and all(item["passed"] for item in report["checks"])
    output = Path(args.output).expanduser().resolve()
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["passed"], "report": str(output)}, indent=2))
    return 0 if report["passed"] else 1


def _mcp(
    base: str,
    token: str,
    payload: Mapping[str, Any],
    *,
    timeout: int,
    extra_headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        **dict(extra_headers or {}),
    }
    return _json_request(
        f"{base}/mcp",
        method="POST",
        json_body=dict(payload),
        headers=headers,
        timeout=timeout,
    )


def _json_request(
    url: str,
    *,
    method: str = "GET",
    json_body: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: int,
) -> dict[str, Any]:
    data = None
    request_headers = {"Accept": "application/json", **dict(headers or {})}
    if json_body is not None:
        data = json.dumps(dict(json_body), separators=(",", ":")).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=request_headers,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        raw = response.read(2 * 1024 * 1024)
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object from {url}")
    return payload


def _form_json(url: str, fields: Mapping[str, str], *, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(dict(fields)).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("token endpoint returned a non-object")
    return payload


def _form_redirect(url: str, fields: Mapping[str, str], *, timeout: int) -> str:
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(dict(fields)).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code != 302:
            raise
        location = str(exc.headers.get("Location") or "")
        if not location:
            raise ValueError("authorization endpoint returned 302 without Location")
        return location
    raise ValueError("authorization endpoint did not redirect")


def _record(report: dict[str, Any], name: str, passed: bool, **details: Any) -> None:
    report["checks"].append({"name": name, "passed": bool(passed), "details": details})


def _required_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {key}")
    return value


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
