from __future__ import annotations

import base64
import hashlib
import http.client
import json
import socket
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

from re_ctm.app import build_application
from re_ctm.config import Settings
from re_ctm.enums import LatexPolicy, NativeMode
from re_ctm.errors import ReCTMError
from re_ctm.server import ReCTMHTTPServer


class HTTPGatewayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        workspace = root / "workspace"
        data = root / "data"
        private = data / "private"
        workspace.mkdir()
        port = _free_port()
        settings = Settings(
            workspace=workspace,
            data_root=data,
            private_root=private,
            debug_root=data / "debug",
            native_mode=NativeMode.SAFE,
            latex_policy=LatexPolicy.STATIC_ONLY,
            oauth_server_url=f"http://127.0.0.1:{port}",
            oauth_password="operator-password",
            token_secret=b"o" * 32,
            capability_secret=b"c" * 32,
        )
        self.application = build_application(settings)
        self.server = ReCTMHTTPServer(("127.0.0.1", port), self.application)
        self.port = port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        port: int | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        result = response.status, {key: value for key, value in response.getheaders()}, data
        connection.close()
        return result

    def test_http_oauth_to_mcp_flow(self) -> None:
        status, _headers, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(body)["complete_flow_locally_validated"])

        unauthorized = self.request(
            "POST",
            "/mcp",
            body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(unauthorized[0], 401)

        registration = {
            "redirect_uris": ["http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none",
        }
        status, _headers, body = self.request(
            "POST",
            "/oauth/register",
            body=json.dumps(registration).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201)
        client = json.loads(body)
        verifier = "B" * 43
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        auth_params = {
            "client_id": client["client_id"],
            "redirect_uri": "http://127.0.0.1/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": f"http://127.0.0.1:{self.port}",
            "state": "unit-state",
        }
        status, _headers, page = self.request(
            "GET",
            "/oauth/authorize?" + urllib.parse.urlencode(auth_params),
        )
        self.assertEqual(status, 200)
        self.assertIn(b"Authorize Re-CTM", page)

        form = urllib.parse.urlencode({**auth_params, "password": "operator-password"}).encode()
        status, headers, _body = self.request(
            "POST",
            "/oauth/authorize",
            body=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 302)
        code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["Location"]).query)["code"][0]

        token_form = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1/callback",
                "code_verifier": verifier,
                "client_id": client["client_id"],
                "resource": f"http://127.0.0.1:{self.port}",
            }
        ).encode()
        status, _headers, body = self.request(
            "POST",
            "/oauth/token",
            body=token_form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        access_token = json.loads(body)["access_token"]

        status, _headers, body = self.request(
            "POST",
            "/mcp",
            body=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/list",
                    "params": {},
                }
            ).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["result"]["tools"]), 31)

        modern_request = {
            "jsonrpc": "2.0",
            "id": "modern-http",
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        }
        status, _headers, body = self.request(
            "POST",
            "/mcp",
            body=json.dumps(modern_request).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/list",
            },
        )
        self.assertEqual(status, 200)
        modern_result = json.loads(body)["result"]
        self.assertEqual(modern_result["resultType"], "complete")
        self.assertEqual(modern_result["cacheScope"], "private")

        status, _headers, body = self.request(
            "POST",
            "/mcp",
            body=json.dumps(modern_request).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
                "MCP-Protocol-Version": "2026-07-28",
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"]["code"], -32020)

    def test_dynamic_loopback_oauth_origin_supports_cloudflare_style_forwarding(self) -> None:
        root = Path(self.temp.name) / "dynamic-oauth"
        workspace = root / "workspace"
        data = root / "data"
        private = data / "private"
        workspace.mkdir(parents=True)
        port = _free_port()
        application = build_application(
            Settings(
                workspace=workspace,
                data_root=data,
                private_root=private,
                debug_root=data / "debug",
                native_mode=NativeMode.SAFE,
                latex_policy=LatexPolicy.STATIC_ONLY,
                oauth_server_url="",
                oauth_password="operator-password",
                token_secret=b"d" * 32,
                capability_secret=b"c" * 32,
            )
        )
        server = ReCTMHTTPServer(("127.0.0.1", port), application)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        forwarded = {
            "X-Forwarded-Host": "example.trycloudflare.com",
            "X-Forwarded-Proto": "https",
        }
        public_base = "https://example.trycloudflare.com"
        try:
            status, _headers, body = self.request(
                "GET",
                "/.well-known/oauth-authorization-server",
                headers=forwarded,
                port=port,
            )
            self.assertEqual(status, 200)
            metadata = json.loads(body)
            self.assertEqual(metadata["issuer"], public_base)
            self.assertEqual(metadata["registration_endpoint"], public_base + "/oauth/register")

            status, _headers, body = self.request(
                "GET",
                "/.well-known/mcp.json",
                headers=forwarded,
                port=port,
            )
            self.assertEqual(status, 200)
            server_card = json.loads(body)
            self.assertEqual(server_card["endpoint"], public_base + "/mcp")
            self.assertEqual(server_card["oauth"]["resource"], public_base)

            status, _headers, body = self.request(
                "GET",
                "/.well-known/oauth-authorization-server",
                port=port,
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["issuer"], f"http://127.0.0.1:{port}")

            registration = {
                "redirect_uris": ["http://127.0.0.1/callback"],
                "token_endpoint_auth_method": "none",
            }
            status, _headers, body = self.request(
                "POST",
                "/oauth/register",
                body=json.dumps(registration).encode(),
                headers={"Content-Type": "application/json", **forwarded},
                port=port,
            )
            self.assertEqual(status, 201)
            client = json.loads(body)
            verifier = "E" * 43
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            auth_params = {
                "client_id": client["client_id"],
                "redirect_uri": "http://127.0.0.1/callback",
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": public_base,
                "state": "cloudflare-state",
            }
            form = urllib.parse.urlencode({**auth_params, "password": "operator-password"}).encode()
            status, headers, _body = self.request(
                "POST",
                "/oauth/authorize",
                body=form,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": public_base,
                    **forwarded,
                },
                port=port,
            )
            self.assertEqual(status, 302)
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["Location"]).query)["code"][0]

            token_form = urllib.parse.urlencode(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "http://127.0.0.1/callback",
                    "code_verifier": verifier,
                    "client_id": client["client_id"],
                    "resource": public_base,
                }
            ).encode()
            status, _headers, body = self.request(
                "POST",
                "/oauth/token",
                body=token_form,
                headers={"Content-Type": "application/x-www-form-urlencoded", **forwarded},
                port=port,
            )
            self.assertEqual(status, 200)
            access_token = json.loads(body)["access_token"]

            ping_body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
            status, _headers, _body = self.request(
                "POST",
                "/mcp",
                body=ping_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
                port=port,
            )
            self.assertEqual(status, 401)

            status, unauthorized_headers, _body = self.request(
                "POST",
                "/mcp",
                body=ping_body,
                headers={"Content-Type": "application/json", **forwarded},
                port=port,
            )
            self.assertEqual(status, 401)
            self.assertIn(
                public_base + "/.well-known/oauth-protected-resource",
                unauthorized_headers["WWW-Authenticate"],
            )

            status, _headers, body = self.request(
                "POST",
                "/mcp",
                body=ping_body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {access_token}",
                    **forwarded,
                },
                port=port,
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["result"], {})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_oauth_routes_do_not_inherit_mcp_origin_gate(self) -> None:
        external_origin = "https://browser.example"
        status, _headers, body = self.request(
            "GET",
            "/.well-known/oauth-authorization-server",
            headers={"Origin": external_origin},
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body)["issuer"],
            f"http://127.0.0.1:{self.port}",
        )

        registration = {
            "redirect_uris": ["http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none",
        }
        status, _headers, _body = self.request(
            "POST",
            "/oauth/register",
            body=json.dumps(registration).encode(),
            headers={"Content-Type": "application/json", "Origin": external_origin},
        )
        self.assertEqual(status, 201)

        status, _headers, body = self.request(
            "OPTIONS",
            "/oauth/authorize",
            headers={"Origin": external_origin},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"]["code"], "ORIGIN_DENIED")

        status, _headers, body = self.request(
            "POST",
            "/mcp",
            body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode(),
            headers={"Content-Type": "application/json", "Origin": external_origin},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"]["code"], "ORIGIN_DENIED")

    def test_fixed_oauth_origin_ignores_forwarded_host(self) -> None:
        status, _headers, body = self.request(
            "GET",
            "/.well-known/oauth-authorization-server",
            headers={
                "X-Forwarded-Host": "attacker.example",
                "X-Forwarded-Proto": "https",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["issuer"], f"http://127.0.0.1:{self.port}")

    def test_dynamic_oauth_origin_refuses_non_loopback_bind(self) -> None:
        root = Path(self.temp.name) / "dynamic-non-loopback"
        workspace = root / "workspace"
        data = root / "data"
        private = data / "private"
        workspace.mkdir(parents=True)
        application = build_application(
            Settings(
                workspace=workspace,
                data_root=data,
                private_root=private,
                debug_root=data / "debug",
                native_mode=NativeMode.SAFE,
                latex_policy=LatexPolicy.STATIC_ONLY,
                oauth_server_url="",
                oauth_password="operator-password",
                token_secret=b"n" * 32,
                capability_secret=b"c" * 32,
            )
        )
        try:
            with self.assertRaises(ReCTMError) as denied:
                ReCTMHTTPServer(("0.0.0.0", _free_port()), application)
            self.assertEqual(denied.exception.code, "OAUTH_DYNAMIC_ISSUER_REQUIRES_LOOPBACK")
        finally:
            application.close()

    def test_bind_failure_preserves_original_os_error(self) -> None:
        root = Path(self.temp.name) / "bind-failure"
        workspace = root / "workspace"
        data = root / "data"
        private = data / "private"
        workspace.mkdir(parents=True)
        with socket.socket() as blocker:
            blocker.bind(("127.0.0.1", 0))
            blocker.listen(1)
            occupied_port = int(blocker.getsockname()[1])
            application = build_application(
                Settings(
                    workspace=workspace,
                    data_root=data,
                    private_root=private,
                    debug_root=data / "debug",
                    native_mode=NativeMode.SAFE,
                    latex_policy=LatexPolicy.STATIC_ONLY,
                    oauth_server_url=f"http://127.0.0.1:{occupied_port}",
                    oauth_password="operator-password",
                    token_secret=b"t" * 32,
                    capability_secret=b"c" * 32,
                )
            )
            with self.assertRaises(OSError):
                ReCTMHTTPServer(("127.0.0.1", occupied_port), application)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


if __name__ == "__main__":
    unittest.main()
