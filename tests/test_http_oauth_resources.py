from __future__ import annotations

import base64
import hashlib
import http.client
import json
import tempfile
import threading
import unittest
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from re_ctm.app import build_application
from re_ctm.config import Settings
from re_ctm.enums import LatexPolicy
from re_ctm.oauth import _decode_signed_token
from re_ctm.server import MCP_PROTECTED_RESOURCE_METADATA_PATH, ReCTMHTTPServer


class HTTPResourceOAuthTestCase(unittest.TestCase):
    @contextmanager
    def gateway(self, fixed_origin: str = "") -> Iterator[tuple[int, str]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            data = root / "data"
            application = build_application(Settings(
                workspace=workspace, data_root=data, private_root=data / "private",
                debug_root=data / "debug", latex_policy=LatexPolicy.STATIC_ONLY,
                oauth_server_url=fixed_origin, oauth_password="operator-password",
                token_secret=b"r" * 32, capability_secret=b"c" * 32,
            ))
            server = ReCTMHTTPServer(("127.0.0.1", 0), application, access_log_enabled=False)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield port, fixed_origin or f"http://127.0.0.1:{port}"
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    def request(
        self, port: int, method: str, path: str, *, body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def form(
        self, port: int, path: str, params: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], bytes]:
        return self.request(
            port, "POST", path, body=urllib.parse.urlencode(params).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
        )

    def exercise_flow(self, port: int, base: str, headers: dict[str, str]) -> str:
        status, _, body = self.request(
            port, "GET", "/.well-known/oauth-authorization-server", headers=headers
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["issuer"], base)
        for path, expected in (
            ("/.well-known/oauth-protected-resource", base),
            (MCP_PROTECTED_RESOURCE_METADATA_PATH, base + "/mcp"),
        ):
            status, _, body = self.request(port, "GET", path, headers=headers)
            self.assertEqual(status, 200)
            metadata = json.loads(body)
            self.assertEqual(metadata["resource"], expected)
            self.assertEqual(metadata["authorization_servers"], [base])
        ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
        status, challenge, _ = self.request(
            port, "POST", "/mcp", body=ping, headers={"Content-Type": "application/json", **headers}
        )
        self.assertEqual(status, 401)
        self.assertEqual(
            challenge["WWW-Authenticate"],
            f'Bearer realm="re-ctm", resource_metadata="{base}{MCP_PROTECTED_RESOURCE_METADATA_PATH}"',
        )
        registration = {"redirect_uris": ["http://127.0.0.1/callback"], "token_endpoint_auth_method": "none"}
        status, _, body = self.request(
            port, "POST", "/oauth/register", body=json.dumps(registration).encode(),
            headers={"Content-Type": "application/json", **headers},
        )
        self.assertEqual(status, 201)
        client = json.loads(body)
        verifier = "R" * 43
        pkce = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        access_token = ""
        for resource in (base, base + "/mcp"):
            with self.subTest(resource=resource):
                authorization = {
                    "client_id": client["client_id"], "redirect_uri": "http://127.0.0.1/callback",
                    "response_type": "code", "code_challenge": pkce, "code_challenge_method": "S256",
                    "resource": resource, "state": "resource-state",
                }
                status, _, page = self.request(
                    port, "GET", "/oauth/authorize?" + urllib.parse.urlencode(authorization), headers=headers
                )
                self.assertEqual(status, 200)
                self.assertIn(resource.encode(), page)
                status, redirect, _ = self.form(
                    port, "/oauth/authorize", {**authorization, "password": "operator-password"}, headers
                )
                self.assertEqual(status, 302)
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect["Location"]).query)
                self.assertEqual(query["state"], ["resource-state"])
                exchange = {
                    "grant_type": "authorization_code", "code": query["code"][0],
                    "client_id": client["client_id"], "redirect_uri": authorization["redirect_uri"],
                    "code_verifier": verifier, "resource": resource,
                }
                status, _, body = self.form(port, "/oauth/token", exchange, headers)
                self.assertEqual(status, 200)
                access_token = json.loads(body)["access_token"]
                claims = _decode_signed_token(access_token, b"r" * 32)
                self.assertEqual(claims["iss"], base)
                self.assertEqual(claims["aud"], resource)
                status, _, body = self.request(
                    port, "POST", "/mcp", body=ping,
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {access_token}", **headers},
                )
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["result"], {})

        for resource in (base + "/other", base + "/mcp/", "https://wrong.example/mcp"):
            with self.subTest(wrong_resource=resource):
                status, _, body = self.form(
                    port, "/oauth/authorize",
                    {**authorization, "resource": resource, "password": "operator-password"}, headers,
                )
                self.assertEqual(status, 403)
                self.assertEqual(json.loads(body)["error"]["code"], "OAUTH_INVALID_TARGET")
        for resource in (base, base + "/other", "https://wrong.example/mcp"):
            with self.subTest(exchange_resource=resource):
                status, redirect, _ = self.form(
                    port, "/oauth/authorize", {**authorization, "password": "operator-password"}, headers
                )
                self.assertEqual(status, 302)
                code = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect["Location"]).query)["code"][0]
                status, _, body = self.form(
                    port, "/oauth/token", {**exchange, "code": code, "resource": resource}, headers
                )
                self.assertEqual(status, 403)
                self.assertEqual(json.loads(body)["error"]["code"], "OAUTH_INVALID_GRANT")
        return access_token

    def test_fixed_origin_full_resource_flow_ignores_proxy_headers(self) -> None:
        with self.gateway("https://fixed.example.test") as (port, base):
            self.exercise_flow(port, base, {
                "X-Forwarded-Host": "attacker.example", "X-Forwarded-Proto": "https",
            })

    def test_dynamic_loopback_full_resource_flow(self) -> None:
        with self.gateway() as (port, base):
            self.exercise_flow(port, base, {})

    def test_dynamic_forwarded_full_resource_flow_rejects_other_origin(self) -> None:
        with self.gateway() as (port, _):
            base = "https://fixture.trycloudflare.com"
            token = self.exercise_flow(port, base, {
                "X-Forwarded-Host": "fixture.trycloudflare.com", "X-Forwarded-Proto": "https",
            })
            ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
            for extra in ({}, {"X-Forwarded-Host": "other.example", "X-Forwarded-Proto": "https"}):
                with self.subTest(headers=extra):
                    status, _, body = self.request(
                        port, "POST", "/mcp", body=ping,
                        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}", **extra},
                    )
                    self.assertEqual(status, 401)
                    self.assertEqual(json.loads(body)["error"]["code"], "OAUTH_UNAUTHORIZED")


if __name__ == "__main__":
    unittest.main()
