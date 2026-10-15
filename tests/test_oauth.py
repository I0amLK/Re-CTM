from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from re_ctm.debug import DebugEventBus
from re_ctm.errors import ReCTMError
from re_ctm.oauth import OAuthService, OAuthStore, _decode_signed_token, _encode_signed_token


class OAuthServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = OAuthStore(root / "oauth.sqlite3")
        self.debug = DebugEventBus(root / "events.jsonl", root / "private", enabled=True)
        self.service = OAuthService(
            server_url="https://re-ctm.example.test",
            password="operator-password",
            token_secret=b"o" * 32,
            store=self.store,
            debug=self.debug,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_dcr_pkce_single_use_code_and_access_token(self) -> None:
        registered = self.service.register(
            {
                "redirect_uris": ["http://127.0.0.1/callback"],
                "token_endpoint_auth_method": "none",
                "client_name": "Unit Client",
            },
            trace_id="tr-register",
        )
        verifier = "A" * 43
        challenge = urllib.parse.quote_plus(
            __import__("base64").urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        )
        params = {
            "client_id": registered["client_id"],
            "redirect_uri": "http://127.0.0.1/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": "https://re-ctm.example.test",
            "state": "state-1",
        }
        with self.assertRaises(ReCTMError) as denied:
            self.service.authorize(params, password="wrong", trace_id="tr-denied")
        self.assertEqual(denied.exception.code, "OAUTH_ACCESS_DENIED")

        redirect = self.service.authorize(
            params,
            password="operator-password",
            trace_id="tr-authorize",
        )
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect).query)
        code = query["code"][0]
        token = self.service.exchange_code(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1/callback",
                "code_verifier": verifier,
                "client_id": registered["client_id"],
                "resource": "https://re-ctm.example.test",
            },
            trace_id="tr-token",
        )["access_token"]
        principal = self.service.validate_authorization_header(
            f"Bearer {token}",
            trace_id="tr-validate",
        )
        self.assertEqual(principal.client_id, registered["client_id"])

        with self.assertRaises(ReCTMError) as reused:
            self.service.exchange_code(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "http://127.0.0.1/callback",
                    "code_verifier": verifier,
                    "client_id": registered["client_id"],
                    "resource": "https://re-ctm.example.test",
                },
                trace_id="tr-reuse",
            )
        self.assertEqual(reused.exception.code, "OAUTH_INVALID_GRANT")

    def authorization_params(self, resource: str) -> dict[str, str]:
        registered = self.service.register(
            {"redirect_uris": ["http://127.0.0.1/callback"]}, trace_id="tr-resource-register"
        )
        challenge = base64.urlsafe_b64encode(hashlib.sha256(b"A" * 43).digest()).rstrip(b"=").decode()
        return {
            "client_id": registered["client_id"], "redirect_uri": "http://127.0.0.1/callback",
            "response_type": "code", "code_challenge": challenge,
            "code_challenge_method": "S256", "resource": resource,
        }

    def issue_code(self, params: dict[str, str], *, base_url: str | None = None) -> str:
        redirect = self.service.authorize(
            params, password="operator-password", trace_id="tr-resource-authorize", base_url=base_url
        )
        return urllib.parse.parse_qs(urllib.parse.urlsplit(redirect).query)["code"][0]

    def exchange_params(self, params: dict[str, str], code: str) -> dict[str, str]:
        return {
            "grant_type": "authorization_code", "code": code, "code_verifier": "A" * 43,
            "client_id": params["client_id"], "redirect_uri": params["redirect_uri"],
            "resource": params["resource"],
        }

    def test_metadata_and_exact_resource_audiences_preserve_legacy_origin(self) -> None:
        base = self.service.server_url
        self.assertEqual(self.service.protected_resource_metadata()["resource"], base)
        metadata = self.service.protected_mcp_resource_metadata()
        self.assertEqual(metadata["resource"], base + "/mcp")
        self.assertEqual(metadata["authorization_servers"], [base])
        for resource in (base, base + "/", base + "/mcp"):
            with self.subTest(resource=resource):
                params = self.authorization_params(resource)
                code = self.issue_code(params)
                token = self.service.exchange_code(
                    self.exchange_params(params, code), trace_id="tr-resource-token"
                )["access_token"]
                claims = _decode_signed_token(token, self.service.token_secret)
                self.assertEqual(claims["iss"], base)
                self.assertEqual(claims["aud"], base if resource == base + "/" else resource)
                principal = self.service.validate_authorization_header(
                    f"Bearer {token}", trace_id="tr-resource-validate"
                )
                self.assertEqual(principal.client_id, params["client_id"])

    def test_wrong_resource_is_rejected_at_authorization(self) -> None:
        base = self.service.server_url
        params = self.authorization_params(base)
        for resource in (
            "", "https://elsewhere.example/mcp", base + "/other", base + "/mcp/",
            base + "/mcp?x=1", base + "/mcp#fragment", base + "/mcp/../mcp",
            base + "/%6dcp", base + "/mcpé",
        ):
            with self.subTest(resource=resource):
                with self.assertRaises(ReCTMError) as denied:
                    self.service.validate_authorization_request({**params, "resource": resource})
                self.assertEqual(denied.exception.code, "OAUTH_INVALID_TARGET")

    def test_code_cannot_change_between_origin_mcp_or_other_resources(self) -> None:
        base = self.service.server_url
        for issued, exchanged in (
            (base, base + "/mcp"), (base + "/mcp", base),
            (base + "/mcp", "https://elsewhere.example/mcp"),
            (base + "/mcp", base + "/mcp/"), (base + "/mcp", base + "/mcpé"),
        ):
            with self.subTest(issued=issued, exchanged=exchanged):
                params = self.authorization_params(issued)
                code = self.issue_code(params)
                exchange = {**self.exchange_params(params, code), "resource": exchanged}
                with self.assertRaises(ReCTMError) as denied:
                    self.service.exchange_code(exchange, trace_id="tr-resource-wrong-exchange")
                self.assertEqual(denied.exception.code, "OAUTH_INVALID_GRANT")
                with self.assertRaises(ReCTMError) as reused:
                    self.service.exchange_code(
                        self.exchange_params(params, code), trace_id="tr-resource-reused"
                    )
                self.assertEqual(reused.exception.code, "OAUTH_INVALID_GRANT")

    def test_dynamic_code_and_bearer_remain_origin_bound(self) -> None:
        self.service.server_url = ""
        first = "https://first.example"
        second = "https://second.example"
        params = self.authorization_params(first + "/mcp")
        for resource in (first + "/mcp", second + "/mcp"):
            with self.subTest(resource=resource):
                code = self.issue_code(params, base_url=first)
                exchange = {**self.exchange_params(params, code), "resource": resource}
                with self.assertRaises(ReCTMError) as denied:
                    self.service.exchange_code(exchange, trace_id="tr-origin-denied", base_url=second)
                self.assertEqual(denied.exception.code, "OAUTH_INVALID_GRANT")
        code = self.issue_code(params, base_url=first)
        token = self.service.exchange_code(
            self.exchange_params(params, code), trace_id="tr-origin-token", base_url=first
        )["access_token"]
        self.service.validate_authorization_header(
            f"Bearer {token}", trace_id="tr-origin-valid", base_url=first
        )
        with self.assertRaises(ReCTMError) as denied:
            self.service.validate_authorization_header(
                f"Bearer {token}", trace_id="tr-origin-invalid", base_url=second
            )
        self.assertEqual(denied.exception.code, "OAUTH_UNAUTHORIZED")

    def test_signed_wrong_audience_or_issuer_is_rejected(self) -> None:
        base = self.service.server_url
        params = self.authorization_params(base + "/mcp")
        code = self.issue_code(params)
        token = self.service.exchange_code(
            self.exchange_params(params, code), trace_id="tr-claims-token"
        )["access_token"]
        claims = _decode_signed_token(token, self.service.token_secret)
        for override in (
            {"aud": base + "/other"}, {"aud": base + "/mcp/"},
            {"aud": "https://elsewhere.example/mcp"}, {"aud": [base + "/mcp"]},
            {"iss": "https://elsewhere.example"}, {"iss": base + "/mcp"},
        ):
            with self.subTest(override=override):
                forged = _encode_signed_token({**claims, **override}, self.service.token_secret)
                with self.assertRaises(ReCTMError) as denied:
                    self.service.validate_authorization_header(f"Bearer {forged}", trace_id="tr-claims-deny")
                self.assertEqual(denied.exception.code, "OAUTH_UNAUTHORIZED")


if __name__ == "__main__":
    unittest.main()
