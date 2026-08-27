from __future__ import annotations

import hashlib
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from re_ctm.debug import DebugEventBus
from re_ctm.errors import ReCTMError
from re_ctm.oauth import OAuthService, OAuthStore


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


if __name__ == "__main__":
    unittest.main()
