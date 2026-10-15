from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import secrets
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from re_ctm.app import build_application
from re_ctm.config import Settings
from re_ctm.enums import LatexPolicy
from re_ctm.server import ReCTMHTTPServer

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "smoke_oauth_mcp.py"
SPEC = importlib.util.spec_from_file_location("release_oauth_smoke", SCRIPT)
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class OAuthSmokeScriptTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        workspace = root / "workspace"
        workspace.mkdir()
        self.password = secrets.token_urlsafe(32)
        application = build_application(Settings(
            workspace=workspace, data_root=root / "state",
            private_root=root / "state" / "private", debug_root=root / "state" / "debug",
            native_exec_backend="disabled", latex_policy=LatexPolicy.STATIC_ONLY,
            oauth_password=self.password, token_secret=secrets.token_bytes(32),
            capability_secret=secrets.token_bytes(32),
        ))
        self.server = ReCTMHTTPServer(("127.0.0.1", 0), application, access_log_enabled=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.output = root / "evidence" / "smoke.json"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def run_smoke(self) -> tuple[int, dict]:
        with contextlib.redirect_stdout(io.StringIO()):
            code = smoke.main(["--base-url", self.base, "--output", str(self.output)],
                              password=self.password)
        text = self.output.read_text()
        self.assertNotIn(self.password, text)
        return code, json.loads(text)

    def test_real_loopback_oauth_and_current_contract(self) -> None:
        code, report = self.run_smoke()
        self.assertEqual(code, 0, report)
        checks = {item["name"]: item for item in report["checks"]}
        self.assertTrue(report["passed"])
        self.assertEqual(checks["fixed_tool_catalog"]["details"]["tool_names"],
                         list(smoke.EXPECTED_TOOL_NAMES))
        self.assertEqual(checks["retired_aliases_rejected"]["details"]["rejected"],
                         list(smoke.RETIRED_TOOL_NAMES))
        for name in ("authorization_code_replay_denied", "unauthorized_resource_challenge",
                     "unapproved_browser_origin_denied", "path_protected_resource_metadata",
                     "authorization_html_form", "modern_mcp_and_non_inheritance"):
            self.assertTrue(checks[name]["passed"], name)

    def test_callback_uses_live_token_without_persisting_it(self) -> None:
        observed = {}
        def exercise(base, token, client_id):
            observed.update(token=token, client_id=client_id)
            ping = smoke._mcp(base, token,
                              {"jsonrpc": "2.0", "id": 90, "method": "ping"}, timeout=5)
            return {"passed": ping.get("result") == {}, "transport": "authenticated_http_mcp"}
        with contextlib.redirect_stdout(io.StringIO()):
            code = smoke.main(["--base-url", self.base, "--output", str(self.output)],
                              password=self.password, exercise=exercise)
        text = self.output.read_text()
        self.assertEqual(code, 0)
        self.assertNotIn(observed["token"], text)
        self.assertNotIn(observed["client_id"], text)
        self.assertTrue(json.loads(text)["checks"][-1]["passed"])

    def test_smoke_rejects_previous_24_tool_catalog(self) -> None:
        original = smoke._mcp
        def missing_tool(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[2].get("method") == "tools/list":
                result["result"]["tools"] = result["result"]["tools"][:-1]
            return result
        with patch.object(smoke, "_mcp", side_effect=missing_tool):
            code, report = self.run_smoke()
        self.assertEqual(code, 1)
        failed = [item["name"] for item in report["checks"] if not item["passed"]]
        self.assertEqual(failed, ["fixed_tool_catalog"])

    def test_smoke_rejects_accepted_legacy_alias(self) -> None:
        original = smoke._mcp
        def accepted_alias(*args, **kwargs):
            if args[2].get("params", {}).get("name") == "rethlas_status":
                return {"result": {"structuredContent": {"error": {"code": "RUN_NOT_FOUND"}}}}
            return original(*args, **kwargs)
        with patch.object(smoke, "_mcp", side_effect=accepted_alias):
            code, report = self.run_smoke()
        self.assertEqual(code, 1)
        self.assertFalse(next(item for item in report["checks"]
                              if item["name"] == "retired_aliases_rejected")["passed"])

    def test_failure_report_omits_secret_bearing_exception(self) -> None:
        with patch.object(smoke, "_json_request",
                          side_effect=ValueError("token=" + self.password)):
            code, report = self.run_smoke()
        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertEqual(report["checks"][-1]["details"]["exception_type"], "ValueError")

    def test_base_url_rejects_embedded_credentials_and_paths(self) -> None:
        for base in ("http://user:password@127.0.0.1", "http://127.0.0.1/mcp",
                     "http://127.0.0.1?secret=value", "http://127.0.0.1#fragment"):
            with self.subTest(base=base), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    smoke.main(["--base-url", base, "--output", str(self.output)],
                               password=self.password)


if __name__ == "__main__":
    unittest.main()
