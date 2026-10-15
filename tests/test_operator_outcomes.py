from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_ctm.app import build_application
from re_ctm.config import Settings
from re_ctm.debug import DebugEvent
from re_ctm.enums import LatexPolicy
from re_ctm.oauth import OAuthPrincipal


class OperatorOutcomeTestCase(unittest.TestCase):
    def test_returned_denials_and_submission_corrections_are_not_success_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            events: list[DebugEvent] = []
            app = build_application(Settings(
                workspace=workspace, data_root=root / "data",
                private_root=root / "data" / "private", debug_root=root / "data" / "debug",
                native_exec_backend="disabled", latex_policy=LatexPolicy.STATIC_ONLY,
                token_secret=b"t" * 32, capability_secret=b"c" * 32,
                oauth_password="test-password",
            ), debug_observer=events.append)
            principal = OAuthPrincipal(client_id="test-client", subject="test-client", scope="mcp")
            cases = [
                ({"ok": True}, "tool.call_finished"),
                ({"ok": False, "error": {"code": "DENIED", "message": "private message"}},
                 "tool.call_failed"),
                ({"ok": True, "capability": "raw-capability-not-for-logs", "writes_applied": 1,
                  "submission": {"ok": False, "writes_retained": True,
                                 "error": {"code": "INVALID_ARGUMENT", "message": "private message"}}},
                 "tool.call_submission_rejected"),
            ]
            try:
                for payload, expected in cases:
                    app.tools._handlers["server_info"] = lambda *_args, value=payload: dict(value)
                    app.tools.call("server_info", {}, principal)
                    self.assertEqual(events[-1].event_type, expected)
                    rendered = json.dumps(events[-1].details)
                    self.assertNotIn("raw-capability-not-for-logs", rendered)
                    self.assertNotIn("private message", rendered)
            finally:
                app.close()


if __name__ == "__main__":
    unittest.main()
