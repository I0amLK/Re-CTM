from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_ctm.debug import DebugEventBus


class DebugEventBusTestCase(unittest.TestCase):
    def test_secrets_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "events.jsonl"
            bus = DebugEventBus(path, root / "private", enabled=True, trace_payloads=True)
            bus.emit(
                "test",
                "unit",
                details={
                    "access_token": "very-secret-token",
                    "authorization": "Bearer abcdefghijklmnopqrstuvwxyz",
                    "safe": "visible",
                },
            )
            event = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(event["details"]["access_token"], "<redacted>")
        self.assertEqual(event["details"]["authorization"], "<redacted>")
        self.assertEqual(event["details"]["safe"], "visible")


if __name__ == "__main__":
    unittest.main()
