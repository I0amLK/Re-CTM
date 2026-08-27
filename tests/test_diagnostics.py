from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_ctm.capabilities import CapabilityAuthority
from re_ctm.debug import DebugEventBus
from re_ctm.diagnostics import build_debug_bundle
from re_ctm.enums import LatexPolicy
from re_ctm.latex import LatexGate
from re_ctm.storage import StateStore
from re_ctm.vault import PrivateVault
from re_ctm.workflow import WorkflowEngine


class DiagnosticsTestCase(unittest.TestCase):
    def test_bundle_contains_hashes_not_private_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            data_root = Path(temp) / "data"
            private = data_root / "private"
            debug = DebugEventBus(data_root / "debug" / "events.jsonl", private, enabled=True)
            store = StateStore(private / "state.sqlite3")
            try:
                vault = PrivateVault(private)
                engine = WorkflowEngine(
                    store,
                    vault,
                    CapabilityAuthority(b"c" * 32, store, debug),
                    debug,
                    LatexGate(LatexPolicy.STATIC_ONLY),
                )
                result = engine.start(
                    owner_id="client-1",
                    problem_id="diagnostics",
                    problem_tex="PRIVATE-PROBLEM-CONTENT",
                    references=[],
                )
                bundle = build_debug_bundle(data_root, result["run_id"])
            finally:
                store.close()
        serialized = json.dumps(bundle)
        self.assertNotIn("PRIVATE-PROBLEM-CONTENT", serialized)
        self.assertFalse(bundle["redaction"]["problem_or_proof_contents_included"])
        self.assertTrue(
            any(item["path"] == "input/problem.tex" for item in bundle["file_manifest"])
        )


if __name__ == "__main__":
    unittest.main()
