from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from re_ctm.capabilities import CapabilityAuthority
from re_ctm.debug import DebugEventBus
from re_ctm.enums import LatexPolicy, NativeMode
from re_ctm.latex import LatexGate
from re_ctm.mcp import (
    META_CLIENT_CAPABILITIES,
    META_PROTOCOL_VERSION,
    META_SERVER_INFO,
    MCPDispatcher,
)
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.oauth import OAuthPrincipal
from re_ctm.storage import StateStore
from re_ctm.tools import TOOL_SPECS, ToolRuntime
from re_ctm.vault import PrivateVault
from re_ctm.workflow import WorkflowEngine


class MCPDispatcherTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        workspace = root / "workspace"
        private = root / "private"
        workspace.mkdir()
        private.mkdir()
        debug = DebugEventBus(root / "events.jsonl", private, enabled=True)
        self.store = StateStore(private / "state.sqlite3")
        vault = PrivateVault(private)
        capabilities = CapabilityAuthority(b"c" * 32, self.store, debug)
        workflow = WorkflowEngine(
            self.store,
            vault,
            capabilities,
            debug,
            LatexGate(LatexPolicy.STATIC_ONLY),
        )
        native = NativeRuntime(
            NativeWorkspace(workspace, private_root=private),
            NativeMode.DANGEROUS,
            debug,
        )
        self.tools = ToolRuntime(native, workflow, debug)
        self.dispatcher = MCPDispatcher(self.tools)
        self.principal = OAuthPrincipal("client-1", "client-1", "mcp")

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_fixed_catalog_and_initialize(self) -> None:
        initialized = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25"},
            },
            self.principal,
        )
        self.assertEqual(initialized["result"]["serverInfo"]["name"], "re-ctm")
        listed = self.dispatcher.dispatch(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            self.principal,
        )
        names = [item["name"] for item in listed["result"]["tools"]]
        self.assertEqual(names, list(TOOL_SPECS))
        self.assertEqual(len(names), 19)

        modern_requested_in_handshake = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "initialize",
                "params": {"protocolVersion": "2026-07-28"},
            },
            self.principal,
        )
        self.assertEqual(
            modern_requested_in_handshake["result"]["protocolVersion"],
            "2025-11-25",
        )

    def test_modern_request_is_shaped_per_request(self) -> None:
        modern_meta = {
            META_PROTOCOL_VERSION: "2026-07-28",
            META_CLIENT_CAPABILITIES: {},
        }
        listed = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": "modern-1",
                "method": "tools/list",
                "params": {"_meta": modern_meta},
            },
            self.principal,
        )
        result = listed["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["cacheScope"], "private")
        self.assertEqual(result["ttlMs"], 0)
        self.assertEqual(result["_meta"][META_SERVER_INFO]["name"], "re-ctm")

    def test_server_info_reports_non_inheritance(self) -> None:
        result = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "server_info", "arguments": {}},
            },
            self.principal,
        )["result"]
        structured = result["structuredContent"]
        self.assertEqual(structured["native"]["native_mode"], "dangerous")
        self.assertFalse(structured["native"]["workflow_authority_inherited"])
        self.assertIn("never implies", structured["authorization_axioms"]["non_inheritance"])


if __name__ == "__main__":
    unittest.main()
