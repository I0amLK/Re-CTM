from __future__ import annotations

import base64
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
        self.workspace = workspace
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
        self.assertIn("every concrete mathematical", initialized["result"]["instructions"])
        self.assertIn("workspace_export_path", initialized["result"]["instructions"])
        listed = self.dispatcher.dispatch(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            self.principal,
        )
        names = [item["name"] for item in listed["result"]["tools"]]
        self.assertEqual(names, list(TOOL_SPECS))
        self.assertEqual(len(names), 31)
        self.assertEqual(listed["result"]["tools"][0]["outputSchema"]["required"], ["ok"])
        rethlas_start = next(
            item for item in listed["result"]["tools"] if item["name"] == "rethlas_start"
        )
        self.assertIn("every concrete mathematical", rethlas_start["description"])
        self.assertIn("export_path", rethlas_start["inputSchema"]["properties"])
        self.assertFalse(rethlas_start["annotations"]["destructiveHint"])
        self.assertFalse(rethlas_start["annotations"]["readOnlyHint"])

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

    def test_ctm_tool_arguments_are_validated_before_dispatch(self) -> None:
        missing = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "exec_command", "arguments": {}},
            },
            self.principal,
        )
        self.assertEqual(missing["error"]["code"], -32602)
        self.assertEqual(missing["error"]["data"]["reason"], "invalid_arguments")

        unknown_argument = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "x", "bogus": True}},
            },
            self.principal,
        )
        self.assertEqual(unknown_argument["error"]["code"], -32602)

        unknown_tool = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "not_a_tool", "arguments": {}},
            },
            self.principal,
        )
        self.assertEqual(unknown_tool["error"]["code"], -32602)
        self.assertEqual(unknown_tool["error"]["data"]["reason"], "unknown_tool")

    def test_rethlas_start_records_workspace_export_path(self) -> None:
        started = self.tools.call(
            "rethlas_start",
            {
                "problem_tex": r"\textbf{Problem.} Prove $1=1$.",
                "problem_id": "one-equals-one",
                "export_path": "results/one-equals-one.tex",
            },
            self.principal,
        )
        self.assertFalse(started["isError"])
        self.assertEqual(
            started["structuredContent"]["workspace_export_path"],
            "results/one-equals-one.tex",
        )

        denied = self.tools.call(
            "rethlas_start",
            {
                "problem_tex": r"\textbf{Problem.} Prove $2=2$.",
                "export_path": "/tmp/proof.tex",
            },
            self.principal,
        )
        self.assertTrue(denied["isError"])
        self.assertEqual(denied["structuredContent"]["error"]["code"], "ABSOLUTE_PATH_DENIED")

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
        self.assertEqual(structured["permission_mode"], "dangerous")
        self.assertTrue(structured["dangerously_skip_all_permissions"])
        self.assertEqual(structured["endpoint_path"], "/mcp")
        self.assertEqual(structured["output_retention"]["buffer_bytes_per_stream"], 524288)
        self.assertEqual(structured["tools"][:18], list(TOOL_SPECS)[:18])

    def test_view_image_returns_image_content_block(self) -> None:
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZlS8AAAAASUVORK5CYII="
        )
        (self.workspace / "pixel.png").write_bytes(png)
        result = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "view_image", "arguments": {"path": "pixel.png"}},
            },
            self.principal,
        )["result"]
        self.assertEqual(result["content"][1]["type"], "image")
        self.assertEqual(result["content"][1]["mimeType"], "image/png")
        self.assertNotIn("_mcp_image_data", result["structuredContent"])


if __name__ == "__main__":
    unittest.main()
