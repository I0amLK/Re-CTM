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
from re_ctm.tools import PUBLIC_TOOL_NAMES, ToolRuntime
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
        self.assertIn("rethlas_step", initialized["result"]["instructions"])
        self.assertIn("workspace_export_path", initialized["result"]["instructions"])
        listed = self.dispatcher.dispatch(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            self.principal,
        )
        names = [item["name"] for item in listed["result"]["tools"]]
        self.assertEqual(names, list(PUBLIC_TOOL_NAMES))
        self.assertEqual(len(names), 24)
        self.assertNotIn("rethlas_next", names)
        self.assertIn("rethlas_step", names)
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

    def test_rethlas_step_facade_and_hidden_legacy_alias(self) -> None:
        started = self.tools.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove $1=1$.", "problem_id": "facade"},
            self.principal,
        )["structuredContent"]
        run_id = started["run_id"]
        task = self.tools.call(
            "rethlas_step",
            {"run_id": run_id},
            self.principal,
        )["structuredContent"]
        self.assertEqual(task["state"], "assess")
        advanced = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": task["capability"],
                "writes": [
                    {
                        "resource": "memory:generation:immediate_conclusions",
                        "content": {"conclusion": "Reflexivity."},
                    },
                    {
                        "resource": "memory:generation:events",
                        "content": {"event_type": "assessment"},
                    },
                ],
                "action": "assessment_complete",
            },
            self.principal,
        )["structuredContent"]
        self.assertEqual(advanced["state"], "explore")
        self.assertEqual(advanced["writes_applied"], 2)

        recoverable = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": advanced["capability"],
                "writes": [
                    {"resource": "memory:generation:events", "content": {"event_type": "explore"}}
                ],
                "action": "wrong_action",
            },
            self.principal,
        )
        self.assertFalse(recoverable["isError"])
        recoverable_payload = recoverable["structuredContent"]
        self.assertEqual(recoverable_payload["state"], "explore")
        self.assertEqual(
            recoverable_payload["submission"]["error"]["code"],
            "INVALID_COMMIT_ACTION",
        )
        self.assertTrue(recoverable_payload["submission"]["writes_retained"])
        stale = self.tools.call(
            "rethlas_read",
            {"capability": advanced["capability"], "resource": "problem"},
            self.principal,
        )
        self.assertTrue(stale["isError"])
        self.assertEqual(stale["structuredContent"]["error"]["code"], "CAPABILITY_REVOKED")
        stale_step = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": advanced["capability"],
                "action": "exploration_complete",
                "payload": {},
            },
            self.principal,
        )
        self.assertTrue(stale_step["isError"])
        self.assertEqual(
            stale_step["structuredContent"]["error"]["code"],
            "CAPABILITY_REVOKED",
        )
        recovered = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": recoverable_payload["capability"],
                "action": "exploration_complete",
            },
            self.principal,
        )["structuredContent"]
        self.assertEqual(recovered["state"], "propose_plans")

        listed_names = [item["name"] for item in self.tools.list_tools()]
        self.assertNotIn("rethlas_status", listed_names)
        legacy = self.tools.call(
            "rethlas_status",
            {"run_id": run_id},
            self.principal,
        )["structuredContent"]
        self.assertTrue(legacy["ok"])
        self.assertEqual(legacy["state"], "propose_plans")

        legacy_over_mcp = self.dispatcher.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "rethlas_status", "arguments": {"run_id": run_id}},
            },
            self.principal,
        )
        self.assertTrue(legacy_over_mcp["result"]["structuredContent"]["ok"])
        self.assertEqual(
            legacy_over_mcp["result"]["structuredContent"]["state"],
            "propose_plans",
        )

    def test_rethlas_step_rejects_cross_run_envelope_pair_before_writes(self) -> None:
        first = self.tools.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove $1=1$.", "problem_id": "run-a"},
            self.principal,
        )["structuredContent"]
        second = self.tools.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove $2=2$.", "problem_id": "run-b"},
            self.principal,
        )["structuredContent"]
        first_task = self.tools.call(
            "rethlas_step", {"run_id": first["run_id"]}, self.principal
        )["structuredContent"]
        second_task = self.tools.call(
            "rethlas_step", {"run_id": second["run_id"]}, self.principal
        )["structuredContent"]

        mixed = self.tools.call(
            "rethlas_step",
            {
                "run_id": second["run_id"],
                "capability": first_task["capability"],
                "writes": [
                    {
                        "resource": "memory:generation:immediate_conclusions",
                        "content": {"conclusion": "Must not land in either run."},
                    }
                ],
                "action": "assessment_complete",
            },
            self.principal,
        )
        self.assertTrue(mixed["isError"])
        self.assertEqual(
            mixed["structuredContent"]["error"]["code"],
            "CAPABILITY_RUN_MISMATCH",
        )
        self.assertEqual(self.store.get_run(first["run_id"])["state"], "assess")
        self.assertEqual(self.store.get_run(second["run_id"])["state"], "assess")

        still_valid = self.tools.call(
            "rethlas_read",
            {"capability": first_task["capability"], "resource": "problem"},
            self.principal,
        )
        self.assertFalse(still_valid["isError"])
        self.assertNotEqual(first_task["capability"], second_task["capability"])

    def test_rethlas_step_write_validation_is_recoverable_and_retains_prior_writes(self) -> None:
        started = self.tools.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove $1=1$.", "problem_id": "write-recovery"},
            self.principal,
        )["structuredContent"]
        run_id = started["run_id"]
        task = self.tools.call(
            "rethlas_step",
            {"run_id": run_id},
            self.principal,
        )["structuredContent"]

        recoverable = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": task["capability"],
                "writes": [
                    {
                        "resource": "memory:generation:immediate_conclusions",
                        "content": {"conclusion": "Reflexivity."},
                    },
                    {
                        "resource": "memory:generation:events",
                        "content": ["this batch shape is intentionally invalid"],
                    },
                ],
                "action": "assessment_complete",
            },
            self.principal,
        )
        self.assertFalse(recoverable["isError"])
        payload = recoverable["structuredContent"]
        self.assertEqual(payload["state"], "assess")
        self.assertEqual(payload["writes_applied"], 1)
        self.assertTrue(payload["submission"]["recoverable"])
        self.assertTrue(payload["submission"]["retryable"])
        self.assertTrue(payload["submission"]["error"]["retryable"])
        self.assertTrue(payload["submission"]["writes_retained"])
        self.assertEqual(
            payload["submission"]["failed_write"],
            {"index": 1, "resource": "memory:generation:events"},
        )
        self.assertIn("write_contract", payload["task"])

        corrected = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": payload["capability"],
                "writes": [
                    {
                        "resource": "memory:generation:events",
                        "content": {"event_type": "assessment", "summary": "Corrected second record only."},
                    }
                ],
                "action": "assessment_complete",
                "payload": {},
            },
            self.principal,
        )["structuredContent"]
        self.assertEqual(corrected["state"], "explore")

    def test_planning_contract_rejects_string_lists_and_preserves_dependencies(self) -> None:
        started = self.tools.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove a planning test statement.", "problem_id": "plan-contract"},
            self.principal,
        )["structuredContent"]
        run_id = started["run_id"]
        assess = self.tools.call("rethlas_step", {"run_id": run_id}, self.principal)["structuredContent"]
        explore = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assess["capability"],
                "writes": [
                    {"resource": "memory:generation:immediate_conclusions", "content": {"summary": "Initial deduction."}},
                    {"resource": "memory:generation:events", "content": {"event_type": "assessment"}},
                ],
                "action": "assessment_complete",
                "payload": {},
            },
            self.principal,
        )["structuredContent"]
        planning = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": explore["capability"],
                "writes": [
                    {"resource": "memory:generation:events", "content": {"event_type": "exploration"}}
                ],
                "action": "exploration_complete",
                "payload": {},
            },
            self.principal,
        )["structuredContent"]
        self.assertEqual(planning["state"], "propose_plans")
        self.assertEqual(planning["task"]["write_contract"], [])
        self.assertEqual(planning["task"]["commit_payload_schema"]["required"], ["plans"])

        invalid = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": planning["capability"],
                "action": "plans_proposed",
                "payload": {
                    "plans": [
                        {"summary": "Route one", "subgoals": ["A"], "motivation": "not-an-array"},
                        {"summary": "Route two", "subgoals": ["B"]},
                    ]
                },
            },
            self.principal,
        )
        self.assertFalse(invalid["isError"])
        invalid_payload = invalid["structuredContent"]
        self.assertEqual(invalid_payload["state"], "propose_plans")
        self.assertTrue(invalid_payload["submission"]["recoverable"])
        self.assertTrue(invalid_payload["submission"]["error"]["retryable"])
        self.assertIn("motivation", invalid_payload["submission"]["error"]["message"])

        direct = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": invalid_payload["capability"],
                "action": "plans_proposed",
                "payload": {
                    "plans": [
                        {
                            "plan_id": "route-a",
                            "summary": "Route one",
                            "subgoals": ["A"],
                            "motivation": ["First approach"],
                            "dependencies": ["Lemma A"],
                            "risks": ["Risk A"],
                        },
                        {
                            "plan_id": "route-b",
                            "summary": "Route two",
                            "subgoals": ["B"],
                            "motivation": ["Second approach"],
                            "dependencies": [],
                            "risks": ["Risk B"],
                        },
                    ]
                },
            },
            self.principal,
        )["structuredContent"]
        self.assertEqual(direct["state"], "direct_proving")
        self.assertEqual(direct["context"]["active_plans"][0]["dependencies"], ["Lemma A"])

    def test_zero_guess_easy_flow_reaches_done_without_schema_corrections(self) -> None:
        started = self.tools.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove $1=1$.", "problem_id": "zero-guess-e2e"},
            self.principal,
        )["structuredContent"]
        run_id = started["run_id"]

        assess = self.tools.call("rethlas_step", {"run_id": run_id}, self.principal)["structuredContent"]
        self.assertEqual(assess["state"], "assess")
        self.assertEqual(assess["task"]["minimal_submission"]["action"], "assessment_complete")
        assembled = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assess["capability"],
                **assess["task"]["minimal_submission"],
            },
            self.principal,
        )["structuredContent"]
        self.assertNotIn("error", assembled.get("submission", {}))
        self.assertEqual(assembled["state"], "assemble")
        self.assertEqual(assembled["context"].get("project_context"), None)
        self.assertIn(
            "proof_manifest",
            assembled["task"]["required_records_for_outcome"]["proof"],
        )

        proof = (
            "\\documentclass{article}\n"
            "\\usepackage{amsmath,amsthm}\n"
            "\\newtheorem{theorem}{Theorem}\n"
            "\\begin{document}\n"
            "\\begin{theorem} $1=1$. \\end{theorem}\n"
            "\\begin{proof} This follows from reflexivity of equality. \\end{proof}\n"
            "\\end{document}\n"
        )
        verify = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assembled["capability"],
                "writes": [
                    {"resource": "proof", "content": proof},
                    {
                        "resource": "proof_manifest",
                        "content": {
                            "target_statement_tex": r"$1=1$.",
                            "dependency_revision_ids": [],
                            "reference_ids": [],
                            "conditional_hypotheses": [],
                            "computational_evidence": [],
                        },
                    },
                ],
                "action": assembled["task"]["commit_action"],
                "payload": {"outcome": "proof"},
            },
            self.principal,
        )["structuredContent"]
        self.assertNotIn("error", verify.get("submission", {}))
        self.assertEqual(verify["state"], "verify")

        verification_submission = verify["task"]["minimal_submission"]
        done = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": verify["capability"],
                **verification_submission,
            },
            self.principal,
        )["structuredContent"]
        self.assertNotIn("error", done.get("submission", {}))
        self.assertEqual(done["state"], "done")
        self.assertEqual(done["verdict"], "correct")
        self.assertTrue(done["final_artifact_available"])
        exported = self.workspace / done["workspace_export_path"]
        self.assertTrue(exported.is_file())
        self.assertEqual(exported.read_text(encoding="utf-8"), proof)

    def test_rethlas_step_exposes_stable_screening_ids_and_accepts_partial_progress(self) -> None:
        started = self.tools.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove a test statement.", "problem_id": "screening"},
            self.principal,
        )["structuredContent"]
        run_id = started["run_id"]
        assess = self.tools.call("rethlas_step", {"run_id": run_id}, self.principal)["structuredContent"]
        explore = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assess["capability"],
                "writes": [
                    {"resource": "memory:generation:immediate_conclusions", "content": {"x": 1}},
                    {"resource": "memory:generation:events", "content": {"event_type": "assessment"}},
                ],
                "action": "assessment_complete",
            },
            self.principal,
        )["structuredContent"]
        planning = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": explore["capability"],
                "writes": [
                    {"resource": "memory:generation:events", "content": {"event_type": "explore"}}
                ],
                "action": "exploration_complete",
            },
            self.principal,
        )["structuredContent"]
        direct = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": planning["capability"],
                "action": "plans_proposed",
                "payload": {
                    "plans": [
                        {"plan_id": "free text A", "summary": "First route", "subgoals": ["A1"]},
                        {"plan_id": "free text B", "summary": "Second route", "subgoals": ["B1"]},
                    ]
                },
            },
            self.principal,
        )["structuredContent"]
        active = direct["context"]["active_plans"]
        self.assertEqual([plan["plan_id"] for plan in active], ["plan-r1-1", "plan-r1-2"])
        self.assertEqual(active[0]["subgoals"][0]["subgoal_id"], "sg-1")

        partial_result = self.tools.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": direct["capability"],
                "writes": [
                    {"resource": "memory:generation:proof_steps", "content": {"attempt": "plan-r1-1"}}
                ],
                "action": "direct_proving_complete",
                "payload": {
                    "screening": {
                        "plan-r1-1": {
                            "sg-1": {"status": "stuck", "summary": "Need one more lemma."}
                        }
                    }
                },
            },
            self.principal,
        )
        self.assertFalse(partial_result["isError"])
        partial = partial_result["structuredContent"]
        self.assertEqual(partial["state"], "direct_proving")
        self.assertFalse(partial["submission"]["complete"])
        self.assertEqual(
            partial["submission"]["missing_screening"],
            [{"plan_id": "plan-r1-2", "subgoal_id": "sg-1", "text": "B1"}],
        )
        self.assertIn("plan-r1-2.sg-1", partial_result["content"][0]["text"])

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
        self.assertEqual(structured["tool_count"], 24)
        self.assertEqual(structured["tools"], list(PUBLIC_TOOL_NAMES))
        self.assertEqual(len(structured["hidden_legacy_rethlas_aliases"]), 11)

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
