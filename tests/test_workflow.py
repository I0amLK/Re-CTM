from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from re_ctm.capabilities import CapabilityAuthority, CapabilityClaims
from re_ctm.debug import DebugEventBus
from re_ctm.enums import LatexPolicy, NativeMode, WorkflowState
from re_ctm.errors import ReCTMError
from re_ctm.latex import LatexGate
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.oauth import OAuthPrincipal
from re_ctm.storage import StateStore
from re_ctm.tools import ToolRuntime
from re_ctm.vault import PrivateVault
from re_ctm.workflow import WorkflowEngine


VALID_PROOF = r"""\documentclass{article}
\usepackage{amsmath,amsthm}
\newtheorem{theorem}{Theorem}
\begin{document}
\begin{theorem}
For every real number $x$, one has $x^2\geq 0$.
\end{theorem}
\begin{proof}
If $x\geq0$, then $x^2\geq0$. If $x<0$, then $-x>0$ and
$x^2=(-x)^2\geq0$.
\end{proof}
\end{document}
"""


class FakeResearchProvider:
    def search_theorems(self, *, query: str, num_results: int, search_intent: str) -> dict:
        return {
            "query": query,
            "search_intent": search_intent,
            "count": 1,
            "results": [
                {
                    "title": "Test theorem",
                    "theorem": "A complete test statement.",
                    "arxiv_id": "0000.00000",
                    "theorem_id": "T1",
                    "paper_id": "P1",
                }
            ][:num_results],
            "endpoint": "https://example.invalid/theorem-search",
            "source_trust": "external_unverified",
            "usage_rule": "Read context and verify applicability before use.",
        }


class WorkflowTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.root = root
        private = root / "private"
        debug = DebugEventBus(
            root / "debug" / "events.jsonl",
            private,
            enabled=True,
        )
        store = StateStore(private / "state.sqlite3")
        vault = PrivateVault(private)
        capabilities = CapabilityAuthority(b"c" * 32, store, debug, default_ttl_seconds=600)
        self.store = store
        self.vault = vault
        self.debug = debug
        self.capabilities = capabilities
        self.engine = WorkflowEngine(
            store,
            vault,
            capabilities,
            debug,
            LatexGate(LatexPolicy.STATIC_ONLY),
        )
        self.owner = "oauth-client-1"

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _start(self) -> str:
        result = self.engine.start(
            owner_id=self.owner,
            problem_id="square-nonnegative",
            problem_tex=r"\textbf{Problem.} Prove that $x^2\geq0$ for every real $x$.",
            references=[{"name": "notes.txt", "content": "Ordered field axioms."}],
            native_mode=NativeMode.DANGEROUS.value,
        )
        return result["run_id"]

    def _next(self, run_id: str) -> dict:
        return self.engine.next_task(owner_id=self.owner, run_id=run_id)

    def _write(self, task: dict, resource: str, content: object) -> None:
        self.engine.write(
            owner_id=self.owner,
            capability=task["capability"],
            resource=resource,
            content=content,
        )

    def _commit(self, task: dict, action: str, payload: dict | None = None) -> dict:
        return self.engine.commit(
            owner_id=self.owner,
            capability=task["capability"],
            action=action,
            payload=payload or {},
        )

    def test_full_branch_verify_finalize_flow(self) -> None:
        run_id = self._start()

        assess = self._next(run_id)
        self.assertEqual(assess["state"], WorkflowState.ASSESS.value)
        self._write(
            assess,
            "memory:generation:immediate_conclusions",
            {"conclusion": "The order axioms split the proof into x>=0 and x<0."},
        )
        self._write(
            assess,
            "memory:generation:events",
            {"event_type": "assessment", "status": "complete"},
        )
        self._commit(assess, "assessment_complete")

        explore = self._next(run_id)
        self._write(
            explore,
            "memory:generation:events",
            {"event_type": "explore", "result": "two elementary routes"},
        )
        self._commit(explore, "exploration_complete")

        planning = self._next(run_id)
        plans = [
            {
                "plan_id": "order-split",
                "summary": "Split on the sign of x and use closure of nonnegative products.",
                "subgoals": ["x>=0 case", "x<0 case"],
            },
            {
                "plan_id": "absolute-value",
                "summary": "Rewrite x^2 as |x|^2 and use nonnegativity of absolute value.",
                "subgoals": ["absolute value is nonnegative", "square preserves nonnegativity"],
            },
        ]
        self._commit(planning, "plans_proposed", {"plans": plans})

        direct = self._next(run_id)
        self._write(
            direct,
            "memory:generation:proof_steps",
            {"plan_id": "order-split", "status": "partial"},
        )
        self._commit(
            direct,
            "direct_proving_complete",
            {
                "outcome": "needs_branches",
                "screening": [
                    {
                        "plan_id": "order-split",
                        "status": "partial",
                        "subgoal_results": [
                            {
                                "subgoal": "x>=0 case",
                                "status": "solved",
                                "summary": "Closure of nonnegative multiplication proves this case.",
                            },
                            {
                                "subgoal": "x<0 case",
                                "status": "partial",
                                "summary": "The sign conversion is clear but the complete route is delegated.",
                            },
                        ],
                        "key_stuck_points": ["Complete the negative case without skipping the order lemma."],
                    },
                    {
                        "plan_id": "absolute-value",
                        "status": "stuck",
                        "subgoal_results": [
                            {
                                "subgoal": "absolute value is nonnegative",
                                "status": "solved",
                                "summary": "This follows from the definition of absolute value.",
                            },
                            {
                                "subgoal": "square preserves nonnegativity",
                                "status": "stuck",
                                "summary": "The direct attempt risks circularly using the target claim.",
                            },
                        ],
                        "key_stuck_points": ["Avoid circular use of square nonnegativity."],
                    },
                ],
                "branch_plans": [{"plan_id": "order-split"}, {"plan_id": "absolute-value"}],
            },
        )

        branch_a = self._next(run_id)
        self.assertEqual(branch_a["role"], "branch")
        snapshot = self.engine.read(
            owner_id=self.owner,
            capability=branch_a["capability"],
            resource="snapshot",
        )
        self.assertEqual(len(snapshot["content"]["branch_requests"]), 2)
        branch_status = self.engine.status(owner_id=self.owner, run_id=run_id)["branches"]
        other_branch = next(item["branch_id"] for item in branch_status if item["branch_id"] != branch_a["context"]["branch_id"])
        with self.assertRaises(ReCTMError) as denied:
            self.engine.read(
                owner_id=self.owner,
                capability=branch_a["capability"],
                resource=f"branch:{other_branch}",
            )
        self.assertIn(denied.exception.code, {"ROLE_ACCESS_DENIED", "CROSS_BRANCH_ACCESS_DENIED"})
        self._write(
            branch_a,
            "memory:branch:proof_steps",
            {"step": "sign split", "status": "solved"},
        )
        committed_a = self._commit(
            branch_a,
            "branch_complete",
            {"status": "solved", "summary": "Elementary sign split works.", "proof_route": "split on sign"},
        )
        self.assertFalse(committed_a["barrier_complete"])
        with self.assertRaises(ReCTMError) as revoked:
            self.engine.read(
                owner_id=self.owner,
                capability=branch_a["capability"],
                resource="snapshot",
            )
        self.assertIn(revoked.exception.code, {"CAPABILITY_REVOKED", "CAPABILITY_STALE"})

        branch_b = self._next(run_id)
        self.assertNotEqual(branch_b["context"]["branch_id"], branch_a["context"]["branch_id"])
        with self.assertRaises(ReCTMError):
            self.engine.read(
                owner_id=self.owner,
                capability=branch_b["capability"],
                resource=f"branch:{branch_a['context']['branch_id']}",
            )
        self._write(
            branch_b,
            "memory:branch:proof_steps",
            {"step": "absolute value route", "status": "solved"},
        )
        committed_b = self._commit(
            branch_b,
            "branch_complete",
            {"status": "solved", "summary": "Absolute value route works.", "proof_route": "use |x|"},
        )
        self.assertTrue(committed_b["barrier_complete"])

        join = self._next(run_id)
        sealed = self.engine.read(
            owner_id=self.owner,
            capability=join["capability"],
            resource="branch:sealed:all",
        )["content"]
        self.assertEqual(len(sealed), 2)
        self._commit(
            join,
            "join_complete",
            {
                "outcome": "solved",
                "considered_branch_ids": [
                    branch_a["context"]["branch_id"],
                    branch_b["context"]["branch_id"],
                ],
                "selected_branch_id": branch_a["context"]["branch_id"],
                "selected_plan": "order-split",
                "summary": "Use the shorter route.",
            },
        )

        assembler = self._next(run_id)
        self._write(assembler, "proof", VALID_PROOF)
        self._commit(assembler, "proof_submitted")

        verifier = self._next(run_id)
        self.assertEqual(verifier["state"], WorkflowState.VERIFY.value)
        with self.assertRaises(ReCTMError) as firewall:
            self.engine.read(
                owner_id=self.owner,
                capability=verifier["capability"],
                resource="memory:generation:proof_steps",
            )
        self.assertIn(
            firewall.exception.code,
            {"ROLE_ACCESS_DENIED", "VERIFIER_DATA_FIREWALL"},
        )
        self._write(
            verifier,
            "memory:verifier:statement_checks",
            {
                "location": "Main theorem",
                "status": "checked",
                "critical_errors": [],
                "gaps": [],
            },
        )
        self._write(
            verifier,
            "memory:verifier:events",
            {
                "event_type": "verification_audit_complete",
                "assumption_audit": "complete",
                "sequential_audit": "complete",
            },
        )
        report = {
            "verification_report": {
                "summary": "Every step follows from elementary ordered-field facts.",
                "critical_errors": [],
                "gaps": [],
            },
            "verdict": "wrong",
            "repair_hints": "This model-supplied verdict must be ignored by the server.",
        }
        self._write(verifier, "verification_report", report)
        verified = self._commit(verifier, "verification_submitted")
        self.assertEqual(verified["verdict"], "correct")

        native_workspace = self.root / "native-workspace"
        native_workspace.mkdir()
        native = NativeRuntime(
            NativeWorkspace(native_workspace, private_root=self.root / "private"),
            NativeMode.DANGEROUS,
            self.debug,
        )
        tools = ToolRuntime(native, self.engine, self.debug)
        principal = OAuthPrincipal(client_id=self.owner, subject=self.owner, scope="mcp")
        terminal_result = tools.call(
            "rethlas_next",
            {"run_id": run_id},
            principal,
        )
        terminal = terminal_result["structuredContent"]
        self.assertEqual(terminal["state"], WorkflowState.DONE.value)
        self.assertTrue(terminal["workspace_export"]["ok"])
        automatic_path = native_workspace / terminal["workspace_export_path"]
        self.assertEqual(automatic_path.read_text(encoding="utf-8"), VALID_PROOF)
        repeated = tools.call("rethlas_next", {"run_id": run_id}, principal)
        self.assertEqual(
            repeated["structuredContent"]["workspace_export"]["status"],
            "unchanged",
        )

        final = self.engine.get_artifact(owner_id=self.owner, run_id=run_id, artifact="final_tex")
        self.assertEqual(final["content"], VALID_PROOF)
        self.assertEqual(final["workspace_export_path"], terminal["workspace_export_path"])

        default_export = tools.call(
            "rethlas_export_final",
            {"run_id": run_id},
            principal,
        )
        self.assertFalse(default_export["isError"])
        self.assertEqual(default_export["structuredContent"]["export"]["status"], "unchanged")

        exported = tools.call(
            "rethlas_export_final",
            {"run_id": run_id, "path": "exports/proof_verified.tex"},
            principal,
        )
        export_path = native_workspace / "exports" / "proof_verified.tex"
        self.assertEqual(export_path.read_text(encoding="utf-8"), VALID_PROOF)
        self.assertFalse(exported["structuredContent"]["workflow_authority_inherited_by_native"])
        baseline_required = tools.call(
            "rethlas_export_final",
            {"run_id": run_id, "path": "exports/proof_verified.tex"},
            principal,
        )
        self.assertTrue(baseline_required["isError"])
        self.assertEqual(
            baseline_required["structuredContent"]["error"]["code"],
            "EXPORT_BASELINE_REQUIRED",
        )

        events_path = Path(self.temp.name) / "debug" / "events.jsonl"
        events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(event["event_type"] == "capability.denied" for event in events))
        self.assertTrue(any(event["event_type"] == "workflow.transition" for event in events))
        serialized = json.dumps(events)
        self.assertNotIn(branch_a["capability"], serialized)

    def test_wrong_report_cannot_finalize(self) -> None:
        run_id = self._start()
        run = self.store.get_run(run_id)
        self.assertEqual(run["metadata"]["native_mode_at_creation"], "dangerous")
        self.assertFalse(run["sealed"])
        with self.assertRaises(ReCTMError):
            self.engine.get_artifact(owner_id=self.owner, run_id=run_id, artifact="final_tex")

    def test_owner_isolation(self) -> None:
        run_id = self._start()
        with self.assertRaises(ReCTMError) as denied:
            self.engine.status(owner_id="another-oauth-client", run_id=run_id)
        self.assertEqual(denied.exception.code, "RUN_OWNER_MISMATCH")

    def test_capability_is_bound_to_oauth_owner(self) -> None:
        run_id = self._start()
        task = self._next(run_id)
        with self.assertRaises(ReCTMError) as denied:
            self.engine.read(
                owner_id="another-oauth-client",
                capability=task["capability"],
                resource="problem",
            )
        self.assertEqual(denied.exception.code, "CAPABILITY_OWNER_MISMATCH")

    def test_native_mode_is_not_a_workflow_capability_claim(self) -> None:
        self.assertNotIn("native_mode", CapabilityClaims.__dataclass_fields__)

    def test_direct_screening_must_cover_every_plan_and_subgoal(self) -> None:
        run_id = self._start()
        assess = self._next(run_id)
        self._write(
            assess,
            "memory:generation:immediate_conclusions",
            {"conclusion": "Initial consequence."},
        )
        self._write(assess, "memory:generation:events", {"event_type": "assessment"})
        self._commit(assess, "assessment_complete")
        explore = self._next(run_id)
        self._write(explore, "memory:generation:events", {"event_type": "explore"})
        self._commit(explore, "exploration_complete")
        planning = self._next(run_id)
        self._commit(
            planning,
            "plans_proposed",
            {
                "plans": [
                    {"plan_id": "a", "summary": "Plan A", "subgoals": ["A1"]},
                    {"plan_id": "b", "summary": "Plan B", "subgoals": ["B1"]},
                ]
            },
        )
        direct = self._next(run_id)
        self._write(
            direct,
            "memory:generation:proof_steps",
            {"plan_id": "a", "status": "stuck"},
        )
        with self.assertRaises(ReCTMError) as denied:
            self._commit(
                direct,
                "direct_proving_complete",
                {
                    "outcome": "needs_branches",
                    "screening": [
                        {
                            "plan_id": "a",
                            "status": "stuck",
                            "subgoal_results": [
                                {"subgoal": "A1", "status": "stuck", "summary": "Blocked."}
                            ],
                            "key_stuck_points": ["Missing lemma."],
                        }
                    ],
                    "branch_plans": [{"plan_id": "a"}, {"plan_id": "b"}],
                },
            )
        self.assertEqual(denied.exception.code, "INVALID_ARGUMENT")

    def test_external_retrieval_is_capability_gated_and_persisted(self) -> None:
        self.engine.research = FakeResearchProvider()
        run_id = self._start()
        assess = self._next(run_id)
        result = self.engine.retrieve(
            owner_id=self.owner,
            capability=assess["capability"],
            query="A complete mathematical statement",
            search_intent="theorem",
            num_results=3,
        )
        self.assertEqual(result["count"], 1)
        events = self.vault.read_generation_memory(run_id, "events")
        self.assertTrue(
            any(item.get("event_type") == "external_theorem_search" for item in events)
        )
        with self.assertRaises(ReCTMError) as denied:
            self.engine.retrieve(
                owner_id="another-oauth-client",
                capability=assess["capability"],
                query="same statement",
            )
        self.assertEqual(denied.exception.code, "CAPABILITY_OWNER_MISMATCH")

    def test_steering_resume_and_cancel_survive_engine_rebuild(self) -> None:
        run_id = self._start()
        self.engine.steer(
            owner_id=self.owner,
            run_id=run_id,
            message="Prefer an order-theoretic proof before using absolute values.",
        )
        rebuilt = WorkflowEngine(
            self.store,
            self.vault,
            self.capabilities,
            self.debug,
            LatexGate(LatexPolicy.STATIC_ONLY),
            FakeResearchProvider(),
        )
        resumed = rebuilt.resume(owner_id=self.owner, run_id=run_id)
        self.assertEqual(resumed["state"], WorkflowState.ASSESS.value)
        self.assertEqual(
            resumed["context"]["user_steering"],
            ["Prefer an order-theoretic proof before using absolute values."],
        )
        cancelled = rebuilt.cancel(
            owner_id=self.owner,
            run_id=run_id,
            reason="manual_disconnect_test",
        )
        self.assertEqual(cancelled["state"], WorkflowState.CANCELLED.value)
        status = rebuilt.status(owner_id=self.owner, run_id=run_id)
        self.assertTrue(status["sealed"])
        with self.assertRaises(ReCTMError) as terminal:
            rebuilt.resume(owner_id=self.owner, run_id=run_id)
        self.assertEqual(terminal.exception.code, "RUN_TERMINAL")
        with self.assertRaises(ReCTMError) as old_capability:
            rebuilt.read(
                owner_id=self.owner,
                capability=resumed["capability"],
                resource="problem",
            )
        self.assertIn(
            old_capability.exception.code,
            {"CAPABILITY_REVOKED", "CAPABILITY_STALE", "CAPABILITY_STATE_MISMATCH"},
        )


if __name__ == "__main__":
    unittest.main()
