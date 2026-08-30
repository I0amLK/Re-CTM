from __future__ import annotations

import json
import os
import signal
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from re_ctm.capabilities import CapabilityAuthority
from re_ctm.debug import DebugEventBus
from re_ctm.enums import LatexPolicy, NativeMode, WorkflowRole
from re_ctm.errors import ReCTMError
from re_ctm.latex import LatexGate
from re_ctm.mcp import MCPDispatcher
from re_ctm.native import NativeRuntime, NativeWorkspace
from re_ctm.oauth import OAuthPrincipal
from re_ctm.processes import CommandManager
from re_ctm.research import HTTPResponse, PaperSearchClient
from re_ctm.storage import STATE_SCHEMA_VERSION, StateStore
from re_ctm.tools import ToolRuntime, _validate_schema_value, validate_tool_arguments
from re_ctm.vault import PrivateVault
from re_ctm.workflow import WorkflowEngine


PROOF = (
    "\\documentclass{article}\n"
    "\\usepackage{amsmath,amsthm}\n"
    "\\newtheorem{theorem}{Theorem}\n"
    "\\begin{document}\n"
    "\\begin{theorem} $1=1$. \\end{theorem}\n"
    "\\begin{proof} By reflexivity. \\end{proof}\n"
    "\\end{document}\n"
)


class StateMigrationTestCase(unittest.TestCase):
    def test_unversioned_v1_database_migrates_additively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE runs (
                    run_id TEXT PRIMARY KEY,
                    problem_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    status TEXT NOT NULL,
                    epoch INTEGER NOT NULL DEFAULT 1,
                    round_index INTEGER NOT NULL DEFAULT 0,
                    transition_seq INTEGER NOT NULL DEFAULT 0,
                    latex_passed INTEGER NOT NULL DEFAULT 0,
                    verdict TEXT,
                    sealed INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO runs(run_id, problem_id, owner_id, state, status, created_at, updated_at)
                VALUES('old-run', 'old', 'owner', 'assess', 'active', 't0', 't0');
                PRAGMA user_version = 0;
                """
            )
            connection.commit()
            connection.close()

            store = StateStore(path)
            try:
                self.assertEqual(store.schema_version(), STATE_SCHEMA_VERSION)
                self.assertEqual(store.get_run("old-run")["owner_id"], "owner")
                self.assertIsNotNone(
                    store._fetch_one(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='projects'",
                        (),
                    )
                )
                self.assertIsNotNone(
                    store._fetch_one(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='domains'",
                        (),
                    )
                )
            finally:
                store.close()

    def test_newer_database_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version = 999")
            connection.close()
            with self.assertRaises(ReCTMError) as caught:
                StateStore(path)
            self.assertEqual(caught.exception.code, "STATE_SCHEMA_NEWER_THAN_RUNTIME")


class V020MCPTestCase(unittest.TestCase):
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
        capabilities = CapabilityAuthority(b"v" * 32, self.store, debug)
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
        self.principal = OAuthPrincipal("owner", "owner", "mcp")
        self.other = OAuthPrincipal("other", "other", "mcp")
        self.workspace = workspace

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def call(self, name: str, arguments: dict, principal: OAuthPrincipal | None = None) -> dict:
        result = self.tools.call(name, arguments, principal or self.principal)
        if result["isError"]:
            raise AssertionError(result["structuredContent"])
        return result["structuredContent"]

    def create_project_claim(self, title: str, statement: str) -> tuple[str, str, str]:
        project = self.call(
            "rethlas_control",
            {"action": "project_create", "title": "Research project"},
        )["project"]
        created = self.call(
            "rethlas_control",
            {
                "action": "claim_create",
                "project_id": project["project_id"],
                "title": title,
                "statement_tex": statement,
            },
        )
        return project["project_id"], created["claim"]["claim_id"], created["revision"]["revision_id"]

    def finish_compact(
        self,
        *,
        project_id: str,
        claim_id: str,
        dependencies: list[str] | None = None,
        conditions: list[str] | None = None,
        started: dict | None = None,
    ) -> dict:
        started = started or self.call(
            "rethlas_start",
            {
                "problem_tex": r"\textbf{Problem.} Prove $1=1$.",
                "project_id": project_id,
                "target_claim_id": claim_id,
                "workflow_mode": "compact",
            },
        )
        run_id = started["run_id"]
        assess = self.call("rethlas_step", {"run_id": run_id})
        assembled = self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assess["capability"],
                **assess["task"]["minimal_submission"],
            },
        )
        self.assertEqual(assembled["state"], "assemble")
        verify = self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assembled["capability"],
                "writes": [
                    {"resource": "proof", "content": PROOF},
                    {
                        "resource": "proof_manifest",
                        "content": {
                            "target_statement_tex": r"$1=1$.",
                            "dependency_revision_ids": dependencies or [],
                            "reference_ids": [],
                            "conditional_hypotheses": conditions or [],
                            "computational_evidence": [],
                        },
                    },
                ],
                "action": "proof_submitted",
                "payload": {"outcome": "proof"},
            },
        )
        self.assertEqual(verify["state"], "verify")
        return self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": verify["capability"],
                **verify["task"]["minimal_submission"],
            },
        )

    def test_compact_project_promotion_and_conditional_dependency_propagation(self) -> None:
        project_id, dependency_claim, _ = self.create_project_claim("Conditional lemma", r"$1=1$.")
        dependency_done = self.finish_compact(
            project_id=project_id,
            claim_id=dependency_claim,
            conditions=["GRH"],
        )
        self.assertEqual(dependency_done["state"], "done")
        dependency_revision = self.store.current_claim_revision(dependency_claim, owner_id="owner")
        assert dependency_revision is not None
        self.assertEqual(dependency_revision["evidence_status"], "CONDITIONAL")
        self.assertEqual(dependency_revision["conditions"], ["GRH"])

        target = self.call(
            "rethlas_control",
            {
                "action": "claim_create",
                "project_id": project_id,
                "title": "Dependent theorem",
                "statement_tex": r"$1=1$.",
            },
        )
        target_claim = target["claim"]["claim_id"]
        target_done = self.finish_compact(
            project_id=project_id,
            claim_id=target_claim,
            dependencies=[dependency_revision["revision_id"]],
        )
        self.assertEqual(target_done["state"], "done")
        target_revision = self.store.current_claim_revision(target_claim, owner_id="owner")
        assert target_revision is not None
        self.assertEqual(target_revision["evidence_status"], "CONDITIONAL")
        self.assertEqual(target_revision["conditions"], ["GRH"])
        graph = self.call(
            "rethlas_inspect",
            {"operation": "dependency_graph", "project_id": project_id},
        )
        self.assertIn(
            (target_revision["revision_id"], dependency_revision["revision_id"], "depends_on"),
            {(edge["from_revision_id"], edge["to_revision_id"], edge["edge_type"]) for edge in graph["edges"]},
        )

        denied = self.tools.call(
            "rethlas_inspect",
            {"operation": "project_status", "project_id": project_id},
            self.other,
        )
        self.assertTrue(denied["isError"])
        self.assertEqual(denied["structuredContent"]["error"]["code"], "PROJECT_OWNER_MISMATCH")

    def test_registry_promotion_conflict_does_not_invalidate_verified_run(self) -> None:
        project_id, claim_id, base = self.create_project_claim("Concurrent theorem", r"$1=1$.")
        started = self.call(
            "rethlas_start",
            {
                "problem_tex": r"\textbf{Problem.} Prove $1=1$.",
                "project_id": project_id,
                "target_claim_id": claim_id,
                "workflow_mode": "compact",
            },
        )
        revised = self.call(
            "rethlas_control",
            {
                "action": "claim_revise",
                "claim_id": claim_id,
                "statement_tex": r"$1=1$ with a concurrent edit.",
                "expected_base_revision_id": base,
            },
        )["revision"]
        done = self.finish_compact(
            project_id=project_id,
            claim_id=claim_id,
            started=started,
        )
        self.assertEqual(done["state"], "done")
        run = self.store.get_run(started["run_id"])
        self.assertEqual(run["metadata"]["registry_promotion"]["status"], "conflict")
        current = self.store.current_claim_revision(claim_id, owner_id="owner")
        assert current is not None
        self.assertEqual(current["revision_id"], revised["revision_id"])
        self.assertTrue((self.workspace / done["workspace_export_path"]).is_file())

    def test_registry_promotion_error_is_nonfatal_and_retried_on_terminal_step(self) -> None:
        project_id, claim_id, open_revision_id = self.create_project_claim(
            "Retry promotion theorem",
            r"$1=1$.",
        )
        with mock.patch.object(
            self.store,
            "promote_verified_run",
            side_effect=ReCTMError(
                "REGISTRY_TEMPORARY_FAILURE",
                "Synthetic registry failure.",
                category="runtime",
                retryable=True,
            ),
        ):
            done = self.finish_compact(project_id=project_id, claim_id=claim_id)
        self.assertEqual(done["state"], "done")
        self.assertEqual(done["verdict"], "correct")
        current = self.store.current_claim_revision(claim_id, owner_id="owner")
        assert current is not None
        self.assertEqual(current["revision_id"], open_revision_id)
        run = self.store.get_run(done["run_id"])
        self.assertEqual(run["metadata"]["registry_promotion"]["status"], "error")
        retried = self.call("rethlas_step", {"run_id": done["run_id"]})
        self.assertEqual(retried["state"], "done")
        promoted = self.store.current_claim_revision(claim_id, owner_id="owner")
        assert promoted is not None
        self.assertEqual(promoted["evidence_status"], "VERIFIED")
        self.assertNotEqual(promoted["revision_id"], open_revision_id)

    def test_superseded_verified_revision_remains_available_in_project_snapshot(self) -> None:
        project_id, claim_id, _ = self.create_project_claim(
            "Stable verified dependency",
            r"$1=1$.",
        )
        self.finish_compact(project_id=project_id, claim_id=claim_id)
        verified = self.store.current_claim_revision(claim_id, owner_id="owner")
        assert verified is not None
        self.assertEqual(verified["evidence_status"], "VERIFIED")
        revised = self.call(
            "rethlas_control",
            {
                "action": "claim_revise",
                "claim_id": claim_id,
                "statement_tex": r"$1=1$ with a stronger formulation.",
                "expected_base_revision_id": verified["revision_id"],
            },
        )["revision"]
        self.assertEqual(revised["evidence_status"], "OPEN")
        historical = self.store.get_claim_revision(verified["revision_id"], owner_id="owner")
        self.assertEqual(historical["lifecycle_status"], "SUPERSEDED")
        started = self.call(
            "rethlas_start",
            {
                "problem_tex": r"\textbf{Problem.} Prove another local statement.",
                "project_id": project_id,
                "workflow_mode": "full",
                "register_result": False,
            },
        )
        assess = self.call("rethlas_step", {"run_id": started["run_id"]})
        visible_ids = {
            item["revision_id"]
            for item in assess["context"]["project_context"]["verified_revisions"]
        }
        self.assertIn(verified["revision_id"], visible_ids)

    def test_project_artifact_is_portable_and_excludes_private_reasoning(self) -> None:
        project_id, claim_id, _ = self.create_project_claim("Portable theorem", r"$1=1$.")
        self.finish_compact(project_id=project_id, claim_id=claim_id)
        manifest = self.call(
            "rethlas_artifact",
            {"action": "get", "project_id": project_id, "artifact": "project_manifest"},
        )["content"]
        serialized = json.dumps(manifest, sort_keys=True)
        self.assertIn("proof_sha256", serialized)
        self.assertNotIn("owner_id", manifest["project"])
        self.assertTrue(manifest["revision_provenance"])
        provenance = next(iter(manifest["revision_provenance"].values()))
        self.assertTrue(provenance["proof_manifest_sha256"])
        self.assertEqual(provenance["reference_audits"], [])
        self.assertNotIn("generation_memory", serialized)
        self.assertNotIn("capability", serialized.lower())

    def test_project_summary_tex_rejects_unsafe_open_claim_latex(self) -> None:
        project = self.call(
            "rethlas_control",
            {"action": "project_create", "title": "Unsafe summary fixture"},
        )["project"]
        self.call(
            "rethlas_control",
            {
                "action": "claim_create",
                "project_id": project["project_id"],
                "title": "Open unsafe claim",
                "statement_tex": r"\input{secret.tex}",
            },
        )
        result = self.tools.call(
            "rethlas_artifact",
            {
                "action": "get",
                "project_id": project["project_id"],
                "artifact": "project_summary_tex",
            },
            self.principal,
        )
        self.assertTrue(result["isError"])
        self.assertEqual(
            result["structuredContent"]["error"]["code"],
            "PROJECT_SUMMARY_LATEX_UNSAFE",
        )

    def test_reference_audit_disposition_requires_matching_evidence(self) -> None:
        started = self.call(
            "rethlas_start",
            {
                "problem_tex": r"\textbf{Problem.} Prove $1=1$.",
                "references": [{"name": "source.txt", "content": "Reference statement."}],
            },
        )
        references = self.call(
            "rethlas_inspect",
            {"operation": "reference_audit", "run_id": started["run_id"]},
        )["references"]
        reference_id = references[0]["reference_id"]
        source_snapshot_id = self.store.list_source_snapshots(reference_id)[0]["source_snapshot_id"]
        self.tools.workflow.vault.write_proof(started["run_id"], PROOF)
        self.store.write_proof_manifest(
            started["run_id"],
            {
                "target_statement_tex": r"$1=1$.",
                "dependency_revision_ids": [],
                "reference_ids": [reference_id],
                "conditional_hypotheses": [],
                "computational_evidence": [],
                "project_snapshot_id": None,
                "workflow_protocol_version": 2,
            },
        )
        claims = type(
            "VerifierClaims",
            (),
            {
                "run_id": started["run_id"],
                "domain_id": "test-verifier-domain",
                "role": WorkflowRole.VERIFIER,
            },
        )()
        with self.assertRaises(ReCTMError) as source_error:
            self.tools.workflow._write_resource(  # internal invariant unit test
                claims,
                "reference_audit",
                {"reference_id": reference_id, "disposition": "SOURCE_VERIFIED"},
            )
        self.assertEqual(source_error.exception.code, "INVALID_ARGUMENT")
        with self.assertRaises(ReCTMError):
            self.tools.workflow._write_resource(
                claims,
                "reference_audit",
                {"reference_id": reference_id, "disposition": "INDEPENDENTLY_REDERIVED"},
            )
        with self.assertRaises(ReCTMError):
            self.tools.workflow._write_resource(
                claims,
                "reference_audit",
                {"reference_id": reference_id, "disposition": "NOT_MATERIAL"},
            )
        accepted = self.tools.workflow._write_resource(
            claims,
            "reference_audit",
            {
                "reference_id": reference_id,
                "disposition": "SOURCE_VERIFIED",
                "evidence_basis": "stored_source_snapshot",
                "evidence_locator": source_snapshot_id,
                "source_checked": True,
                "assumptions_checked": True,
                "notation_checked": True,
                "material": True,
            },
        )
        self.assertEqual(accepted["disposition"], "SOURCE_VERIFIED")

        discovered = self.store.register_reference(
            run_id=started["run_id"],
            project_id=None,
            provider="paper_search",
            identity_key="paper-search-fixture",
            title="Discovery metadata only",
            source_uri="https://openalex.org/W123",
        )
        discovery_snapshot = self.store.create_source_snapshot(
            reference_id=discovered["reference_id"],
            provider="paper_search",
            source_uri="https://openalex.org/W123",
            content='{"title":"Discovery metadata only"}',
            content_type="application/json",
        )
        with self.assertRaises(ReCTMError) as discovery_error:
            self.tools.workflow._write_resource(
                claims,
                "reference_audit",
                {
                    "reference_id": discovered["reference_id"],
                    "disposition": "SOURCE_VERIFIED",
                    "evidence_basis": "stored_source_snapshot",
                    "evidence_locator": discovery_snapshot["source_snapshot_id"],
                    "source_checked": True,
                    "assumptions_checked": True,
                    "notation_checked": True,
                    "material": True,
                },
            )
        self.assertEqual(discovery_error.exception.code, "INVALID_ARGUMENT")

    def test_reference_requires_full_lane_and_missing_audit_is_server_gap(self) -> None:
        started = self.call(
            "rethlas_start",
            {
                "problem_tex": r"\textbf{Problem.} Prove $1=1$.",
                "references": [
                    {"name": "source.txt", "content": "Reference statement.", "source": "inline:test"}
                ],
            },
        )
        run_id = started["run_id"]
        assess = self.call("rethlas_step", {"run_id": run_id})
        explore = self.call(
            "rethlas_step",
            {"run_id": run_id, "capability": assess["capability"], **assess["task"]["minimal_submission"]},
        )
        self.assertEqual(explore["state"], "explore")
        planning = self.call(
            "rethlas_step",
            {"run_id": run_id, "capability": explore["capability"], **explore["task"]["minimal_submission"]},
        )
        direct = self.call(
            "rethlas_step",
            {"run_id": run_id, "capability": planning["capability"], **planning["task"]["minimal_submission"]},
        )
        active = direct["context"]["active_plans"]
        screening = {
            plan["plan_id"]: {
                subgoal["subgoal_id"]: {"status": "solved", "summary": "Immediate for the test target."}
                for subgoal in plan["subgoals"]
            }
            for plan in active
        }
        assembled = self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": direct["capability"],
                "writes": [{"resource": "memory:generation:proof_steps", "content": {"summary": "Proof route complete."}}],
                "action": "direct_proving_complete",
                "payload": {
                    "screening": screening,
                    "selected_plan_id": active[0]["plan_id"],
                    "proof_route": "Use reflexivity.",
                },
            },
        )
        refs = self.call("rethlas_inspect", {"operation": "reference_audit", "run_id": run_id})["references"]
        self.assertEqual(len(refs), 1)
        reference_id = refs[0]["reference_id"]
        verify = self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assembled["capability"],
                "writes": [
                    {"resource": "proof", "content": PROOF},
                    {
                        "resource": "proof_manifest",
                        "content": {
                            "target_statement_tex": r"$1=1$.",
                            "dependency_revision_ids": [],
                            "reference_ids": [reference_id],
                            "conditional_hypotheses": [],
                            "computational_evidence": [],
                        },
                    },
                ],
                "action": "proof_submitted",
                "payload": {},
            },
        )
        self.assertEqual(verify["state"], "verify")
        self.assertEqual(verify["task"]["reference_ids_requiring_audit"], [reference_id])
        self.assertNotIn(
            "memory:verifier:reference_checks",
            [item.get("resource") for item in verify["task"]["write_contract"]],
        )
        self.assertIn("reference_preconditions", verify["task"]["commit_payload_contract"])
        repair = self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": verify["capability"],
                **verify["task"]["minimal_submission"],
            },
        )
        self.assertEqual(repair["state"], "repair")
        self.assertEqual(repair["submission"]["verdict"], "wrong")
        report = self.call(
            "rethlas_artifact",
            {"action": "get", "run_id": run_id, "artifact": "verification_report"},
        )["content"]
        gaps = report["verification_report"]["gaps"]
        self.assertTrue(any(item["location"] == f"reference:{reference_id}" for item in gaps))

    def test_compact_second_wrong_verdict_escalates_to_full_exploration(self) -> None:
        started = self.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove $1=1$.", "workflow_mode": "compact"},
        )
        run_id = started["run_id"]
        assess = self.call("rethlas_step", {"run_id": run_id})
        assembled = self.call(
            "rethlas_step",
            {"run_id": run_id, "capability": assess["capability"], **assess["task"]["minimal_submission"]},
        )
        manifest = {
            "target_statement_tex": r"$1=1$.",
            "dependency_revision_ids": [],
            "reference_ids": [],
            "conditional_hypotheses": [],
            "computational_evidence": [],
        }
        verify = self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": assembled["capability"],
                "writes": [
                    {"resource": "proof", "content": PROOF},
                    {"resource": "proof_manifest", "content": manifest},
                ],
                "action": "proof_submitted",
                "payload": {"outcome": "proof"},
            },
        )

        def wrong_submission(capability: str) -> dict:
            return self.call(
                "rethlas_step",
                {
                    "run_id": run_id,
                    "capability": capability,
                    "writes": [
                        {"resource": "memory:verifier:statement_checks", "content": {"location": "proof", "status": "gap", "summary": "test gap"}},
                        {"resource": "memory:verifier:events", "content": {"event_type": "audit_complete", "summary": "audit complete"}},
                        {
                            "resource": "verification_report",
                            "content": {
                                "verification_report": {
                                    "summary": "A gap remains.",
                                    "critical_errors": [],
                                    "gaps": [{"location": "proof", "issue": "test gap"}],
                                },
                                "repair_hints": "Repair the test gap.",
                            },
                        },
                    ],
                    "action": "verification_submitted",
                    "payload": {},
                },
            )

        repair = wrong_submission(verify["capability"])
        self.assertEqual(repair["state"], "repair")
        changed_proof = PROOF.replace("By reflexivity.", "By reflexivity of equality.")
        verify_again = self.call(
            "rethlas_step",
            {
                "run_id": run_id,
                "capability": repair["capability"],
                "writes": [
                    {"resource": "proof", "content": changed_proof},
                    {"resource": "proof_manifest", "content": manifest},
                ],
                "action": "repair_submitted",
                "payload": {},
            },
        )
        self.assertEqual(verify_again["state"], "verify")
        explored = wrong_submission(verify_again["capability"])
        self.assertEqual(explored["state"], "explore")
        self.assertEqual(self.store.get_run(run_id)["metadata"]["effective_workflow_mode"], "full")


class PaperSearchClientTestCase(unittest.TestCase):
    def test_fixed_openalex_provider_normalizes_paper_search(self) -> None:
        def transport(request, timeout, maximum):
            self.assertEqual(request.full_url.split("?", 1)[0], "https://api.openalex.org/works")
            body = json.dumps(
                {
                    "results": [
                        {
                            "id": "https://openalex.org/W123",
                            "display_name": "A Paper",
                            "doi": "https://doi.org/10.1000/test",
                            "publication_year": 2026,
                            "authorships": [{"author": {"display_name": "A. Author"}}],
                            "primary_location": {"landing_page_url": "https://example.org/paper"},
                            "open_access": {"oa_url": "https://example.org/open"},
                        }
                    ]
                }
            ).encode()
            return HTTPResponse(200, body, "application/json")

        client = PaperSearchClient(transport=transport)
        result = client.search_papers(query="class field theory", author="Author", num_results=5)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["paper_id"], "W123")
        self.assertEqual(result["results"][0]["doi"], "10.1000/test")

    def test_paper_provider_rejects_arbitrary_host(self) -> None:
        with self.assertRaises(ReCTMError):
            PaperSearchClient("https://example.com/works")

    def test_paper_provider_rejects_cross_host_redirect(self) -> None:
        def transport(request, timeout, maximum):
            return HTTPResponse(
                200,
                b'{"results":[]}',
                "application/json",
                final_url="https://127.0.0.1/internal",
            )

        client = PaperSearchClient(transport=transport)
        with self.assertRaises(ReCTMError) as caught:
            client.search_papers(query="class field theory")
        self.assertEqual(caught.exception.code, "PAPER_SEARCH_URL_DENIED")


class SchemaAndProcessTestCase(unittest.TestCase):
    def test_schema_validator_supports_const_oneof_anyof(self) -> None:
        schema = {
            "type": "object",
            "required": ["operation"],
            "properties": {"operation": {"const": "paper"}},
            "oneOf": [
                {"type": "object", "required": ["operation", "query"], "properties": {"operation": {"const": "paper"}, "query": {"type": "string"}}},
                {"type": "object", "required": ["operation", "id"], "properties": {"operation": {"const": "paper"}, "id": {"type": "integer"}}},
            ],
            "anyOf": [
                {"type": "object", "required": ["query"]},
                {"type": "object", "required": ["id"]},
            ],
        }
        _validate_schema_value({"operation": "paper", "query": "x"}, schema, path="value")
        with self.assertRaises(ReCTMError):
            _validate_schema_value({"operation": "wrong", "query": "x"}, schema, path="value")

    def test_typed_facade_operations_are_zero_guess_at_schema_layer(self) -> None:
        validate_tool_arguments(
            "rethlas_retrieve",
            {"capability": "cap", "query": "finite groups"},
        )
        validate_tool_arguments(
            "rethlas_retrieve",
            {"capability": "cap", "query": "class field theory", "operation": "paper_search"},
        )
        validate_tool_arguments(
            "rethlas_retrieve",
            {"capability": "cap", "operation": "paper_search", "author": "Schmidt"},
        )
        with self.assertRaises(ReCTMError):
            validate_tool_arguments(
                "rethlas_retrieve",
                {"capability": "cap", "operation": "paper_search"},
            )
        with self.assertRaises(ReCTMError):
            validate_tool_arguments(
                "rethlas_control",
                {"action": "claim_revise", "claim_id": "claim-1"},
            )
        with self.assertRaises(ReCTMError):
            validate_tool_arguments(
                "rethlas_inspect",
                {"operation": "project_status"},
            )
        with self.assertRaises(ReCTMError):
            validate_tool_arguments(
                "rethlas_artifact",
                {"action": "get", "artifact": "project_manifest"},
            )

    def test_timeout_and_external_signal_report_termination_provenance(self) -> None:
        manager = CommandManager()
        try:
            timed = manager.start(
                ["/bin/sh", "-lc", "sleep 5"],
                env=os.environ.copy(),
                timeout_ms=50,
                yield_time_ms=200,
                max_output_bytes=4096,
                stdin_text="",
                tty=False,
                verbosity="full",
                preview_bytes=1024,
            )
            self.assertEqual(timed["termination"]["source"], "command_timeout")
            self.assertTrue(timed["termination"]["term_sent_by_re_ctm"])
            self.assertEqual(timed["termination"]["requested_timeout_ms"], 50)

            running = manager.start(
                ["/bin/sh", "-lc", "sleep 5"],
                env=os.environ.copy(),
                timeout_ms=5000,
                yield_time_ms=0,
                max_output_bytes=4096,
                stdin_text="",
                tty=False,
                verbosity="full",
                preview_bytes=1024,
            )
            command = manager._get(running["command_id"], stdin=False)
            os.killpg(command.process.pid, signal.SIGKILL)
            time.sleep(0.05)
            polled = manager.poll(
                running["command_id"],
                chars="",
                yield_time_ms=0,
                max_output_bytes=4096,
                verbosity="full",
                preview_bytes=1024,
            )
            self.assertEqual(polled["termination"]["source"], "external_or_unknown")
            self.assertEqual(polled["termination"]["observed_signal"], "SIGKILL")
            self.assertFalse(polled["termination"]["kill_sent_by_re_ctm"])
        finally:
            manager.close()


if __name__ == "__main__":
    unittest.main()
