from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from re_ctm.errors import ReCTMError
from re_ctm.oauth import OAuthPrincipal
from re_ctm.rethlas_contracts import (
    CONTROL_DEFAULT_CANCEL_REASON,
    HIDDEN_LEGACY_ALIAS_SEMANTICS,
    INSPECT_DEFAULT_PROJECTS_LIMIT,
    INSPECT_DEFAULT_SEARCH_LIMIT,
    INSPECT_DEFAULT_THEOREM_SEARCH_LIMIT,
    RETRIEVE_DEFAULT_NUM_RESULTS,
    RETRIEVE_DEFAULT_OPERATION,
    RETRIEVE_DEFAULT_SEARCH_INTENT,
    RETHLAS_TOOL_NAMES,
    START_DEFAULT_PROBLEM_ID,
    START_DEFAULT_REGISTER_RESULT,
    START_DEFAULT_WORKFLOW_MODE,
    facade_schema,
)
from re_ctm.tools import (
    CTM_NATIVE_TOOL_NAMES,
    PUBLIC_TOOL_NAMES,
    TOOL_SPECS,
    ToolRuntime,
    _validate_schema_value,
    validate_tool_arguments,
)


CAPABILITY = "a" * 96 + "." + "b" * 43

EXPECTED_HIDDEN_ALIAS_SEMANTICS = {
    "rethlas_next": ("rethlas_step", "current_task"),
    "rethlas_read": ("rethlas_inspect", "read"),
    "rethlas_write": ("rethlas_step", "legacy_write"),
    "rethlas_search": ("rethlas_inspect", "search"),
    "rethlas_commit": ("rethlas_step", "legacy_commit"),
    "rethlas_status": ("rethlas_inspect", "status"),
    "rethlas_steer": ("rethlas_control", "steer"),
    "rethlas_resume": ("rethlas_step", "resume_current_task"),
    "rethlas_cancel": ("rethlas_control", "cancel"),
    "rethlas_get_artifact": ("rethlas_artifact", "get"),
    "rethlas_export_final": ("rethlas_artifact", "export_final_tex"),
}


FACADE_VARIANT_SAMPLES: dict[str, list[dict[str, object]]] = {
    "rethlas_step": [
        {"run_id": "run-1"},
        {
            "run_id": "run-1",
            "capability": CAPABILITY,
            "writes": [{"resource": "memory:generation:events", "content": {"x": 1}}],
            "action": "assessment_complete",
            "payload": {},
        },
    ],
    "rethlas_retrieve": [
        {
            "capability": CAPABILITY,
            "query": "finite groups",
            "operation": "theorem_search",
            "search_intent": "theorem",
            "num_results": 3,
        },
        {
            "capability": CAPABILITY,
            "operation": "paper_search",
            "query": "class field theory",
            "author": "Schmidt",
            "title": "Example",
            "keywords": "class fields",
            "num_results": 4,
        },
        {"capability": CAPABILITY, "operation": "paper_lookup", "query": "arXiv:1"},
        {"capability": CAPABILITY, "operation": "theorem_context", "query": "ref-1"},
    ],
    "rethlas_inspect": [
        {"operation": "status", "run_id": "run-1"},
        {"operation": "read", "capability": CAPABILITY, "resource": "problem"},
        {
            "operation": "search",
            "capability": CAPABILITY,
            "resource": "memory:generation:events",
            "query": "lemma",
            "limit": 7,
        },
        {"operation": "projects", "limit": 7},
        {"operation": "project_status", "project_id": "project-1"},
        {"operation": "claim", "claim_id": "claim-1"},
        {
            "operation": "theorem_search",
            "project_id": "project-1",
            "query": "lemma",
            "limit": 7,
        },
        {"operation": "dependency_graph", "project_id": "project-1"},
        {"operation": "reference_audit", "run_id": "run-1"},
    ],
    "rethlas_control": [
        {"action": "steer", "run_id": "run-1", "message": "Prefer the short proof."},
        {"action": "cancel", "run_id": "run-1", "reason": "test"},
        {
            "action": "project_create",
            "project_id": "project-1",
            "title": "Project",
            "metadata": {"source": "test"},
        },
        {
            "action": "claim_create",
            "project_id": "project-1",
            "claim_id": "claim-1",
            "title": "Claim",
            "statement_tex": "$1=1$",
            "conditions": ["A"],
            "metadata": {"source": "test"},
        },
        {
            "action": "claim_revise",
            "claim_id": "claim-1",
            "statement_tex": "$1=1$",
            "conditions": ["A"],
            "expected_base_revision_id": "rev-1",
        },
    ],
    "rethlas_artifact": [
        {"action": "get", "run_id": "run-1", "artifact": "verification_report"},
        {"action": "get", "project_id": "project-1", "artifact": "project_manifest"},
        {
            "action": "export",
            "run_id": "run-1",
            "artifact": "final_tex",
            "path": "proof.tex",
            "expected_sha256": "a" * 64,
        },
        {
            "action": "export",
            "project_id": "project-1",
            "artifact": "project_summary_tex",
            "path": "summary.tex",
            "expected_sha256": "a" * 64,
        },
    ],
}


KNOWN_ARGUMENT_VALUES: dict[str, object] = {
    "run_id": "run-x",
    "project_id": "project-x",
    "claim_id": "claim-x",
    "capability": CAPABILITY,
    "resource": "problem",
    "query": "query",
    "limit": 3,
    "operation": "status",
    "action": "get",
    "message": "message",
    "reason": "reason",
    "title": "title",
    "statement_tex": "$1=1$",
    "conditions": ["A"],
    "expected_base_revision_id": "rev-x",
    "metadata": {},
    "artifact": "final_tex",
    "path": "artifact.tex",
    "expected_sha256": "b" * 64,
    "author": "Author",
    "keywords": "keyword",
    "search_intent": "theorem",
    "num_results": 3,
    "writes": [],
    "payload": {},
}


class RethlasFacadeContractTestCase(unittest.TestCase):
    def test_public_facades_use_authoritative_contract_schemas(self) -> None:
        self.assertEqual(
            PUBLIC_TOOL_NAMES,
            CTM_NATIVE_TOOL_NAMES + RETHLAS_TOOL_NAMES,
        )
        self.assertEqual(len(PUBLIC_TOOL_NAMES), 24)
        for name in RETHLAS_TOOL_NAMES:
            with self.subTest(name=name):
                self.assertEqual(TOOL_SPECS[name].input_schema, facade_schema(name))

    def test_hidden_aliases_have_explicit_facade_semantics_and_stay_hidden(self) -> None:
        self.assertEqual(HIDDEN_LEGACY_ALIAS_SEMANTICS, EXPECTED_HIDDEN_ALIAS_SEMANTICS)
        native = MagicMock()
        workflow = MagicMock()
        debug = MagicMock()
        runtime = ToolRuntime(native, workflow, debug)
        for alias, (facade, semantic) in HIDDEN_LEGACY_ALIAS_SEMANTICS.items():
            with self.subTest(alias=alias, semantic=semantic):
                self.assertIn(alias, TOOL_SPECS)
                self.assertIn(alias, runtime._handlers)
                self.assertNotIn(alias, PUBLIC_TOOL_NAMES)
                self.assertIn(facade, RETHLAS_TOOL_NAMES)

    def test_start_schema_required_optional_and_forbidden_fields(self) -> None:
        minimal = {"problem_tex": r"\textbf{Problem.} Prove $1=1$."}
        validate_tool_arguments("rethlas_start", minimal)
        validate_tool_arguments(
            "rethlas_start",
            {
                **minimal,
                "problem_id": "p",
                "project_id": "project-1",
                "target_claim_id": "claim-1",
                "workflow_mode": "compact",
                "register_result": False,
                "export_path": "proof.tex",
                "references": [{"name": "ref", "content": "body", "source": "local"}],
            },
        )
        with self.assertRaises(ReCTMError):
            validate_tool_arguments("rethlas_start", {})
        with self.assertRaises(ReCTMError):
            validate_tool_arguments("rethlas_start", {**minimal, "operation": "status"})

    def test_every_discriminated_variant_enforces_required_and_forbidden_fields(self) -> None:
        for tool_name, samples in FACADE_VARIANT_SAMPLES.items():
            schema = facade_schema(tool_name)
            variants = schema["oneOf"]
            self.assertEqual(len(samples), len(variants), tool_name)
            known_fields = set(schema["properties"])
            for index, (variant, sample) in enumerate(zip(variants, samples, strict=True)):
                with self.subTest(tool=tool_name, variant=index):
                    validate_tool_arguments(tool_name, sample)
                    _validate_schema_value(sample, variant, path="variant")
                    for required in variant["required"]:
                        missing = dict(sample)
                        missing.pop(required, None)
                        with self.assertRaises(ReCTMError, msg=f"{tool_name}:{index}:{required}"):
                            _validate_schema_value(missing, variant, path="variant")
                    forbidden = sorted(known_fields - set(variant["properties"]))
                    for field in forbidden:
                        bad = dict(sample)
                        bad[field] = KNOWN_ARGUMENT_VALUES[field]
                        with self.assertRaises(ReCTMError, msg=f"{tool_name}:{index}:{field}"):
                            validate_tool_arguments(tool_name, bad)

    def test_schema_default_annotations_match_runtime_constants(self) -> None:
        start = facade_schema("rethlas_start")["properties"]
        self.assertEqual(start["problem_id"]["default"], START_DEFAULT_PROBLEM_ID)
        self.assertEqual(start["workflow_mode"]["default"], START_DEFAULT_WORKFLOW_MODE)
        self.assertEqual(start["register_result"]["default"], START_DEFAULT_REGISTER_RESULT)

        retrieve = facade_schema("rethlas_retrieve")["properties"]
        self.assertEqual(retrieve["operation"]["default"], RETRIEVE_DEFAULT_OPERATION)
        self.assertEqual(
            retrieve["search_intent"]["default"], RETRIEVE_DEFAULT_SEARCH_INTENT
        )
        self.assertEqual(retrieve["num_results"]["default"], RETRIEVE_DEFAULT_NUM_RESULTS)

        inspect_variants = facade_schema("rethlas_inspect")["oneOf"]
        defaults = {
            variant["properties"]["operation"].get("const"): variant["properties"]
            .get("limit", {})
            .get("default")
            for variant in inspect_variants
        }
        self.assertEqual(defaults["search"], INSPECT_DEFAULT_SEARCH_LIMIT)
        self.assertEqual(defaults["projects"], INSPECT_DEFAULT_PROJECTS_LIMIT)
        self.assertEqual(
            defaults["theorem_search"], INSPECT_DEFAULT_THEOREM_SEARCH_LIMIT
        )

    def test_runtime_uses_contract_defaults_and_validates_before_handlers(self) -> None:
        native = MagicMock()
        native.mode.value = "safe"
        workflow = MagicMock()
        debug = MagicMock()
        runtime = ToolRuntime(native, workflow, debug)
        principal = OAuthPrincipal("client-1", "client-1", "mcp")

        workflow.start.return_value = {"ok": True}
        runtime.call(
            "rethlas_start",
            {"problem_tex": r"\textbf{Problem.} Prove $1=1$."},
            principal,
        )
        start_kwargs = workflow.start.call_args.kwargs
        self.assertEqual(start_kwargs["problem_id"], START_DEFAULT_PROBLEM_ID)
        self.assertEqual(start_kwargs["workflow_mode"], START_DEFAULT_WORKFLOW_MODE)
        self.assertEqual(start_kwargs["register_result"], START_DEFAULT_REGISTER_RESULT)

        workflow.retrieve.return_value = {"ok": True}
        runtime.call(
            "rethlas_retrieve",
            {"capability": CAPABILITY, "query": "finite groups"},
            principal,
        )
        retrieve_kwargs = workflow.retrieve.call_args.kwargs
        self.assertEqual(retrieve_kwargs["operation"], RETRIEVE_DEFAULT_OPERATION)
        self.assertEqual(
            retrieve_kwargs["search_intent"], RETRIEVE_DEFAULT_SEARCH_INTENT
        )
        self.assertEqual(retrieve_kwargs["num_results"], RETRIEVE_DEFAULT_NUM_RESULTS)

        workflow.search.return_value = {"ok": True}
        runtime.call(
            "rethlas_inspect",
            {
                "operation": "search",
                "capability": CAPABILITY,
                "resource": "memory:generation:events",
                "query": "lemma",
            },
            principal,
        )
        self.assertEqual(
            workflow.search.call_args.kwargs["limit"], INSPECT_DEFAULT_SEARCH_LIMIT
        )

        workflow.store.list_projects.return_value = []
        runtime.call("rethlas_inspect", {"operation": "projects"}, principal)
        self.assertEqual(
            workflow.store.list_projects.call_args.kwargs["limit"],
            INSPECT_DEFAULT_PROJECTS_LIMIT,
        )

        workflow.store.project_dependency_graph.return_value = {
            "claims": [{"claim_id": "claim-1", "title": "lemma"}],
            "revisions": [
                {
                    "claim_id": "claim-1",
                    "statement_tex": "lemma",
                    "conditions": [],
                    "revision_id": f"rev-{index}",
                }
                for index in range(25)
            ],
        }
        theorem_result = runtime.call(
            "rethlas_inspect",
            {"operation": "theorem_search", "project_id": "project-1", "query": "lemma"},
            principal,
        )["structuredContent"]
        self.assertEqual(len(theorem_result["results"]), INSPECT_DEFAULT_THEOREM_SEARCH_LIMIT)

        workflow.cancel.return_value = {"ok": True}
        runtime.call(
            "rethlas_control",
            {"action": "cancel", "run_id": "run-1"},
            principal,
        )
        self.assertEqual(
            workflow.cancel.call_args.kwargs["reason"], CONTROL_DEFAULT_CANCEL_REASON
        )

        workflow.get_artifact.reset_mock()
        rejected = runtime.call(
            "rethlas_artifact",
            {"action": "get", "run_id": "run-1"},
            principal,
        )
        self.assertTrue(rejected["isError"])
        self.assertFalse(workflow.get_artifact.called)


if __name__ == "__main__":
    unittest.main()

