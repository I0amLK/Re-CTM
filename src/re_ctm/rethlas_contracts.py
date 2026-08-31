from __future__ import annotations

import copy
from typing import Any

from .capabilities import (
    CAPABILITY_TOKEN_MAX_LENGTH,
    CAPABILITY_TOKEN_MIN_LENGTH,
    CAPABILITY_TOKEN_PATTERN,
)


RETHLAS_TOOL_NAMES = (
    "rethlas_start",
    "rethlas_step",
    "rethlas_inspect",
    "rethlas_retrieve",
    "rethlas_control",
    "rethlas_artifact",
)

HIDDEN_LEGACY_ALIAS_SEMANTICS = {
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
_HIDDEN_LEGACY_TOOL_NAMES = tuple(HIDDEN_LEGACY_ALIAS_SEMANTICS)
LEGACY_RETHLAS_TOOL_NAMES = (
    "rethlas_start",
    *_HIDDEN_LEGACY_TOOL_NAMES[:4],
    "rethlas_retrieve",
    *_HIDDEN_LEGACY_TOOL_NAMES[4:],
)

RETRIEVE_THEOREM_SEARCH = "theorem_search"
RETRIEVE_PAPER_SEARCH = "paper_search"
RETRIEVE_PAPER_LOOKUP = "paper_lookup"
RETRIEVE_THEOREM_CONTEXT = "theorem_context"
RETRIEVE_OPERATIONS = (
    RETRIEVE_THEOREM_SEARCH,
    RETRIEVE_PAPER_SEARCH,
    RETRIEVE_PAPER_LOOKUP,
    RETRIEVE_THEOREM_CONTEXT,
)
RETRIEVE_DEFAULT_OPERATION = RETRIEVE_THEOREM_SEARCH
RETRIEVE_DEFAULT_SEARCH_INTENT = "theorem"
RETRIEVE_DEFAULT_NUM_RESULTS = 10

INSPECT_STATUS = "status"
INSPECT_READ = "read"
INSPECT_SEARCH = "search"
INSPECT_PROJECTS = "projects"
INSPECT_PROJECT_STATUS = "project_status"
INSPECT_CLAIM = "claim"
INSPECT_THEOREM_SEARCH = "theorem_search"
INSPECT_DEPENDENCY_GRAPH = "dependency_graph"
INSPECT_REFERENCE_AUDIT = "reference_audit"
INSPECT_OPERATIONS = (
    INSPECT_STATUS,
    INSPECT_READ,
    INSPECT_SEARCH,
    INSPECT_PROJECTS,
    INSPECT_PROJECT_STATUS,
    INSPECT_CLAIM,
    INSPECT_THEOREM_SEARCH,
    INSPECT_DEPENDENCY_GRAPH,
    INSPECT_REFERENCE_AUDIT,
)
INSPECT_DEFAULT_SEARCH_LIMIT = 20
INSPECT_DEFAULT_PROJECTS_LIMIT = 100
INSPECT_DEFAULT_THEOREM_SEARCH_LIMIT = 20

CONTROL_STEER = "steer"
CONTROL_CANCEL = "cancel"
CONTROL_PROJECT_CREATE = "project_create"
CONTROL_CLAIM_CREATE = "claim_create"
CONTROL_CLAIM_REVISE = "claim_revise"
CONTROL_ACTIONS = (
    CONTROL_STEER,
    CONTROL_CANCEL,
    CONTROL_PROJECT_CREATE,
    CONTROL_CLAIM_CREATE,
    CONTROL_CLAIM_REVISE,
)
CONTROL_DEFAULT_CANCEL_REASON = "user_cancelled"

ARTIFACT_GET = "get"
ARTIFACT_EXPORT = "export"
ARTIFACT_ACTIONS = (ARTIFACT_GET, ARTIFACT_EXPORT)
RUN_ARTIFACTS = (
    "draft_tex",
    "final_tex",
    "proof_manifest",
    "verification_report",
    "reference_audit",
    "transition_log",
    "debug_manifest",
)
PROJECT_ARTIFACTS = ("project_manifest", "project_summary_tex")

START_DEFAULT_PROBLEM_ID = "problem"
START_DEFAULT_WORKFLOW_MODE = "auto"
START_DEFAULT_REGISTER_RESULT = True


CAPABILITY_INPUT_SCHEMA = {
    "type": "string",
    "minLength": CAPABILITY_TOKEN_MIN_LENGTH,
    "maxLength": CAPABILITY_TOKEN_MAX_LENGTH,
    "pattern": CAPABILITY_TOKEN_PATTERN,
    "description": (
        "Opaque server-issued handle. Copy it verbatim from the current task envelope; "
        "never decode, edit, normalize, concatenate, or synthesize it."
    ),
}


def _closed_object(
    *,
    required: tuple[str, ...] | list[str],
    properties: dict[str, Any],
    **extra: Any,
) -> dict[str, Any]:
    return {
        "type": "object",
        "required": list(required),
        "properties": properties,
        "additionalProperties": False,
        **extra,
    }


RETHLAS_STEP_WRITES_SCHEMA = {
    "type": "array",
    "items": _closed_object(
        required=("resource", "content"),
        properties={
            "resource": {"type": "string", "minLength": 1},
            "content": {
                "description": (
                    "Match the current task.write_contract entry for this resource. "
                    "Memory resources accept one JSON object per write; do not batch records "
                    "as an array unless explicitly allowed by that contract."
                )
            },
        },
    ),
}


_START_SCHEMA = _closed_object(
    required=("problem_tex",),
    properties={
        "problem_tex": {"type": "string", "minLength": 1},
        "problem_id": {"type": "string", "default": START_DEFAULT_PROBLEM_ID},
        "project_id": {
            "type": "string",
            "description": "Optional owner project to snapshot and link to this run.",
        },
        "target_claim_id": {
            "type": "string",
            "description": (
                "Optional claim in project_id to receive a mechanically promoted revision "
                "after finalization."
            ),
        },
        "workflow_mode": {
            "type": "string",
            "enum": ["auto", "compact", "full"],
            "default": START_DEFAULT_WORKFLOW_MODE,
        },
        "register_result": {
            "type": "boolean",
            "default": START_DEFAULT_REGISTER_RESULT,
        },
        "export_path": {
            "type": "string",
            "description": (
                "Optional workspace-relative .tex destination. Defaults to "
                "rethlas-output/<run_id>/proof_verified.tex."
            ),
        },
        "references": {
            "type": "array",
            "default": [],
            "items": _closed_object(
                required=("name", "content"),
                properties={
                    "name": {"type": "string", "minLength": 1},
                    "content": {"type": "string", "minLength": 1},
                    "source": {"type": "string"},
                },
            ),
        },
    },
)


_STEP_SCHEMA = _closed_object(
    required=("run_id",),
    properties={
        "run_id": {"type": "string", "minLength": 1},
        "capability": CAPABILITY_INPUT_SCHEMA,
        "writes": RETHLAS_STEP_WRITES_SCHEMA,
        "action": {
            "type": "string",
            "minLength": 1,
            "description": "Use the current task.commit_action exactly.",
        },
        "payload": {
            "type": "object",
            "description": (
                "Match the current task.commit_payload_schema exactly; use an empty object "
                "when the schema has no required fields."
            ),
        },
    },
    oneOf=[
        _closed_object(
            required=("run_id",),
            properties={"run_id": {"type": "string", "minLength": 1}},
        ),
        _closed_object(
            required=("run_id", "capability", "action"),
            properties={
                "run_id": {"type": "string", "minLength": 1},
                "capability": CAPABILITY_INPUT_SCHEMA,
                "writes": RETHLAS_STEP_WRITES_SCHEMA,
                "action": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Use the current task.commit_action exactly.",
                },
                "payload": {
                    "type": "object",
                    "description": (
                        "Match the current task.commit_payload_schema exactly; use an empty "
                        "object when the schema has no required fields."
                    ),
                },
            },
        ),
    ],
)


_RETRIEVE_SCHEMA = _closed_object(
    required=("capability",),
    properties={
        "capability": CAPABILITY_INPUT_SCHEMA,
        "query": {"type": "string", "minLength": 1},
        "operation": {
            "type": "string",
            "enum": list(RETRIEVE_OPERATIONS),
            "default": RETRIEVE_DEFAULT_OPERATION,
        },
        "author": {"type": "string", "minLength": 1},
        "title": {"type": "string", "minLength": 1},
        "keywords": {"type": "string", "minLength": 1},
        "search_intent": {
            "type": "string",
            "enum": ["theorem", "construction", "example", "counterexample", "background"],
            "default": RETRIEVE_DEFAULT_SEARCH_INTENT,
        },
        "num_results": {
            "type": "integer",
            "minimum": 1,
            "maximum": 50,
            "default": RETRIEVE_DEFAULT_NUM_RESULTS,
        },
    },
    oneOf=[
        _closed_object(
            required=("capability", "query"),
            properties={
                "capability": CAPABILITY_INPUT_SCHEMA,
                "query": {"type": "string", "minLength": 1},
                "operation": {"const": RETRIEVE_THEOREM_SEARCH},
                "search_intent": {
                    "type": "string",
                    "enum": [
                        "theorem",
                        "construction",
                        "example",
                        "counterexample",
                        "background",
                    ],
                    "default": RETRIEVE_DEFAULT_SEARCH_INTENT,
                },
                "num_results": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": RETRIEVE_DEFAULT_NUM_RESULTS,
                },
            },
        ),
        _closed_object(
            required=("capability", "operation"),
            properties={
                "capability": CAPABILITY_INPUT_SCHEMA,
                "operation": {"const": RETRIEVE_PAPER_SEARCH},
                "query": {"type": "string", "minLength": 1},
                "author": {"type": "string", "minLength": 1},
                "title": {"type": "string", "minLength": 1},
                "keywords": {"type": "string", "minLength": 1},
                "num_results": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": RETRIEVE_DEFAULT_NUM_RESULTS,
                },
            },
            anyOf=[
                {"type": "object", "required": ["query"]},
                {"type": "object", "required": ["author"]},
                {"type": "object", "required": ["title"]},
                {"type": "object", "required": ["keywords"]},
            ],
        ),
        _closed_object(
            required=("capability", "operation", "query"),
            properties={
                "capability": CAPABILITY_INPUT_SCHEMA,
                "operation": {"const": RETRIEVE_PAPER_LOOKUP},
                "query": {"type": "string", "minLength": 1},
            },
        ),
        _closed_object(
            required=("capability", "operation", "query"),
            properties={
                "capability": CAPABILITY_INPUT_SCHEMA,
                "operation": {"const": RETRIEVE_THEOREM_CONTEXT},
                "query": {"type": "string", "minLength": 1},
            },
        ),
    ],
)


_INSPECT_SCHEMA = _closed_object(
    required=("operation",),
    properties={
        "operation": {"type": "string", "enum": list(INSPECT_OPERATIONS)},
        "run_id": {"type": "string"},
        "project_id": {"type": "string"},
        "claim_id": {"type": "string"},
        "capability": CAPABILITY_INPUT_SCHEMA,
        "resource": {"type": "string"},
        "query": {"type": "string"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
    },
    oneOf=[
        _closed_object(
            required=("operation", "run_id"),
            properties={
                "operation": {"const": INSPECT_STATUS},
                "run_id": {"type": "string", "minLength": 1},
            },
        ),
        _closed_object(
            required=("operation", "capability", "resource"),
            properties={
                "operation": {"const": INSPECT_READ},
                "capability": CAPABILITY_INPUT_SCHEMA,
                "resource": {"type": "string", "minLength": 1},
            },
        ),
        _closed_object(
            required=("operation", "capability", "resource", "query"),
            properties={
                "operation": {"const": INSPECT_SEARCH},
                "capability": CAPABILITY_INPUT_SCHEMA,
                "resource": {"type": "string", "minLength": 1},
                "query": {"type": "string"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": INSPECT_DEFAULT_SEARCH_LIMIT,
                },
            },
        ),
        _closed_object(
            required=("operation",),
            properties={
                "operation": {"const": INSPECT_PROJECTS},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": INSPECT_DEFAULT_PROJECTS_LIMIT,
                },
            },
        ),
        _closed_object(
            required=("operation", "project_id"),
            properties={
                "operation": {"const": INSPECT_PROJECT_STATUS},
                "project_id": {"type": "string", "minLength": 1},
            },
        ),
        _closed_object(
            required=("operation", "claim_id"),
            properties={
                "operation": {"const": INSPECT_CLAIM},
                "claim_id": {"type": "string", "minLength": 1},
            },
        ),
        _closed_object(
            required=("operation", "project_id", "query"),
            properties={
                "operation": {"const": INSPECT_THEOREM_SEARCH},
                "project_id": {"type": "string", "minLength": 1},
                "query": {"type": "string", "minLength": 1},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": INSPECT_DEFAULT_THEOREM_SEARCH_LIMIT,
                },
            },
        ),
        _closed_object(
            required=("operation", "project_id"),
            properties={
                "operation": {"const": INSPECT_DEPENDENCY_GRAPH},
                "project_id": {"type": "string", "minLength": 1},
            },
        ),
        _closed_object(
            required=("operation", "run_id"),
            properties={
                "operation": {"const": INSPECT_REFERENCE_AUDIT},
                "run_id": {"type": "string", "minLength": 1},
            },
        ),
    ],
)


_CONTROL_SCHEMA = _closed_object(
    required=("action",),
    properties={
        "run_id": {"type": "string"},
        "action": {"type": "string", "enum": list(CONTROL_ACTIONS)},
        "message": {"type": "string"},
        "reason": {"type": "string"},
        "project_id": {"type": "string"},
        "claim_id": {"type": "string"},
        "title": {"type": "string"},
        "statement_tex": {"type": "string"},
        "conditions": {"type": "array", "items": {"type": "string"}},
        "expected_base_revision_id": {"type": "string"},
        "metadata": {"type": "object", "additionalProperties": True},
    },
    oneOf=[
        _closed_object(
            required=("action", "run_id", "message"),
            properties={
                "action": {"const": CONTROL_STEER},
                "run_id": {"type": "string", "minLength": 1},
                "message": {"type": "string", "minLength": 1},
            },
        ),
        _closed_object(
            required=("action", "run_id"),
            properties={
                "action": {"const": CONTROL_CANCEL},
                "run_id": {"type": "string", "minLength": 1},
                "reason": {"type": "string", "default": CONTROL_DEFAULT_CANCEL_REASON},
            },
        ),
        _closed_object(
            required=("action", "title"),
            properties={
                "action": {"const": CONTROL_PROJECT_CREATE},
                "project_id": {"type": "string"},
                "title": {"type": "string", "minLength": 1},
                "metadata": {"type": "object", "additionalProperties": True},
            },
        ),
        _closed_object(
            required=("action", "project_id", "title"),
            properties={
                "action": {"const": CONTROL_CLAIM_CREATE},
                "project_id": {"type": "string", "minLength": 1},
                "claim_id": {"type": "string"},
                "title": {"type": "string", "minLength": 1},
                "statement_tex": {"type": "string"},
                "conditions": {"type": "array", "items": {"type": "string"}},
                "metadata": {"type": "object", "additionalProperties": True},
            },
        ),
        _closed_object(
            required=("action", "claim_id", "statement_tex"),
            properties={
                "action": {"const": CONTROL_CLAIM_REVISE},
                "claim_id": {"type": "string", "minLength": 1},
                "statement_tex": {"type": "string", "minLength": 1},
                "conditions": {"type": "array", "items": {"type": "string"}},
                "expected_base_revision_id": {"type": "string"},
            },
        ),
    ],
)


_ARTIFACT_SCHEMA = _closed_object(
    required=("action",),
    properties={
        "run_id": {"type": "string"},
        "project_id": {"type": "string"},
        "action": {"type": "string", "enum": list(ARTIFACT_ACTIONS)},
        "artifact": {"type": "string", "enum": list(RUN_ARTIFACTS + PROJECT_ARTIFACTS)},
        "path": {"type": "string", "minLength": 1},
        "expected_sha256": {"type": "string"},
    },
    oneOf=[
        _closed_object(
            required=("action", "run_id", "artifact"),
            properties={
                "action": {"const": ARTIFACT_GET},
                "run_id": {"type": "string", "minLength": 1},
                "artifact": {"type": "string", "enum": list(RUN_ARTIFACTS)},
            },
        ),
        _closed_object(
            required=("action", "project_id", "artifact"),
            properties={
                "action": {"const": ARTIFACT_GET},
                "project_id": {"type": "string", "minLength": 1},
                "artifact": {"type": "string", "enum": list(PROJECT_ARTIFACTS)},
            },
        ),
        _closed_object(
            required=("action", "run_id", "artifact"),
            properties={
                "action": {"const": ARTIFACT_EXPORT},
                "run_id": {"type": "string", "minLength": 1},
                "artifact": {"const": "final_tex"},
                "path": {"type": "string", "minLength": 1},
                "expected_sha256": {"type": "string"},
            },
        ),
        _closed_object(
            required=("action", "project_id", "artifact"),
            properties={
                "action": {"const": ARTIFACT_EXPORT},
                "project_id": {"type": "string", "minLength": 1},
                "artifact": {"type": "string", "enum": list(PROJECT_ARTIFACTS)},
                "path": {"type": "string", "minLength": 1},
                "expected_sha256": {"type": "string"},
            },
        ),
    ],
)


_FACADE_SCHEMAS = {
    "rethlas_start": _START_SCHEMA,
    "rethlas_step": _STEP_SCHEMA,
    "rethlas_inspect": _INSPECT_SCHEMA,
    "rethlas_retrieve": _RETRIEVE_SCHEMA,
    "rethlas_control": _CONTROL_SCHEMA,
    "rethlas_artifact": _ARTIFACT_SCHEMA,
}


def facade_schema(name: str) -> dict[str, Any]:
    """Return an isolated copy of the authoritative public façade input schema."""

    try:
        return copy.deepcopy(_FACADE_SCHEMAS[name])
    except KeyError as exc:
        raise KeyError(f"unknown Rethlas façade: {name}") from exc

