from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import __version__
from .debug import DebugEventBus, new_trace_id
from .errors import ReCTMError, invalid_argument
from .native import NativeRuntime
from .oauth import OAuthPrincipal
from .processes import COMMAND_BUFFER_BYTES, COMMAND_HEAD_BUFFER_DIVISOR
from .workflow import WorkflowEngine


@dataclass(frozen=True)
class ToolSpec:
    title: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool = False
    destructive: bool = False
    open_world: bool = False
    idempotent: bool | None = None

    def definition(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": tool_output_schema(),
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.read_only if self.idempotent is None else self.idempotent,
                "openWorldHint": self.open_world,
            },
        }


def tool_output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
            "error": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "message": {"type": "string"},
                    "category": {"type": "string"},
                    "retryable": {"type": "boolean"},
                    "details": {"type": "object", "additionalProperties": True},
                },
                "required": ["code", "message", "category", "retryable", "details"],
                "additionalProperties": True,
            },
        },
        "required": ["ok"],
        "additionalProperties": True,
    }


OBJECT = {"type": "object", "additionalProperties": False, "required": []}

CTM_NATIVE_TOOL_NAMES = (
    "server_info",
    "check_exec_environment",
    "read_file",
    "list_dir",
    "list_files",
    "search_text",
    "apply_patch",
    "exec_command",
    "write_stdin",
    "kill_command",
    "read_output",
    "git_status",
    "git_diff",
    "git_log",
    "git_show",
    "git_blame",
    "request_permissions",
    "view_image",
)

LEGACY_RETHLAS_TOOL_NAMES = (
    "rethlas_start",
    "rethlas_next",
    "rethlas_read",
    "rethlas_write",
    "rethlas_search",
    "rethlas_retrieve",
    "rethlas_commit",
    "rethlas_status",
    "rethlas_steer",
    "rethlas_resume",
    "rethlas_cancel",
    "rethlas_get_artifact",
    "rethlas_export_final",
)

RETHLAS_TOOL_NAMES = (
    "rethlas_start",
    "rethlas_step",
    "rethlas_inspect",
    "rethlas_retrieve",
    "rethlas_control",
    "rethlas_artifact",
)

PUBLIC_TOOL_NAMES = CTM_NATIVE_TOOL_NAMES + RETHLAS_TOOL_NAMES


TOOL_SPECS: dict[str, ToolSpec] = {
    "server_info": ToolSpec(
        "Server info",
        "Return server, workspace, project-context, auth, policy, and fixed-tool metadata.",
        {**OBJECT, "properties": {}},
        read_only=True,
    ),
    "check_exec_environment": ToolSpec(
        "Check exec environment",
        "Return lightweight exec_command sandbox and environment status known to the server.",
        {**OBJECT, "properties": {}},
        read_only=True,
    ),
    "read_file": ToolSpec(
        "Read file",
        "Read a UTF-8 text file slice inside the configured workspace.",
        {
            **OBJECT,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "start_line": {"type": "integer", "minimum": 1, "default": 1},
                "end_line": {"type": "integer", "minimum": 1},
                "max_lines": {"type": "integer", "minimum": 1},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 131072},
                "encoding": {"type": "string", "enum": ["utf-8"], "default": "utf-8"},
            },
        },
        read_only=True,
    ),
    "list_dir": ToolSpec(
        "List directory",
        "List directory entries inside the configured workspace.",
        {
            **OBJECT,
            "properties": {
                "path": {"type": "string", "default": "."},
                "recursive": {"type": "boolean", "default": False},
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 20, "default": 1},
                "max_entries": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
                "include_hidden": {"type": "boolean", "default": False},
                "include_ignored": {"type": "boolean", "default": False},
                "sort": {"type": "string", "enum": ["name", "type", "modified"], "default": "name"},
            },
        },
        read_only=True,
    ),
    "list_files": ToolSpec(
        "List files",
        "List workspace files using glob filters.",
        {
            **OBJECT,
            "properties": {
                "path": {"type": "string", "default": "."},
                "patterns": {"type": "array", "items": {"type": "string"}},
                "glob": {"type": "string"},
                "exclude_patterns": {"type": "array", "items": {"type": "string"}},
                "include_hidden": {"type": "boolean", "default": False},
                "include_ignored": {"type": "boolean", "default": False},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50000, "default": 5000},
                "sort": {"type": "string", "enum": ["path", "modified"], "default": "path"},
            },
        },
        read_only=True,
    ),
    "search_text": ToolSpec(
        "Search text",
        "Search UTF-8 workspace files for text or regex matches.",
        {
            **OBJECT,
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "minLength": 1},
                "path": {"type": "string", "default": "."},
                "regex": {"type": "boolean", "default": False},
                "case_sensitive": {"type": "boolean", "default": False},
                "include_globs": {"type": "array", "items": {"type": "string"}},
                "glob": {"type": "string"},
                "exclude_globs": {"type": "array", "items": {"type": "string"}},
                "context_lines": {"type": "integer", "minimum": 0, "maximum": 5, "default": 0},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
                "max_preview_bytes": {"type": "integer", "minimum": 80, "maximum": 4096, "default": 512},
            },
        },
        read_only=True,
    ),
    "apply_patch": ToolSpec(
        "Apply patch",
        "Stage, validate, and atomically apply a patch envelope. Example: *** Begin Patch\n*** Update File: app.py\n@@\n-old\n+new\n*** End Patch",
        {
            **OBJECT,
            "required": ["patch"],
            "properties": {
                "patch": {"type": "string", "minLength": 1},
                "dry_run": {"type": "boolean", "default": False},
            },
        },
        destructive=True,
    ),
    "exec_command": ToolSpec(
        "Execute command",
        "Run a bounded command under runtime policy. Pass workdir explicitly for reconnect-safe paths. A still-running command returns command_id. Example: {\"cmd\":\"pytest -q\",\"workdir\":\".\",\"yield_time_ms\":30000}. Retained output is bounded per stream; for very large output redirect to a file (cmd > out.log 2>&1) and page it with read_file or search_text.",
        {
            **OBJECT,
            "required": ["cmd"],
            "properties": {
                "cmd": {"type": "string", "minLength": 1},
                "workdir": {"type": "string", "default": "."},
                "cwd": {"type": "string"},
                "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 600000, "default": 30000},
                "yield_time_ms": {"type": "integer", "minimum": 0, "maximum": 30000, "default": 10000},
                "max_output_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 65536},
                "verbosity": {"type": "string", "enum": ["summary", "preview", "full"]},
                "preview_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 4096},
                "stdin": {"type": "string", "default": ""},
                "tty": {"type": "boolean", "default": False},
                "env": {"type": "object", "additionalProperties": {"type": "string"}, "default": {}},
            },
        },
        destructive=True,
        open_world=True,
    ),
    "write_stdin": ToolSpec(
        "Write stdin",
        "Poll or interact with a running command by command_id. Empty chars wait for output; non-empty chars writes to stdin. Example: {\"command_id\":\"abc\",\"chars\":\"\",\"yield_time_ms\":10000}.",
        {
            **OBJECT,
            "required": ["command_id"],
            "properties": {
                "command_id": {"type": "string", "minLength": 1},
                "chars": {"type": "string", "default": ""},
                "yield_time_ms": {"type": "integer", "minimum": 0, "maximum": 30000, "default": 10000},
                "max_output_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 65536},
                "verbosity": {"type": "string", "enum": ["summary", "preview", "full"]},
                "preview_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 4096},
            },
        },
    ),
    "kill_command": ToolSpec(
        "Kill command",
        "Terminate a server-managed command by command_id. Example: {\"command_id\":\"abc\",\"signal\":\"KILL\"}.",
        {
            **OBJECT,
            "required": ["command_id"],
            "properties": {
                "command_id": {"type": "string", "minLength": 1},
                "signal": {"type": "string", "enum": ["TERM", "KILL", "INT"], "default": "TERM"},
                "wait_ms": {"type": "integer", "minimum": 0, "maximum": 30000, "default": 5000},
                "kill_wait_ms": {"type": "integer", "minimum": 0, "maximum": 30000, "default": 2000},
                "max_output_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 65536},
                "verbosity": {"type": "string", "enum": ["summary", "preview", "full"]},
                "preview_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 4096},
            },
        },
        destructive=True,
    ),
    "read_output": ToolSpec(
        "Read output",
        "Read retained command output using an output_ref returned by exec_command/write_stdin. Each stream retains the earliest output (head) plus the most recent output (rolling tail); bytes between them may be evicted and are reported via evicted_gap_bytes. Example: {\"output_ref\":\"command:abc:stdout\",\"offset\":0,\"limit\":4096}.",
        {
            **OBJECT,
            "required": ["output_ref"],
            "properties": {
                "output_ref": {"type": "string", "minLength": 1},
                "stream": {"type": "string", "enum": ["stdout", "stderr"]},
                "offset": {"type": "integer", "minimum": 0, "default": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 4096},
            },
        },
        read_only=True,
    ),
    "git_status": ToolSpec(
        "Git status",
        "Return git working tree status for the workspace.",
        {**OBJECT, "properties": {"path": {"type": "string", "default": "."}, "include_untracked": {"type": "boolean", "default": True}, "max_entries": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000}}},
        read_only=True,
    ),
    "git_diff": ToolSpec(
        "Git diff",
        "Return unified git diff for workspace changes.",
        {**OBJECT, "properties": {"path": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}, "staged": {"type": "boolean", "default": False}, "unstaged": {"type": "boolean", "default": True}, "context_lines": {"type": "integer", "minimum": 0, "maximum": 20, "default": 3}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 262144}}},
        read_only=True,
    ),
    "git_log": ToolSpec(
        "Git log",
        "Return recent git commits with bounded structured metadata.",
        {**OBJECT, "properties": {"path": {"type": "string", "default": "."}, "ref": {"type": "string", "default": "HEAD"}, "max_count": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}, "skip": {"type": "integer", "minimum": 0, "maximum": 10000, "default": 0}}},
        read_only=True,
    ),
    "git_show": ToolSpec(
        "Git show",
        "Return bounded git show output for a revision.",
        {**OBJECT, "properties": {"rev": {"type": "string", "default": "HEAD"}, "path": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}, "include_diff": {"type": "boolean", "default": True}, "context_lines": {"type": "integer", "minimum": 0, "maximum": 20, "default": 3}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576, "default": 262144}}},
        read_only=True,
    ),
    "git_blame": ToolSpec(
        "Git blame",
        "Return bounded git blame metadata for a workspace file.",
        {**OBJECT, "required": ["path"], "properties": {"path": {"type": "string", "minLength": 1}, "rev": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1, "default": 1}, "end_line": {"type": "integer", "minimum": 1}, "max_lines": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200}}},
        read_only=True,
    ),
    "request_permissions": ToolSpec(
        "Request permissions",
        "Report scoped permission-request status without silently granting operations.",
        {**OBJECT, "required": ["tool_name", "permission", "reason", "arguments"], "properties": {"tool_name": {"type": "string", "enum": ["exec_command", "apply_patch"]}, "permission": {"type": "string", "enum": ["network", "destructive_command", "long_timeout", "sensitive_env", "shell_expansion", "inline_script", "privileged_executable", "write_generated_or_ignored"]}, "reason": {"type": "string", "minLength": 1}, "arguments": {"type": "object", "additionalProperties": True}, "scope": {"type": "string", "enum": ["once", "session"], "default": "once"}, "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 300}}},
        read_only=True,
        idempotent=False,
    ),
    "view_image": ToolSpec(
        "View image",
        "Return a workspace image as MCP image content.",
        {**OBJECT, "required": ["path"], "properties": {"path": {"type": "string", "minLength": 1}, "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 10485760, "default": 5242880}, "max_width": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 2000}, "max_height": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 2000}, "auto_resize": {"type": "boolean", "default": True}}},
        read_only=True,
    ),
    "rethlas_start": ToolSpec(
        "Start verified mathematical workflow",
        "Call this first for every concrete mathematical proof, derivation, or verification task unless the user explicitly asks for a direct informal answer. Create a private Rethlas reasoning run; continue with rethlas_step until verification and automatic proof_verified.tex workspace delivery complete.",
        {
            **OBJECT,
            "required": ["problem_tex"],
            "properties": {
                "problem_tex": {"type": "string", "minLength": 1},
                "problem_id": {"type": "string"},
                "export_path": {
                    "type": "string",
                    "description": "Optional workspace-relative .tex destination. Defaults to rethlas-output/<run_id>/proof_verified.tex.",
                },
                "references": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name", "content"],
                        "properties": {
                            "name": {"type": "string"},
                            "content": {"type": "string"},
                            "source": {"type": "string"},
                        },
                    },
                },
            },
        },
    ),
    "rethlas_next": ToolSpec(
        "Get next Rethlas task",
        "Advance mechanical states and issue the current reasoning-domain task and capability.",
        {**OBJECT, "required": ["run_id"], "properties": {"run_id": {"type": "string"}}},
        destructive=True,
    ),
    "rethlas_read": ToolSpec(
        "Read Rethlas logical resource",
        "Read a capability-authorized logical resource; never accepts filesystem paths.",
        {
            **OBJECT,
            "required": ["capability", "resource"],
            "properties": {
                "capability": {"type": "string"},
                "resource": {"type": "string"},
            },
        },
        read_only=True,
    ),
    "rethlas_write": ToolSpec(
        "Write Rethlas logical resource",
        "Write a capability-authorized memory record, proof, join result, or verifier report.",
        {
            **OBJECT,
            "required": ["capability", "resource", "content"],
            "properties": {
                "capability": {"type": "string"},
                "resource": {"type": "string"},
                "content": {},
            },
        },
        destructive=True,
    ),
    "rethlas_search": ToolSpec(
        "Search Rethlas memory",
        "Search a capability-authorized generation or branch memory channel.",
        {
            **OBJECT,
            "required": ["capability", "resource", "query"],
            "properties": {
                "capability": {"type": "string"},
                "resource": {"type": "string"},
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        read_only=True,
    ),
    "rethlas_retrieve": ToolSpec(
        "Retrieve external mathematical results",
        "Query the bounded theorem-search integration under the active Rethlas capability and persist returned unverified references in domain-local memory.",
        {
            **OBJECT,
            "required": ["capability", "query"],
            "properties": {
                "capability": {"type": "string"},
                "query": {"type": "string", "minLength": 1},
                "search_intent": {
                    "type": "string",
                    "enum": [
                        "theorem",
                        "construction",
                        "example",
                        "counterexample",
                        "background"
                    ]
                },
                "num_results": {"type": "integer", "minimum": 1, "maximum": 50}
            }
        },
        read_only=False,
        destructive=False,
        open_world=True,
    ),
    "rethlas_commit": ToolSpec(
        "Commit Rethlas task",
        "Seal the current reasoning domain and request its server-validated workflow transition.",
        {
            **OBJECT,
            "required": ["capability", "action"],
            "properties": {
                "capability": {"type": "string"},
                "action": {"type": "string"},
                "payload": {"type": "object"},
            },
        },
        destructive=True,
    ),
    "rethlas_status": ToolSpec(
        "Rethlas status",
        "Return public run progress without exposing private branch contents.",
        {**OBJECT, "required": ["run_id"], "properties": {"run_id": {"type": "string"}}},
        read_only=True,
    ),
    "rethlas_steer": ToolSpec(
        "Steer Rethlas workflow",
        "Queue user guidance for the next safe generator or repair checkpoint.",
        {
            **OBJECT,
            "required": ["run_id", "message"],
            "properties": {
                "run_id": {"type": "string"},
                "message": {"type": "string", "minLength": 1},
            },
        },
        destructive=True,
    ),
    "rethlas_resume": ToolSpec(
        "Resume Rethlas workflow",
        "Reissue the active task for a non-terminal persisted run.",
        {**OBJECT, "required": ["run_id"], "properties": {"run_id": {"type": "string"}}},
        destructive=True,
    ),
    "rethlas_cancel": ToolSpec(
        "Cancel Rethlas workflow",
        "Cancel and seal a non-terminal run.",
        {
            **OBJECT,
            "required": ["run_id"],
            "properties": {
                "run_id": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
        destructive=True,
    ),
    "rethlas_get_artifact": ToolSpec(
        "Get Rethlas artifact",
        "Return draft LaTeX, final verified LaTeX, verification report, transition log, or terminal debug manifest.",
        {
            **OBJECT,
            "required": ["run_id", "artifact"],
            "properties": {
                "run_id": {"type": "string"},
                "artifact": {
                    "type": "string",
                    "enum": [
                        "draft_tex",
                        "final_tex",
                        "verification_report",
                        "transition_log",
                        "debug_manifest"
                    ],
                },
            },
        },
        read_only=True,
    ),
    "rethlas_export_final": ToolSpec(
        "Export verified LaTeX",
        "Ensure the mechanically finalized proof_verified.tex exists in the workspace through the controlled trust-domain bridge. When path is omitted, use the run's automatic workspace_export_path; an explicit alternate path may be overwritten only with expected_sha256.",
        {
            **OBJECT,
            "required": ["run_id"],
            "properties": {
                "run_id": {"type": "string"},
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Optional alternate workspace-relative .tex path. Defaults to the run's workspace_export_path.",
                },
                "expected_sha256": {"type": "string"},
            },
        },
        destructive=True,
    ),
    "rethlas_step": ToolSpec(
        "Advance Rethlas workflow",
        "Issue the current Rethlas task, or submit its logical writes plus commit payload and immediately return the next task. Always follow the returned task.write_contract, task.commit_payload_schema, and task minimal/example submission instead of guessing JSON shapes. Each memory write is one JSON object unless the current write_contract explicitly says otherwise. Recoverable validation/conflict corrections return a fresh capability and identify whether earlier writes were retained. Incomplete screening is accepted in place and returns exact missing plan/subgoal ids instead of failing the run.",
        {
            **OBJECT,
            "required": ["run_id"],
            "properties": {
                "run_id": {"type": "string", "minLength": 1},
                "capability": {"type": "string"},
                "writes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["resource", "content"],
                        "properties": {
                            "resource": {"type": "string", "minLength": 1},
                            "content": {"description": "Match the current task.write_contract entry for this resource. Memory resources accept one JSON object per write; do not batch records as an array unless explicitly allowed by that contract."},
                        },
                        "additionalProperties": False,
                    },
                },
                "action": {"type": "string", "description": "Use the current task.commit_action exactly."},
                "payload": {"type": "object", "description": "Match the current task.commit_payload_schema exactly; use an empty object when the schema has no required fields."},
            },
        },
        destructive=True,
    ),
    "rethlas_inspect": ToolSpec(
        "Inspect Rethlas run",
        "Inspect public run status or capability-authorized logical resources/memory without changing workflow state.",
        {
            **OBJECT,
            "required": ["operation"],
            "properties": {
                "operation": {"type": "string", "enum": ["status", "read", "search"]},
                "run_id": {"type": "string"},
                "capability": {"type": "string"},
                "resource": {"type": "string"},
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
        read_only=True,
    ),
    "rethlas_control": ToolSpec(
        "Control Rethlas run",
        "Queue owner steering or cancel a run. Resuming/continuing is done by calling rethlas_step with run_id.",
        {
            **OBJECT,
            "required": ["run_id", "action"],
            "properties": {
                "run_id": {"type": "string", "minLength": 1},
                "action": {"type": "string", "enum": ["steer", "cancel"]},
                "message": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
        destructive=True,
    ),
    "rethlas_artifact": ToolSpec(
        "Read or export Rethlas artifact",
        "Return a run artifact or ensure the mechanically finalized LaTeX is written to the workspace. Final export never bypasses the mechanical verification gate.",
        {
            **OBJECT,
            "required": ["run_id", "action"],
            "properties": {
                "run_id": {"type": "string", "minLength": 1},
                "action": {"type": "string", "enum": ["get", "export"]},
                "artifact": {
                    "type": "string",
                    "enum": ["draft_tex", "final_tex", "verification_report", "transition_log", "debug_manifest"],
                },
                "path": {"type": "string", "minLength": 1},
                "expected_sha256": {"type": "string"},
            },
        },
        destructive=True,
    ),
}

if tuple(TOOL_SPECS)[: len(CTM_NATIVE_TOOL_NAMES)] != CTM_NATIVE_TOOL_NAMES:
    raise RuntimeError("Re-CTM must preserve the exact 18-tool CTM prefix")
if any(name not in TOOL_SPECS for name in PUBLIC_TOOL_NAMES):
    raise RuntimeError("Every public Re-CTM tool must have a tool specification")


def validate_tool_arguments(name: str, arguments: Mapping[str, Any]) -> None:
    spec = TOOL_SPECS.get(name)
    if spec is None:
        raise ReCTMError("UNKNOWN_TOOL", f"Unknown tool: {name}", category="validation")
    _validate_schema_value(dict(arguments), spec.input_schema, path="arguments")


def _validate_schema_value(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    expected_type = schema.get("type")
    if expected_type is not None and not _schema_type_matches(value, expected_type):
        raise invalid_argument(f"{path} must be {_schema_type_name(expected_type)}")
    if isinstance(value, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(value) < minimum:
            raise invalid_argument(f"{path} is shorter than {minimum}")
        if "enum" in schema and value not in schema["enum"]:
            raise invalid_argument(f"{path} must be one of {schema['enum']!r}")
    if isinstance(value, int) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            raise invalid_argument(f"{path} must be >= {minimum}")
        if isinstance(maximum, (int, float)) and value > maximum:
            raise invalid_argument(f"{path} must be <= {maximum}")
    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            raise invalid_argument(f"{path} must contain at least {minimum_items} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _validate_schema_value(item, item_schema, path=f"{path}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for key in required if isinstance(required, list) else []:
            if key not in value:
                raise invalid_argument(f"{path}.{key} is required")
        additional = schema.get("additionalProperties", True)
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if isinstance(properties, Mapping) and key in properties:
                child_schema = properties[key]
                if isinstance(child_schema, Mapping):
                    _validate_schema_value(item, child_schema, path=child_path)
            elif additional is False:
                raise invalid_argument(f"{child_path} is not a recognized argument")
            elif isinstance(additional, Mapping):
                _validate_schema_value(item, additional, path=child_path)


def _schema_type_matches(value: Any, expected_type: Any) -> bool:
    if isinstance(expected_type, list):
        return any(_schema_type_matches(value, item) for item in expected_type)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "null":
        return value is None
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "string":
        return isinstance(value, str)
    return False


def _schema_type_name(expected_type: Any) -> str:
    return (
        " or ".join(str(item) for item in expected_type)
        if isinstance(expected_type, list)
        else str(expected_type)
    )


class ToolRuntime:
    def __init__(
        self,
        native: NativeRuntime,
        workflow: WorkflowEngine,
        debug: DebugEventBus,
    ) -> None:
        self.native = native
        self.workflow = workflow
        self.debug = debug
        self._handlers: dict[str, Callable[[OAuthPrincipal, dict[str, Any], str], dict[str, Any]]] = {
            "server_info": self._server_info,
            "check_exec_environment": self._native("check_exec_environment"),
            "read_file": self._native("read_file"),
            "list_dir": self._native("list_dir"),
            "list_files": self._native("list_files"),
            "search_text": self._native("search_text"),
            "apply_patch": self._native("apply_patch"),
            "exec_command": self._native("exec_command"),
            "write_stdin": self._native("write_stdin"),
            "kill_command": self._native("kill_command"),
            "read_output": self._native("read_output"),
            "git_status": self._native("git_status"),
            "git_diff": self._native("git_diff"),
            "git_log": self._native("git_log"),
            "git_show": self._native("git_show"),
            "git_blame": self._native("git_blame"),
            "request_permissions": self._native("request_permissions"),
            "view_image": self._native("view_image"),
            "rethlas_start": self._rethlas_start,
            "rethlas_next": self._rethlas_next,
            "rethlas_read": self._rethlas_read,
            "rethlas_write": self._rethlas_write,
            "rethlas_search": self._rethlas_search,
            "rethlas_retrieve": self._rethlas_retrieve,
            "rethlas_commit": self._rethlas_commit,
            "rethlas_status": self._rethlas_status,
            "rethlas_steer": self._rethlas_steer,
            "rethlas_resume": self._rethlas_resume,
            "rethlas_cancel": self._rethlas_cancel,
            "rethlas_get_artifact": self._rethlas_get_artifact,
            "rethlas_export_final": self._rethlas_export_final,
            "rethlas_step": self._rethlas_step,
            "rethlas_inspect": self._rethlas_inspect,
            "rethlas_control": self._rethlas_control,
            "rethlas_artifact": self._rethlas_artifact,
        }

    def list_tools(self) -> list[dict[str, Any]]:
        return [TOOL_SPECS[name].definition(name) for name in PUBLIC_TOOL_NAMES]

    def call(
        self,
        name: str,
        arguments: Mapping[str, Any] | None,
        principal: OAuthPrincipal,
        *,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        handler = self._handlers.get(name)
        if handler is None:
            raise ReCTMError(
                "UNKNOWN_TOOL",
                f"Unknown tool: {name}",
                category="validation",
            )
        args = dict(arguments or {})
        self.debug.emit(
            "tool.call_started",
            "tool_runtime",
            trace_id=trace,
            decision="allow",
            reason="oauth_principal_and_registered_tool",
            details={
                "tool": name,
                "argument_keys": sorted(args),
                "client_id": principal.client_id,
            },
        )
        try:
            payload = handler(principal, args, trace)
            payload.setdefault("ok", True)
        except ReCTMError as exc:
            payload = {"ok": False, "error": exc.to_payload(), "trace_id": trace}
            self.debug.emit(
                "tool.call_failed",
                "tool_runtime",
                trace_id=trace,
                decision="deny" if exc.category in {"permission", "security"} else "error",
                reason=exc.code,
                details={"tool": name, "error": exc.to_payload()},
            )
            return _tool_result(name, payload, is_error=True)
        except Exception as exc:  # noqa: BLE001 - tool boundary must remain structured
            error = ReCTMError(
                "INTERNAL_ERROR",
                str(exc),
                category="internal",
                details={"exception_type": type(exc).__name__},
            )
            payload = {"ok": False, "error": error.to_payload(), "trace_id": trace}
            run_id = args.get("run_id")
            if isinstance(run_id, str) and run_id:
                try:
                    self.debug.write_last_error(
                        run_id,
                        {
                            "trace_id": trace,
                            "tool": name,
                            "error": error.to_payload(),
                            "argument_keys": sorted(args),
                        },
                    )
                except Exception:
                    pass
            self.debug.emit(
                "tool.call_failed",
                "tool_runtime",
                trace_id=trace,
                decision="error",
                reason="INTERNAL_ERROR",
                details={"tool": name, "error": error.to_payload()},
            )
            return _tool_result(name, payload, is_error=True)
        self.debug.emit(
            "tool.call_finished",
            "tool_runtime",
            trace_id=trace,
            decision="allow" if payload.get("ok") is not False else "deny",
            reason="tool_completed" if payload.get("ok") is not False else "tool_reported_denial",
            details={"tool": name, "result_keys": sorted(payload)},
        )
        return _tool_result(name, payload, is_error=payload.get("ok") is False)

    def _native(
        self,
        method_name: str,
    ) -> Callable[[OAuthPrincipal, dict[str, Any], str], dict[str, Any]]:
        def handler(
            principal: OAuthPrincipal,
            arguments: dict[str, Any],
            trace_id: str,
        ) -> dict[str, Any]:
            _ = principal
            method = getattr(self.native, method_name)
            return method(**{**arguments, "trace_id": trace_id}) if method_name == "exec_command" else method(**arguments)

        return handler

    def _server_info(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        _ = arguments
        exec_environment = self.native.check_exec_environment()
        native_info = self.native.server_info()
        global_tmp = str(exec_environment["global_tmp_write"])
        permission_mode = self.native.mode.value
        return {
            "server": "re-ctm",
            "title": "Re-CTM",
            "version": __version__,
            "supported_protocol_versions": ["2026-07-28", "2025-11-25", "2025-06-18"],
            "workspace": str(self.native.workspace.root),
            "permission_mode": permission_mode,
            "network_allowed": permission_mode != "safe",
            "runtime_dir": "/tmp",
            "home": "/home/re-ctm",
            "tmpdir": "/tmp",
            "cache_dir": "/tmp/cache",
            "auth_enabled": True,
            "dangerously_skip_all_permissions": permission_mode == "dangerous",
            "annotation_override": None,
            "landlock": {
                "available": False,
                "enabled": False,
                "abi_version": None,
                "replacement": "bubblewrap" if native_info.get("native_exec_backend") == "BubblewrapExecBackend" else None,
            },
            "exec_policy": {
                "shell_expansion": "blocked" if permission_mode == "safe" else "allowed",
                "inline_script": "blocked" if permission_mode == "safe" else "allowed",
                "global_tmp_write": global_tmp,
                "secret_env_filter": "disabled" if permission_mode == "dangerous" else "enabled",
            },
            "shell_env_inherit": "none",
            "shell_env_include_only": [],
            "shell_env_exclude": [],
            "output_retention": {
                "buffer_bytes_per_stream": COMMAND_BUFFER_BYTES,
                "head_bytes_per_stream": COMMAND_BUFFER_BYTES // COMMAND_HEAD_BUFFER_DIVISOR,
            },
            "endpoint_path": "/mcp",
            "project_context": {
                "root_instruction_files": [],
                "nested_instruction_files": [],
                "warnings": [],
            },
            "oauth_only": True,
            "oauth_client_id": principal.client_id,
            "tool_count": len(PUBLIC_TOOL_NAMES),
            "tools": list(PUBLIC_TOOL_NAMES),
            "ctm_native_tool_count": len(CTM_NATIVE_TOOL_NAMES),
            "rethlas_tool_count": len(RETHLAS_TOOL_NAMES),
            "ctm_native_tools": list(CTM_NATIVE_TOOL_NAMES),
            "rethlas_tools": list(RETHLAS_TOOL_NAMES),
            "hidden_legacy_rethlas_aliases": [
                name for name in LEGACY_RETHLAS_TOOL_NAMES if name not in RETHLAS_TOOL_NAMES
            ],
            "tool_catalog_stable": True,
            "mathematical_task_routing": (
                "Concrete proof, derivation, proof-repair, and rigorous verification tasks should start with rethlas_start unless the user explicitly requests a direct informal answer."
            ),
            "verified_latex_delivery": {
                "automatic_on_done": True,
                "default_workspace_path": "rethlas-output/<run_id>/proof_verified.tex",
                "explicit_alternate_export_tool": "rethlas_artifact",
            },
            "native": native_info,
            "authorization_axioms": {
                "native": "OAuth identity AND native mode",
                "workflow": "OAuth identity AND signed run capability AND role ACL AND workflow state",
                "non_inheritance": "native dangerous never implies workflow authority",
            },
            "complete_flow_locally_validated": False,
            "trace_id": trace_id,
        }

    def _rethlas_start(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        references = arguments.get("references") or []
        if not isinstance(references, list):
            raise invalid_argument("references must be an array")
        export_path = str(arguments.get("export_path") or "").strip()
        if export_path:
            if not export_path.lower().endswith(".tex"):
                raise invalid_argument("export_path must end in .tex", export_path=export_path)
            export_path = self.native.workspace.resolve_for_write(export_path).display
        return self.workflow.start(
            owner_id=principal.client_id,
            problem_tex=str(arguments.get("problem_tex") or ""),
            problem_id=str(arguments.get("problem_id") or "problem"),
            references=[item for item in references if isinstance(item, Mapping)],
            native_mode=self.native.mode.value,
            workspace_export_path=export_path or None,
            trace_id=trace_id,
        )

    def _rethlas_next(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        return self._attach_done_export_if_needed(
            principal,
            self.workflow.next_task(
                owner_id=principal.client_id,
                run_id=str(arguments.get("run_id") or ""),
                trace_id=trace_id,
            ),
            trace_id,
        )

    def _rethlas_read(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        return self.workflow.read(
            owner_id=principal.client_id,
            capability=str(arguments.get("capability") or ""),
            resource=str(arguments.get("resource") or ""),
            trace_id=trace_id,
        )

    def _rethlas_write(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        return self.workflow.write(
            owner_id=principal.client_id,
            capability=str(arguments.get("capability") or ""),
            resource=str(arguments.get("resource") or ""),
            content=arguments.get("content"),
            trace_id=trace_id,
        )

    def _rethlas_search(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        return self.workflow.search(
            owner_id=principal.client_id,
            capability=str(arguments.get("capability") or ""),
            resource=str(arguments.get("resource") or ""),
            query=str(arguments.get("query") or ""),
            limit=int(arguments.get("limit", 20)),
            trace_id=trace_id,
        )

    def _rethlas_retrieve(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        return self.workflow.retrieve(
            owner_id=principal.client_id,
            capability=str(arguments.get("capability") or ""),
            query=str(arguments.get("query") or ""),
            search_intent=str(arguments.get("search_intent") or "theorem"),
            num_results=int(arguments.get("num_results", 10)),
            trace_id=trace_id,
        )

    def _rethlas_commit(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        payload = arguments.get("payload") or {}
        if not isinstance(payload, Mapping):
            raise invalid_argument("payload must be an object")
        return self.workflow.commit(
            owner_id=principal.client_id,
            capability=str(arguments.get("capability") or ""),
            action=str(arguments.get("action") or ""),
            payload=payload,
            trace_id=trace_id,
        )

    def _recoverable_rethlas_step(
        self,
        *,
        principal: OAuthPrincipal,
        run_id: str,
        capability: str,
        error: ReCTMError,
        write_results: list[dict[str, Any]],
        trace_id: str,
        failed_write: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        current = self.workflow.next_task(
            owner_id=principal.client_id,
            run_id=run_id,
            trace_id=trace_id,
        )
        self.workflow.capabilities.revoke(
            capability,
            "superseded_by_recoverable_step",
            trace_id=trace_id,
        )
        error_payload = error.to_payload()
        error_payload["retryable"] = True
        submission: dict[str, Any] = {
            "ok": False,
            "complete": False,
            "recoverable": True,
            "retryable": True,
            "error": error_payload,
            "writes_retained": bool(write_results),
            "correction": (
                "Use the fresh capability in this response and follow the returned task write_contract and "
                "commit_payload_schema. Do not replay retained writes unless a genuinely new logical record is needed."
            ),
        }
        if failed_write is not None:
            submission["failed_write"] = dict(failed_write)
        return {
            **current,
            "submission": submission,
            "writes_applied": len(write_results),
        }

    def _rethlas_step(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        run_id = str(arguments.get("run_id") or "")
        capability = str(arguments.get("capability") or "")
        writes = arguments.get("writes") or []
        action = str(arguments.get("action") or "")
        payload = arguments.get("payload") or {}
        if not isinstance(writes, list):
            raise invalid_argument("writes must be an array")
        if not isinstance(payload, Mapping):
            raise invalid_argument("payload must be an object")
        if not action and not writes and not capability:
            return self._attach_done_export_if_needed(
                principal,
                self.workflow.next_task(
                    owner_id=principal.client_id,
                    run_id=run_id,
                    trace_id=trace_id,
                ),
                trace_id,
            )
        if not capability:
            raise invalid_argument("capability is required when submitting a Rethlas step")
        if writes and not action:
            raise invalid_argument("action is required when writes are submitted")
        write_results: list[dict[str, Any]] = []
        for index, item in enumerate(writes):
            try:
                if not isinstance(item, Mapping):
                    raise invalid_argument("each write must be an object")
                write_results.append(
                    self.workflow.write(
                        owner_id=principal.client_id,
                        capability=capability,
                        resource=str(item.get("resource") or ""),
                        content=item.get("content"),
                        trace_id=trace_id,
                    )
                )
            except ReCTMError as exc:
                if exc.category not in {"validation", "conflict"}:
                    raise
                failed_resource = (
                    str(item.get("resource") or "")
                    if isinstance(item, Mapping)
                    else ""
                )
                return self._recoverable_rethlas_step(
                    principal=principal,
                    run_id=run_id,
                    capability=capability,
                    error=exc,
                    write_results=write_results,
                    trace_id=trace_id,
                    failed_write={"index": index, "resource": failed_resource},
                )
        if not action:
            raise invalid_argument("action is required to complete a Rethlas step")
        try:
            submission = self.workflow.commit(
                owner_id=principal.client_id,
                capability=capability,
                action=action,
                payload=payload,
                trace_id=trace_id,
            )
        except ReCTMError as exc:
            if exc.category not in {"validation", "conflict"}:
                raise
            return self._recoverable_rethlas_step(
                principal=principal,
                run_id=run_id,
                capability=capability,
                error=exc,
                write_results=write_results,
                trace_id=trace_id,
            )
        next_task = self._attach_done_export_if_needed(
            principal,
            self.workflow.next_task(
                owner_id=principal.client_id,
                run_id=run_id,
                trace_id=trace_id,
            ),
            trace_id,
        )
        self.workflow.capabilities.revoke(
            capability,
            "superseded_by_rethlas_step",
            trace_id=trace_id,
        )
        return {**next_task, "submission": submission, "writes_applied": len(write_results)}

    def _rethlas_inspect(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        operation = str(arguments.get("operation") or "")
        if operation == "status":
            return self.workflow.status(
                owner_id=principal.client_id,
                run_id=str(arguments.get("run_id") or ""),
            )
        capability = str(arguments.get("capability") or "")
        resource = str(arguments.get("resource") or "")
        if operation == "read":
            return self.workflow.read(
                owner_id=principal.client_id,
                capability=capability,
                resource=resource,
                trace_id=trace_id,
            )
        if operation == "search":
            return self.workflow.search(
                owner_id=principal.client_id,
                capability=capability,
                resource=resource,
                query=str(arguments.get("query") or ""),
                limit=int(arguments.get("limit", 20)),
                trace_id=trace_id,
            )
        raise invalid_argument("operation must be status, read, or search")

    def _rethlas_control(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        action = str(arguments.get("action") or "")
        run_id = str(arguments.get("run_id") or "")
        if action == "steer":
            return self.workflow.steer(
                owner_id=principal.client_id,
                run_id=run_id,
                message=str(arguments.get("message") or ""),
                trace_id=trace_id,
            )
        if action == "cancel":
            return self.workflow.cancel(
                owner_id=principal.client_id,
                run_id=run_id,
                reason=str(arguments.get("reason") or "user_cancelled"),
                trace_id=trace_id,
            )
        raise invalid_argument("action must be steer or cancel")

    def _rethlas_artifact(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        action = str(arguments.get("action") or "")
        run_id = str(arguments.get("run_id") or "")
        if action == "get":
            return self.workflow.get_artifact(
                owner_id=principal.client_id,
                run_id=run_id,
                artifact=str(arguments.get("artifact") or "final_tex"),
            )
        if action == "export":
            return self._rethlas_export_final(principal, arguments, trace_id)
        raise invalid_argument("action must be get or export")

    def _rethlas_status(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        _ = trace_id
        return self.workflow.status(
            owner_id=principal.client_id,
            run_id=str(arguments.get("run_id") or ""),
        )

    def _rethlas_steer(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        return self.workflow.steer(
            owner_id=principal.client_id,
            run_id=str(arguments.get("run_id") or ""),
            message=str(arguments.get("message") or ""),
            trace_id=trace_id,
        )

    def _rethlas_resume(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        _ = trace_id
        return self.workflow.resume(
            owner_id=principal.client_id,
            run_id=str(arguments.get("run_id") or ""),
        )

    def _rethlas_cancel(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        return self.workflow.cancel(
            owner_id=principal.client_id,
            run_id=str(arguments.get("run_id") or ""),
            reason=str(arguments.get("reason") or "user_cancelled"),
            trace_id=trace_id,
        )

    def _rethlas_get_artifact(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        _ = trace_id
        return self.workflow.get_artifact(
            owner_id=principal.client_id,
            run_id=str(arguments.get("run_id") or ""),
            artifact=str(arguments.get("artifact") or ""),
        )

    def _rethlas_export_final(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        run_id = str(arguments.get("run_id") or "")
        artifact = self.workflow.get_artifact(
            owner_id=principal.client_id,
            run_id=run_id,
            artifact="final_tex",
        )
        requested_path = str(arguments.get("path") or "").strip()
        if requested_path:
            export_path = requested_path
            export = self.native.export_verified_latex(
                path=export_path,
                content=str(artifact["content"]),
                expected_sha256=(
                    str(arguments["expected_sha256"])
                    if arguments.get("expected_sha256") is not None
                    else None
                ),
                trace_id=trace_id,
            )
        else:
            export_path = str(
                artifact.get("workspace_export_path")
                or f"rethlas-output/{run_id}/proof_verified.tex"
            )
            export = self.native.ensure_verified_latex(
                path=export_path,
                content=str(artifact["content"]),
                trace_id=trace_id,
            )
        return {
            "ok": True,
            "run_id": run_id,
            "artifact": "final_tex",
            "workspace_export_path": export_path,
            "export": export,
            "workflow_authority_inherited_by_native": False,
        }

    def _attach_done_export_if_needed(
        self,
        principal: OAuthPrincipal,
        result: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        if result.get("state") == "done" and result.get("terminal") is True:
            return self._attach_automatic_final_export(
                principal=principal,
                result=result,
                trace_id=trace_id,
            )
        return result

    def _attach_automatic_final_export(
        self,
        *,
        principal: OAuthPrincipal,
        result: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        run_id = str(result.get("run_id") or "")
        artifact = self.workflow.get_artifact(
            owner_id=principal.client_id,
            run_id=run_id,
            artifact="final_tex",
        )
        export_path = str(
            result.get("workspace_export_path")
            or artifact.get("workspace_export_path")
            or f"rethlas-output/{run_id}/proof_verified.tex"
        )
        try:
            export = self.native.ensure_verified_latex(
                path=export_path,
                content=str(artifact["content"]),
                trace_id=trace_id,
            )
        except ReCTMError as exc:
            return {
                **result,
                "workspace_export_path": export_path,
                "workspace_export": {"ok": False, "error": exc.to_payload()},
                "final_artifact_available": True,
            }
        return {
            **result,
            "workspace_export_path": export_path,
            "workspace_export": export,
            "final_artifact_available": True,
            "workflow_authority_inherited_by_native": False,
        }


def _tool_result(name: str, payload: dict[str, Any], *, is_error: bool) -> dict[str, Any]:
    structured = dict(payload)
    image_data = structured.pop("_mcp_image_data", None)
    if is_error:
        error = structured.get("error") or {}
        text = f"{error.get('code', 'TOOL_ERROR')}: {error.get('message', 'Tool failed.')}"
    else:
        text = _render_summary(name, structured)
    content: list[dict[str, Any]] = [{"type": "text", "text": text}]
    if name == "view_image" and isinstance(image_data, str) and image_data:
        content.append(
            {
                "type": "image",
                "data": image_data,
                "mimeType": str(structured.get("mime_type", "application/octet-stream")),
            }
        )
    return {
        "content": content,
        "structuredContent": structured,
        "isError": is_error,
    }


def _render_summary(name: str, payload: Mapping[str, Any]) -> str:
    if name == "rethlas_start":
        return (
            f"Run {payload.get('run_id')} started; verified LaTeX will be written to "
            f"{payload.get('workspace_export_path')} when the workflow reaches done."
        )
    if name in {"rethlas_step", "rethlas_next"}:
        submission = payload.get("submission")
        if name == "rethlas_step" and isinstance(submission, Mapping) and isinstance(submission.get("error"), Mapping):
            error = submission["error"]
            retained = (
                " Successful logical writes were retained; do not replay them."
                if submission.get("writes_retained")
                else ""
            )
            recovery = (
                " Continue with the fresh capability and the returned task contract."
                if submission.get("recoverable")
                else ""
            )
            return (
                f"Run {payload.get('run_id')} remains in {payload.get('state')}; submission needs correction: "
                f"{error.get('code')}: {error.get('message')}.{retained}{recovery}"
            )
        if name == "rethlas_step" and isinstance(submission, Mapping) and submission.get("complete") is False:
            missing = submission.get("missing_screening") or []
            missing_ids = [
                f"{item.get('plan_id')}.{item.get('subgoal_id')}"
                for item in missing
                if isinstance(item, Mapping)
            ]
            return (
                f"Run {payload.get('run_id')} remains in direct_proving; accepted screening progress. "
                f"Still missing: {', '.join(missing_ids) or 'see structuredContent'}."
            )
        if payload.get("state") == "done":
            export = payload.get("workspace_export")
            if isinstance(export, Mapping) and export.get("ok"):
                return (
                    f"Run {payload.get('run_id')} is done and the verified LaTeX was written to "
                    f"{payload.get('workspace_export_path')}."
                )
            return (
                f"Run {payload.get('run_id')} is done; final LaTeX is available, but automatic "
                f"workspace export needs attention at {payload.get('workspace_export_path')}."
            )
        return f"Run {payload.get('run_id')} is in {payload.get('state')} for role {payload.get('role', 'none')}."
    if name in {"rethlas_inspect", "rethlas_status"} and payload.get("state"):
        return f"Run {payload.get('run_id')}: {payload.get('state')} ({payload.get('status')})."
    if name == "rethlas_get_artifact" and payload.get("artifact") == "final_tex":
        return (
            f"Final verified LaTeX for run {payload.get('run_id')} is available; workspace path: "
            f"{payload.get('workspace_export_path')}."
        )
    if name == "server_info":
        return f"Re-CTM {payload.get('version')} with {payload.get('tool_count')} fixed tools."
    summary = payload.get("summary")
    if isinstance(summary, str) and summary:
        return summary
    return f"{name} completed."
