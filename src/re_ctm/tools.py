from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import __version__
from .debug import DebugEventBus, new_trace_id
from .errors import ReCTMError, invalid_argument
from .native import NativeRuntime
from .oauth import OAuthPrincipal
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

RETHLAS_TOOL_NAMES = (
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
        "Start Rethlas workflow",
        "Create a private mathematical reasoning run from a LaTeX problem statement and optional inline references.",
        {
            **OBJECT,
            "required": ["problem_tex"],
            "properties": {
                "problem_tex": {"type": "string", "minLength": 1},
                "problem_id": {"type": "string"},
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
        destructive=True,
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
        read_only=True,
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
        "Copy the mechanically finalized proof_verified.tex into a workspace-relative .tex path through the controlled trust-domain bridge.",
        {
            **OBJECT,
            "required": ["run_id", "path"],
            "properties": {
                "run_id": {"type": "string"},
                "path": {"type": "string", "minLength": 1},
                "expected_sha256": {"type": "string"},
            },
        },
        destructive=True,
    ),
}

if tuple(TOOL_SPECS) != CTM_NATIVE_TOOL_NAMES + RETHLAS_TOOL_NAMES:
    raise RuntimeError("Re-CTM fixed tool catalog must remain CTM 18-tool compatible plus Rethlas tools")


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
        }

    def list_tools(self) -> list[dict[str, Any]]:
        return [spec.definition(name) for name, spec in TOOL_SPECS.items()]

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
                "buffer_bytes_per_stream": 524288,
                "head_bytes_per_stream": 65536,
            },
            "endpoint_path": "/mcp",
            "project_context": {
                "root_instruction_files": [],
                "nested_instruction_files": [],
                "warnings": [],
            },
            "oauth_only": True,
            "oauth_client_id": principal.client_id,
            "tool_count": len(TOOL_SPECS),
            "tools": list(TOOL_SPECS),
            "ctm_native_tool_count": len(CTM_NATIVE_TOOL_NAMES),
            "rethlas_tool_count": len(RETHLAS_TOOL_NAMES),
            "ctm_native_tools": list(CTM_NATIVE_TOOL_NAMES),
            "tool_catalog_stable": True,
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
        return self.workflow.start(
            owner_id=principal.client_id,
            problem_tex=str(arguments.get("problem_tex") or ""),
            problem_id=str(arguments.get("problem_id") or "problem"),
            references=[item for item in references if isinstance(item, Mapping)],
            native_mode=self.native.mode.value,
            trace_id=trace_id,
        )

    def _rethlas_next(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        return self.workflow.next_task(
            owner_id=principal.client_id,
            run_id=str(arguments.get("run_id") or ""),
            trace_id=trace_id,
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
        export = self.native.export_verified_latex(
            path=str(arguments.get("path") or ""),
            content=str(artifact["content"]),
            expected_sha256=(
                str(arguments["expected_sha256"])
                if arguments.get("expected_sha256") is not None
                else None
            ),
            trace_id=trace_id,
        )
        return {
            "ok": True,
            "run_id": run_id,
            "artifact": "final_tex",
            "export": export,
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
    if name == "rethlas_next":
        return f"Run {payload.get('run_id')} is in {payload.get('state')} for role {payload.get('role', 'none')}."
    if name == "rethlas_status":
        return f"Run {payload.get('run_id')}: {payload.get('state')} ({payload.get('status')})."
    if name == "server_info":
        return f"Re-CTM {payload.get('version')} with {payload.get('tool_count')} fixed tools."
    summary = payload.get("summary")
    if isinstance(summary, str) and summary:
        return summary
    return f"{name} completed."
