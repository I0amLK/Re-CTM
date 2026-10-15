from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import __version__
from .debug import DebugEventBus, new_trace_id
from .errors import ReCTMError, invalid_argument
from .latex import static_latex_errors
from .native import NativeRuntime
from .native_catalog import NATIVE_TOOL_DECLARATIONS, NATIVE_TOOL_NAMES, TOOL_CONTRACT_VERSION
from .oauth import OAuthPrincipal
from .processes import COMMAND_BUFFER_BYTES, COMMAND_HEAD_BUFFER_DIVISOR
from .rethlas_contracts import (
    ARTIFACT_EXPORT,
    ARTIFACT_GET,
    CAPABILITY_INPUT_SCHEMA,
    CONTROL_ACTIONS,
    CONTROL_CANCEL,
    CONTROL_CLAIM_CREATE,
    CONTROL_CLAIM_REVISE,
    CONTROL_DEFAULT_CANCEL_REASON,
    CONTROL_PROJECT_CREATE,
    CONTROL_STEER,
    HIDDEN_LEGACY_ALIAS_SEMANTICS,
    INSPECT_CLAIM,
    INSPECT_DEPENDENCY_GRAPH,
    INSPECT_DEFAULT_PROJECTS_LIMIT,
    INSPECT_DEFAULT_SEARCH_LIMIT,
    INSPECT_DEFAULT_THEOREM_SEARCH_LIMIT,
    INSPECT_OPERATIONS,
    INSPECT_PROJECTS,
    INSPECT_PROJECT_STATUS,
    INSPECT_READ,
    INSPECT_REFERENCE_AUDIT,
    INSPECT_SEARCH,
    INSPECT_STATUS,
    INSPECT_THEOREM_SEARCH,
    LEGACY_RETHLAS_TOOL_NAMES,
    PROJECT_ARTIFACTS,
    RETRIEVE_DEFAULT_NUM_RESULTS,
    RETRIEVE_DEFAULT_OPERATION,
    RETRIEVE_DEFAULT_SEARCH_INTENT,
    RETHLAS_TOOL_NAMES,
    START_DEFAULT_PROBLEM_ID,
    START_DEFAULT_REGISTER_RESULT,
    START_DEFAULT_WORKFLOW_MODE,
    facade_schema,
)
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
    output_schema: dict[str, Any] | None = None

    def definition(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema or tool_output_schema(),
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

CTM_NATIVE_TOOL_NAMES = NATIVE_TOOL_NAMES

PUBLIC_TOOL_NAMES = CTM_NATIVE_TOOL_NAMES + RETHLAS_TOOL_NAMES


FACADE_TOOL_SPECS: dict[str, ToolSpec] = {
    'rethlas_start': ToolSpec(
        "Start verified mathematical workflow",
        "Call this first for every concrete mathematical proof, derivation, or verification task unless the user explicitly asks for a direct informal answer. Create a private Rethlas reasoning run; continue with rethlas_step until verification and automatic proof_verified.tex workspace delivery complete.",
        facade_schema("rethlas_start"),
    ),
    'rethlas_step': ToolSpec(
        "Advance Rethlas workflow",
        "Issue the current Rethlas task, or submit its logical writes plus commit payload and immediately return the next task. Always copy run_id and capability verbatim from the same current task envelope; capability is opaque and must never be decoded, edited, normalized, concatenated, or synthesized. Always follow the returned task.write_contract, task.commit_payload_schema, and task minimal/example submission instead of guessing JSON shapes. Each memory write is one JSON object unless the current write_contract explicitly says otherwise. Recoverable validation/conflict corrections return a fresh capability and identify whether earlier writes were retained. Incomplete screening is accepted in place and returns exact missing plan/subgoal ids instead of failing the run.",
        facade_schema("rethlas_step"),
        destructive=True,
    ),
    'rethlas_inspect': ToolSpec(
        "Inspect Rethlas run",
        "Inspect public run status or capability-authorized logical resources/memory without changing workflow state.",
        facade_schema("rethlas_inspect"),
        read_only=True,
    ),
    'rethlas_retrieve': ToolSpec(
        "Retrieve external mathematical research",
        "Use one capability-gated research façade for theorem search, paper discovery/lookup, or stored theorem context. External providers are fixed HTTPS trust domains with bounded responses; returned references remain unverified until verifier audit.",
        facade_schema("rethlas_retrieve"),
        read_only=False,
        destructive=False,
        open_world=True,
    ),
    'rethlas_control': ToolSpec(
        "Control Rethlas run or project",
        "Queue owner steering/cancellation for a run, or create owner-scoped research projects and claims. Verified claim revisions remain finalizer-only and cannot be minted through this tool.",
        facade_schema("rethlas_control"),
        destructive=True,
    ),
    'rethlas_artifact': ToolSpec(
        "Read or export Rethlas artifact",
        "Return/export run artifacts or portable owner project manifests/summaries. Final proof export never bypasses the mechanical verification gate, and project artifacts never expose private reasoning memory.",
        facade_schema("rethlas_artifact"),
        destructive=True,
    ),
}

# Native declarations and facade declarations each have one current authority.
TOOL_SPECS = {
    **{
        declaration["name"]: ToolSpec(
            title=declaration["title"], description=declaration["description"],
            input_schema=declaration["inputSchema"],
            read_only=declaration["annotations"]["readOnlyHint"],
            destructive=declaration["annotations"]["destructiveHint"],
            open_world=declaration["annotations"]["openWorldHint"],
            idempotent=declaration["annotations"]["idempotentHint"],
            output_schema=declaration["outputSchema"],
        ) for declaration in NATIVE_TOOL_DECLARATIONS
    },
    **FACADE_TOOL_SPECS,
}
if tuple(TOOL_SPECS) != PUBLIC_TOOL_NAMES:
    raise RuntimeError("Public catalog must be exactly Native v11 followed by six workflow tools")


def validate_tool_arguments(name: str, arguments: Mapping[str, Any]) -> None:
    spec = TOOL_SPECS.get(name)
    if spec is None:
        raise ReCTMError("UNKNOWN_TOOL", f"Unknown tool: {name}", category="validation")
    _validate_schema_value(dict(arguments), spec.input_schema, path="arguments")


def _validate_schema_value(value: Any, schema: Mapping[str, Any], *, path: str) -> None:
    for candidate in schema.get("allOf", []):
        if isinstance(candidate, Mapping):
            _validate_schema_value(value, candidate, path=path)
    condition = schema.get("if")
    if isinstance(condition, Mapping):
        branch = schema.get("then" if _schema_matches(value, condition, path=path) else "else")
        if isinstance(branch, Mapping):
            _validate_schema_value(value, branch, path=path)
    if isinstance(schema.get("not"), Mapping) and _schema_matches(value, schema["not"], path=path):
        raise invalid_argument(f"{path} matches a forbidden schema")
    if "enum" in schema and value not in schema["enum"]:
        raise invalid_argument(f"{path} must be one of {schema['enum']!r}")
    if "const" in schema and value != schema["const"]:
        raise invalid_argument(f"{path} must equal {schema['const']!r}")
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        matches = sum(
            1 for candidate in one_of
            if isinstance(candidate, Mapping) and _schema_matches(value, candidate, path=path)
        )
        if matches != 1:
            raise invalid_argument(f"{path} must match exactly one oneOf schema")
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and not any(
        isinstance(candidate, Mapping) and _schema_matches(value, candidate, path=path)
        for candidate in any_of
    ):
        raise invalid_argument(f"{path} must match at least one anyOf schema")
    expected_type = schema.get("type")
    if expected_type is not None and not _schema_type_matches(value, expected_type):
        raise invalid_argument(f"{path} must be {_schema_type_name(expected_type)}")
    if isinstance(value, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(value) < minimum:
            raise invalid_argument(f"{path} is shorter than {minimum}")
        maximum = schema.get("maxLength")
        if isinstance(maximum, int) and len(value) > maximum:
            raise invalid_argument(f"{path} is longer than {maximum}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            import re

            if re.fullmatch(pattern, value) is None:
                raise invalid_argument(f"{path} does not match the required pattern")
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
        maximum_items = schema.get("maxItems")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            raise invalid_argument(f"{path} must contain at most {maximum_items} items")
        if schema.get("uniqueItems") and any(item == previous for index, item in enumerate(value) for previous in value[:index]):
            raise invalid_argument(f"{path} must contain unique items")
        prefix = schema.get("prefixItems", [])
        for index, prefix_schema in enumerate(prefix if isinstance(prefix, list) else []):
            if index < len(value) and isinstance(prefix_schema, Mapping):
                _validate_schema_value(value[index], prefix_schema, path=f"{path}[{index}]")
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
        for key, dependencies in schema.get("dependentRequired", {}).items():
            if key in value:
                for dependency in dependencies:
                    if dependency not in value:
                        raise invalid_argument(f"{path}.{key} requires {dependency}")
        for bound, compare in (("minProperties", lambda n: len(value) < n), ("maxProperties", lambda n: len(value) > n)):
            if isinstance(schema.get(bound), int) and compare(schema[bound]):
                raise invalid_argument(f"{path} violates {bound}")
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


def _schema_matches(value: Any, schema: Mapping[str, Any], *, path: str) -> bool:
    try:
        _validate_schema_value(value, schema, path=path)
    except ReCTMError:
        return False
    return True


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
        *, workflow_protocol_version: int = 3,
    ) -> None:
        self.workflow_protocol_version = workflow_protocol_version
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
            "apply_changes": self._native("apply_changes"),
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
            "rethlas_retrieve": self._rethlas_retrieve,
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
            # ToolRuntime is also used directly by tests and embedding callers. Keep
            # the same schema boundary here as MCPDispatcher so no caller can reach
            # a handler with arguments that tools/list says are invalid.
            validate_tool_arguments(name, args)
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
        # A successful transport response can still contain a rejected logical
        # submission. Keep that outcome visible in compact operator output.
        event_type = "tool.call_finished"
        decision = "allow"
        reason = "tool_completed"
        details: dict[str, Any] = {"tool": name, "result_keys": sorted(payload)}
        if payload.get("ok") is False:
            event_type = "tool.call_failed"
            decision = "deny"
            reason = "tool_reported_denial"
            error = payload.get("error")
            if isinstance(error, Mapping):
                details["error"] = {"code": error.get("code")}
        else:
            submission = payload.get("submission")
            if (
                isinstance(submission, Mapping)
                and submission.get("ok") is False
                and isinstance(submission.get("error"), Mapping)
            ):
                event_type = "tool.call_submission_rejected"
                decision = "defer"
                reason = "submission_needs_correction"
                details["error"] = {"code": submission["error"].get("code")}
        self.debug.emit(
            event_type,
            "tool_runtime",
            trace_id=trace,
            decision=decision,
            reason=reason,
            details=details,
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
            method = getattr(self.native, method_name)
            if method_name in {"apply_patch", "apply_changes"}:
                return method(**arguments, principal_scope={"subject": principal.subject, "client_id": principal.client_id, "scope": principal.scope})
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
                "completed_ttl_seconds": 300,
                "max_completed_commands": 32,
            },
            "workspace_mutation_policy": {
                "mode": "unrestricted", "structured_only_supported": False,
                "structured_write_tools": ["apply_patch", "apply_changes"],
                "enforced_by": "bubblewrap" if native_info.get("native_exec_backend") == "BubblewrapExecBackend" else "workspace_path_checks",
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
            "native_tool_count": len(CTM_NATIVE_TOOL_NAMES),
            "rethlas_tool_count": len(RETHLAS_TOOL_NAMES),
            "native_tools": list(CTM_NATIVE_TOOL_NAMES),
            "rethlas_tools": list(RETHLAS_TOOL_NAMES),
            "hidden_alias_count": 0,
            "tool_contract_version": TOOL_CONTRACT_VERSION,
            "tool_catalog_stable": True,
            "mathematical_task_routing": (
                "Concrete proof, derivation, proof-repair, and rigorous verification tasks should start with rethlas_start unless the user explicitly requests a direct informal answer."
            ),
            "verified_latex_delivery": {
                "automatic_on_done": True,
                "default_workspace_path": "rethlas-output/<run_id>/proof_verified.tex",
                "explicit_alternate_export_tool": "rethlas_artifact",
            },
            "research_workspace": {
                "state_schema_version": self.workflow.store.schema_version(),
                "workflow_protocol_version": self.workflow_protocol_version,
                "project_registry": True,
                "compact_verified_lane": True,
                "proof_manifest": True,
                "reference_audit": True,
                "paper_search_provider": "https://api.openalex.org/works",
                "verified_promotion_is_finalizer_only": True,
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
            problem_id=str(arguments.get("problem_id") or START_DEFAULT_PROBLEM_ID),
            references=[item for item in references if isinstance(item, Mapping)],
            native_mode=self.native.mode.value,
            workspace_export_path=export_path or None,
            project_id=(str(arguments.get("project_id") or "").strip() or None),
            target_claim_id=(str(arguments.get("target_claim_id") or "").strip() or None),
            workflow_mode=str(arguments.get("workflow_mode") or START_DEFAULT_WORKFLOW_MODE),
            register_result=bool(arguments.get("register_result", START_DEFAULT_REGISTER_RESULT)),
            workflow_protocol_version=self.workflow_protocol_version,
            creation_key=arguments.get("creation_key"),
            workspace_identity=str(self.native.workspace.root),
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
            operation=str(arguments.get("operation") or RETRIEVE_DEFAULT_OPERATION),
            author=str(arguments.get("author") or ""),
            title=str(arguments.get("title") or ""),
            keywords=str(arguments.get("keywords") or ""),
            search_intent=str(
                arguments.get("search_intent") or RETRIEVE_DEFAULT_SEARCH_INTENT
            ),
            num_results=int(arguments.get("num_results", RETRIEVE_DEFAULT_NUM_RESULTS)),
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

    def _rethlas_step(self, principal: OAuthPrincipal, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
        from .workflow_submission import step
        return step(self, principal, arguments, trace_id)

    def _rethlas_inspect(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        operation = str(arguments.get("operation") or "")
        if operation == INSPECT_STATUS:
            return self.workflow.status(
                owner_id=principal.client_id,
                run_id=str(arguments.get("run_id") or ""),
            )
        capability = str(arguments.get("capability") or "")
        resource = str(arguments.get("resource") or "")
        if operation == INSPECT_READ:
            return self.workflow.read(
                owner_id=principal.client_id,
                capability=capability,
                resource=resource,
                trace_id=trace_id,
            )
        if operation == INSPECT_SEARCH:
            return self.workflow.search(
                owner_id=principal.client_id,
                capability=capability,
                resource=resource,
                query=str(arguments.get("query") or ""),
                limit=int(arguments.get("limit", INSPECT_DEFAULT_SEARCH_LIMIT)),
                trace_id=trace_id,
            )
        if operation == INSPECT_PROJECTS:
            return {
                "ok": True,
                "projects": self.workflow.store.list_projects(
                    principal.client_id,
                    limit=int(arguments.get("limit", INSPECT_DEFAULT_PROJECTS_LIMIT)),
                ),
            }
        if operation == INSPECT_PROJECT_STATUS:
            project_id = str(arguments.get("project_id") or "")
            return {
                "ok": True,
                **self.workflow.store.project_dependency_graph(
                    project_id,
                    owner_id=principal.client_id,
                ),
            }
        if operation == INSPECT_CLAIM:
            claim_id = str(arguments.get("claim_id") or "")
            claim = self.workflow.store.get_claim(claim_id, owner_id=principal.client_id)
            return {
                "ok": True,
                "claim": claim,
                "revisions": self.workflow.store.list_claim_revisions(
                    claim_id,
                    owner_id=principal.client_id,
                ),
            }
        if operation == INSPECT_DEPENDENCY_GRAPH:
            return {
                "ok": True,
                **self.workflow.store.project_dependency_graph(
                    str(arguments.get("project_id") or ""),
                    owner_id=principal.client_id,
                ),
            }
        if operation == INSPECT_REFERENCE_AUDIT:
            run_id = str(arguments.get("run_id") or "")
            self.workflow.status(owner_id=principal.client_id, run_id=run_id)
            references = self.workflow.store.list_run_references(run_id)
            return {
                "ok": True,
                "run_id": run_id,
                "references": [
                    {
                        **reference,
                        "source_snapshots": [
                            {
                                "source_snapshot_id": snapshot["source_snapshot_id"],
                                "provider": snapshot["provider"],
                                "source_uri": snapshot["source_uri"],
                                "content_sha256": snapshot["content_sha256"],
                                "content_type": snapshot["content_type"],
                            }
                            for snapshot in self.workflow.store.list_source_snapshots(
                                reference["reference_id"]
                            )
                        ],
                    }
                    for reference in references
                ],
                "audits": self.workflow.store.list_reference_audits(run_id),
            }
        if operation == INSPECT_THEOREM_SEARCH:
            project_id = str(arguments.get("project_id") or "")
            query = str(arguments.get("query") or "").strip().lower()
            if not query:
                raise invalid_argument("query is required for theorem_search")
            graph = self.workflow.store.project_dependency_graph(project_id, owner_id=principal.client_id)
            matches = []
            for revision in graph["revisions"]:
                claim = next((item for item in graph["claims"] if item["claim_id"] == revision["claim_id"]), {})
                haystack = " ".join(
                    [
                        str(claim.get("title") or ""),
                        str(revision.get("statement_tex") or ""),
                        " ".join(str(item) for item in revision.get("conditions", [])),
                    ]
                ).lower()
                if query in haystack:
                    matches.append({"claim": claim, "revision": revision})
            return {
                "ok": True,
                "project_id": project_id,
                "query": query,
                "results": matches[
                    : int(arguments.get("limit", INSPECT_DEFAULT_THEOREM_SEARCH_LIMIT))
                ],
            }
        raise invalid_argument(
            f"operation must be one of {', '.join(INSPECT_OPERATIONS)}"
        )

    def _rethlas_control(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        action = str(arguments.get("action") or "")
        run_id = str(arguments.get("run_id") or "")
        if action == CONTROL_STEER:
            return self.workflow.steer(
                owner_id=principal.client_id,
                run_id=run_id,
                message=str(arguments.get("message") or ""),
                trace_id=trace_id,
            )
        if action == CONTROL_CANCEL:
            return self.workflow.cancel(
                owner_id=principal.client_id,
                run_id=run_id,
                reason=str(arguments.get("reason") or CONTROL_DEFAULT_CANCEL_REASON),
                trace_id=trace_id,
            )
        if action == CONTROL_PROJECT_CREATE:
            project = self.workflow.store.create_project(
                owner_id=principal.client_id,
                title=str(arguments.get("title") or ""),
                project_id=(str(arguments.get("project_id") or "").strip() or None),
                metadata=(arguments.get("metadata") if isinstance(arguments.get("metadata"), Mapping) else {}),
            )
            return {"ok": True, "project": project}
        if action == CONTROL_CLAIM_CREATE:
            claim = self.workflow.store.create_claim(
                owner_id=principal.client_id,
                project_id=str(arguments.get("project_id") or ""),
                title=str(arguments.get("title") or ""),
                claim_id=(str(arguments.get("claim_id") or "").strip() or None),
                metadata=(arguments.get("metadata") if isinstance(arguments.get("metadata"), Mapping) else {}),
            )
            statement_tex = str(arguments.get("statement_tex") or "").strip()
            revision = None
            if statement_tex:
                conditions = arguments.get("conditions") or []
                if not isinstance(conditions, list):
                    raise invalid_argument("conditions must be an array")
                revision = self.workflow.store.create_open_claim_revision(
                    owner_id=principal.client_id,
                    claim_id=claim["claim_id"],
                    statement_tex=statement_tex,
                    conditions=[str(item) for item in conditions],
                )
            return {"ok": True, "claim": claim, "revision": revision}
        if action == CONTROL_CLAIM_REVISE:
            conditions = arguments.get("conditions") or []
            if not isinstance(conditions, list):
                raise invalid_argument("conditions must be an array")
            revision = self.workflow.store.create_open_claim_revision(
                owner_id=principal.client_id,
                claim_id=str(arguments.get("claim_id") or ""),
                statement_tex=str(arguments.get("statement_tex") or ""),
                conditions=[str(item) for item in conditions],
                expected_base_revision_id=(str(arguments.get("expected_base_revision_id") or "").strip() or None),
            )
            return {"ok": True, "revision": revision}
        raise invalid_argument(f"action must be one of {', '.join(CONTROL_ACTIONS)}")

    def _rethlas_artifact(
        self,
        principal: OAuthPrincipal,
        arguments: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        action = str(arguments.get("action") or "")
        run_id = str(arguments.get("run_id") or "")
        project_id = str(arguments.get("project_id") or "")
        artifact_name = str(arguments.get("artifact") or "")
        if action == ARTIFACT_GET:
            if artifact_name in PROJECT_ARTIFACTS:
                return self._project_artifact(
                    principal,
                    project_id=project_id,
                    artifact=artifact_name,
                )
            return self.workflow.get_artifact(
                owner_id=principal.client_id,
                run_id=run_id,
                artifact=artifact_name,
            )
        if action == ARTIFACT_EXPORT:
            if artifact_name in PROJECT_ARTIFACTS:
                artifact = self._project_artifact(
                    principal,
                    project_id=project_id,
                    artifact=artifact_name,
                )
                path = str(arguments.get("path") or "").strip()
                if not path:
                    suffix = "project_manifest.json" if artifact_name == "project_manifest" else "project_summary.tex"
                    path = f"rethlas-projects/{project_id}/{suffix}"
                content = artifact["content"]
                text = (
                    json.dumps(content, ensure_ascii=False, indent=2) + "\n"
                    if artifact_name == "project_manifest"
                    else str(content)
                )
                export = self.native.export_text_artifact(
                    path=path,
                    content=text,
                    expected_sha256=(str(arguments.get("expected_sha256") or "").strip() or None),
                    trace_id=trace_id,
                    artifact_kind=artifact_name,
                )
                return {"ok": True, "project_id": project_id, "artifact": artifact_name, "export": export}
            return self._rethlas_export_final(principal, arguments, trace_id)
        raise invalid_argument("action must be get or export")

    def _project_artifact(
        self,
        principal: OAuthPrincipal,
        *,
        project_id: str,
        artifact: str,
    ) -> dict[str, Any]:
        if not project_id:
            raise invalid_argument("project_id is required for project artifacts")
        graph = self.workflow.store.project_dependency_graph(
            project_id,
            owner_id=principal.client_id,
        )
        public_project = {
            key: value
            for key, value in graph["project"].items()
            if key != "owner_id"
        }
        revision_provenance: dict[str, Any] = {}
        for revision in graph["revisions"]:
            source_run_id = str(revision.get("source_run_id") or "")
            if not source_run_id:
                continue
            try:
                manifest_record = self.workflow.store.read_proof_manifest(source_run_id)
            except ReCTMError:
                manifest_record = None
            audits = self.workflow.store.list_reference_audits(source_run_id)
            revision_provenance[str(revision["revision_id"])] = {
                "source_run_id": source_run_id,
                "proof_manifest_sha256": (
                    manifest_record["sha256"] if isinstance(manifest_record, Mapping) else None
                ),
                "dependency_revision_ids": (
                    list(manifest_record["manifest"].get("dependency_revision_ids", []))
                    if isinstance(manifest_record, Mapping)
                    else []
                ),
                "reference_ids": (
                    list(manifest_record["manifest"].get("reference_ids", []))
                    if isinstance(manifest_record, Mapping)
                    else []
                ),
                "conditional_hypotheses": (
                    list(manifest_record["manifest"].get("conditional_hypotheses", []))
                    if isinstance(manifest_record, Mapping)
                    else []
                ),
                "computational_evidence_count": (
                    len(manifest_record["manifest"].get("computational_evidence", []))
                    if isinstance(manifest_record, Mapping)
                    else 0
                ),
                "reference_audits": [
                    {
                        key: audit.get(key)
                        for key in (
                            "reference_id", "disposition", "evidence_basis", "evidence_locator", "material",
                            "assumptions_checked", "notation_checked", "source_checked",
                            "independently_rederived", "title", "paper_id", "arxiv_id",
                            "doi", "theorem_id", "source_uri", "source_sha256",
                            "content_sha256",
                        )
                    }
                    for audit in audits
                ],
            }
        if artifact == "project_manifest":
            content = {
                "schema_version": "1.0",
                "project": public_project,
                "claims": graph["claims"],
                "revisions": graph["revisions"],
                "edges": graph["edges"],
                "revision_provenance": revision_provenance,
            }
        elif artifact == "project_summary_tex":
            lines = [
                r"\documentclass{article}",
                r"\usepackage{amsmath,amsthm}",
                r"\begin{document}",
                rf"\section*{{{_latex_escape(str(public_project['title']))}}}",
            ]
            by_claim = {item["claim_id"]: item for item in graph["claims"]}
            for revision in graph["revisions"]:
                if revision.get("lifecycle_status") != "ACTIVE":
                    continue
                claim = by_claim.get(revision["claim_id"], {})
                lines.append(rf"\subsection*{{{_latex_escape(str(claim.get('title') or revision['claim_id']))}}}")
                lines.append(
                    rf"\textbf{{Status:}} {_latex_escape(str(revision.get('evidence_status') or ''))}.\\"
                )
                conditions = revision.get("conditions") or []
                if conditions:
                    lines.append(
                        rf"\textbf{{Conditions:}} {_latex_escape(', '.join(str(item) for item in conditions))}.\\"
                    )
                provenance = revision_provenance.get(str(revision["revision_id"]), {})
                if revision.get("proof_sha256"):
                    lines.append(
                        rf"\textbf{{Proof SHA-256:}} \texttt{{{_latex_escape(str(revision['proof_sha256']))}}}.\\"
                    )
                if provenance:
                    lines.append(
                        rf"\textbf{{Audited references:}} {len(provenance.get('reference_audits', []))}.\\"
                    )
                lines.append(str(revision.get("statement_tex") or ""))
                lines.append("")
            lines.append(r"\end{document}")
            content = "\n".join(lines) + "\n"
            safety_errors = static_latex_errors(content)
            if safety_errors:
                raise ReCTMError(
                    "PROJECT_SUMMARY_LATEX_UNSAFE",
                    "Project summary contains LaTeX operations that are unsafe for a portable artifact.",
                    category="validation",
                    details={"errors": safety_errors},
                )
        else:
            raise invalid_argument("unknown project artifact", artifact=artifact)
        return {"ok": True, "project_id": project_id, "artifact": artifact, "content": content}

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
            reason=str(arguments.get("reason") or CONTROL_DEFAULT_CANCEL_REASON),
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


def _latex_escape(value: str) -> str:
    return (
        value.replace("\\", r"\textbackslash{}")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("$", r"\$")
        .replace("#", r"\#")
        .replace("_", r"\_")
        .replace("{", r"\{")
        .replace("}", r"\}")
    )
