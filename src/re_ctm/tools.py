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

    def definition(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.read_only,
                "openWorldHint": self.open_world,
            },
        }


OBJECT = {"type": "object", "additionalProperties": False}


TOOL_SPECS: dict[str, ToolSpec] = {
    "server_info": ToolSpec(
        "Server info",
        "Return Re-CTM version, native authority, isolation status, and workflow non-inheritance facts.",
        {**OBJECT, "properties": {}},
        read_only=True,
    ),
    "read_file": ToolSpec(
        "Read native file",
        "Read a UTF-8 file inside the native workspace.",
        {
            **OBJECT,
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 10000},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576},
            },
        },
        read_only=True,
    ),
    "list_files": ToolSpec(
        "List native files",
        "Recursively list files inside the native workspace.",
        {
            **OBJECT,
            "properties": {
                "path": {"type": "string"},
                "include_hidden": {"type": "boolean"},
                "include_ignored": {"type": "boolean"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 10000},
            },
        },
        read_only=True,
    ),
    "search_text": ToolSpec(
        "Search native text",
        "Search UTF-8 text inside the native workspace.",
        {
            **OBJECT,
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "minLength": 1},
                "path": {"type": "string"},
                "case_sensitive": {"type": "boolean"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 10000},
            },
        },
        read_only=True,
    ),
    "apply_patch": ToolSpec(
        "Apply native patch",
        "Atomically apply structured add/update/delete operations inside the native workspace.",
        {
            **OBJECT,
            "required": ["operations"],
            "properties": {
                "operations": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["op", "path"],
                        "properties": {
                            "op": {"type": "string", "enum": ["add", "update", "delete"]},
                            "path": {"type": "string"},
                            "content": {"type": "string"},
                            "expected_sha256": {"type": "string"},
                        },
                    },
                },
                "dry_run": {"type": "boolean"},
            },
        },
        destructive=True,
    ),
    "exec_command": ToolSpec(
        "Execute isolated native command",
        "Delegate argv execution to an attested external isolation helper. Fails closed when no helper is configured.",
        {
            **OBJECT,
            "required": ["argv"],
            "properties": {
                "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "workdir": {"type": "string"},
                "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 600000},
            },
        },
        destructive=True,
        open_world=True,
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
            "read_file": self._native("read_file"),
            "list_files": self._native("list_files"),
            "search_text": self._native("search_text"),
            "apply_patch": self._native("apply_patch"),
            "exec_command": self._native("exec_command"),
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
            decision="allow",
            reason="tool_completed",
            details={"tool": name, "result_keys": sorted(payload)},
        )
        return _tool_result(name, payload, is_error=False)

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
        return {
            "server": "re-ctm",
            "version": __version__,
            "oauth_only": True,
            "oauth_client_id": principal.client_id,
            "tool_count": len(TOOL_SPECS),
            "tool_catalog_stable": True,
            "native": self.native.server_info(),
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
    if is_error:
        error = payload.get("error") or {}
        text = f"{error.get('code', 'TOOL_ERROR')}: {error.get('message', 'Tool failed.')}"
    else:
        text = _render_summary(name, payload)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
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
