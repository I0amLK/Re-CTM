from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .capabilities import (
    CapabilityAuthority,
    CapabilityClaims,
    default_permissions,
    role_for_state,
)
from .debug import DebugEventBus, new_trace_id, utc_now
from .enums import DomainStatus, WorkflowRole, WorkflowState
from .errors import ReCTMError, invalid_argument
from .latex import LatexGate
from .methodology import task_for_state
from .research import ResearchProvider, TheoremSearchClient
from .storage import StateStore
from .vault import (
    BRANCH_CHANNELS,
    GENERATION_CHANNELS,
    VERIFIER_CHANNELS,
    PrivateVault,
)


_ID_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")


ALLOWED_TRANSITIONS: frozenset[tuple[WorkflowState, WorkflowState]] = frozenset(
    {
        (WorkflowState.CREATED, WorkflowState.ASSESS),
        (WorkflowState.ASSESS, WorkflowState.EXPLORE),
        (WorkflowState.EXPLORE, WorkflowState.PROPOSE_PLANS),
        (WorkflowState.PROPOSE_PLANS, WorkflowState.DIRECT_PROVING),
        (WorkflowState.DIRECT_PROVING, WorkflowState.ASSEMBLE),
        (WorkflowState.DIRECT_PROVING, WorkflowState.BRANCH_PREPARE),
        (WorkflowState.BRANCH_PREPARE, WorkflowState.BRANCH_RUN),
        (WorkflowState.BRANCH_RUN, WorkflowState.BRANCH_RUN),
        (WorkflowState.BRANCH_RUN, WorkflowState.BRANCH_JOIN),
        (WorkflowState.BRANCH_JOIN, WorkflowState.ASSEMBLE),
        (WorkflowState.BRANCH_JOIN, WorkflowState.IDENTIFY_FAILURES),
        (WorkflowState.IDENTIFY_FAILURES, WorkflowState.REPLAN),
        (WorkflowState.REPLAN, WorkflowState.PROPOSE_PLANS),
        (WorkflowState.ASSEMBLE, WorkflowState.LATEX_VALIDATE),
        (WorkflowState.LATEX_VALIDATE, WorkflowState.VERIFY),
        (WorkflowState.LATEX_VALIDATE, WorkflowState.REPAIR),
        (WorkflowState.VERIFY, WorkflowState.FINALIZE),
        (WorkflowState.VERIFY, WorkflowState.REPAIR),
        (WorkflowState.REPAIR, WorkflowState.LATEX_VALIDATE),
        (WorkflowState.FINALIZE, WorkflowState.DONE),
    }
)


@dataclass(frozen=True)
class TaskEnvelope:
    run_id: str
    state: str
    role: str
    domain_id: str
    capability: str
    task: dict[str, Any]
    context: dict[str, Any]
    trace_id: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "state": self.state,
            "role": self.role,
            "domain_id": self.domain_id,
            "capability": self.capability,
            "task": self.task,
            "context": self.context,
            "trace_id": self.trace_id,
        }


class WorkflowEngine:
    def __init__(
        self,
        store: StateStore,
        vault: PrivateVault,
        capabilities: CapabilityAuthority,
        debug: DebugEventBus,
        latex_gate: LatexGate,
        research: ResearchProvider | None = None,
    ) -> None:
        self.store = store
        self.vault = vault
        self.capabilities = capabilities
        self.debug = debug
        self.latex_gate = latex_gate
        self.research = research or TheoremSearchClient()

    def start(
        self,
        *,
        owner_id: str,
        problem_tex: str,
        problem_id: str | None = None,
        references: Iterable[Mapping[str, Any]] = (),
        native_mode: str = "safe",
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        if not owner_id.strip():
            raise invalid_argument("owner_id is required")
        if not problem_tex.strip():
            raise invalid_argument("problem_tex is required")
        resolved_problem_id = _safe_component(problem_id or "problem")
        run_id = f"run-{resolved_problem_id}-{secrets.token_hex(6)}"
        vault_result = self.vault.initialize_run(
            run_id,
            problem_tex=problem_tex,
            references=references,
            metadata={
                "problem_id": resolved_problem_id,
                "owner_id": owner_id,
                "created_at": utc_now(),
            },
        )
        self.store.create_run(
            run_id=run_id,
            problem_id=resolved_problem_id,
            owner_id=owner_id,
            state=WorkflowState.CREATED.value,
            metadata={
                "native_mode_at_creation": native_mode,
                "problem_sha256": vault_result["problem_sha256"],
                "reference_count": vault_result["reference_count"],
                "manual_validation_required": True,
                "active_plans": [],
                "branch_requests": [],
                "latex_result": None,
            },
        )
        self.debug.emit(
            "workflow.run_created",
            "workflow_engine",
            trace_id=trace,
            run_id=run_id,
            decision="allow",
            reason="valid_problem_input",
            details={
                "problem_id": resolved_problem_id,
                "problem_sha256": vault_result["problem_sha256"],
                "reference_count": vault_result["reference_count"],
                "native_mode_recorded_only": native_mode,
            },
        )
        self._transition(
            run_id,
            WorkflowState.CREATED,
            WorkflowState.ASSESS,
            trace_id=trace,
            actor="system",
            reason="run_initialized",
        )
        return {
            "ok": True,
            "run_id": run_id,
            "state": WorkflowState.ASSESS.value,
            "manual_validation_required": True,
            "trace_id": trace,
        }

    def next_task(
        self,
        *,
        owner_id: str,
        run_id: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        run = self._require_owner(run_id, owner_id)
        run = self._advance_mechanical(run, trace)
        state = WorkflowState(run["state"])
        if state.terminal:
            return {
                "ok": True,
                "run_id": run_id,
                "state": state.value,
                "terminal": True,
                "verdict": run.get("verdict"),
                "trace_id": trace,
            }
        role = role_for_state(state)
        if role is None:
            raise ReCTMError(
                "NO_ACTIVE_ROLE",
                f"No model role is active in state {state.value}.",
                category="runtime",
            )
        domain = self._ensure_domain(run, role, trace)
        capability = self.capabilities.issue(
            run_id=run_id,
            domain_id=domain["domain_id"],
            role=role,
            permissions=default_permissions(role),
            trace_id=trace,
        )
        context = self._task_context(run, state, role, domain)
        steering: list[dict[str, Any]] = []
        if role in {WorkflowRole.GENERATOR, WorkflowRole.REPAIR}:
            steering = self.store.consume_steering(run_id)
        if steering:
            context["user_steering"] = [item["message"] for item in steering]
        envelope = TaskEnvelope(
            run_id=run_id,
            state=state.value,
            role=role.value,
            domain_id=domain["domain_id"],
            capability=capability,
            task=task_for_state(state),
            context=context,
            trace_id=trace,
        )
        self.debug.emit(
            "workflow.task_issued",
            "workflow_engine",
            trace_id=trace,
            run_id=run_id,
            actor_role=role.value,
            domain_id=domain["domain_id"],
            decision="allow",
            reason="active_role_task",
            details={"state": state.value, "steering_count": len(steering)},
        )
        return {"ok": True, **envelope.to_payload()}

    def read(
        self,
        *,
        owner_id: str,
        capability: str,
        resource: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        claims = self.capabilities.validate(
            capability,
            owner_id=owner_id,
            action="read",
            resource=resource,
            trace_id=trace,
        )
        content = self._read_resource(claims, resource)
        return {
            "ok": True,
            "run_id": claims.run_id,
            "resource": resource,
            "content": content,
            "trace_id": trace,
        }

    def write(
        self,
        *,
        owner_id: str,
        capability: str,
        resource: str,
        content: Any,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        claims = self.capabilities.validate(
            capability,
            owner_id=owner_id,
            action="write",
            resource=resource,
            trace_id=trace,
        )
        result = self._write_resource(claims, resource, content)
        self.debug.emit(
            "workflow.resource_written",
            "workflow_engine",
            trace_id=trace,
            run_id=claims.run_id,
            actor_role=claims.role.value,
            domain_id=claims.domain_id,
            decision="allow",
            reason="resource_acl_passed",
            details={"resource": resource, "result": result},
        )
        return {
            "ok": True,
            "run_id": claims.run_id,
            "resource": resource,
            "result": result,
            "trace_id": trace,
        }

    def search(
        self,
        *,
        owner_id: str,
        capability: str,
        resource: str,
        query: str,
        limit: int = 20,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        claims = self.capabilities.validate(
            capability,
            owner_id=owner_id,
            action="search",
            resource=resource,
            trace_id=trace,
        )
        if not query.strip():
            raise invalid_argument("query is required")
        records: list[dict[str, Any]] = []
        if resource.startswith("memory:generation:"):
            channel = resource.rsplit(":", 1)[-1]
            records = self.vault.read_generation_memory(claims.run_id, channel)
        elif resource.startswith("memory:branch:"):
            channel = resource.rsplit(":", 1)[-1]
            branch_id = self._branch_id_for_domain(claims.domain_id)
            records = self.vault.read_branch_memory(claims.run_id, branch_id, channel)
        else:
            raise invalid_argument("resource is not searchable", resource=resource)
        return {
            "ok": True,
            "run_id": claims.run_id,
            "resource": resource,
            "query": query,
            "results": self.vault.search_records(records, query, limit=limit),
            "trace_id": trace,
        }

    def retrieve(
        self,
        *,
        owner_id: str,
        capability: str,
        query: str,
        search_intent: str = "theorem",
        num_results: int = 10,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        claims = self.capabilities.validate(
            capability,
            owner_id=owner_id,
            action="retrieve",
            resource="external:theorems",
            trace_id=trace,
        )
        result = self.research.search_theorems(
            query=query,
            num_results=num_results,
            search_intent=search_intent,
        )
        record = {
            "event_type": "external_theorem_search",
            "query": result["query"],
            "search_intent": search_intent,
            "result_count": result["count"],
            "results": result["results"],
            "source_trust": result["source_trust"],
            "usage_rule": result["usage_rule"],
            "created_at": utc_now(),
        }
        if claims.role in {WorkflowRole.GENERATOR, WorkflowRole.REPAIR}:
            self.vault.append_generation_memory(claims.run_id, "events", record)
        elif claims.role is WorkflowRole.BRANCH:
            branch_id = self._branch_id_for_domain(claims.domain_id)
            self.vault.append_branch_memory(claims.run_id, branch_id, "events", record)
        elif claims.role is WorkflowRole.VERIFIER:
            self.vault.append_verifier_memory(claims.run_id, "events", record)
        else:
            raise ReCTMError(
                "ROLE_ACCESS_DENIED",
                "The active workflow role cannot perform external theorem retrieval.",
                category="permission",
            )
        self.debug.emit(
            "research.theorem_search_completed",
            "workflow_engine",
            trace_id=trace,
            run_id=claims.run_id,
            actor_role=claims.role.value,
            domain_id=claims.domain_id,
            decision="allow",
            reason="research_capability_passed",
            details={
                "search_intent": search_intent,
                "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "result_count": result["count"],
            },
        )
        return {
            "ok": True,
            "run_id": claims.run_id,
            **result,
            "trace_id": trace,
        }

    def commit(
        self,
        *,
        owner_id: str,
        capability: str,
        action: str,
        payload: Mapping[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        claims = self.capabilities.validate(
            capability,
            owner_id=owner_id,
            action="commit",
            resource="workflow",
            trace_id=trace,
        )
        run = self.store.get_run(claims.run_id)
        state = WorkflowState(run["state"])
        data = dict(payload or {})
        result = self._commit_action(run, claims, action, data, trace)
        return {"ok": True, "trace_id": trace, **result}

    def status(self, *, owner_id: str, run_id: str) -> dict[str, Any]:
        run = self._require_owner(run_id, owner_id)
        branches = self.store.list_branches(run_id)
        return {
            "ok": True,
            "run_id": run_id,
            "problem_id": run["problem_id"],
            "state": run["state"],
            "status": run["status"],
            "round_index": run["round_index"],
            "transition_seq": run["transition_seq"],
            "latex_passed": run["latex_passed"],
            "verdict": run["verdict"],
            "sealed": run["sealed"],
            "branches": [
                {
                    "branch_id": branch["branch_id"],
                    "plan_id": branch["plan_id"],
                    "status": branch["status"],
                    "order_index": branch["order_index"],
                }
                for branch in branches
            ],
            "manual_validation_required": True,
        }

    def steer(
        self,
        *,
        owner_id: str,
        run_id: str,
        message: str,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        run = self._require_owner(run_id, owner_id)
        state = WorkflowState(run["state"])
        if state.terminal:
            raise ReCTMError("RUN_TERMINAL", "Cannot steer a terminal run.", category="conflict")
        if not message.strip():
            raise invalid_argument("steering message is required")
        item_id = self.store.add_steering(run_id, owner_id, message.strip())
        self.debug.emit(
            "steering.submitted",
            "workflow_engine",
            trace_id=trace,
            run_id=run_id,
            decision="allow",
            reason="owner_submitted_guidance",
            details={"steering_id": item_id, "message_length": len(message)},
        )
        return {"ok": True, "run_id": run_id, "steering_id": item_id, "trace_id": trace}

    def cancel(
        self,
        *,
        owner_id: str,
        run_id: str,
        reason: str = "user_cancelled",
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        run = self._require_owner(run_id, owner_id)
        state = WorkflowState(run["state"])
        if state.terminal:
            return self.status(owner_id=owner_id, run_id=run_id)
        result = self.store.transition_run(
            run_id=run_id,
            expected_state=state.value,
            after_state=WorkflowState.CANCELLED.value,
            trace_id=trace,
            actor=owner_id,
            reason=reason,
            status="cancelled",
            sealed=True,
        )
        self.debug.emit(
            "workflow.transition",
            "workflow_engine",
            trace_id=trace,
            run_id=run_id,
            before_state=state.value,
            after_state=WorkflowState.CANCELLED.value,
            decision="allow",
            reason=reason,
        )
        return {"ok": True, "run_id": run_id, "state": result["state"], "trace_id": trace}

    def resume(self, *, owner_id: str, run_id: str) -> dict[str, Any]:
        run = self._require_owner(run_id, owner_id)
        if WorkflowState(run["state"]).terminal:
            raise ReCTMError(
                "RUN_TERMINAL",
                "Terminal runs cannot be resumed automatically.",
                category="conflict",
            )
        return self.next_task(owner_id=owner_id, run_id=run_id)

    def get_artifact(
        self,
        *,
        owner_id: str,
        run_id: str,
        artifact: str,
    ) -> dict[str, Any]:
        run = self._require_owner(run_id, owner_id)
        state = WorkflowState(run["state"])
        if artifact == "draft_tex":
            content = self.vault.read_proof(run_id)
        elif artifact == "verification_report":
            content = self.vault.read_verification_report(run_id)
        elif artifact == "final_tex":
            if state != WorkflowState.DONE or not run["sealed"]:
                raise ReCTMError(
                    "ARTIFACT_NOT_FINAL",
                    "Final LaTeX is available only after mechanical finalization.",
                    category="permission",
                )
            content = self.vault.read_final_proof(run_id)
        elif artifact == "transition_log":
            content = self.store.list_transitions(run_id)
        elif artifact == "debug_manifest":
            if not state.terminal:
                raise ReCTMError(
                    "DEBUG_BUNDLE_NOT_AVAILABLE",
                    "Debug manifests are exposed only for terminal runs.",
                    category="permission",
                )
            content = self._manual_validation_manifest(run)
        else:
            raise invalid_argument("unknown artifact", artifact=artifact)
        return {"ok": True, "run_id": run_id, "artifact": artifact, "content": content}

    def _advance_mechanical(self, run: dict[str, Any], trace_id: str) -> dict[str, Any]:
        while True:
            state = WorkflowState(run["state"])
            if state == WorkflowState.BRANCH_PREPARE:
                run = self._prepare_branch_round(run, trace_id)
                continue
            if state == WorkflowState.LATEX_VALIDATE:
                run = self._run_latex_gate(run, trace_id)
                continue
            if state == WorkflowState.FINALIZE:
                run = self._finalize(run, trace_id)
                continue
            return run

    def _ensure_domain(
        self,
        run: Mapping[str, Any],
        role: WorkflowRole,
        trace_id: str,
    ) -> dict[str, Any]:
        run_id = str(run["run_id"])
        state = WorkflowState(str(run["state"]))
        if role == WorkflowRole.BRANCH:
            branches = self.store.list_branches(run_id)
            active = next((item for item in branches if item["status"] == "running"), None)
            if active is None:
                active = next((item for item in branches if item["status"] == "pending"), None)
                if active is None:
                    raise ReCTMError(
                        "BRANCH_BARRIER_INCONSISTENT",
                        "Branch-run state has no pending or running branch.",
                        category="internal",
                    )
                active = self.store.update_branch_status(active["branch_id"], "running")
            return self.store.get_domain(active["domain_id"])

        existing = self.store.list_domains(run_id, role=role.value, status=DomainStatus.OPEN.value)
        current = next(
            (
                item
                for item in reversed(existing)
                if item.get("metadata", {}).get("state") == state.value
            ),
            None,
        )
        if current is not None:
            return current
        domain_id = f"{role.value}-{state.value}-{run['epoch']}-{secrets.token_hex(3)}"
        domain = self.store.create_domain(
            domain_id=domain_id,
            run_id=run_id,
            role=role.value,
            metadata={"state": state.value},
        )
        self.debug.emit(
            "domain.created",
            "workflow_engine",
            trace_id=trace_id,
            run_id=run_id,
            actor_role=role.value,
            domain_id=domain_id,
            decision="allow",
            reason="active_state_requires_domain",
            details={"state": state.value},
        )
        return domain

    def _task_context(
        self,
        run: Mapping[str, Any],
        state: WorkflowState,
        role: WorkflowRole,
        domain: Mapping[str, Any],
    ) -> dict[str, Any]:
        context: dict[str, Any] = {
            "problem_id": run["problem_id"],
            "round_index": run["round_index"],
            "available_logical_resources": _resources_for_role(role),
            "manual_validation_required": True,
        }
        if role == WorkflowRole.BRANCH:
            branch_id = str(domain.get("metadata", {}).get("branch_id") or "")
            branch = self.store.get_branch(branch_id)
            context.update(
                {
                    "branch_id": branch_id,
                    "plan_id": branch["plan_id"],
                    "snapshot_id": branch["snapshot_id"],
                    "information_barrier": "Other branch results are unavailable until join.",
                }
            )
        elif role == WorkflowRole.JOIN:
            context["sealed_branch_ids"] = [
                item["branch_id"] for item in self.store.list_branches(run["run_id"])
            ]
        elif role == WorkflowRole.VERIFIER:
            context["data_firewall"] = [
                "No generation memory",
                "No branch internals",
                "No steering history",
                "No generator confidence",
            ]
        elif role == WorkflowRole.REPAIR:
            latex_result = run.get("metadata", {}).get("latex_result")
            if isinstance(latex_result, Mapping):
                context["latex_result"] = dict(latex_result)
                context["repair_source"] = (
                    "latex_gate"
                    if not bool(latex_result.get("gate_passed"))
                    else "verification_report"
                )
        return context

    def _read_resource(self, claims: CapabilityClaims, resource: str) -> Any:
        if resource == "problem":
            return self.vault.read_problem(claims.run_id)
        if resource == "references" or resource == "references:approved":
            manifest = self.vault.read_references_manifest(claims.run_id)
            return {
                "manifest": manifest,
                "references": [
                    {"name": item["name"], "content": self.vault.read_reference(claims.run_id, item["name"])}
                    for item in manifest
                ],
            }
        if resource == "steering":
            return []
        if resource == "snapshot":
            domain = self.store.get_domain(claims.domain_id)
            snapshot_id = str(domain.get("snapshot_id") or domain.get("metadata", {}).get("snapshot_id") or "")
            return self.vault.read_snapshot(claims.run_id, snapshot_id)
        if resource == "branch:self":
            branch_id = self._branch_id_for_domain(claims.domain_id)
            branch = self.store.get_branch(branch_id)
            return {
                "assignment": self.vault._read_json(  # internal logical path, never caller supplied
                    self.vault.run_root(claims.run_id) / "branches" / branch_id / "assignment.json"
                ),
                "status": branch["status"],
            }
        if resource.startswith("branch:sealed:"):
            branches = self.store.list_branches(claims.run_id)
            if not branches or any(item["status"] != "sealed" for item in branches):
                raise ReCTMError(
                    "BRANCH_BARRIER_NOT_COMPLETE",
                    "All branches must be sealed before join reads.",
                    category="permission",
                )
            return {
                item["branch_id"]: self.vault.read_branch_result(claims.run_id, item["branch_id"])
                for item in branches
            }
        if resource.startswith("memory:generation:"):
            return self.vault.read_generation_memory(claims.run_id, resource.rsplit(":", 1)[-1])
        if resource.startswith("memory:verifier:"):
            return self.vault.read_verifier_memory(claims.run_id, resource.rsplit(":", 1)[-1])
        if resource.startswith("memory:branch:"):
            branch_id = self._branch_id_for_domain(claims.domain_id)
            return self.vault.read_branch_memory(claims.run_id, branch_id, resource.rsplit(":", 1)[-1])
        if resource == "join_result":
            return self.vault.read_join_result(claims.run_id)
        if resource == "proof":
            return self.vault.read_proof(claims.run_id)
        if resource == "verification_report":
            return self.vault.read_verification_report(claims.run_id)
        raise invalid_argument("unknown logical resource", resource=resource)

    def _write_resource(
        self,
        claims: CapabilityClaims,
        resource: str,
        content: Any,
    ) -> dict[str, Any]:
        if resource.startswith("memory:generation:"):
            channel = resource.rsplit(":", 1)[-1]
            if channel not in GENERATION_CHANNELS or not isinstance(content, Mapping):
                raise invalid_argument("generation memory writes require a known channel and JSON object")
            path = self.vault.append_generation_memory(claims.run_id, channel, dict(content))
            return {"path_kind": "generation_memory", "channel": channel, "file": path.name}
        if resource.startswith("memory:verifier:"):
            channel = resource.rsplit(":", 1)[-1]
            if channel not in VERIFIER_CHANNELS or not isinstance(content, Mapping):
                raise invalid_argument("verifier memory writes require a known channel and JSON object")
            path = self.vault.append_verifier_memory(claims.run_id, channel, dict(content))
            return {"path_kind": "verifier_memory", "channel": channel, "file": path.name}
        if resource.startswith("memory:branch:"):
            channel = resource.rsplit(":", 1)[-1]
            if channel not in BRANCH_CHANNELS or not isinstance(content, Mapping):
                raise invalid_argument("branch memory writes require a known channel and JSON object")
            branch_id = self._branch_id_for_domain(claims.domain_id)
            path = self.vault.append_branch_memory(claims.run_id, branch_id, channel, dict(content))
            return {"path_kind": "branch_memory", "branch_id": branch_id, "channel": channel, "file": path.name}
        if resource == "join_result":
            if not isinstance(content, Mapping):
                raise invalid_argument("join_result must be a JSON object")
            path = self.vault.write_join_result(claims.run_id, dict(content))
            return {"path_kind": "join_result", "file": path.name}
        if resource == "proof":
            if not isinstance(content, str):
                raise invalid_argument("proof must be a LaTeX string")
            path = self.vault.write_proof(claims.run_id, content)
            return {"path_kind": "draft_tex", "file": path.name, "size": len(content.encode("utf-8"))}
        if resource == "verification_report":
            if not isinstance(content, Mapping):
                raise invalid_argument("verification_report must be a JSON object")
            normalized = _normalize_verification_report(dict(content))
            path = self.vault.write_verification_report(claims.run_id, normalized)
            return {"path_kind": "verification_report", "file": path.name}
        if resource == "branch:self":
            raise ReCTMError(
                "BRANCH_RESULT_REQUIRES_COMMIT",
                "Branch results are written and sealed atomically by branch_complete.",
                category="validation",
            )
        raise invalid_argument("unknown or non-writable logical resource", resource=resource)

    def _commit_action(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        action: str,
        payload: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        state = WorkflowState(str(run["state"]))
        expected_action = task_for_state(state).get("commit_action")
        if action != expected_action:
            raise ReCTMError(
                "INVALID_COMMIT_ACTION",
                "Commit action does not match the active workflow task.",
                category="validation",
                details={"expected": expected_action, "received": action, "state": state.value},
            )

        if action == "assessment_complete":
            self._require_records(claims.run_id, "immediate_conclusions")
            after = WorkflowState.EXPLORE
        elif action == "exploration_complete":
            self._require_records(claims.run_id, "events")
            after = WorkflowState.PROPOSE_PLANS
        elif action == "plans_proposed":
            plans = _validate_plans(payload.get("plans"))
            for plan in plans:
                self.vault.append_generation_memory(
                    claims.run_id,
                    "subgoals",
                    {**plan, "record_type": "decomposition_plan", "status": "proposed"},
                )
            self.store.update_run_metadata(claims.run_id, {"active_plans": plans})
            after = WorkflowState.DIRECT_PROVING
        elif action == "direct_proving_complete":
            self._require_records(claims.run_id, "proof_steps")
            active_plans = run.get("metadata", {}).get("active_plans", [])
            screening = _validate_direct_screening(
                payload.get("screening"),
                active_plans,
            )
            self.vault.append_generation_memory(
                claims.run_id,
                "proof_steps",
                {
                    "record_type": "direct_screening_round",
                    "plans": screening,
                    "created_at": utc_now(),
                },
            )
            outcome = str(payload.get("outcome") or "")
            if outcome == "solved":
                if not str(payload.get("proof_route") or "").strip():
                    raise invalid_argument("solved outcome requires proof_route")
                solved_plan_ids = {
                    item["plan_id"] for item in screening if item["status"] == "solved"
                }
                selected_plan_id = str(payload.get("selected_plan_id") or "")
                if not solved_plan_ids or selected_plan_id not in solved_plan_ids:
                    raise invalid_argument(
                        "solved outcome requires selected_plan_id for a plan whose screening status is solved"
                    )
                self.vault.write_join_result(
                    claims.run_id,
                    {
                        "source": "direct_proving",
                        "status": "solved",
                        "selected_plan_id": selected_plan_id,
                        "proof_route": payload["proof_route"],
                        "screening": screening,
                    },
                )
                after = WorkflowState.ASSEMBLE
            elif outcome == "needs_branches":
                if any(item["status"] == "solved" for item in screening):
                    raise invalid_argument(
                        "needs_branches is invalid when direct screening already solved a plan"
                    )
                branch_plans = _validate_branch_requests(
                    payload.get("branch_plans"),
                    active_plans,
                )
                self.store.update_run_metadata(
                    claims.run_id,
                    {"branch_requests": branch_plans, "last_direct_screening": screening},
                )
                after = WorkflowState.BRANCH_PREPARE
            else:
                raise invalid_argument("outcome must be solved or needs_branches")
        elif action == "branch_complete":
            return self._commit_branch(run, claims, payload, trace_id)
        elif action == "join_complete":
            outcome = str(payload.get("outcome") or "")
            if outcome not in {"solved", "failed"}:
                raise invalid_argument("join outcome must be solved or failed")
            branches = self.store.list_branches(claims.run_id)
            sealed_ids = {str(item["branch_id"]) for item in branches if item["status"] == "sealed"}
            considered = payload.get("considered_branch_ids")
            if not isinstance(considered, list) or {str(item) for item in considered} != sealed_ids:
                raise invalid_argument(
                    "join must explicitly consider every sealed branch exactly once",
                    sealed_branch_ids=sorted(sealed_ids),
                )
            branch_results = {
                branch_id: self.vault.read_branch_result(claims.run_id, branch_id)
                for branch_id in sealed_ids
            }
            if outcome == "solved":
                selected = str(payload.get("selected_branch_id") or "")
                synthesis_route = str(payload.get("synthesis_proof_route") or "").strip()
                selected_result = branch_results.get(selected)
                if not synthesis_route and (
                    not isinstance(selected_result, Mapping)
                    or selected_result.get("status") != "solved"
                ):
                    raise invalid_argument(
                        "solved join requires a solved selected_branch_id or synthesis_proof_route"
                    )
            else:
                common_failures = payload.get("common_failures")
                if not isinstance(common_failures, list) or not common_failures:
                    raise invalid_argument("failed join requires non-empty common_failures")
            normalized_join = {
                **payload,
                "considered_branch_ids": sorted(sealed_ids),
                "joined_at": utc_now(),
            }
            self.vault.write_join_result(claims.run_id, normalized_join)
            self.vault.append_generation_memory(
                claims.run_id,
                "branch_states",
                {
                    "record_type": "branch_join",
                    "outcome": outcome,
                    "considered_branch_ids": sorted(sealed_ids),
                },
            )
            after = WorkflowState.ASSEMBLE if outcome == "solved" else WorkflowState.IDENTIFY_FAILURES
        elif action == "failures_identified":
            if not isinstance(payload.get("summary"), Mapping):
                raise invalid_argument("failures_identified requires summary object")
            self.vault.append_generation_memory(
                claims.run_id,
                "failed_paths",
                {"record_type": "key_failures_summary", **dict(payload["summary"])},
            )
            after = WorkflowState.REPLAN
        elif action == "replan_complete":
            if not isinstance(payload.get("decision"), Mapping):
                raise invalid_argument("replan_complete requires decision object")
            self.vault.append_generation_memory(
                claims.run_id,
                "big_decisions",
                dict(payload["decision"]),
            )
            after = WorkflowState.PROPOSE_PLANS
        elif action == "proof_submitted":
            proof = self.vault.read_proof(claims.run_id)
            self.store.update_run_metadata(
                claims.run_id,
                {"last_submitted_proof_sha256": hashlib.sha256(proof.encode("utf-8")).hexdigest()},
            )
            after = WorkflowState.LATEX_VALIDATE
        elif action == "verification_submitted":
            self._require_verifier_records(claims.run_id, "statement_checks")
            self._require_verifier_records(claims.run_id, "events")
            proof = self.vault.read_proof(claims.run_id)
            if _proof_declares_external_references(proof):
                self._require_verifier_records(claims.run_id, "reference_checks")
            report = self.vault.read_verification_report(claims.run_id)
            normalized = _normalize_verification_report(report)
            critical = normalized["verification_report"]["critical_errors"]
            gaps = normalized["verification_report"]["gaps"]
            verdict = "correct" if not critical and not gaps else "wrong"
            normalized["verdict"] = verdict
            if verdict == "correct":
                normalized["repair_hints"] = ""
            elif not str(normalized.get("repair_hints") or "").strip():
                raise invalid_argument("wrong verification requires non-empty repair_hints")
            self.vault.write_verification_report(claims.run_id, normalized)
            self.vault.append_verifier_memory(
                claims.run_id,
                "verification_reports",
                normalized,
            )
            self.vault.append_generation_memory(
                claims.run_id,
                "verification_reports",
                normalized,
            )
            self.store.update_run_metadata(
                claims.run_id,
                {
                    "last_verified_proof_sha256": hashlib.sha256(proof.encode("utf-8")).hexdigest(),
                    "last_verifier_audit": {
                        "statement_checks": len(
                            self.vault.read_verifier_memory(claims.run_id, "statement_checks")
                        ),
                        "reference_checks": len(
                            self.vault.read_verifier_memory(claims.run_id, "reference_checks")
                        ),
                    },
                },
            )
            if verdict == "correct" and not run["latex_passed"]:
                raise ReCTMError(
                    "LATEX_GATE_NOT_PASSED",
                    "A mathematically correct report cannot finalize before the LaTeX gate passes.",
                    category="conflict",
                )
            after = WorkflowState.FINALIZE if verdict == "correct" else WorkflowState.REPAIR
            return self._seal_and_transition(
                run,
                claims,
                after,
                trace_id,
                reason=f"server_computed_verdict_{verdict}",
                verdict=verdict,
            )
        elif action == "repair_submitted":
            proof = self.vault.read_proof(claims.run_id)
            proof_sha256 = hashlib.sha256(proof.encode("utf-8")).hexdigest()
            prior_sha256 = str(
                run.get("metadata", {}).get("last_verified_proof_sha256") or ""
            )
            if prior_sha256 and proof_sha256 == prior_sha256:
                raise ReCTMError(
                    "REPAIR_DID_NOT_CHANGE_PROOF",
                    "A failed verification cannot be resubmitted unchanged.",
                    category="validation",
                )
            self.store.update_run_metadata(
                claims.run_id,
                {"last_submitted_proof_sha256": proof_sha256},
            )
            after = WorkflowState.LATEX_VALIDATE
        else:
            raise invalid_argument("unsupported commit action", action=action)
        return self._seal_and_transition(
            run,
            claims,
            after,
            trace_id,
            reason=action,
        )

    def _commit_branch(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        payload: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        branch_id = self._branch_id_for_domain(claims.domain_id)
        if not self.vault.read_branch_memory(claims.run_id, branch_id, "proof_steps"):
            raise ReCTMError(
                "WORKFLOW_PRECONDITION_FAILED",
                "Branch proof_steps memory must be non-empty before sealing.",
                category="validation",
                details={"branch_id": branch_id, "channel": "proof_steps"},
            )
        status = str(payload.get("status") or "")
        if status not in {"solved", "partial", "failed"}:
            raise invalid_argument("branch status must be solved, partial, or failed")
        summary = str(payload.get("summary") or "").strip()
        proof_route = str(payload.get("proof_route") or "").strip()
        unproved_subgoals = [str(item) for item in payload.get("unproved_subgoals") or []]
        failure_evidence = [str(item) for item in payload.get("failure_evidence") or []]
        if not summary:
            raise invalid_argument("branch result requires a non-empty summary")
        if status == "solved" and not proof_route:
            raise invalid_argument("solved branch result requires proof_route")
        if status in {"partial", "failed"} and not (unproved_subgoals or failure_evidence):
            raise invalid_argument(
                "partial or failed branch result requires unproved_subgoals or failure_evidence"
            )
        result_payload = {
            "branch_id": branch_id,
            "plan_id": self.store.get_branch(branch_id)["plan_id"],
            "status": status,
            "summary": summary,
            "proof_route": proof_route or None,
            "proved_subgoals": list(payload.get("proved_subgoals") or []),
            "unproved_subgoals": unproved_subgoals,
            "failure_evidence": failure_evidence,
        }
        path = self.vault.write_branch_result(claims.run_id, branch_id, result_payload)
        self.store.update_branch_status(branch_id, "sealed", result_path=str(path))
        self.store.seal_domain(claims.domain_id)
        self.vault.append_generation_memory(
            claims.run_id,
            "branch_states",
            {
                "record_type": "branch_sealed",
                "branch_id": branch_id,
                "plan_id": result_payload["plan_id"],
                "status": status,
            },
        )
        branches = self.store.list_branches(claims.run_id)
        barrier_complete = bool(branches) and all(item["status"] == "sealed" for item in branches)
        after = WorkflowState.BRANCH_JOIN if barrier_complete else WorkflowState.BRANCH_RUN
        result = self._transition(
            claims.run_id,
            WorkflowState.BRANCH_RUN,
            after,
            trace_id=trace_id,
            actor=claims.role.value,
            reason="branch_sealed_barrier_complete" if barrier_complete else "branch_sealed_next_pending",
            evidence={"branch_id": branch_id, "status": status, "barrier_complete": barrier_complete},
        )
        return {
            "run_id": claims.run_id,
            "state": result["state"],
            "branch_id": branch_id,
            "branch_status": "sealed",
            "barrier_complete": barrier_complete,
        }

    def _seal_and_transition(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        after: WorkflowState,
        trace_id: str,
        *,
        reason: str,
        verdict: str | None = None,
    ) -> dict[str, Any]:
        self.store.seal_domain(claims.domain_id)
        result = self._transition(
            claims.run_id,
            WorkflowState(str(run["state"])),
            after,
            trace_id=trace_id,
            actor=claims.role.value,
            reason=reason,
            verdict=verdict,
        )
        return {"run_id": claims.run_id, "state": result["state"], "verdict": result["verdict"]}

    def _prepare_branch_round(self, run: Mapping[str, Any], trace_id: str) -> dict[str, Any]:
        requests = run.get("metadata", {}).get("branch_requests", [])
        if not isinstance(requests, list) or not requests:
            raise ReCTMError(
                "BRANCH_REQUESTS_MISSING",
                "Branch preparation requires persisted branch requests.",
                category="internal",
            )
        snapshot_id = f"round-{int(run['round_index']) + 1}-{secrets.token_hex(4)}"
        snapshot_payload = {
            "snapshot_id": snapshot_id,
            "created_at": utc_now(),
            "problem": self.vault.read_problem(run["run_id"]),
            "references_manifest": self.vault.read_references_manifest(run["run_id"]),
            "generation_memory": {
                channel: self.vault.read_generation_memory(run["run_id"], channel)
                for channel in GENERATION_CHANNELS
                if channel != "events"
            },
            "branch_requests": requests,
        }
        snapshot = self.vault.create_snapshot(run["run_id"], snapshot_id, snapshot_payload)
        for index, plan in enumerate(requests):
            branch_id = f"branch-{int(run['round_index']) + 1}-{index + 1}-{secrets.token_hex(3)}"
            domain_id = f"branch-domain-{branch_id}"
            self.store.create_domain(
                domain_id=domain_id,
                run_id=run["run_id"],
                role=WorkflowRole.BRANCH.value,
                snapshot_id=snapshot_id,
                order_index=index,
                metadata={
                    "state": WorkflowState.BRANCH_RUN.value,
                    "branch_id": branch_id,
                    "snapshot_id": snapshot_id,
                },
            )
            self.store.create_branch(
                branch_id=branch_id,
                run_id=run["run_id"],
                plan_id=plan["plan_id"],
                domain_id=domain_id,
                snapshot_id=snapshot_id,
                order_index=index,
                metadata={"plan": plan},
            )
            self.vault.initialize_branch(
                run["run_id"],
                branch_id,
                {
                    "branch_id": branch_id,
                    "plan": plan,
                    "snapshot_id": snapshot_id,
                    "snapshot_sha256": snapshot["sha256"],
                },
            )
        self.store.update_run_metadata(
            run["run_id"],
            {"active_snapshot_id": snapshot_id, "branch_requests": []},
        )
        return self._transition(
            run["run_id"],
            WorkflowState.BRANCH_PREPARE,
            WorkflowState.BRANCH_RUN,
            trace_id=trace_id,
            actor="system",
            reason="frozen_snapshot_and_branch_domains_created",
            evidence={"snapshot_id": snapshot_id, "branch_count": len(requests)},
            round_delta=1,
        )

    def _run_latex_gate(self, run: Mapping[str, Any], trace_id: str) -> dict[str, Any]:
        proof = self.vault.read_proof(run["run_id"])
        workdir = self.vault.run_root(run["run_id"]) / "verification" / "latex"
        result = self.latex_gate.validate(proof, workdir)
        self.store.update_run_metadata(run["run_id"], {"latex_result": result.to_payload()})
        self.debug.emit(
            "latex.gate_result",
            "latex_gate",
            trace_id=trace_id,
            run_id=run["run_id"],
            before_state=WorkflowState.LATEX_VALIDATE.value,
            decision="allow" if result.gate_passed else "deny",
            reason="latex_gate_passed" if result.gate_passed else "latex_gate_failed",
            details=result.to_payload(),
        )
        return self._transition(
            run["run_id"],
            WorkflowState.LATEX_VALIDATE,
            WorkflowState.VERIFY if result.gate_passed else WorkflowState.REPAIR,
            trace_id=trace_id,
            actor="latex_gate",
            reason="latex_gate_passed" if result.gate_passed else "latex_gate_failed",
            evidence=result.to_payload(),
            latex_passed=result.gate_passed,
        )

    def _finalize(self, run: Mapping[str, Any], trace_id: str) -> dict[str, Any]:
        if not run["latex_passed"] or run.get("verdict") != "correct":
            raise ReCTMError(
                "FINALIZATION_GATE_DENIED",
                "Finalization requires a passed LaTeX gate and server-computed correct verdict.",
                category="permission",
            )
        report = self.vault.read_verification_report(run["run_id"])
        normalized = _normalize_verification_report(report)
        if normalized["verification_report"]["critical_errors"] or normalized["verification_report"]["gaps"]:
            raise ReCTMError(
                "FINALIZATION_GATE_DENIED",
                "Verification findings are not empty.",
                category="permission",
            )
        target = self.vault.finalize_proof(run["run_id"])
        result = self._transition(
            run["run_id"],
            WorkflowState.FINALIZE,
            WorkflowState.DONE,
            trace_id=trace_id,
            actor="finalizer_gate",
            reason="latex_and_verification_gates_passed",
            evidence={
                "artifact": target.name,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            },
            status="done",
            sealed=True,
        )
        self._write_manual_validation_manifest(result)
        return result

    def _transition(
        self,
        run_id: str,
        before: WorkflowState,
        after: WorkflowState,
        *,
        trace_id: str,
        actor: str,
        reason: str,
        evidence: Mapping[str, Any] | None = None,
        latex_passed: bool | None = None,
        verdict: str | None = None,
        status: str | None = None,
        sealed: bool | None = None,
        round_delta: int = 0,
    ) -> dict[str, Any]:
        if after not in {WorkflowState.CANCELLED, WorkflowState.FAILED} and (before, after) not in ALLOWED_TRANSITIONS:
            raise ReCTMError(
                "INVALID_STATE_TRANSITION",
                f"Transition is not allowed: {before.value} -> {after.value}",
                category="internal",
            )
        result = self.store.transition_run(
            run_id=run_id,
            expected_state=before.value,
            after_state=after.value,
            trace_id=trace_id,
            actor=actor,
            reason=reason,
            evidence=evidence,
            latex_passed=latex_passed,
            verdict=verdict,
            status=status,
            sealed=sealed,
            round_delta=round_delta,
        )
        self.debug.emit(
            "workflow.transition",
            "workflow_engine",
            trace_id=trace_id,
            run_id=run_id,
            actor_role=actor,
            before_state=before.value,
            after_state=after.value,
            decision="allow",
            reason=reason,
            details={"evidence": dict(evidence or {}), "epoch": result["epoch"]},
        )
        self.debug.write_state_snapshot(run_id, int(result["transition_seq"]), result)
        return result

    def _require_owner(self, run_id: str, owner_id: str) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        if run["owner_id"] != owner_id:
            raise ReCTMError(
                "RUN_OWNER_MISMATCH",
                "OAuth identity does not own this run.",
                category="permission",
            )
        return run

    def _require_records(self, run_id: str, channel: str) -> None:
        if not self.vault.read_generation_memory(run_id, channel):
            raise ReCTMError(
                "WORKFLOW_PRECONDITION_FAILED",
                f"Required generation memory channel is empty: {channel}",
                category="validation",
                details={"channel": channel},
            )

    def _require_verifier_records(self, run_id: str, channel: str) -> None:
        if not self.vault.read_verifier_memory(run_id, channel):
            raise ReCTMError(
                "WORKFLOW_PRECONDITION_FAILED",
                f"Required verifier memory channel is empty: {channel}",
                category="validation",
                details={"channel": channel},
            )

    def _branch_id_for_domain(self, domain_id: str) -> str:
        domain = self.store.get_domain(domain_id)
        branch_id = str(domain.get("metadata", {}).get("branch_id") or "")
        if not branch_id:
            raise ReCTMError(
                "DOMAIN_BRANCH_MISSING",
                "Branch domain has no branch id.",
                category="internal",
            )
        return branch_id

    def _manual_validation_manifest(self, run: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run["run_id"],
            "state": run["state"],
            "verdict": run.get("verdict"),
            "latex_passed": bool(run.get("latex_passed")),
            "transition_count": int(run.get("transition_seq", 0)),
            "manual_checks_still_required": [
                "real webpage OAuth and MCP compatibility",
                "target-PC hard isolation under native dangerous mode",
                "real external theorem and web retrieval",
                "multi-turn mathematical quality and domain switching",
                "target LaTeX toolchain reproduction",
            ],
        }

    def _write_manual_validation_manifest(self, run: Mapping[str, Any]) -> Path:
        target = self.vault.run_root(run["run_id"]) / "debug" / "manual-validation-manifest.json"
        payload = self._manual_validation_manifest(run)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return target


def _safe_component(value: str) -> str:
    cleaned = _ID_COMPONENT.sub("-", value.strip()).strip("-._")
    return cleaned[:80] or "problem"


def _resources_for_role(role: WorkflowRole) -> list[str]:
    return {
        WorkflowRole.GENERATOR: [
            "problem",
            "references",
            "memory:generation:<channel>",
            "steering",
        ],
        WorkflowRole.BRANCH: [
            "problem",
            "references",
            "snapshot",
            "branch:self",
            "memory:branch:<channel>",
        ],
        WorkflowRole.JOIN: ["problem", "snapshot", "branch:sealed:all", "join_result"],
        WorkflowRole.ASSEMBLER: [
            "problem",
            "references",
            "memory:generation:<channel>",
            "join_result",
            "proof",
        ],
        WorkflowRole.VERIFIER: [
            "problem",
            "proof",
            "references:approved",
            "memory:verifier:<channel>",
            "verification_report",
        ],
        WorkflowRole.REPAIR: [
            "problem",
            "proof",
            "verification_report",
            "memory:generation:<channel>",
        ],
        WorkflowRole.FINALIZER: [],
    }[role]


def _validate_plans(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < 2:
        raise invalid_argument("plans must contain at least two materially different plans")
    plans: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise invalid_argument("each plan must be a JSON object")
        plan_id = _safe_component(str(item.get("plan_id") or ""))
        summary = str(item.get("summary") or "").strip()
        subgoals = item.get("subgoals")
        if not summary or not isinstance(subgoals, list) or not subgoals:
            raise invalid_argument("each plan requires summary and non-empty subgoals")
        if plan_id in seen:
            raise invalid_argument("plan ids must be unique", plan_id=plan_id)
        seen.add(plan_id)
        plans.append(
            {
                "plan_id": plan_id,
                "summary": summary,
                "subgoals": [str(goal) for goal in subgoals],
                "motivation": list(item.get("motivation") or []),
                "risks": list(item.get("risks") or []),
            }
        )
    if len({plan["summary"].lower() for plan in plans}) != len(plans):
        raise invalid_argument("plans must have materially distinct summaries")
    return plans


def _validate_direct_screening(value: Any, active_plans: Any) -> list[dict[str, Any]]:
    if not isinstance(active_plans, list) or not active_plans:
        raise invalid_argument("direct screening requires active decomposition plans")
    known = {
        str(plan.get("plan_id")): plan
        for plan in active_plans
        if isinstance(plan, Mapping)
    }
    if not isinstance(value, list) or len(value) != len(known):
        raise invalid_argument(
            "screening must contain exactly one report for every active plan",
            active_plan_ids=sorted(known),
        )
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise invalid_argument("each screening report must be an object")
        plan_id = str(item.get("plan_id") or "")
        if plan_id not in known or plan_id in seen:
            raise invalid_argument(
                "screening plan_id must identify one unused active plan",
                plan_id=plan_id,
            )
        seen.add(plan_id)
        status = str(item.get("status") or "")
        if status not in {"solved", "partial", "stuck"}:
            raise invalid_argument("screening status must be solved, partial, or stuck")
        subgoal_results = item.get("subgoal_results")
        expected_subgoals = [str(goal) for goal in known[plan_id].get("subgoals") or []]
        if not isinstance(subgoal_results, list) or len(subgoal_results) != len(expected_subgoals):
            raise invalid_argument(
                "screening must report every subgoal exactly once",
                plan_id=plan_id,
                expected_subgoals=expected_subgoals,
            )
        result_by_subgoal: dict[str, dict[str, str]] = {}
        for raw_result in subgoal_results:
            if not isinstance(raw_result, Mapping):
                raise invalid_argument("each subgoal result must be an object")
            subgoal = str(raw_result.get("subgoal") or "")
            subgoal_status = str(raw_result.get("status") or "")
            summary = str(raw_result.get("summary") or "").strip()
            if (
                subgoal not in expected_subgoals
                or subgoal in result_by_subgoal
                or subgoal_status not in {"solved", "partial", "stuck"}
                or not summary
            ):
                raise invalid_argument(
                    "subgoal result requires one known subgoal, valid status, and summary",
                    plan_id=plan_id,
                    subgoal=subgoal,
                )
            result_by_subgoal[subgoal] = {
                "subgoal": subgoal,
                "status": subgoal_status,
                "summary": summary,
            }
        key_stuck_points = [str(point) for point in item.get("key_stuck_points") or [] if str(point)]
        if status in {"partial", "stuck"} and not key_stuck_points:
            raise invalid_argument(
                "partial or stuck plan screening requires key_stuck_points",
                plan_id=plan_id,
            )
        if status == "solved" and any(
            result["status"] != "solved" for result in result_by_subgoal.values()
        ):
            raise invalid_argument(
                "a solved plan requires every subgoal result to be solved",
                plan_id=plan_id,
            )
        normalized.append(
            {
                "plan_id": plan_id,
                "status": status,
                "subgoal_results": [result_by_subgoal[subgoal] for subgoal in expected_subgoals],
                "key_stuck_points": key_stuck_points,
            }
        )
    return normalized


def _validate_branch_requests(value: Any, active_plans: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise invalid_argument("branch_plans must be a non-empty array")
    known = {
        str(plan.get("plan_id")): plan
        for plan in active_plans
        if isinstance(plan, Mapping)
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        plan_id = str(item.get("plan_id") if isinstance(item, Mapping) else item)
        if plan_id not in known or plan_id in seen:
            raise invalid_argument("branch plan is not an active decomposition plan", plan_id=plan_id)
        seen.add(plan_id)
        result.append(dict(known[plan_id]))
    if seen != set(known):
        raise invalid_argument(
            "recursive branch round requires exactly one branch for every active plan",
            missing_plan_ids=sorted(set(known) - seen),
        )
    return result


def _proof_declares_external_references(proof: str) -> bool:
    return re.search(
        r"(?:\\cite\b|arXiv\s*(?:id)?\s*[:=]|paper[_\s-]?id\s*[:=]|theorem[_\s-]?id\s*[:=])",
        proof,
        re.I,
    ) is not None


def _normalize_verification_report(payload: dict[str, Any]) -> dict[str, Any]:
    report = payload.get("verification_report")
    if not isinstance(report, Mapping):
        raise invalid_argument("verification_report object is required")
    summary = str(report.get("summary") or "").strip()
    critical = _normalize_findings(report.get("critical_errors"), "critical_errors")
    gaps = _normalize_findings(report.get("gaps"), "gaps")
    if not summary:
        raise invalid_argument("verification report summary is required")
    return {
        "verification_report": {
            "summary": summary,
            "critical_errors": critical,
            "gaps": gaps,
        },
        "verdict": "correct" if not critical and not gaps else "wrong",
        "repair_hints": str(payload.get("repair_hints") or ""),
    }


def _normalize_findings(value: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise invalid_argument(f"{label} must be an array")
    findings: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise invalid_argument(f"each {label} entry must be an object")
        location = str(item.get("location") or "").strip()
        issue = str(item.get("issue") or "").strip()
        if not location or not issue:
            raise invalid_argument(f"each {label} entry requires location and issue")
        findings.append({"location": location, "issue": issue})
    return findings
