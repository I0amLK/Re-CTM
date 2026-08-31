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
        (WorkflowState.ASSESS, WorkflowState.ASSEMBLE),
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
        (WorkflowState.ASSEMBLE, WorkflowState.EXPLORE),
        (WorkflowState.LATEX_VALIDATE, WorkflowState.VERIFY),
        (WorkflowState.LATEX_VALIDATE, WorkflowState.REPAIR),
        (WorkflowState.VERIFY, WorkflowState.FINALIZE),
        (WorkflowState.VERIFY, WorkflowState.REPAIR),
        (WorkflowState.VERIFY, WorkflowState.EXPLORE),
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
        workspace_export_path: str | None = None,
        project_id: str | None = None,
        target_claim_id: str | None = None,
        workflow_mode: str = "auto",
        register_result: bool = True,
        workflow_protocol_version: int = 1,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        if not owner_id.strip():
            raise invalid_argument("owner_id is required")
        if not problem_tex.strip():
            raise invalid_argument("problem_tex is required")
        if workflow_mode not in {"auto", "compact", "full"}:
            raise invalid_argument("workflow_mode must be auto, compact, or full")
        if workflow_protocol_version not in {1, 2}:
            raise invalid_argument("workflow_protocol_version must be 1 or 2")
        if target_claim_id and not project_id:
            raise invalid_argument("target_claim_id requires project_id")
        if project_id:
            self.store.get_project(project_id, owner_id=owner_id)
            if target_claim_id:
                target_claim = self.store.get_claim(target_claim_id, owner_id=owner_id)
                if target_claim["project_id"] != project_id:
                    raise invalid_argument("target_claim_id must belong to project_id")
        resolved_problem_id = _safe_component(problem_id or "problem")
        reference_inputs: list[dict[str, Any]] = []
        for item in references:
            if not isinstance(item, Mapping):
                raise invalid_argument("references must contain only JSON objects")
            reference_inputs.append(dict(item))
        run_id = f"run-{resolved_problem_id}-{secrets.token_hex(6)}"
        resolved_export_path = (
            workspace_export_path.strip()
            if workspace_export_path and workspace_export_path.strip()
            else f"rethlas-output/{run_id}/proof_verified.tex"
        )
        vault_result = self.vault.initialize_run(
            run_id,
            problem_tex=problem_tex,
            references=reference_inputs,
            metadata={
                "problem_id": resolved_problem_id,
                "owner_id": owner_id,
                "created_at": utc_now(),
            },
        )
        project_snapshot: dict[str, Any] | None = None
        base_revision_id: str | None = None
        if project_id:
            project_snapshot = self.store.create_project_snapshot(project_id, owner_id=owner_id)
            if target_claim_id:
                current = self.store.current_claim_revision(target_claim_id, owner_id=owner_id)
                base_revision_id = current["revision_id"] if current else None
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
                "workspace_export_path": resolved_export_path,
                "workflow_protocol_version": workflow_protocol_version,
                "requested_workflow_mode": workflow_mode,
                "effective_workflow_mode": "full" if workflow_mode == "full" else "pending",
                "compact_verifier_failures": 0,
                "project_id": project_id,
                "project_snapshot_id": project_snapshot["snapshot_id"] if project_snapshot else None,
                "target_claim_id": target_claim_id,
            },
        )
        if project_snapshot is not None:
            self.store.link_run_to_project(
                run_id=run_id,
                owner_id=owner_id,
                project_id=project_id or "",
                project_snapshot_id=project_snapshot["snapshot_id"],
                target_claim_id=target_claim_id,
                base_revision_id=base_revision_id,
                requested_workflow_mode=workflow_mode,
                effective_workflow_mode="full" if workflow_mode == "full" else "pending",
                register_result=register_result,
            )
        reference_manifest = self.vault.read_references_manifest(run_id)
        for index, item in enumerate(reference_manifest):
            original = reference_inputs[index] if index < len(reference_inputs) else {}
            reference = self.store.register_reference(
                run_id=run_id,
                project_id=project_id,
                provider="inline",
                identity_key=f"inline:{item['name']}:{item['sha256']}",
                title=str(original.get("name") or item["name"]),
                source_uri=str(original.get("source") or "inline"),
                source_state="candidate",
                content_sha256=str(item.get("sha256") or ""),
                metadata={"vault_name": item["name"], "size": item.get("size")},
            )
            self.store.create_source_snapshot(
                reference_id=reference["reference_id"],
                provider="inline",
                source_uri=str(original.get("source") or "inline"),
                content=str(original.get("content") or ""),
                content_type="text/plain",
                metadata={"vault_name": item["name"]},
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
                "workflow_protocol_version": workflow_protocol_version,
                "workflow_mode": workflow_mode,
                "project_linked": project_snapshot is not None,
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
            "workspace_export_path": resolved_export_path,
            "workflow_protocol_version": workflow_protocol_version,
            "workflow_mode": workflow_mode,
            "project_id": project_id,
            "project_snapshot_id": project_snapshot["snapshot_id"] if project_snapshot else None,
            "target_claim_id": target_claim_id,
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
                "workspace_export_path": run.get("metadata", {}).get(
                    "workspace_export_path"
                ),
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
            task=self._task_for_run(run, state),
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

    def _task_for_run(self, run: Mapping[str, Any], state: WorkflowState) -> dict[str, Any]:
        task = task_for_state(state)
        protocol_version = int(run.get("metadata", {}).get("workflow_protocol_version") or 1)
        task["workflow_protocol_version"] = protocol_version
        if protocol_version >= 2 and state == WorkflowState.ASSESS:
            task["commit_payload_schema"] = {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "route": {"type": "string", "enum": ["compact", "full"]},
                    "route_reason": {"type": "string"},
                    "requires_external_retrieval": {"type": "boolean"},
                    "requires_multiple_plans": {"type": "boolean"},
                },
            }
            task["minimal_submission"]["payload"] = {
                "route": "compact",
                "route_reason": "The target is a local lemma with a direct self-contained proof.",
                "requires_external_retrieval": False,
                "requires_multiple_plans": False,
            }
            task["route_policy"] = (
                "Recommend compact only for a direct self-contained argument that does not need external retrieval "
                "or competing decomposition plans. The server makes the final route decision."
            )
        if protocol_version >= 2 and state in {WorkflowState.ASSEMBLE, WorkflowState.REPAIR}:
            contracts = list(task.get("write_contract") or [])
            if not any(item.get("resource") == "proof_manifest" for item in contracts if isinstance(item, Mapping)):
                contracts.append(
                    {
                        "resource": "proof_manifest",
                        "required": True,
                        "content_schema": {
                            "type": "object",
                            "required": [
                                "target_statement_tex",
                                "dependency_revision_ids",
                                "reference_ids",
                                "conditional_hypotheses",
                                "computational_evidence",
                            ],
                            "additionalProperties": False,
                            "properties": {
                                "target_statement_tex": {"type": "string", "minLength": 1},
                                "dependency_revision_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
                                "reference_ids": {"type": "array", "items": {"type": "string", "minLength": 1}},
                                "conditional_hypotheses": {"type": "array", "items": {"type": "string", "minLength": 1}},
                                "computational_evidence": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                            },
                        },
                        "example": {
                            "target_statement_tex": "Complete target statement in LaTeX.",
                            "dependency_revision_ids": [],
                            "reference_ids": [],
                            "conditional_hypotheses": [],
                            "computational_evidence": [],
                        },
                    }
                )
            task["write_contract"] = contracts
            required = list(task.get("required_records") or [])
            if "proof_manifest" not in required:
                required.append("proof_manifest")
            task["required_records"] = required
            minimal = dict(task.get("minimal_submission") or {})
            minimal_writes = list(minimal.get("writes") or [])
            if not any(
                isinstance(item, Mapping) and item.get("resource") == "proof_manifest"
                for item in minimal_writes
            ):
                minimal_writes.append(
                    {
                        "resource": "proof_manifest",
                        "content": {
                            "target_statement_tex": "Complete target statement in LaTeX.",
                            "dependency_revision_ids": [],
                            "reference_ids": [],
                            "conditional_hypotheses": [],
                            "computational_evidence": [],
                        },
                    }
                )
            minimal["writes"] = minimal_writes
            task["minimal_submission"] = minimal
            if state == WorkflowState.ASSEMBLE:
                compact = str(run.get("metadata", {}).get("effective_workflow_mode") or "") == "compact"
                if compact:
                    conditional_contracts: list[dict[str, Any]] = []
                    for contract in task["write_contract"]:
                        if not isinstance(contract, Mapping):
                            continue
                        normalized_contract = dict(contract)
                        if normalized_contract.get("resource") in {"proof", "proof_manifest"}:
                            normalized_contract.pop("required", None)
                            normalized_contract["required_when"] = (
                                "Required when payload.outcome=proof; omit when payload.outcome=escalate."
                            )
                        conditional_contracts.append(normalized_contract)
                    task["write_contract"] = conditional_contracts
                    task["required_records"] = []
                    task["required_records_for_outcome"] = {
                        "proof": ["proof", "proof_manifest"],
                        "escalate": [],
                    }
                    task["commit_payload_schema"] = {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "outcome": {"type": "string", "enum": ["proof", "escalate"]},
                            "escalation_reason": {"type": "string"},
                        },
                    }
                    task["commit_payload_contract"] = {
                        "outcome": "Use proof after writing proof and proof_manifest. Use escalate without proof writes when full exploration is required.",
                    }
                    task["minimal_submission"]["payload"] = {"outcome": "proof"}
                else:
                    task["commit_payload_schema"] = {"type": "object", "additionalProperties": False, "properties": {}}
                    task["commit_payload_contract"] = {
                        "proof": "Full-mode assembly writes proof and proof_manifest, then commits an empty payload."
                    }
                    task["minimal_submission"]["payload"] = {}
        if protocol_version >= 2 and state == WorkflowState.VERIFY:
            contracts = [
                dict(item)
                for item in (task.get("write_contract") or [])
                if isinstance(item, Mapping)
                and item.get("resource") != "memory:verifier:reference_checks"
            ]
            if not any(item.get("resource") == "reference_audit" for item in contracts if isinstance(item, Mapping)):
                contracts.append(
                    {
                        "resource": "reference_audit",
                        "required_when": "For every reference_id listed in proof_manifest.reference_ids.",
                        "content_schema": {
                            "type": "object",
                            "required": ["reference_id", "disposition", "evidence_basis", "evidence_locator"],
                            "additionalProperties": False,
                            "properties": {
                                "reference_id": {"type": "string", "minLength": 1},
                                "disposition": {
                                    "type": "string",
                                    "enum": ["SOURCE_VERIFIED", "INDEPENDENTLY_REDERIVED", "UNRESOLVED", "NOT_MATERIAL"],
                                },
                                "evidence_basis": {
                                    "type": "string",
                                    "enum": [
                                        "stored_source_snapshot", "external_source_inspection",
                                        "independent_derivation", "not_material", "unresolved"
                                    ],
                                },
                                "evidence_locator": {"type": "string"},
                                "material": {"type": "boolean"},
                                "assumptions_checked": {"type": "boolean"},
                                "notation_checked": {"type": "boolean"},
                                "source_checked": {"type": "boolean"},
                                "independently_rederived": {"type": "boolean"},
                                "notes": {"type": "string"},
                            },
                        },
                        "example": {
                            "reference_id": "ref-...",
                            "disposition": "SOURCE_VERIFIED",
                            "evidence_basis": "external_source_inspection",
                            "evidence_locator": "DOI/arXiv/source location inspected by the verifier",
                            "material": True,
                            "assumptions_checked": True,
                            "notation_checked": True,
                            "source_checked": True,
                            "independently_rederived": False,
                            "notes": "Assumptions and local notation match the cited statement.",
                        },
                    }
                )
            task["write_contract"] = contracts
            task["commit_payload_contract"] = {
                "memory_preconditions": (
                    "At least one memory:verifier:statement_checks record and one "
                    "memory:verifier:events audit-complete record."
                ),
                "reference_preconditions": (
                    "Every proof_manifest.reference_id is covered by structured reference_audit. "
                    "SOURCE_VERIFIED must identify the stored source snapshot or an external source "
                    "location actually inspected; INDEPENDENTLY_REDERIVED must identify the independent derivation. "
                    "Missing or UNRESOLVED material coverage becomes a server-derived verification gap."
                ),
                "server_reads_report_from": (
                    "the verification_report logical write; do not echo the report in commit payload"
                ),
            }
            task["rules"] = [
                rule
                for rule in (task.get("rules") or [])
                if "reference checks" not in str(rule).lower()
            ] + [
                "For protocol 2, use structured reference_audit writes rather than legacy memory:verifier:reference_checks records."
            ]
            try:
                manifest = self.store.read_proof_manifest(str(run["run_id"]))["manifest"]
            except ReCTMError:
                manifest = {}
            reference_ids = [
                str(item) for item in manifest.get("reference_ids", []) if isinstance(item, str)
            ]
            task["reference_ids_requiring_audit"] = reference_ids
            if reference_ids:
                examples = list(task.get("submission_examples") or [])
                examples.append(
                    {
                        "description": "Audit every material reference before verification_submitted.",
                        "writes": [
                            {
                                "resource": "reference_audit",
                                "content": {
                                    "reference_id": reference_id,
                                    "disposition": "SOURCE_VERIFIED",
                                    "evidence_basis": "external_source_inspection",
                                    "evidence_locator": "Replace with the source location actually inspected.",
                                    "material": True,
                                    "assumptions_checked": True,
                                    "notation_checked": True,
                                    "source_checked": True,
                                    "independently_rederived": False,
                                    "notes": "Replace with the actual audit result.",
                                },
                            }
                            for reference_id in reference_ids
                        ],
                        "action": "verification_submitted",
                        "payload": {},
                    }
                )
                task["submission_examples"] = examples
            task["reference_audit_policy"] = (
                "Every material reference listed by proof_manifest must receive a disposition plus evidence_basis/evidence_locator. "
                "Missing or UNRESOLVED material references are converted into server-side verification gaps even if the submitted report omits them."
            )
        return task

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
        operation: str = "theorem_search",
        author: str = "",
        title: str = "",
        keywords: str = "",
        search_intent: str = "theorem",
        num_results: int = 10,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        trace = trace_id or new_trace_id()
        if operation not in {"theorem_search", "paper_search", "paper_lookup", "theorem_context"}:
            raise invalid_argument("unsupported retrieval operation", operation=operation)
        claims = self.capabilities.validate(
            capability,
            owner_id=owner_id,
            action="retrieve",
            resource="external:theorems" if operation == "theorem_search" else "external:research",
            trace_id=trace,
        )
        if operation == "theorem_search":
            result = self.research.search_theorems(
                query=query,
                num_results=num_results,
                search_intent=search_intent,
            )
        elif operation == "paper_search":
            search_papers = getattr(self.research, "search_papers", None)
            if not callable(search_papers):
                raise ReCTMError(
                    "PAPER_SEARCH_UNSUPPORTED",
                    "The configured research provider has no paper search.",
                    category="runtime",
                )
            result = search_papers(
                query=query,
                author=author,
                title=title,
                keywords=keywords,
                num_results=num_results,
            )
        elif operation == "paper_lookup":
            lookup_paper = getattr(self.research, "lookup_paper", None)
            if not callable(lookup_paper):
                raise ReCTMError(
                    "PAPER_SEARCH_UNSUPPORTED",
                    "The configured research provider has no paper lookup.",
                    category="runtime",
                )
            result = lookup_paper(identifier=query)
        else:
            reference = self.store.get_reference(query.strip())
            if reference["run_id"] != claims.run_id:
                raise ReCTMError("REFERENCE_RUN_MISMATCH", "The requested theorem context is outside the active run.", category="permission")
            metadata = dict(reference.get("metadata") or {})
            return {
                "ok": True,
                "run_id": claims.run_id,
                "operation": operation,
                "reference": reference,
                "content": str(metadata.get("retrieved_theorem") or ""),
                "source_trust": reference.get("source_state") or "candidate",
                "usage_rule": "This is stored discovery context, not proof that the source statement was checked in the original paper.",
                "trace_id": trace,
            }
        project_run = self.store.get_project_run(claims.run_id, owner_id=owner_id)
        registered_results: list[dict[str, Any]] = []
        for item in result["results"]:
            identity_material = "|".join(
                [
                    str(item.get("paper_id") or ""),
                    str(item.get("arxiv_id") or ""),
                    str(item.get("theorem_id") or ""),
                    str(item.get("title") or ""),
                    str(item.get("theorem") or ""),
                ]
            )
            identity_key = operation + ":" + hashlib.sha256(identity_material.encode("utf-8")).hexdigest()
            reference = self.store.register_reference(
                run_id=claims.run_id,
                project_id=project_run["project_id"] if project_run else None,
                provider=operation,
                identity_key=identity_key,
                title=str(item.get("title") or ""),
                paper_id=str(item.get("paper_id") or ""),
                arxiv_id=str(item.get("arxiv_id") or ""),
                doi=str(item.get("doi") or ""),
                theorem_id=str(item.get("theorem_id") or ""),
                source_uri=str(item.get("source_uri") or item.get("landing_page_url") or ""),
                source_state="candidate",
                metadata={
                    "retrieved_theorem": str(item.get("theorem") or ""),
                    "authors": item.get("authors") or [],
                    "publication_year": item.get("publication_year"),
                    "open_access_url": item.get("open_access_url") or "",
                },
            )
            source_snapshot = self.store.create_source_snapshot(
                reference_id=reference["reference_id"],
                provider=operation,
                source_uri=str(item.get("source_uri") or item.get("landing_page_url") or result.get("endpoint") or ""),
                content=json.dumps(item, ensure_ascii=False, sort_keys=True),
                content_type="application/json",
                metadata={"operation": operation, "query": result.get("query")},
            )
            registered_results.append(
                {
                    **item,
                    "reference_id": reference["reference_id"],
                    "source_snapshot_id": source_snapshot["source_snapshot_id"],
                    "source_snapshot_sha256": source_snapshot["content_sha256"],
                }
            )
        result = {**result, "results": registered_results, "count": len(registered_results)}
        record = {
            "event_type": f"external_{operation}",
            "query": result["query"],
            "operation": operation,
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
            "research.retrieval_completed",
            "workflow_engine",
            trace_id=trace,
            run_id=claims.run_id,
            actor_role=claims.role.value,
            domain_id=claims.domain_id,
            decision="allow",
            reason="research_capability_passed",
            details={
                "operation": operation,
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
            "workspace_export_path": run.get("metadata", {}).get(
                "workspace_export_path"
            ),
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
        elif artifact == "proof_manifest":
            content = self.store.read_proof_manifest(run_id)
        elif artifact == "reference_audit":
            references = self.store.list_run_references(run_id)
            content = {
                "references": [
                    {
                        **item,
                        "source_snapshots": self.store.list_source_snapshots(item["reference_id"]),
                    }
                    for item in references
                ],
                "audits": self.store.list_reference_audits(run_id),
            }
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
        return {
            "ok": True,
            "run_id": run_id,
            "artifact": artifact,
            "content": content,
            "workspace_export_path": run.get("metadata", {}).get(
                "workspace_export_path"
            ),
        }

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
            if state == WorkflowState.DONE:
                run = self._retry_pending_registry_promotion(run, trace_id)
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
        protocol_version = int(run.get("metadata", {}).get("workflow_protocol_version") or 1)
        resources = list(_resources_for_role(role))
        if protocol_version >= 2:
            if role is WorkflowRole.VERIFIER:
                resources = [
                    "references:candidates" if item == "references:approved" else item
                    for item in resources
                ]
                for resource in ("proof_manifest", "project:verified_dependencies"):
                    if resource not in resources:
                        resources.append(resource)
            elif role in {WorkflowRole.GENERATOR, WorkflowRole.BRANCH, WorkflowRole.ASSEMBLER, WorkflowRole.REPAIR}:
                if "project:verified_dependencies" not in resources:
                    resources.append("project:verified_dependencies")
        context: dict[str, Any] = {
            "problem_id": run["problem_id"],
            "round_index": run["round_index"],
            "available_logical_resources": resources,
            "manual_validation_required": True,
        }
        project_run = self.store.get_project_run(str(run["run_id"]), owner_id=str(run["owner_id"]))
        if project_run is not None:
            snapshot = self.store.get_project_snapshot(
                project_run["project_snapshot_id"],
                owner_id=str(run["owner_id"]),
            )
            verified = [
                item for item in snapshot["revisions"]
                if item.get("evidence_status") in {"VERIFIED", "CONDITIONAL"}
            ]
            if role is WorkflowRole.VERIFIER:
                try:
                    manifest = self.store.read_proof_manifest(str(run["run_id"]))["manifest"]
                except ReCTMError:
                    manifest = {}
                dependency_ids = {
                    str(item) for item in manifest.get("dependency_revision_ids", []) if isinstance(item, str)
                }
                context["project_context"] = {
                    "project_snapshot_id": snapshot["snapshot_id"],
                    "project_snapshot_sha256": snapshot["snapshot_sha256"],
                    "verified_dependencies": [
                        item for item in verified if item.get("revision_id") in dependency_ids
                    ],
                }
            else:
                context["project_context"] = {
                    "project_id": project_run["project_id"],
                    "project_snapshot_id": snapshot["snapshot_id"],
                    "project_snapshot_sha256": snapshot["snapshot_sha256"],
                    "target_claim_id": project_run.get("target_claim_id"),
                    "base_revision_id": project_run.get("base_revision_id"),
                    "effective_workflow_mode": project_run.get("effective_workflow_mode"),
                    "verified_revisions": verified,
                }
        if state == WorkflowState.DIRECT_PROVING:
            active_plans = run.get("metadata", {}).get("active_plans", [])
            progress = run.get("metadata", {}).get("direct_screening_progress", {})
            public_plans = _public_active_plans(active_plans)
            preferred_shape: dict[str, Any] = {}
            if public_plans and public_plans[0].get("subgoals"):
                first_plan = public_plans[0]
                first_subgoal = first_plan["subgoals"][0]
                preferred_shape = {
                    str(first_plan["plan_id"]): {
                        str(first_subgoal["subgoal_id"]): {
                            "status": "solved|partial|stuck",
                            "summary": "...",
                        }
                    }
                }
            context.update(
                {
                    "active_plans": public_plans,
                    "screening_progress": progress if isinstance(progress, Mapping) else {},
                    "screening_contract": {
                        "preferred_shape": preferred_shape,
                        "server_derives": [
                            "plan status",
                            "overall solved-vs-branch outcome",
                            "branch set when no plan is solved",
                            "stuck-point summary",
                        ],
                        "incomplete_submission": "Accepted without transition; response lists missing plan/subgoal ids.",
                    },
                }
            )
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
        if resource == "references":
            manifest = self.vault.read_references_manifest(claims.run_id)
            return {
                "manifest": manifest,
                "references": [
                    {"name": item["name"], "content": self.vault.read_reference(claims.run_id, item["name"])}
                    for item in manifest
                ],
            }
        if resource in {"references:candidates", "references:approved"}:
            protocol_version = int(
                self.store.get_run(claims.run_id).get("metadata", {}).get("workflow_protocol_version") or 1
            )
            if resource == "references:approved" and protocol_version < 2:
                manifest = self.vault.read_references_manifest(claims.run_id)
                return {
                    "manifest": manifest,
                    "references": [
                        {"name": item["name"], "content": self.vault.read_reference(claims.run_id, item["name"])}
                        for item in manifest
                    ],
                }
            references = self.store.list_run_references(claims.run_id)
            audits = {item["reference_id"]: item for item in self.store.list_reference_audits(claims.run_id)}
            if resource == "references:approved":
                references = [
                    item for item in references
                    if audits.get(item["reference_id"], {}).get("disposition")
                    in {"SOURCE_VERIFIED", "INDEPENDENTLY_REDERIVED", "NOT_MATERIAL"}
                ]
            enriched: list[dict[str, Any]] = []
            for item in references:
                metadata = dict(item.get("metadata") or {})
                content = ""
                vault_name = str(metadata.get("vault_name") or "")
                if vault_name:
                    content = self.vault.read_reference(claims.run_id, vault_name)
                elif metadata.get("retrieved_theorem"):
                    content = str(metadata["retrieved_theorem"])
                source_snapshots = []
                for snapshot in self.store.list_source_snapshots(item["reference_id"]):
                    snapshot_metadata = dict(snapshot.get("metadata") or {})
                    source_snapshots.append(
                        {
                            "source_snapshot_id": snapshot["source_snapshot_id"],
                            "provider": snapshot["provider"],
                            "source_uri": snapshot["source_uri"],
                            "content_sha256": snapshot["content_sha256"],
                            "content_type": snapshot["content_type"],
                            "content": str(snapshot_metadata.get("content") or ""),
                        }
                    )
                enriched.append(
                    {
                        **item,
                        "content": content,
                        "source_snapshots": source_snapshots,
                        "audit": audits.get(item["reference_id"]),
                    }
                )
            return {"references": enriched}
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
        if resource == "proof_manifest":
            return self.store.read_proof_manifest(claims.run_id)
        if resource == "project:verified_dependencies":
            project_run = self.store.get_project_run(claims.run_id, owner_id=claims.owner_id)
            if project_run is None:
                return {"project_id": None, "snapshot_id": None, "revisions": []}
            snapshot = self.store.get_project_snapshot(
                project_run["project_snapshot_id"],
                owner_id=claims.owner_id,
            )
            revisions = [
                item for item in snapshot["revisions"]
                if item.get("evidence_status") in {"VERIFIED", "CONDITIONAL"}
            ]
            if claims.role is WorkflowRole.VERIFIER:
                manifest = self.store.read_proof_manifest(claims.run_id)["manifest"]
                dependency_ids = {
                    str(item) for item in manifest.get("dependency_revision_ids", []) if isinstance(item, str)
                }
                revisions = [item for item in revisions if item.get("revision_id") in dependency_ids]
            return {
                "project_id": project_run["project_id"],
                "snapshot_id": snapshot["snapshot_id"],
                "snapshot_sha256": snapshot["snapshot_sha256"],
                "revisions": revisions,
            }
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
        if resource == "proof_manifest":
            if not isinstance(content, Mapping):
                raise invalid_argument("proof_manifest must be a JSON object")
            manifest = self._normalize_proof_manifest(claims, content)
            stored = self.store.write_proof_manifest(claims.run_id, manifest)
            return {"path_kind": "proof_manifest", "sha256": stored["sha256"]}
        if resource == "verification_report":
            if not isinstance(content, Mapping):
                raise invalid_argument("verification_report must be a JSON object")
            normalized = _normalize_verification_report(dict(content))
            path = self.vault.write_verification_report(claims.run_id, normalized)
            return {"path_kind": "verification_report", "file": path.name}
        if resource == "reference_audit":
            if claims.role is not WorkflowRole.VERIFIER or not isinstance(content, Mapping):
                raise invalid_argument("reference_audit writes require a verifier JSON object")
            raw_reference_id = content.get("reference_id")
            raw_disposition = content.get("disposition")
            if not isinstance(raw_reference_id, str) or not isinstance(raw_disposition, str):
                raise invalid_argument("reference_audit requires reference_id and disposition")
            reference_id = raw_reference_id.strip()
            disposition = raw_disposition.strip()
            if not reference_id or not disposition:
                raise invalid_argument("reference_audit requires non-empty reference_id and disposition")
            raw_evidence_basis = content.get("evidence_basis")
            raw_evidence_locator = content.get("evidence_locator")
            if not isinstance(raw_evidence_basis, str) or not isinstance(raw_evidence_locator, str):
                raise invalid_argument("reference_audit requires evidence_basis and evidence_locator strings")
            evidence_basis = raw_evidence_basis.strip()
            evidence_locator = raw_evidence_locator.strip()
            valid_evidence_basis = {
                "stored_source_snapshot",
                "external_source_inspection",
                "independent_derivation",
                "not_material",
                "unresolved",
            }
            if evidence_basis not in valid_evidence_basis:
                raise invalid_argument("reference_audit.evidence_basis is unsupported")
            boolean_fields = (
                "material", "assumptions_checked", "notation_checked",
                "source_checked", "independently_rederived",
            )
            for field in boolean_fields:
                if field in content and not isinstance(content[field], bool):
                    raise invalid_argument(f"reference_audit.{field} must be boolean")
            notes = content.get("notes", "")
            if not isinstance(notes, str):
                raise invalid_argument("reference_audit.notes must be a string")
            material = content.get("material", True)
            assumptions_checked = content.get("assumptions_checked", False)
            notation_checked = content.get("notation_checked", False)
            source_checked = content.get("source_checked", False)
            independently_rederived = content.get("independently_rederived", False)
            if disposition == "SOURCE_VERIFIED" and not (
                source_checked and assumptions_checked and notation_checked
            ):
                raise invalid_argument(
                    "SOURCE_VERIFIED requires source_checked, assumptions_checked, and notation_checked to be true"
                )
            if disposition == "SOURCE_VERIFIED":
                if evidence_basis not in {"stored_source_snapshot", "external_source_inspection"}:
                    raise invalid_argument(
                        "SOURCE_VERIFIED requires stored_source_snapshot or external_source_inspection evidence_basis"
                    )
                if not evidence_locator:
                    raise invalid_argument("SOURCE_VERIFIED requires a non-empty evidence_locator")
                if evidence_basis == "stored_source_snapshot":
                    snapshots = {
                        item["source_snapshot_id"]: item
                        for item in self.store.list_source_snapshots(reference_id)
                    }
                    if evidence_locator not in snapshots:
                        raise invalid_argument(
                            "Stored source evidence_locator must identify a source snapshot for the audited reference"
                        )
                    if snapshots[evidence_locator].get("provider") != "inline":
                        raise invalid_argument(
                            "Stored theorem/paper discovery snapshots are unverified metadata, not original-source evidence; use external_source_inspection after checking the actual source"
                        )
            if disposition == "INDEPENDENTLY_REDERIVED" and not independently_rederived:
                raise invalid_argument(
                    "INDEPENDENTLY_REDERIVED requires independently_rederived=true"
                )
            if disposition == "INDEPENDENTLY_REDERIVED" and evidence_basis != "independent_derivation":
                raise invalid_argument(
                    "INDEPENDENTLY_REDERIVED requires evidence_basis=independent_derivation"
                )
            if disposition == "INDEPENDENTLY_REDERIVED" and not evidence_locator:
                raise invalid_argument("INDEPENDENTLY_REDERIVED requires a non-empty evidence_locator")
            if disposition == "NOT_MATERIAL" and material:
                raise invalid_argument("NOT_MATERIAL requires material=false")
            if disposition == "NOT_MATERIAL" and evidence_basis != "not_material":
                raise invalid_argument("NOT_MATERIAL requires evidence_basis=not_material")
            if disposition == "UNRESOLVED" and evidence_basis != "unresolved":
                raise invalid_argument("UNRESOLVED requires evidence_basis=unresolved")
            audit = self.store.write_reference_audit(
                run_id=claims.run_id,
                reference_id=reference_id,
                disposition=disposition,
                evidence_basis=evidence_basis,
                evidence_locator=evidence_locator,
                verifier_domain_id=claims.domain_id,
                proof_sha256=hashlib.sha256(
                    self.vault.read_proof(claims.run_id).encode("utf-8")
                ).hexdigest(),
                proof_manifest_sha256=self.store.read_proof_manifest(
                    claims.run_id
                )["sha256"],
                material=material,
                assumptions_checked=assumptions_checked,
                notation_checked=notation_checked,
                source_checked=source_checked,
                independently_rederived=independently_rederived,
                notes=notes,
            )
            return {"path_kind": "reference_audit", "reference_id": reference_id, "disposition": audit["disposition"]}
        if resource == "branch:self":
            raise ReCTMError(
                "BRANCH_RESULT_REQUIRES_COMMIT",
                "Branch results are written and sealed atomically by branch_complete.",
                category="validation",
            )
        raise invalid_argument("unknown or non-writable logical resource", resource=resource)

    def _normalize_proof_manifest(
        self,
        claims: CapabilityClaims,
        content: Mapping[str, Any],
    ) -> dict[str, Any]:
        statement = content.get("target_statement_tex")
        if not isinstance(statement, str) or not statement.strip():
            raise invalid_argument("proof_manifest.target_statement_tex must be a non-empty string")
        dependency_ids = _string_array(
            content.get("dependency_revision_ids"),
            label="proof_manifest dependency_revision_ids",
        )
        reference_ids = _string_array(
            content.get("reference_ids"),
            label="proof_manifest reference_ids",
        )
        conditions = _string_array(
            content.get("conditional_hypotheses"),
            label="proof_manifest conditional_hypotheses",
        )
        computational = content.get("computational_evidence")
        if not isinstance(computational, list) or any(not isinstance(item, Mapping) for item in computational):
            raise invalid_argument("proof_manifest computational_evidence must be an array of JSON objects")
        project_run = self.store.get_project_run(claims.run_id, owner_id=claims.owner_id)
        snapshot_revision_ids: set[str] = set()
        if project_run is not None:
            snapshot = self.store.get_project_snapshot(
                project_run["project_snapshot_id"],
                owner_id=claims.owner_id,
            )
            snapshot_revision_ids = {
                str(item.get("revision_id"))
                for item in snapshot["revisions"]
                if item.get("evidence_status") in {"VERIFIED", "CONDITIONAL"}
            }
        if dependency_ids and project_run is None:
            raise invalid_argument("Standalone runs cannot declare project dependency revisions")
        invalid_dependencies = sorted(set(dependency_ids) - snapshot_revision_ids)
        if invalid_dependencies:
            raise invalid_argument(
                "proof_manifest dependencies must come from the frozen verified project snapshot",
                invalid_revision_ids=invalid_dependencies,
            )
        known_references = {
            item["reference_id"] for item in self.store.list_run_references(claims.run_id)
        }
        invalid_references = sorted(set(reference_ids) - known_references)
        if invalid_references:
            raise invalid_argument(
                "proof_manifest reference_ids must identify references registered for this run",
                invalid_reference_ids=invalid_references,
            )
        return {
            "target_statement_tex": statement.strip(),
            "dependency_revision_ids": dependency_ids,
            "reference_ids": reference_ids,
            "conditional_hypotheses": conditions,
            "computational_evidence": [dict(item) for item in computational],
            "project_snapshot_id": project_run["project_snapshot_id"] if project_run else None,
            "workflow_protocol_version": int(
                self.store.get_run(claims.run_id).get("metadata", {}).get("workflow_protocol_version") or 1
            ),
        }

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
            after = self._commit_assessment_complete(run, claims, payload)
        elif action == "exploration_complete":
            after = self._commit_exploration_complete(claims)
        elif action == "plans_proposed":
            after = self._commit_plans_proposed(run, claims, payload)
        elif action == "direct_proving_complete":
            direct_result = self._commit_direct_proving_complete(run, claims, payload)
            if isinstance(direct_result, dict):
                return direct_result
            after = direct_result
        elif action == "branch_complete":
            return self._commit_branch(run, claims, payload, trace_id)
        elif action == "join_complete":
            after = self._commit_join_complete(claims, payload)
        elif action == "failures_identified":
            after = self._commit_failures_identified(claims, payload)
        elif action == "replan_complete":
            after = self._commit_replan_complete(claims, payload)
        elif action == "proof_submitted":
            proof_result = self._commit_proof_submitted(run, claims, payload, trace_id)
            if isinstance(proof_result, dict):
                return proof_result
            after = proof_result
        elif action == "verification_submitted":
            return self._commit_verification_submitted(run, claims, trace_id)
        elif action == "repair_submitted":
            after = self._commit_repair_submitted(run, claims)
        else:
            raise invalid_argument("unsupported commit action", action=action)
        return self._seal_and_transition(
            run,
            claims,
            after,
            trace_id,
            reason=action,
        )

    def _commit_assessment_complete(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        payload: Mapping[str, Any],
    ) -> WorkflowState:
        self._require_records(claims.run_id, "immediate_conclusions")
        protocol_version = int(run.get("metadata", {}).get("workflow_protocol_version") or 1)
        if protocol_version < 2:
            return WorkflowState.EXPLORE

        requested = str(run.get("metadata", {}).get("requested_workflow_mode") or "auto")
        route = str(payload.get("route") or "full")
        needs_retrieval = bool(payload.get("requires_external_retrieval"))
        needs_plans = bool(payload.get("requires_multiple_plans"))
        has_registered_refs = bool(self.store.list_run_references(claims.run_id))
        compact_allowed = not needs_retrieval and not needs_plans and not has_registered_refs
        if requested == "full":
            effective_mode = "full"
        elif requested == "compact":
            effective_mode = "compact" if compact_allowed else "full"
        else:
            effective_mode = "compact" if route == "compact" and compact_allowed else "full"
        self.store.update_run_metadata(
            claims.run_id,
            {
                "effective_workflow_mode": effective_mode,
                "workflow_route_reason": str(payload.get("route_reason") or ""),
                "compact_route_allowed": compact_allowed,
            },
        )
        project_run = self.store.get_project_run(claims.run_id, owner_id=claims.owner_id)
        if project_run is not None:
            self.store.set_project_run_mode(claims.run_id, effective_mode)
        return WorkflowState.ASSEMBLE if effective_mode == "compact" else WorkflowState.EXPLORE

    def _commit_exploration_complete(self, claims: CapabilityClaims) -> WorkflowState:
        self._require_records(claims.run_id, "events")
        return WorkflowState.PROPOSE_PLANS

    def _commit_plans_proposed(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        payload: Mapping[str, Any],
    ) -> WorkflowState:
        plans = _validate_plans(
            payload.get("plans"),
            plan_round=int(run.get("round_index") or 0) + 1,
        )
        for plan in plans:
            self.vault.append_generation_memory(
                claims.run_id,
                "subgoals",
                {**plan, "record_type": "decomposition_plan", "status": "proposed"},
            )
        self.store.update_run_metadata(
            claims.run_id,
            {"active_plans": plans, "direct_screening_progress": {}},
        )
        return WorkflowState.DIRECT_PROVING

    def _commit_direct_proving_complete(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        payload: Mapping[str, Any],
    ) -> WorkflowState | dict[str, Any]:
        self._require_records(claims.run_id, "proof_steps")
        active_plans = run.get("metadata", {}).get("active_plans", [])
        screening, progress, missing = _merge_direct_screening(
            payload.get("screening"),
            active_plans,
            run.get("metadata", {}).get("direct_screening_progress"),
        )
        self.store.update_run_metadata(
            claims.run_id,
            {"direct_screening_progress": progress},
        )
        if missing:
            return {
                "run_id": claims.run_id,
                "state": WorkflowState.DIRECT_PROVING.value,
                "complete": False,
                "screening_complete": False,
                "missing_screening": missing,
                "accepted_progress": screening,
                "verdict": run.get("verdict"),
            }
        self.vault.append_generation_memory(
            claims.run_id,
            "proof_steps",
            {
                "record_type": "direct_screening_round",
                "plans": screening,
                "created_at": utc_now(),
            },
        )
        solved_plan_ids = [
            item["plan_id"] for item in screening if item["status"] == "solved"
        ]
        if solved_plan_ids:
            if not str(payload.get("proof_route") or "").strip():
                raise invalid_argument("solved outcome requires proof_route")
            selected_plan_id = str(payload.get("selected_plan_id") or "")
            source_to_plan = {
                str(plan.get("source_plan_id")): str(plan.get("plan_id"))
                for plan in active_plans
                if isinstance(plan, Mapping) and str(plan.get("source_plan_id") or "")
            }
            selected_plan_id = source_to_plan.get(selected_plan_id, selected_plan_id)
            if not selected_plan_id and len(solved_plan_ids) == 1:
                selected_plan_id = solved_plan_ids[0]
            if selected_plan_id not in solved_plan_ids:
                raise invalid_argument(
                    "selected_plan_id must identify a completely solved plan",
                    solved_plan_ids=solved_plan_ids,
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
            return WorkflowState.ASSEMBLE

        branch_plans = [dict(plan) for plan in active_plans if isinstance(plan, Mapping)]
        self.store.update_run_metadata(
            claims.run_id,
            {"branch_requests": branch_plans, "last_direct_screening": screening},
        )
        return WorkflowState.BRANCH_PREPARE

    def _commit_join_complete(
        self,
        claims: CapabilityClaims,
        payload: Mapping[str, Any],
    ) -> WorkflowState:
        branches = self.store.list_branches(claims.run_id)
        sealed_ids = {
            str(item["branch_id"]) for item in branches if item["status"] == "sealed"
        }
        considered = payload.get("considered_branch_ids")
        if considered is not None:
            considered_ids = _string_array(
                considered,
                label="considered_branch_ids",
            )
            if any(item not in sealed_ids for item in considered_ids):
                raise invalid_argument(
                    "considered_branch_ids may contain only sealed branch ids; complete coverage is server-derived",
                    sealed_branch_ids=sorted(sealed_ids),
                )
        branch_results = {
            branch_id: self.vault.read_branch_result(claims.run_id, branch_id)
            for branch_id in sealed_ids
        }
        solved_branch_ids = sorted(
            branch_id
            for branch_id, result in branch_results.items()
            if isinstance(result, Mapping) and result.get("status") == "solved"
        )
        raw_selected = payload.get("selected_branch_id")
        if raw_selected is not None and not isinstance(raw_selected, str):
            raise invalid_argument("selected_branch_id must be a string when supplied")
        selected = (raw_selected or "").strip()
        raw_synthesis_route = payload.get("synthesis_proof_route")
        if raw_synthesis_route is not None and not isinstance(raw_synthesis_route, str):
            raise invalid_argument("synthesis_proof_route must be a string when supplied")
        synthesis_route = (raw_synthesis_route or "").strip()
        if not selected and not synthesis_route and len(solved_branch_ids) == 1:
            selected = solved_branch_ids[0]
        if selected and selected not in solved_branch_ids:
            raise invalid_argument(
                "selected_branch_id must identify a solved sealed branch",
                selected_branch_id=selected,
                solved_branch_ids=solved_branch_ids,
            )
        if not selected and not synthesis_route and len(solved_branch_ids) > 1:
            raise invalid_argument(
                "multiple solved branches require selected_branch_id or synthesis_proof_route",
                solved_branch_ids=solved_branch_ids,
            )
        outcome = "solved" if synthesis_route or selected else "failed"
        common_failures: list[str] | None = None
        if outcome == "failed":
            common_failures = _string_array(
                payload.get("common_failures"),
                label="common_failures",
                required=True,
            )
        normalized_join = {
            **payload,
            "outcome": outcome,
            "selected_branch_id": selected or None,
            "considered_branch_ids": sorted(sealed_ids),
            "joined_at": utc_now(),
        }
        if common_failures is not None:
            normalized_join["common_failures"] = common_failures
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
        return (
            WorkflowState.ASSEMBLE
            if outcome == "solved"
            else WorkflowState.IDENTIFY_FAILURES
        )

    def _commit_failures_identified(
        self,
        claims: CapabilityClaims,
        payload: Mapping[str, Any],
    ) -> WorkflowState:
        if not isinstance(payload.get("summary"), Mapping):
            raise invalid_argument("failures_identified requires summary object")
        self.vault.append_generation_memory(
            claims.run_id,
            "failed_paths",
            {"record_type": "key_failures_summary", **dict(payload["summary"])},
        )
        return WorkflowState.REPLAN

    def _commit_replan_complete(
        self,
        claims: CapabilityClaims,
        payload: Mapping[str, Any],
    ) -> WorkflowState:
        if not isinstance(payload.get("decision"), Mapping):
            raise invalid_argument("replan_complete requires decision object")
        self.vault.append_generation_memory(
            claims.run_id,
            "big_decisions",
            dict(payload["decision"]),
        )
        return WorkflowState.PROPOSE_PLANS

    def _commit_proof_submitted(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        payload: Mapping[str, Any],
        trace_id: str,
    ) -> WorkflowState | dict[str, Any]:
        protocol_version = int(run.get("metadata", {}).get("workflow_protocol_version") or 1)
        if protocol_version >= 2 and str(payload.get("outcome") or "proof") == "escalate":
            if str(run.get("metadata", {}).get("effective_workflow_mode") or "") != "compact":
                raise invalid_argument("Only a compact assembly may escalate to full exploration")
            self.store.update_run_metadata(
                claims.run_id,
                {
                    "effective_workflow_mode": "full",
                    "compact_escalation_reason": str(
                        payload.get("escalation_reason")
                        or "assembly requested full exploration"
                    ),
                },
            )
            project_run = self.store.get_project_run(claims.run_id, owner_id=claims.owner_id)
            if project_run is not None:
                self.store.set_project_run_mode(claims.run_id, "full")
            return self._seal_and_transition(
                run,
                claims,
                WorkflowState.EXPLORE,
                trace_id,
                reason="compact_assembly_escalated_to_full",
            )
        proof = self.vault.read_proof(claims.run_id)
        if protocol_version >= 2:
            self.store.read_proof_manifest(claims.run_id)
        self.store.update_run_metadata(
            claims.run_id,
            {"last_submitted_proof_sha256": hashlib.sha256(proof.encode("utf-8")).hexdigest()},
        )
        return WorkflowState.LATEX_VALIDATE

    def _commit_verification_submitted(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
        trace_id: str,
    ) -> dict[str, Any]:
        self._require_verifier_records(claims.run_id, "statement_checks")
        self._require_verifier_records(claims.run_id, "events")
        proof = self.vault.read_proof(claims.run_id)
        protocol_version = int(run.get("metadata", {}).get("workflow_protocol_version") or 1)
        if protocol_version < 2 and _proof_declares_external_references(proof):
            self._require_verifier_records(claims.run_id, "reference_checks")
        report = self.vault.read_verification_report(claims.run_id)
        normalized = _normalize_verification_report(report)
        critical = normalized["verification_report"]["critical_errors"]
        gaps = normalized["verification_report"]["gaps"]
        server_reference_gaps: list[dict[str, str]] = []
        if protocol_version >= 2:
            manifest_record = self.store.read_proof_manifest(claims.run_id)
            manifest = manifest_record["manifest"]
            audit_by_reference = {
                item["reference_id"]: item
                for item in self.store.list_reference_audits(claims.run_id)
            }
            for reference_id in manifest.get("reference_ids", []):
                audit = audit_by_reference.get(reference_id)
                if audit is None:
                    finding = {
                        "location": f"reference:{reference_id}",
                        "issue": "Material reference has no verifier audit disposition.",
                    }
                    gaps.append(finding)
                    server_reference_gaps.append(finding)
                    continue
                if audit.get("disposition") not in {
                    "SOURCE_VERIFIED",
                    "INDEPENDENTLY_REDERIVED",
                    "NOT_MATERIAL",
                }:
                    finding = {
                        "location": f"reference:{reference_id}",
                        "issue": "Material reference remains unresolved after verifier audit.",
                    }
                    gaps.append(finding)
                    server_reference_gaps.append(finding)
        verdict = "correct" if not critical and not gaps else "wrong"
        normalized["verdict"] = verdict
        if verdict == "correct":
            normalized["repair_hints"] = ""
        elif not str(normalized.get("repair_hints") or "").strip():
            if server_reference_gaps:
                normalized["repair_hints"] = (
                    "Resolve the server-detected reference audit gaps before resubmission: "
                    + "; ".join(
                        f"{item['location']}: {item['issue']}"
                        for item in server_reference_gaps
                    )
                )
            else:
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
                    "legacy_reference_checks": len(
                        self.vault.read_verifier_memory(claims.run_id, "reference_checks")
                    ),
                    "structured_reference_audits": len(
                        self.store.list_reference_audits(claims.run_id)
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
        if verdict == "correct":
            after = WorkflowState.FINALIZE
        else:
            compact = (
                str(run.get("metadata", {}).get("effective_workflow_mode") or "")
                == "compact"
            )
            failures = int(run.get("metadata", {}).get("compact_verifier_failures") or 0) + (
                1 if compact else 0
            )
            if compact:
                self.store.update_run_metadata(
                    claims.run_id,
                    {"compact_verifier_failures": failures},
                )
            if compact and failures >= 2:
                self.store.update_run_metadata(
                    claims.run_id,
                    {
                        "effective_workflow_mode": "full",
                        "compact_escalated_after_verifier": True,
                    },
                )
                project_run = self.store.get_project_run(
                    claims.run_id,
                    owner_id=claims.owner_id,
                )
                if project_run is not None:
                    self.store.set_project_run_mode(claims.run_id, "full")
                after = WorkflowState.EXPLORE
            else:
                after = WorkflowState.REPAIR
        return self._seal_and_transition(
            run,
            claims,
            after,
            trace_id,
            reason=(
                "compact_verifier_escalated_to_full"
                if verdict == "wrong" and after == WorkflowState.EXPLORE
                else f"server_computed_verdict_{verdict}"
            ),
            verdict=verdict,
        )

    def _commit_repair_submitted(
        self,
        run: Mapping[str, Any],
        claims: CapabilityClaims,
    ) -> WorkflowState:
        proof = self.vault.read_proof(claims.run_id)
        protocol_version = int(run.get("metadata", {}).get("workflow_protocol_version") or 1)
        if protocol_version >= 2:
            self.store.read_proof_manifest(claims.run_id)
        proof_sha256 = hashlib.sha256(proof.encode("utf-8")).hexdigest()
        prior_sha256 = str(run.get("metadata", {}).get("last_verified_proof_sha256") or "")
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
        return WorkflowState.LATEX_VALIDATE

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
        raw_status = payload.get("status")
        status = raw_status.strip() if isinstance(raw_status, str) else ""
        if status not in {"solved", "partial", "failed"}:
            raise invalid_argument("branch status must be solved, partial, or failed")
        raw_summary = payload.get("summary")
        if not isinstance(raw_summary, str):
            raise invalid_argument("branch result summary must be a string")
        summary = raw_summary.strip()
        raw_proof_route = payload.get("proof_route")
        if raw_proof_route is not None and not isinstance(raw_proof_route, str):
            raise invalid_argument("branch proof_route must be a string when supplied")
        proof_route = (raw_proof_route or "").strip()
        proved_subgoals = _string_array(
            payload.get("proved_subgoals"),
            label="proved_subgoals",
        )
        unproved_subgoals = _string_array(
            payload.get("unproved_subgoals"),
            label="unproved_subgoals",
        )
        failure_evidence = _string_array(
            payload.get("failure_evidence"),
            label="failure_evidence",
        )
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
            "proved_subgoals": proved_subgoals,
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
        result = self._retry_pending_registry_promotion(result, trace_id)
        self._write_manual_validation_manifest(result)
        return result

    def _retry_pending_registry_promotion(
        self,
        run: Mapping[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        if WorkflowState(str(run["state"])) != WorkflowState.DONE:
            return dict(run)
        protocol_version = int(run.get("metadata", {}).get("workflow_protocol_version") or 1)
        if protocol_version < 2:
            return dict(run)
        project_run = self.store.get_project_run(
            str(run["run_id"]),
            owner_id=str(run["owner_id"]),
        )
        if project_run is None or project_run.get("promotion_status") in {
            "promoted", "conflict", "not_requested"
        }:
            return dict(run)
        try:
            manifest_record = self.store.read_proof_manifest(str(run["run_id"]))
            manifest = manifest_record["manifest"]
            effective_conditions = {
                item.strip()
                for item in manifest.get("conditional_hypotheses", [])
                if isinstance(item, str) and item.strip()
            }
            for revision_id in manifest.get("dependency_revision_ids", []):
                revision = self.store.get_claim_revision(
                    str(revision_id),
                    owner_id=str(run["owner_id"]),
                )
                effective_conditions.update(
                    item.strip()
                    for item in revision.get("conditions", [])
                    if isinstance(item, str) and item.strip()
                )
            final_proof = self.vault.read_final_proof(str(run["run_id"]))
            promotion = self.store.promote_verified_run(
                run_id=str(run["run_id"]),
                owner_id=str(run["owner_id"]),
                statement_tex=str(manifest["target_statement_tex"]),
                proof_sha256=hashlib.sha256(final_proof.encode("utf-8")).hexdigest(),
                effective_conditions=sorted(effective_conditions),
                manifest=manifest,
            )
            self.store.update_run_metadata(
                str(run["run_id"]),
                {
                    "proof_manifest_sha256": manifest_record["sha256"],
                    "effective_conditions": sorted(effective_conditions),
                    "registry_promotion": promotion,
                },
            )
            self.debug.emit(
                "registry.finalized_run_promotion",
                "workflow_engine",
                trace_id=trace_id,
                run_id=str(run["run_id"]),
                decision="allow",
                reason=str(promotion.get("status") or "unknown"),
                details={
                    "status": promotion.get("status"),
                    "revision_id": (
                        promotion.get("revision", {}).get("revision_id")
                        if isinstance(promotion.get("revision"), Mapping)
                        else None
                    ),
                },
            )
        except ReCTMError as exc:
            promotion = {"status": "error", "error": exc.to_payload()}
            try:
                self.store.update_run_metadata(
                    str(run["run_id"]),
                    {"registry_promotion": promotion},
                )
            except ReCTMError:
                pass
            self.debug.emit(
                "registry.finalized_run_promotion",
                "workflow_engine",
                trace_id=trace_id,
                run_id=str(run["run_id"]),
                decision="deny",
                reason=exc.code,
                details={"status": "error", "error": exc.to_payload()},
            )
        return self.store.get_run(str(run["run_id"]))

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


def _validate_plans(value: Any, *, plan_round: int = 1) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < 2:
        raise invalid_argument("plans must contain at least two materially different plans")
    plans: list[dict[str, Any]] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, Mapping):
            raise invalid_argument("each plan must be a JSON object")
        raw_source_plan_id = item.get("plan_id")
        if raw_source_plan_id is not None and not isinstance(raw_source_plan_id, str):
            raise invalid_argument("plan_id must be a string when supplied")
        source_plan_id = (raw_source_plan_id or "").strip()
        plan_id = f"plan-r{max(1, plan_round)}-{index}"
        raw_summary = item.get("summary")
        if not isinstance(raw_summary, str) or not raw_summary.strip():
            raise invalid_argument("each plan requires a non-empty string summary")
        summary = raw_summary.strip()
        normalized_subgoals = _string_array(
            item.get("subgoals"),
            label="plan subgoals",
            required=True,
            plan_id=plan_id,
        )
        motivation = _string_array(
            item.get("motivation"),
            label="plan motivation",
            plan_id=plan_id,
        )
        dependencies = _string_array(
            item.get("dependencies"),
            label="plan dependencies",
            plan_id=plan_id,
        )
        risks = _string_array(
            item.get("risks"),
            label="plan risks",
            plan_id=plan_id,
        )
        plans.append(
            {
                "plan_id": plan_id,
                "source_plan_id": source_plan_id or None,
                "summary": summary,
                "subgoals": normalized_subgoals,
                "subgoal_ids": [f"sg-{subgoal_index}" for subgoal_index in range(1, len(normalized_subgoals) + 1)],
                "motivation": motivation,
                "dependencies": dependencies,
                "risks": risks,
            }
        )
    if len({plan["summary"].lower() for plan in plans}) != len(plans):
        raise invalid_argument("plans must have materially distinct summaries")
    return plans


def _public_active_plans(active_plans: Any) -> list[dict[str, Any]]:
    if not isinstance(active_plans, list):
        return []
    public: list[dict[str, Any]] = []
    for plan in active_plans:
        if not isinstance(plan, Mapping):
            continue
        texts = [str(goal) for goal in plan.get("subgoals") or []]
        ids = [str(item) for item in plan.get("subgoal_ids") or []]
        if len(ids) != len(texts):
            ids = [f"sg-{index}" for index in range(1, len(texts) + 1)]
        public.append(
            {
                "plan_id": str(plan.get("plan_id") or ""),
                "source_plan_id": plan.get("source_plan_id"),
                "summary": str(plan.get("summary") or ""),
                "subgoals": [
                    {"subgoal_id": subgoal_id, "text": text}
                    for subgoal_id, text in zip(ids, texts)
                ],
                "motivation": list(plan.get("motivation") or []),
                "dependencies": list(plan.get("dependencies") or []),
                "risks": list(plan.get("risks") or []),
            }
        )
    return public


def _string_array(
    value: Any,
    *,
    label: str,
    required: bool = False,
    **details: Any,
) -> list[str]:
    if value is None:
        if required:
            raise invalid_argument(f"{label} must be a non-empty array of non-empty strings", **details)
        return []
    if not isinstance(value, list) or (required and not value):
        raise invalid_argument(
            f"{label} must be {'a non-empty ' if required else 'an '}array of non-empty strings",
            **details,
        )
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise invalid_argument(f"{label} entries must be non-empty strings", **details)
        normalized.append(item.strip())
    return normalized


def _merge_direct_screening(
    value: Any,
    active_plans: Any,
    previous: Any = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, dict[str, str]]], list[dict[str, str]]]:
    if not isinstance(active_plans, list) or not active_plans:
        raise invalid_argument("direct screening requires active decomposition plans")
    known = {
        str(plan.get("plan_id")): plan
        for plan in active_plans
        if isinstance(plan, Mapping)
    }
    source_to_plan = {
        str(plan.get("source_plan_id")): str(plan.get("plan_id"))
        for plan in active_plans
        if isinstance(plan, Mapping) and str(plan.get("source_plan_id") or "")
    }
    progress: dict[str, dict[str, dict[str, str]]] = {}
    if isinstance(previous, Mapping):
        for plan_id, raw_results in previous.items():
            if plan_id in known and isinstance(raw_results, Mapping):
                progress[str(plan_id)] = {
                    str(subgoal_id): dict(result)
                    for subgoal_id, result in raw_results.items()
                    if isinstance(result, Mapping)
                }

    submissions: list[tuple[str, Any]] = []
    if value is None:
        submissions = []
    elif isinstance(value, Mapping):
        submissions = [(str(plan_id), raw_results) for plan_id, raw_results in value.items()]
    elif isinstance(value, list):
        for item in value:
            if not isinstance(item, Mapping):
                raise invalid_argument("each screening report must be an object")
            submissions.append((str(item.get("plan_id") or ""), item.get("subgoal_results")))
    else:
        raise invalid_argument("screening must be an object keyed by plan_id or a legacy report array")

    for plan_id, raw_results in submissions:
        plan_id = source_to_plan.get(plan_id, plan_id)
        if plan_id not in known:
            raise invalid_argument(
                "screening plan_id is not active",
                plan_id=plan_id,
                active_plan_ids=sorted(known),
            )
        plan = known[plan_id]
        texts = [str(goal) for goal in plan.get("subgoals") or []]
        ids = [str(item) for item in plan.get("subgoal_ids") or []]
        if len(ids) != len(texts):
            ids = [f"sg-{index}" for index in range(1, len(texts) + 1)]
        by_text = {text: subgoal_id for subgoal_id, text in zip(ids, texts)}
        entries: list[tuple[str, Any]] = []
        if isinstance(raw_results, Mapping):
            entries = [(str(subgoal_id), raw_result) for subgoal_id, raw_result in raw_results.items()]
        elif isinstance(raw_results, list):
            for raw_result in raw_results:
                if not isinstance(raw_result, Mapping):
                    raise invalid_argument("each subgoal result must be an object", plan_id=plan_id)
                subgoal_id = str(raw_result.get("subgoal_id") or "")
                if not subgoal_id:
                    subgoal_id = by_text.get(str(raw_result.get("subgoal") or ""), "")
                entries.append((subgoal_id, raw_result))
        else:
            raise invalid_argument("plan screening must contain subgoal result objects", plan_id=plan_id)
        bucket = progress.setdefault(plan_id, {})
        for subgoal_id, raw_result in entries:
            if subgoal_id not in ids or not isinstance(raw_result, Mapping):
                raise invalid_argument(
                    "screening subgoal_id is not active for the plan",
                    plan_id=plan_id,
                    subgoal_id=subgoal_id,
                    active_subgoal_ids=ids,
                )
            raw_status = raw_result.get("status")
            raw_summary = raw_result.get("summary")
            status = raw_status.strip() if isinstance(raw_status, str) else ""
            summary = raw_summary.strip() if isinstance(raw_summary, str) else ""
            if status not in {"solved", "partial", "stuck"} or not summary:
                raise invalid_argument(
                    "subgoal screening requires status solved|partial|stuck and a non-empty summary",
                    plan_id=plan_id,
                    subgoal_id=subgoal_id,
                )
            bucket[subgoal_id] = {"status": status, "summary": summary}

    normalized: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    for plan_id, plan in known.items():
        texts = [str(goal) for goal in plan.get("subgoals") or []]
        ids = [str(item) for item in plan.get("subgoal_ids") or []]
        if len(ids) != len(texts):
            ids = [f"sg-{index}" for index in range(1, len(texts) + 1)]
        bucket = progress.get(plan_id, {})
        results: list[dict[str, str]] = []
        for subgoal_id, text in zip(ids, texts):
            result = bucket.get(subgoal_id)
            if not isinstance(result, Mapping):
                missing.append({"plan_id": plan_id, "subgoal_id": subgoal_id, "text": text})
                continue
            results.append(
                {
                    "subgoal_id": subgoal_id,
                    "subgoal": text,
                    "status": str(result.get("status") or ""),
                    "summary": str(result.get("summary") or ""),
                }
            )
        statuses = [result["status"] for result in results]
        plan_status = (
            "solved"
            if len(results) == len(ids) and statuses and all(status == "solved" for status in statuses)
            else "stuck"
            if any(status == "stuck" for status in statuses)
            else "partial"
        )
        normalized.append(
            {
                "plan_id": plan_id,
                "status": plan_status,
                "subgoal_results": results,
                "key_stuck_points": [
                    result["summary"] for result in results if result["status"] != "solved"
                ],
            }
        )
    return normalized, progress, missing


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
