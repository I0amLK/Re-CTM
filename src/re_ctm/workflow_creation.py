"""Bounded creation requests and enrolled, no-clobber restartable initialization."""
from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any, Iterable, Mapping

from .debug import new_trace_id
from .errors import invalid_argument
from .storage_receipts import canonical
from .vault import _safe_reference_name
from .vault_effects import lock_run


def workspace_hash(workspace: str, *, kind: str = "step") -> str:
    return hashlib.sha256(f"mtm-{kind}-workspace-v1\0".encode() + workspace.encode()).hexdigest()


def start_run(engine: Any, *, owner_id: str, problem_tex: str, problem_id: str | None = None,
              references: Iterable[Mapping[str, Any]] = (), native_mode: str = "dangerous",
              workspace_export_path: str | None = None, project_id: str | None = None,
              target_claim_id: str | None = None, workflow_mode: str = "auto", register_result: bool = True,
              workflow_protocol_version: int = 3, trace_id: str | None = None,
              creation_key: str | None = None, workspace_identity: str = "") -> dict[str, Any]:
    from .workflow import _safe_component
    trace = trace_id or new_trace_id()
    if not isinstance(owner_id, str) or not owner_id.strip() or not isinstance(problem_tex, str) or not problem_tex.strip():
        raise invalid_argument("owner_id and problem_tex are required")
    if workflow_mode not in {"auto", "compact", "full"} or type(workflow_protocol_version) is not int or workflow_protocol_version not in {1, 2, 3}:
        raise invalid_argument("Unsupported workflow mode or protocol version")
    if type(register_result) is not bool or (target_claim_id and not project_id):
        raise invalid_argument("Invalid project registration request")
    if creation_key is not None and (not isinstance(creation_key, str) or re.fullmatch(r"[A-Za-z0-9_-]{16,128}", creation_key) is None):
        raise invalid_argument("creation_key must contain 16–128 ASCII letters, digits, underscores or hyphens")
    if project_id:
        engine.store.get_project(project_id, owner_id=owner_id)
        if target_claim_id:
            claim = engine.store.get_claim(target_claim_id, owner_id=owner_id)
            if claim["project_id"] != project_id:
                raise invalid_argument("target_claim_id must belong to project_id")
    resolved_problem = _safe_component(problem_id or "problem")
    normalized = []
    names: set[str] = set()
    byte_count = len(problem_tex.encode("utf-8"))
    for item in references:
        if len(normalized) >= 128 or not isinstance(item, Mapping) or set(item) - {"name", "content", "source"}:
            raise invalid_argument("references must contain at most 128 typed reference objects")
        name, content, source = item.get("name"), item.get("content"), item.get("source", "inline")
        if not all(isinstance(value, str) for value in (name, content, source)) or not name or not content:
            raise invalid_argument("references require non-empty name and content strings")
        safe_name = _safe_reference_name(name)
        if safe_name != name or name == "manifest.json" or name in names:
            raise invalid_argument("Reference names must be unique safe filenames distinct from manifest.json")
        names.add(name)
        byte_count += len(content.encode("utf-8")) + len(name.encode("utf-8")) + len(source.encode("utf-8"))
        normalized.append({"name": name, "content": content, "source": source})
    if byte_count > 8 * 1024 * 1024:
        raise invalid_argument("Creation text exceeds 8 MiB")
    request = {"version": "mtm-start-request-v1", "problem_id": resolved_problem, "problem_tex": problem_tex,
               "references": normalized, "export_path": workspace_export_path, "project_id": project_id,
               "target_claim_id": target_claim_id, "workflow_mode": workflow_mode, "register_result": register_result,
               "workflow_protocol_version": workflow_protocol_version, "native_mode": native_mode}
    request_digest = hashlib.sha256(canonical(request).encode()).hexdigest()
    # Unkeyed creation remains non-replayable by clients, but its internal setup
    # uses the same exact-file and single-transaction initialization machinery.
    key = creation_key or secrets.token_urlsafe(32)
    key_digest = hashlib.sha256(key.encode()).hexdigest()
    receipt = engine.store.reserve_creation(owner_id, key_digest, workspace_hash(workspace_identity, kind="start"),
                                           request_digest, f"run-{resolved_problem}-{secrets.token_hex(6)}")
    run_id = receipt["run_id"]
    replayed = not receipt["reserved"]
    with lock_run(engine.vault.private_root, run_id):
        receipt = engine.store.resume_creation(receipt)
        if receipt["status"] == "completed":
            run = engine.store.get_run(run_id)
        else:
            export_path = workspace_export_path or f"rethlas-output/{run_id}/proof_verified.tex"
            result = engine.vault.initialize_run(run_id, problem_tex=problem_tex, references=normalized,
                         metadata={"problem_id": resolved_problem, "owner_id": owner_id, "created_at": receipt["created_at"]}, replay_safe=True)
            metadata = {"native_mode_at_creation": native_mode, "problem_sha256": result["problem_sha256"],
                        "reference_count": result["reference_count"], "manual_validation_required": True,
                        "active_plans": [], "branch_requests": [], "latex_result": None,
                        "workspace_export_path": export_path, "workflow_protocol_version": workflow_protocol_version,
                        "requested_workflow_mode": workflow_mode, "effective_workflow_mode": "full" if workflow_mode == "full" else "pending",
                        "compact_verifier_failures": 0, "project_id": project_id, "target_claim_id": target_claim_id}
            engine.store.prepare_creation_records(receipt, problem_id=resolved_problem, metadata=metadata,
                        project_id=project_id, target_claim_id=target_claim_id, workflow_mode=workflow_mode,
                        register_result=register_result, references=normalized)
            run = engine.store.complete_creation(receipt)
    engine.debug.emit("workflow.run_created", "workflow_engine", trace_id=trace, run_id=run_id,
                      decision="allow", reason="creation_receipt_completed", details={"replayed": replayed, "workflow_protocol_version": workflow_protocol_version})
    metadata = run["metadata"]
    return {"ok": True, "run_id": run_id, "state": run["state"], "workspace_export_path": metadata["workspace_export_path"],
            "workflow_protocol_version": metadata["workflow_protocol_version"], "workflow_mode": workflow_mode,
            "project_id": project_id, "project_snapshot_id": metadata.get("project_snapshot_id"), "target_claim_id": target_claim_id,
            "manual_validation_required": True, "creation_replayed": replayed, "trace_id": trace}
