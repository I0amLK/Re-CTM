"""The public step transaction: signed authority, durable evidence, then task view."""
from __future__ import annotations
import hashlib
from typing import Any, Mapping
from .errors import ReCTMError
from .storage_receipts import canonical, unknown
from .workflow_creation import workspace_hash
from .vault_effects import lock_run


def receipt_response(receipt: Mapping[str, Any], *, replayed: bool = True) -> dict[str, Any]:
    result = receipt.get("result")
    if not isinstance(result, Mapping):
        raise unknown()
    good = result["disposition"] == "applied"
    submission = {"ok": good, "complete": result["complete"], "replayed": replayed, "retryable": False,
                  "writes_retained": result["writes_applied"] > 0}
    if not good:
        submission.update(recoverable=True, retained_write_prefix_len=result["writes_applied"], correction="Fetch the current task separately. Omit the retained write prefix; do not replay the consumed capability.",
                          error={"code": result["error_code"], "category": "conflict"})
    return {"ok": True, "run_id": receipt["run_id"], "state": result["state"], "state_is_historical": True,
            "writes_applied": 0 if replayed else result["writes_applied"], "submission": submission,
            "receipt": dict(result), "task_required": True,
            "next_action": {"tool": "rethlas_step", "arguments": {"run_id": receipt["run_id"]}}}


def step(runtime: Any, principal: Any, arguments: dict[str, Any], trace_id: str) -> dict[str, Any]:
    engine, store = runtime.workflow, runtime.workflow.store
    run_id = arguments["run_id"]
    if "capability" not in arguments:
        return runtime._attach_done_export_if_needed(principal, engine.next_task(owner_id=principal.client_id, run_id=run_id, trace_id=trace_id), trace_id)
    capability, action = arguments["capability"], arguments["action"]
    writes, payload = arguments.get("writes", []), arguments.get("payload", {})
    digest = hashlib.sha256(canonical({"version": "mtm-step-request-v1", "run_id": run_id, "action": action,
                                      "payload": payload, "writes": writes}).encode()).hexdigest()
    workspace = workspace_hash(str(runtime.native.workspace.root))
    claims, receipt = engine.capabilities.submission_receipt(capability, owner_id=principal.client_id, run_id=run_id,
                                                           workspace_sha256=workspace, request_sha256=digest)
    if receipt is not None:
        if arguments.get("recover_only") and receipt["result"] is None:
            receipt = engine.recover_submission(receipt)
            engine.capabilities.revoke(capability, "submission_reconciled", trace_id=trace_id)
        return receipt_response(receipt)
    if arguments.get("recover_only"):
        raise ReCTMError("SUBMISSION_RECEIPT_NOT_FOUND", "No receipt exists for this exact submission; no work was executed.", category="conflict", retryable=False)
    claims = engine.capabilities.validate(capability, owner_id=principal.client_id, action="commit", resource="workflow",
                                          trace_id=trace_id, expected_run_id=run_id)
    receipt = store.reserve_submission(claims, capability_sha256=hashlib.sha256(capability.encode()).hexdigest(),
                                       workspace_sha256=workspace, request_sha256=digest)
    if not receipt["reserved"]:
        return receipt_response(receipt)
    write_results = []
    # The shared permanent inode fences recovery against an active worker. No
    # observer callback or external program is invoked while this lock is held.
    with lock_run(engine.vault.private_root, run_id):
        execution = store.activate_submission(receipt, claims, len(writes))
        phase = "caller_write"
        failed_write = None
        try:
            for index, item in enumerate(writes):
                failed_write = {"index": index, "resource": item["resource"]}
                write_results.append(engine.write_submission(owner_id=principal.client_id, capability=capability,
                    resource=item["resource"], content=item["content"], execution=execution, index=index))
            phase = "commit"
            failed_write = None
            store.arm_submission_commit(execution)
            submission = engine.commit(owner_id=principal.client_id, capability=capability, action=action,
                                       payload=payload, trace_id=execution["trace_id"])
        except ReCTMError as exc:
            # Only a known, between-effects correction can close a receipt.
            # File/opaque/commit uncertainty remains pending and never retries.
            caller_correction = phase == "caller_write" and exc.category == "permission" and exc.code == "ROLE_ACCESS_DENIED"
            if exc.category not in {"validation", "conflict"} and not caller_correction:
                raise
            current = store.observe_submission(receipt)
            if current["result"] is not None:
                return receipt_response(current, replayed=False)
            try:
                receipt = store.record_submission_outcome(receipt, {"disposition": "correction_required",
                    "state": claims.issued_state.value, "writes_applied": len(write_results), "complete": False, "error_code": exc.code})
            except ReCTMError:
                raise unknown() from exc
            engine.capabilities.revoke(capability, "submission_correction_required", trace_id=execution["trace_id"])
            correction = receipt_response(receipt, replayed=False)
            correction["submission"].update(retryable=True, error={**exc.to_payload(), "retryable": True})
            if failed_write is not None:
                correction["submission"]["failed_write"] = failed_write
        else:
            receipt = store.record_submission_outcome(receipt, {"disposition": "applied", "state": submission["state"],
                "writes_applied": len(write_results), "complete": submission.get("complete", True), "error_code": None})
            engine.capabilities.revoke(capability, "submission_completed", trace_id=execution["trace_id"])
            correction = None
    # Task construction is deliberately after durable completion. A failure here
    # returns historical evidence and cannot cause another write or transition.
    try:
        task = runtime._attach_done_export_if_needed(principal, engine.next_task(owner_id=principal.client_id, run_id=run_id, trace_id=trace_id), trace_id)
    except Exception:
        return receipt_response(receipt, replayed=False)
    if correction is not None:
        return {**task, "submission": correction["submission"], "writes_applied": len(write_results), "receipt": receipt["result"]}
    return {**task, "submission": submission, "writes_applied": len(write_results), "receipt": receipt["result"]}
