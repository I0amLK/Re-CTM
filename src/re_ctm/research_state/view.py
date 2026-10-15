"""Deterministic bounded advisory context. No proof, verifier or finalizer authority."""
from __future__ import annotations

import json
from typing import Any

from .model import ResearchState
from .normalize import ResearchNormalization
from .protocol import malformed

MAX_RESEARCH_BASE_VIEW_BYTES = 16384
MAX_RESEARCH_TASK_VIEW_BYTES = 24576


def select_advice(state: ResearchState) -> dict[str, Any]:
    def advice(rule: str, focus: str | None, summary: str, *facts: str) -> dict[str, Any]:
        return {"rule_id": rule, "focus_node_id": focus, "summary": summary, "evidence_facts": list(facts)}
    if state.nodes[state.target_node_id].status == "route_solved" or any(route["route_solved"] for route in state.plan_routes.values()):
        return advice("R08_ASSEMBLE", state.target_node_id, "A complete route is available; assemble the full LaTeX proof.", "at_least_one_active_route=route_solved")
    refuted = next((node for node in state.critical_nodes if state.nodes[node].status == "refuted"), None)
    if refuted and not any(not route["invalid_nodes"] for route in state.plan_routes.values()):
        return advice("R01_REPLAN_REFUTED", refuted, "A proof-critical claim is refuted and no viable alternative route remains; replan around the counterexample.", f"refuted_critical_node={refuted}", "viable_alternative_routes=0")
    for node in state.critical_blockers:
        attempts = [item for item in state.attempts if item.node_id == node]
        failures = sum(item.method == "direct" and item.outcome == "failed" for item in attempts)
        if failures >= 2 and not any(item.method == "counterexample" for item in attempts):
            return advice("R03_TEST_COUNTEREXAMPLE", node, "Repeated direct proof attempts failed; test the smallest meaningful examples before another proof attempt.", f"direct_failed_attempts={failures}", "counterexample_attempts=0")
    for node in state.critical_blockers:
        attempts = [item for item in state.attempts if item.node_id == node]
        if any(item.obstruction == "missing_reference" for item in attempts) and not any(item.method == "retrieval" for item in attempts):
            return advice("R04_RETRIEVE_FOCUSED", node, "The current obstruction is a missing external result; retrieve one focused source for this claim.", f"missing_reference_node={node}", "focused_retrieval_attempts=0")
    retrievals = [item for item in state.attempts if item.method == "retrieval"]
    consecutive, focus = 0, None
    for item in reversed(retrievals):
        if item.outcome != "inconclusive":
            break
        consecutive += 1
        focus = item.node_id
    if consecutive >= 2:
        return advice("R05_STOP_RETRIEVAL", focus, "Recent retrieval attempts added no new material; stop searching and synthesize the sources already collected.", f"consecutive_no_novelty_retrievals={consecutive}")
    for node in state.actionable_frontier:
        if node in state.critical_nodes and not any(item.node_id == node for item in state.attempts):
            return advice("R06_SCREEN_FRONTIER", node, "An untouched proof-critical frontier claim is actionable; attempt it directly or test a diagnostic toy example.", f"untouched_actionable_node={node}")
    for node in state.critical_blockers:
        progress = sum(item.node_id == node and item.method != "retrieval" and item.outcome == "progress" for item in state.attempts)
        if state.nodes[node].status == "partial" and progress >= 2:
            return advice("R07_CONSOLIDATE", node, "Several non-retrieval attempts made compatible partial progress; consolidate them into one reusable lemma.", f"partial_progress_attempts={progress}")
    focus = next(iter(state.critical_blockers or state.actionable_frontier), None)
    return advice("R09_REVIEW_STATE", focus, "No more specific research rule applies; review the current declarations and choose the next mathematical action.", "specific_advisory_rule_match=none")


def task_view(normalization: ResearchNormalization, role: str) -> dict[str, Any] | None:
    """Return broad context only for generator/repair; deny every other role by default."""
    if role not in ("generator", "repair"):
        return None
    state, truncated = normalization.state, False
    def text(value: str, maximum: int) -> str:
        nonlocal truncated
        if len(value.encode("utf-8")) > maximum:
            truncated = True
            return value.encode("utf-8")[:maximum].decode("utf-8", errors="ignore")
        return value
    def node_view(node_id: str, maximum: int = 768) -> dict[str, str]:
        node = state.nodes[node_id]
        return {"node_id": node.node_id, "statement": text(node.statement, maximum), "status": node.status}
    focus = next(iter(state.critical_blockers), None)
    attempts = [item for item in state.attempts if item.node_id == focus] or list(state.attempts)
    partials = [node.node_id for node in state.nodes.values() if node.status == "partial"]
    truncated = any(len(items) > maximum for items, maximum in ((state.actionable_frontier, 5), (attempts, 5), (partials, 5), (normalization.warnings, 3)))
    recent = []
    for item in list(reversed(attempts))[:5]:
        if len(item.evidence_ids) > 3:
            truncated = True
        recent.append({"attempt_id": item.attempt_id, "node_id": item.node_id, "method": item.method, "outcome": item.outcome,
                       "summary": text(item.summary, 768), "obstruction": item.obstruction, "evidence_ids": [text(value, 256) for value in item.evidence_ids[:3]]})
    retrievals = [item for item in state.attempts if item.method == "retrieval"]
    consecutive = 0
    for item in reversed(retrievals):
        if item.outcome != "inconclusive":
            break
        consecutive += 1
    probes = [item for item in state.attempts if item.method == "counterexample"]
    result = {"advisory_only": True, "target": node_view(state.target_node_id, 2048), "current_blocker": node_view(focus) if focus else None,
              "frontier": [node_view(node) for node in state.actionable_frontier[:5]], "recent_attempts": recent,
              "counterexample_coverage": "found" if any(item.outcome == "refuted" for item in probes) else "attempted" if probes else "not_attempted",
              "retrieval": {"attempts": len(retrievals), "new_material_attempts": sum(item.outcome == "progress" for item in retrievals), "consecutive_no_new_material": consecutive},
              "preserved_partial_results": [node_view(node) for node in partials[:5]], "suggested_next_action": select_advice(state), "graph_digest": state.digest,
              "counts": {"nodes": len(state.nodes), "attempts": len(state.attempts), "decisions": len(state.decisions), "critical_blockers": len(state.critical_blockers), "actionable_frontier": len(state.actionable_frontier)},
              "warnings": [{"code": text(item["code"], 128), "location": text(item["location"], 512), "message": text(item["message"], 512)} for item in normalization.warnings[:3]]}
    result["truncated"] = truncated
    size = len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    if size > MAX_RESEARCH_BASE_VIEW_BYTES:
        raise malformed("research_task_view_bytes", f"base view exceeds {MAX_RESEARCH_BASE_VIEW_BYTES} bytes")
    return result
