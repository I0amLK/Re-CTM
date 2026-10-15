"""Read-only normalization of protocol-1/2/3 vault history into the graph model.

Legacy prose is retained as advisory evidence, never silently promoted to proof.
Only caller-authorized, already-readable channels may be passed to this module.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable

from .model import ResearchAttempt, ResearchDecision, ResearchNode, ResearchSnapshot, ResearchState, project
from .protocol import (METHODS, NODE_KINDS, OBSTRUCTIONS, _MISSING, bounded_count, identifier,
                       malformed, object_value, protocol_node_id, required_text, text_array)


@dataclass(frozen=True)
class ResearchNormalization:
    snapshot: ResearchSnapshot
    state: ResearchState
    warnings: tuple[dict[str, str], ...]
    summary: dict[str, Any]


def _truncate(value: str, maximum: int) -> str:
    return value.encode("utf-8")[:maximum].decode("utf-8", errors="ignore")


class _Warnings:
    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []
        self.omitted = 0

    def add(self, code: str, location: str, message: str) -> None:
        if len(self.items) < 127:
            self.items.append({"code": code, "location": _truncate(location, 512), "message": _truncate(message, 1024)})
        else:
            self.omitted += 1

    def finish(self) -> tuple[dict[str, str], ...]:
        if self.omitted:
            self.items.append({"code": "warnings_truncated", "location": "normalization", "message": f"{self.omitted} additional normalization warnings were omitted"})
        return tuple(self.items)


def _summary(record: dict[str, Any]) -> str | None:
    return next((record[key].strip() for key in ("summary", "obstruction", "reason", "decision", "next_step") if isinstance(record.get(key), str) and record[key].strip()), None)


def _array(record: dict[str, Any], name: str, limit: int = 64, max_bytes: int = 8192) -> list[str]:
    return text_array(record.get(name, _MISSING), name, limit, text_maximum=max_bytes)


def normalize_research(target_statement: str, round_index: int, active_plans: Any, screening_progress: Any,
                       *, proof_steps: Iterable[Any] = (), counterexamples: Iterable[Any] = (), failed_paths: Iterable[Any] = (),
                       big_decisions: Iterable[Any] = (), events: Iterable[Any] = (), registered_reference_ids: Iterable[str] = (),
                       branch_results: Iterable[Any] = (), join_result: Any = None, verification_reports: Iterable[Any] = ()) -> ResearchNormalization:
    channels = {"proof_steps": list(proof_steps), "counterexamples": list(counterexamples), "failed_paths": list(failed_paths),
                "big_decisions": list(big_decisions), "events": list(events), "branch_results": list(branch_results), "verification_reports": list(verification_reports)}
    for channel, values in channels.items():
        bounded_count(channel, len(values), 2048)
    warnings = _Warnings()
    nodes = {"target": ResearchNode("target", target_statement, "target")}
    plans = _normalize_plans(active_plans, screening_progress, round_index, nodes, warnings)
    attempts: list[ResearchAttempt] = []
    decisions: list[ResearchDecision] = []
    sequence = 0

    def attempt(attempt_id: str, node_id: str, record: dict[str, Any], method: str, outcome: str, summary: str,
                obstruction: str | None = None, evidence: Iterable[str] = (), actor: str = "legacy-generation") -> None:
        nonlocal sequence
        sequence += 1
        attempts.append(ResearchAttempt(attempt_id, node_id, record.get("actor_domain_id", actor), method, outcome, summary,
                                        obstruction, tuple(evidence), round_index, sequence))
        bounded_count("research_attempts", len(attempts), 2048)

    for index, raw in enumerate(channels["proof_steps"]):
        record = raw if isinstance(raw, dict) else {}
        if record.get("record_type") != "direct_screening_round":
            continue
        raw_plans = record.get("plans")
        if not isinstance(raw_plans, list):
            warnings.add("malformed_direct_round", f"proof_steps[{index}]", "direct_screening_round has no plans array")
            continue
        bounded_count("direct_screening_plans", len(raw_plans), 64)
        for plan_index, raw_plan in enumerate(raw_plans):
            plan = raw_plan if isinstance(raw_plan, dict) else {}
            plan_id = plan.get("plan_id")
            if plan_id not in plans:
                warnings.add("unknown_direct_plan", f"proof_steps[{index}]", "direct-screening attempt refers to an unknown plan")
                continue
            results = plan.get("subgoal_results")
            if not isinstance(results, list):
                warnings.add("missing_subgoal_results", f"proof_steps[{index}]", "direct-screening plan has no subgoal_results array")
                continue
            bounded_count("direct_screening_results", len(results), 64)
            for result_index, raw_result in enumerate(results):
                result = object_value(raw_result, "direct_screening_result")
                node = next((node for node in plans[plan_id] if node["subgoal_id"] == result.get("subgoal_id")), None)
                if node is None:
                    warnings.add("unknown_direct_subgoal", f"proof_steps[{index}]", "direct-screening result refers to an unknown subgoal")
                    continue
                status = result.get("status")
                outcome = {"solved": "route_solved", "partial": "progress", "stuck": "failed"}.get(status, "inconclusive")
                if outcome == "inconclusive":
                    warnings.add("unknown_direct_screening_status", f"proof_steps[{index}]", "unknown status is treated as inconclusive")
                method = result.get("method", "direct")
                obstruction = result.get("obstruction") or ("no_progress" if status == "stuck" else None)
                attempt(result.get("attempt_id", f"attempt:direct:{index + 1}:{plan_index + 1}:{result_index + 1}"), node["node_id"], record,
                        method, outcome, result.get("summary") or "Direct screening produced no summary.", obstruction, _array(result, "evidence_ids", 32, 1024))
    recognized = _branches(channels["branch_results"], plans, nodes, attempt, warnings)
    for index, raw in enumerate(channels["counterexamples"]):
        record = raw if isinstance(raw, dict) else {}
        location = f"counterexamples[{index}]"
        explicit = "node_id" in record
        node_id = record.get("node_id")
        valid = not explicit or node_id in nodes
        if not valid:
            warnings.add("unknown_counterexample_node", location, "unknown counterexample node remains inconclusive in shadow")
        node_id = node_id if node_id in nodes else "target"
        status = record.get("status", record.get("result", record.get("outcome", "inconclusive")))
        witness = record.get("witness")
        meaningful = bool(witness.strip()) if isinstance(witness, str) else (bool(witness) if isinstance(witness, (dict, list)) else witness is not None)
        claimed = status in ("found", "refuted", "counterexample_found")
        found = claimed and meaningful and valid
        if claimed and not meaningful:
            warnings.add("counterexample_without_witness", location, "claimed counterexample has no witness and is treated as inconclusive")
        if found:
            nodes[node_id] = replace(nodes[node_id], status="refuted")
        attempt(f"attempt:{record['record_id']}" if "record_id" in record else f"attempt:counterexample:{index + 1}", node_id, record,
                "counterexample", "refuted" if found else "inconclusive", _summary(record) or "Counterexample probe was inconclusive.",
                "false_claim" if found else None, _array(record, "evidence_ids", 32, 1024))
    retrieval = _retrieval(channels["events"], nodes, frozenset(registered_reference_ids), attempt, warnings)
    ignored = 0
    for index, raw in enumerate(channels["failed_paths"]):
        record = raw if isinstance(raw, dict) else {}
        summary = _summary(record)
        if summary is None:
            ignored += 1
            warnings.add("failure_without_summary", f"failed_paths[{index}]", "failure record has no concise summary")
            continue
        affected = _array(record, "affected_node_ids") or ["target"]
        for node_index, node_id in enumerate(affected):
            if node_id not in nodes:
                raise malformed("failed_paths", "failure record refers to an unknown canonical node")
            obstruction = record.get("obstruction_class", "unknown")
            if obstruction not in OBSTRUCTIONS:
                obstruction = "unknown"
            attempt(f"attempt:{record['record_id']}:{node_index + 1}" if "record_id" in record else f"attempt:failure:{index + 1}:{node_index + 1}", node_id, record, "synthesis", "failed", summary, obstruction)
    for index, raw in enumerate(channels["big_decisions"]):
        record = raw if isinstance(raw, dict) else {}
        reason = _summary(record)
        if reason is None:
            ignored += 1
            warnings.add("decision_without_reason", f"big_decisions[{index}]", "decision record has no concise reason")
            continue
        sequence += 1
        superseded, preserved = [], []
        for plan_id in _array(record, "superseded_plan_ids"):
            if plan_id in plans:
                superseded.append(plan_id)
            else:
                warnings.add("unknown_decision_plan", f"big_decisions[{index}]", f"unknown active plan: {plan_id}")
        for node_id in _array(record, "preserved_node_ids"):
            if node_id in nodes:
                preserved.append(node_id)
            else:
                warnings.add("unknown_preserved_node", f"big_decisions[{index}]", f"unknown preserved node: {node_id}")
        focus = record.get("selected_focus_node_id")
        if focus is not None and focus not in nodes:
            warnings.add("unknown_focus_node", f"big_decisions[{index}]", "unknown focus node")
            focus = None
        decisions.append(ResearchDecision(f"decision:legacy:{index + 1}", reason, tuple(superseded), tuple(preserved), tuple(_array(record, "new_constraints")), focus, sequence))
        bounded_count("research_decisions", len(decisions), 256)
    for index, raw in enumerate(channels["verification_reports"]):
        report = raw if isinstance(raw, dict) else {}
        findings = report.get("verification_report", report)
        if not isinstance(findings, dict):
            findings = report
        critical, gaps = findings.get("critical_errors", []), findings.get("gaps", [])
        critical, gaps = len(critical) if isinstance(critical, list) else 0, len(gaps) if isinstance(gaps, list) else 0
        if critical + gaps:
            attempt(f"attempt:repair:{index + 1}", "target", report, "repair", "failed", report.get("repair_hints") or f"Verifier reported {critical} critical error(s) and {gaps} gap(s).", "unknown", actor="legacy-repair")
    if isinstance(join_result, dict) and join_result:
        sequence += 1
        selected = join_result.get("selected_plan_id")
        branch_id = join_result.get("selected_branch_id")
        if selected is None and branch_id:
            selected = next((record.get("plan_id") for record in channels["branch_results"] if isinstance(record, dict) and record.get("branch_id") == branch_id), None)
            if selected is None:
                warnings.add("unknown_join_branch", "join_result.selected_branch_id", "no recognized sealed branch result")
        focus = None
        if selected in plans:
            focus = plans[selected][-1]["node_id"]
        elif selected is not None:
            warnings.add("unknown_join_plan", "join_result.selected_plan_id", "unknown active plan")
        decisions.append(ResearchDecision("decision:legacy:join", f"Branch join outcome: {join_result.get('outcome', 'unknown')}.", selected_focus_node_id=focus, event_seq=sequence))
    snapshot = ResearchSnapshot("target", tuple(nodes.values()), tuple(attempts), tuple(decisions), tuple(sorted(plans)))
    state = project(snapshot)
    collected = warnings.finish()
    summary = {"source_records": {key: len(value) for key, value in channels.items()}, "normalized_nodes": len(nodes),
               "normalized_attempts": len(attempts), "normalized_decisions": len(decisions), "retrieval_events": retrieval[0],
               "novel_reference_ids": retrieval[1], "repeated_reference_ids": retrieval[2], "recognized_branch_results": recognized,
               "ignored_records": ignored, "warning_count": len(collected)}
    return ResearchNormalization(snapshot, state, collected, summary)


def _normalize_plans(active_plans: Any, screening_progress: Any, round_index: int, nodes: dict[str, ResearchNode], warnings: _Warnings) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(active_plans, list):
        raise malformed("active_plans", "array required")
    bounded_count("active_plans", len(active_plans), 64)
    progress = {} if screening_progress is None else object_value(screening_progress, "screening_progress")
    bounded_count("screening_progress", len(progress), 64)
    plans = {}
    for index, raw in enumerate(active_plans):
        plan = object_value(raw, "active_plans")
        plan_id = identifier(plan.get("plan_id"), "plan_id", local=True)
        if plan_id in plans:
            raise malformed("active_plans", "duplicate plan_id")
        goals = plan.get("research_subgoals")
        canonical = isinstance(goals, list)
        if not canonical:
            statements = text_array(plan.get("subgoals", _MISSING), "subgoals", required=True, text_maximum=16384)
            ids = text_array(plan.get("subgoal_ids", _MISSING), "subgoal_ids", required=True, unique=True, text_maximum=128)
            if len(ids) != len(statements):
                raise malformed("active_plans", "subgoals and subgoal_ids must have equal lengths")
            goals = [{"statement": statement, "subgoal_id": subgoal_id, "node_id": protocol_node_id(plan_id, subgoal_id), "kind": "lemma", "depends_on": []} for subgoal_id, statement in zip(ids, statements)]
        if not goals:
            raise malformed("research_subgoals", "non-empty canonical research subgoals required")
        bounded_count("research_subgoals", len(goals), 64)
        local_ids = set()
        plans[plan_id] = []
        for goal_index, raw_goal in enumerate(goals):
            goal = object_value(raw_goal, "research_subgoals")
            subgoal_id = identifier(goal.get("subgoal_id"), "subgoal_id", local=True)
            node_id = protocol_node_id(plan_id, subgoal_id)
            if goal.get("node_id") != node_id or subgoal_id in local_ids or node_id in nodes:
                raise malformed("research_subgoals", "duplicate or mismatched canonical node/subgoal identifier")
            local_ids.add(subgoal_id)
            kind = goal.get("kind", "lemma")
            if kind not in NODE_KINDS or (canonical and type(goal.get("critical")) is not bool):
                raise malformed("research_subgoals", "valid kind and boolean critical are required")
            plan_progress = progress.get(plan_id, {})
            if not isinstance(plan_progress, dict):
                raise malformed("screening_progress", "plan progress must be object")
            raw_status = plan_progress.get(subgoal_id, {})
            raw_status = raw_status.get("status") if isinstance(raw_status, dict) else None
            status = {"solved": "route_solved", "partial": "partial", "stuck": "blocked"}.get(raw_status, "open")
            if raw_status is not None and raw_status not in ("solved", "partial", "stuck"):
                warnings.add("unknown_screening_status", "screening_progress", "unknown status treated as open in shadow")
            nodes[node_id] = ResearchNode(node_id, goal.get("statement"), kind, status,
                                          tuple(text_array(goal.get("depends_on", _MISSING), "depends_on", unique=True, text_maximum=128)),
                                          plan_id, goal.get("critical"), 1, round_index, index + 1, goal_index + 1)
            plans[plan_id].append({"node_id": node_id, "subgoal_id": subgoal_id, "statement": nodes[node_id].statement})
            bounded_count("research_nodes", len(nodes), 256)
    for plan_id in progress:
        if plan_id not in plans:
            warnings.add("inactive_screening_plan", "screening_progress." + plan_id, "screening progress refers to a plan that is not active")
    return plans


def _branches(records: list[Any], plans: dict[str, list[dict[str, Any]]], nodes: dict[str, ResearchNode], attempt: Any, warnings: _Warnings) -> int:
    recognized = 0
    for index, raw in enumerate(records):
        result = raw if isinstance(raw, dict) else {}
        plan_id, status = result.get("plan_id"), result.get("status", "failed")
        if plan_id not in plans:
            warnings.add("inactive_branch_plan" if plan_id else "missing_branch_plan", f"branch_results[{index}]", "branch plan is missing or no longer active")
            continue
        if status not in ("solved", "partial", "failed"):
            warnings.add("invalid_branch_status", f"branch_results[{index}]", "branch status is unknown")
            continue
        goals, touched = plans[plan_id], set()
        def resolve(label: str) -> str | None:
            return next((node["node_id"] for node in goals if label in (node["node_id"], node["subgoal_id"], node["statement"])), None)
        proved, unproved = _array(result, "proved_subgoals"), _array(result, "unproved_subgoals")
        obstructions = result.get("obstructions", [])
        if not isinstance(obstructions, list):
            raise malformed("branch.obstructions", "array required")
        bounded_count("branch.obstructions", len(obstructions), 64)
        obstruction_map = {}
        for item in obstructions:
            item = object_value(item, "branch.obstruction")
            node_id = item.get("node_id")
            if node_id not in [goal["node_id"] for goal in goals] or node_id in obstruction_map or item.get("class") not in OBSTRUCTIONS:
                raise malformed("branch.obstructions", "duplicate, out-of-plan node or unknown class")
            obstruction_map[node_id] = (item["class"], _array(item, "evidence_ids", 32, 1024))
        if status == "solved":
            touched.update(node["node_id"] for node in goals)
            for node_id in touched:
                nodes[node_id] = replace(nodes[node_id], status="route_solved")
        else:
            for labels, new_status, warning in ((proved, "route_solved", "unknown_proved_subgoal"), (unproved, "blocked", "unknown_unproved_subgoal")):
                for label in labels:
                    node_id = resolve(label)
                    if node_id is None:
                        warnings.add(warning, f"branch_results[{index}]", f"subgoal does not match active plan: {label}")
                    else:
                        touched.add(node_id)
                        if new_status == "route_solved" or nodes[node_id].status != "route_solved":
                            nodes[node_id] = replace(nodes[node_id], status=new_status)
            if status == "failed" and not touched:
                touched.update(node["node_id"] for node in goals)
                for node_id in touched:
                    if nodes[node_id].status != "route_solved":
                        nodes[node_id] = replace(nodes[node_id], status="blocked")
            touched.update(obstruction_map)
            for node_id in obstruction_map:
                if nodes[node_id].status != "route_solved":
                    nodes[node_id] = replace(nodes[node_id], status="blocked")
        for node_index, node_id in enumerate(sorted(touched)):
            obstruction, evidence = obstruction_map.get(node_id, ("no_progress" if status == "failed" else None, []))
            attempt(f"attempt:branch:{index + 1}:{node_index + 1}", node_id, result, "synthesis", {"solved": "route_solved", "partial": "progress", "failed": "failed"}[status],
                    result.get("summary") or "Branch completed without a summary.", obstruction, evidence, actor=f"legacy-branch:{result.get('branch_id') or 'unknown'}")
        recognized += 1
    return recognized


def _retrieval(events: list[Any], nodes: dict[str, ResearchNode], registered: frozenset[str], attempt: Any, warnings: _Warnings) -> tuple[int, int, int]:
    seen, assessed = set(), set()
    count = novel = repeated = 0
    for index, raw in enumerate(events):
        event = raw if isinstance(raw, dict) else {}
        event_type = event.get("event_type", "")
        if event_type == "retrieval_assessment":
            count += 1
            references = _array(event, "reference_ids", 32, 1024)
            if not set(references) <= registered:
                raise malformed("events.reference_ids", "protocol-3 retrieval record contains an unregistered reference_id")
            evidence = []
            for reference in references:
                if reference in seen:
                    repeated += 1
                else:
                    seen.add(reference)
                    novel += 1
                if reference not in assessed:
                    assessed.add(reference)
                    evidence.append(reference)
            node_id = event.get("node_id") or "target"
            if node_id not in nodes:
                raise malformed("events.node_id", "protocol-3 retrieval record refers to an unknown node")
            progress = event.get("outcome") == "new_material" and bool(evidence)
            attempt(f"attempt:{event['record_id']}" if "record_id" in event else f"attempt:retrieval:{index + 1}", node_id, event, "retrieval", "progress" if progress else "inconclusive", event.get("summary") or "Retrieval assessment was inconclusive.", None if progress else "no_progress", evidence)
        elif isinstance(event_type, str) and event_type.startswith("external_"):
            count += 1
            results = event.get("results")
            if not isinstance(results, list):
                warnings.add("retrieval_without_results", f"events[{index}]", "external retrieval event has no results array")
                continue
            bounded_count("retrieval_results", len(results), 64)
            evidence = []
            for result in results:
                reference = result.get("reference_id") if isinstance(result, dict) else None
                if not isinstance(reference, str):
                    continue
                if reference not in registered:
                    warnings.add("unregistered_retrieval_reference", f"events[{index}].results", "retrieval result reference_id is absent from authoritative registry")
                elif reference in seen:
                    repeated += 1
                else:
                    seen.add(reference)
                    novel += 1
                    evidence.append(reference)
            if len(evidence) > 32:
                warnings.add("retrieval_evidence_truncated", f"events[{index}].results", "novel evidence was counted but only 32 locators are attached")
            attempt(f"attempt:retrieval:{index + 1}", "target", event, "retrieval", "progress" if evidence else "inconclusive", f"{event.get('operation', 'research')} registered {len(evidence)} previously unseen reference id(s).", None if evidence else "no_progress", evidence[:32])
    return count, novel, repeated
