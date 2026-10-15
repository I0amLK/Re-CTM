"""MTM-compatible verified fact preparation and advisory research memory.

These helpers never grant workflow authority or mark a proof verified. Persistence
of prepared facts belongs exclusively to the existing finalizer promotion gate.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, AbstractSet, Any, Mapping, Sequence

from .errors import ReCTMError
from .fact_graph import FactGraph, bm25_rank
from .research_state.model import ResearchState

if TYPE_CHECKING:
    from .storage import StateStore

MAX_MANIFEST_FACTS = 32
MAX_FACT_TEXT_BYTES = 65_536
MAX_PROJECT_MEMORY_BYTES = 6_000
MAX_RESEARCH_TASK_VIEW_BYTES = 24_576


def manifest_facts_schema() -> dict[str, Any]:
    return {"type": "array", "minItems": 1, "maxItems": MAX_MANIFEST_FACTS,
            "description": "Optional verified fact DAG. The last fact states the target; statements and proofs must occur exactly in the final proof. Predecessors name earlier local keys or active project fact IDs. Omission synthesizes one target fact.",
            "items": {"type": "object", "additionalProperties": False,
                      "required": ["key", "statement_tex", "proof_tex", "predecessors", "glossary_introduces"],
                      "properties": {"key": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9_.-]+$"},
                                     "statement_tex": {"type": "string", "minLength": 1, "maxLength": MAX_FACT_TEXT_BYTES},
                                     "proof_tex": {"type": "string", "minLength": 1, "maxLength": MAX_FACT_TEXT_BYTES},
                                     "predecessors": {"type": "array", "maxItems": 64, "items": {"type": "string", "minLength": 1}},
                                     "glossary_introduces": {"type": "object", "maxProperties": 64,
                                                             "additionalProperties": {"type": "string", "maxLength": 4096}},
                                     "intuition": {"type": "string", "maxLength": 4096}}}}


@dataclass(frozen=True)
class VerifiedFact:
    fact_id: str
    statement_tex: str
    proof_tex: str
    intuition: str
    glossary_introduces: Mapping[str, str]
    predecessors: tuple[str, ...]


@dataclass(frozen=True)
class ProjectFinding:
    finding_id: str
    kind: str
    claim: str
    evidence: str
    verifiable: bool
    links_json: str


def normalize(text: str) -> str:
    return " ".join(text.split())


def compute_fact_id(project_id: str, predecessors: Sequence[str], glossary: Mapping[str, str],
                    statement: str, proof: str) -> str:
    # Spaces and Unicode are part of the Danus/MTM cross-language golden contract.
    canonical = json.dumps({"glossary_introduces": dict(glossary),
                            "predecessors": sorted(predecessors), "problem_id": project_id,
                            "proof": normalize(proof), "statement": normalize(statement)},
                           sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _invalid(message: str) -> ReCTMError:
    return ReCTMError("INVALID_PROOF_FACTS", message, category="validation")


def _text(value: Any, maximum: int, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()) or len(value.encode()) > maximum:
        raise _invalid("Fact contains a missing, invalid, or oversized text field.")
    return value


def validate_manifest_facts(value: Any, target: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_MANIFEST_FACTS:
        raise _invalid("facts must contain between 1 and 32 entries.")
    keys: set[str] = set()
    normalized = []
    fields = {"key", "statement_tex", "proof_tex", "predecessors", "glossary_introduces", "intuition"}
    for index, entry in enumerate(value):
        if not isinstance(entry, dict) or entry.keys() - fields:
            raise _invalid("Each fact must be an object containing only declared fields.")
        key = _text(entry.get("key"), 128)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", key) or key in keys:
            raise _invalid("Fact keys must be unique ASCII identifiers.")
        keys.add(key)
        statement = _text(entry.get("statement_tex"), MAX_FACT_TEXT_BYTES)
        proof = _text(entry.get("proof_tex"), MAX_FACT_TEXT_BYTES)
        predecessors = entry.get("predecessors")
        if (not isinstance(predecessors, list) or len(predecessors) > 64
                or any(not isinstance(item, str) or not item for item in predecessors)):
            raise _invalid("Fact predecessors must be bounded non-empty strings.")
        glossary = entry.get("glossary_introduces")
        if (not isinstance(glossary, dict) or len(glossary) > 64
                or any(not isinstance(key, str) or len(key.encode()) > 256
                       or not isinstance(text, str) or len(text.encode()) > 4096
                       for key, text in glossary.items())):
            raise _invalid("Fact glossary is invalid or too large.")
        intuition = _text(entry.get("intuition", ""), 4096, nonempty=False)
        if index + 1 == len(value) and normalize(statement) != normalize(target):
            raise _invalid("The final fact must state the proof target.")
        normalized.append({"key": key, "statement_tex": statement, "proof_tex": proof,
                           "predecessors": list(predecessors), "glossary_introduces": dict(glossary),
                           "intuition": intuition})
    return normalized


def prepare_verified_facts(project_id: str, target: str, final_proof: str,
                           manifest: Mapping[str, Any], dependency_fact_ids: Sequence[str],
                           known_fact_ids: AbstractSet[str]) -> list[VerifiedFact]:
    explicit = "facts" in manifest
    entries = (validate_manifest_facts(manifest["facts"], target) if explicit else
               [{"key": "target", "statement_tex": target, "proof_tex": final_proof,
                 "predecessors": [], "glossary_introduces": {}, "intuition": ""}])
    by_key: dict[str, str] = {}
    batch_ids: set[str] = set()
    result = []
    for index, entry in enumerate(entries):
        statement = _text(entry["statement_tex"], MAX_FACT_TEXT_BYTES)
        proof = _text(entry["proof_tex"], MAX_FACT_TEXT_BYTES)
        if proof not in final_proof or (explicit and statement not in final_proof):
            raise _invalid("Each declared fact statement and proof must occur in the final verified proof.")
        predecessors = set(dependency_fact_ids) if index + 1 == len(entries) else set()
        for reference in entry["predecessors"]:
            fact_id = by_key.get(reference)
            if fact_id is None and reference in known_fact_ids:
                fact_id = reference
            if fact_id is None:
                raise _invalid("Fact predecessor must name an earlier fact or a verified project fact.")
            predecessors.add(fact_id)
        if len(predecessors) > 64:
            raise _invalid("Merged fact predecessors exceed the 64-fact bound.")
        fact_id = compute_fact_id(project_id, sorted(predecessors), entry["glossary_introduces"], statement, proof)
        if fact_id in predecessors:
            raise _invalid("Fact cannot depend on itself.")
        if fact_id in batch_ids:
            raise _invalid("Fact manifest contains duplicate content-addressed facts.")
        batch_ids.add(fact_id)
        by_key[entry["key"]] = fact_id
        result.append(VerifiedFact(fact_id, statement, proof, entry["intuition"],
                                   dict(sorted(entry["glossary_introduces"].items())),
                                   tuple(sorted(predecessors))))
    return result


def prepare_promotion_facts(store: StateStore, project_run: Mapping[str, Any], owner_id: str,
                            manifest: Mapping[str, Any], proof: str) -> list[VerifiedFact]:
    project_id = project_run["project_id"]
    known = store.active_project_fact_ids(project_id, owner_id=owner_id)
    dependencies = manifest.get("dependency_revision_ids", [])
    if not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies):
        raise _invalid("Proof dependencies must be revision identifiers.")
    dependency_ids = []
    for revision_id in dependencies:
        revision = store.get_claim_revision(revision_id, owner_id=owner_id)
        fact_id = revision.get("fact_id")
        if not isinstance(fact_id, str):
            raise _invalid("A legacy dependency revision has no verified fact; promote it through a new verified run first.")
        if fact_id not in known:
            raise _invalid("Proof manifest depends on a missing, foreign, or revoked fact.")
        dependency_ids.append(fact_id)
    target = _text(manifest.get("target_statement_tex"), MAX_FACT_TEXT_BYTES)
    return prepare_verified_facts(project_id, target, proof, manifest, dependency_ids, known)


def _compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def project_findings(project_id: str, run_id: str, state: ResearchState) -> list[ProjectFinding]:
    findings: dict[str, ProjectFinding] = {}

    def add(kind: str, claim: str, evidence: str, verifiable: bool, links: Mapping[str, Any]) -> None:
        claim, evidence = claim[:2048], evidence[:2048]
        body = {"project_id": project_id, "run_id": run_id, "kind": kind, "claim": claim,
                "evidence": evidence, "verifiable": verifiable, "links": dict(links)}
        finding_id = hashlib.sha256(_compact(body).encode()).hexdigest()
        findings[finding_id] = ProjectFinding(finding_id, kind, claim, evidence, verifiable, _compact(links))

    for node in state.nodes.values():
        if node.node_id != state.target_node_id and node.status in ("partial", "route_solved"):
            add("conclusion" if node.status == "partial" else "proof_attempt", node.statement,
                node.status, True, {"node_id": node.node_id})
    for attempt in state.attempts:
        links = {"node_id": attempt.node_id, "attempt_id": attempt.attempt_id}
        if attempt.outcome in ("failed", "refuted"):
            add("dead_end", attempt.summary, attempt.method, False, links)
        if attempt.method == "counterexample":
            add("counterexample", attempt.summary, attempt.outcome, attempt.outcome == "route_solved", links)
        if attempt.obstruction is not None:
            add("obstacle", attempt.obstruction, attempt.summary, False, links)
    for plan_id in state.active_plan_ids:
        # Keep the same first-eight-node projection as MTM before truncating text.
        summary = "; ".join([node.statement for node in state.nodes.values() if node.plan_id == plan_id][:8])
        if summary:
            add("plan", summary, "Active normalized research plan", False, {"plan_id": plan_id})
    return [findings[key] for key in sorted(findings)]


def bounded_memory_text(value: str, maximum_bytes: int) -> str:
    encoded = value.encode()
    return value if len(encoded) <= maximum_bytes else encoded[:maximum_bytes - 3].decode("utf-8", "ignore") + "..."


def project_memory_view(store: StateStore, project_id: str, owner_id: str, run_id: str,
                        state: ResearchState, *, budget: int = MAX_PROJECT_MEMORY_BYTES) -> dict[str, Any]:
    target = state.nodes[state.target_node_id].statement
    blocker = state.nodes[state.critical_blockers[0]].statement if state.critical_blockers else ""
    query = target + " " + blocker
    candidates = store.memory_fact_candidates(project_id, owner_id=owner_id)
    summaries = {row["fact_id"]: row for row in candidates}
    documents = [row["statement_tex"] + " " + row["intuition"] for row in candidates]
    selected: set[str] = set()
    cache: dict[str, list[str]] = {}
    for index in bm25_rank(query, documents):
        if len(selected) >= 8:
            break
        closure: set[str] = set()
        pending = [candidates[index]["fact_id"]]
        while pending:
            fact_id = pending.pop()
            if fact_id in closure:
                continue
            closure.add(fact_id)
            if len(closure) > 8:
                break
            if fact_id not in cache:
                cache[fact_id] = store.memory_fact_predecessors(project_id, fact_id)
            for predecessor in cache[fact_id]:
                if predecessor not in summaries:
                    summaries[predecessor] = store.memory_fact_summary(project_id, predecessor)
                pending.append(predecessor)
        if len(selected | closure) <= 8:
            selected.update(closure)
    graph = FactGraph({fact_id: cache[fact_id] for fact_id in selected})
    nodes = [{"fact_id": fact_id, "statement": bounded_memory_text(summaries[fact_id]["statement_tex"], 192)}
             for fact_id in graph.topological_order]
    edges = [[key, predecessor] for key, values in graph.predecessors.items() for predecessor in sorted(values)]
    findings = store.list_project_findings(project_id, owner_id=owner_id)
    groups = {"prior_dead_ends": {"dead_end"}, "prior_counterexamples": {"counterexample"},
              "obstacles": {"obstacle"}, "other_findings": {"conclusion", "example", "proof_attempt", "plan", "direction"}}
    view: dict[str, Any] = {"advisory_only": True,
                           "fact_graph": {"nodes": nodes, "edges": edges, "truncated": len(candidates) > len(selected)},
                           "truncated": len(findings) >= 1024}
    for name, kinds in groups.items():
        rows = [row for row in findings if row["run_id"] != run_id and row["kind"] in kinds]
        documents = [row["claim"] + " " + row["evidence"] for row in rows]
        view[name] = [{"finding_id": rows[index]["finding_id"], "kind": rows[index]["kind"],
                       "claim": bounded_memory_text(rows[index]["claim"], 96),
                       "evidence": bounded_memory_text(rows[index]["evidence"], 96),
                       "verifiable": bool(rows[index]["verifiable"]), "status": rows[index]["status"]}
                      for index in bm25_rank(query, documents)[:5]]
    view["graph_digest"] = "sha256:" + hashlib.sha256(_compact(view["fact_graph"]).encode()).hexdigest()
    for name in ("other_findings", "obstacles", "prior_counterexamples", "prior_dead_ends"):
        while len(_compact(view).encode()) > budget and view[name]:
            view[name].pop()
            view["truncated"] = True
    # JSON escaping can inflate even short strings. Remove topological sinks, so
    # every retained fact still has its complete predecessor closure.
    while len(_compact(view).encode()) > budget and nodes:
        removed = nodes.pop()["fact_id"]
        edges[:] = [edge for edge in edges if edge[0] != removed]
        view["fact_graph"]["truncated"] = view["truncated"] = True
        view["graph_digest"] = "sha256:" + hashlib.sha256(_compact(view["fact_graph"]).encode()).hexdigest()
    if len(_compact(view).encode()) > budget:
        raise ReCTMError("PROJECT_MEMORY_BUDGET", "Project memory budget is too small.", category="validation")
    return view


def attach_project_memory(research_view: Mapping[str, Any], memory: Mapping[str, Any]) -> dict[str, Any]:
    result = {**research_view, "project_memory": dict(memory)}
    if len(_compact(result).encode()) > MAX_RESEARCH_TASK_VIEW_BYTES:
        raise ReCTMError("RESEARCH_TASK_VIEW_LIMIT", "Project memory exceeded the research task view budget.",
                        category="validation")
    return result
