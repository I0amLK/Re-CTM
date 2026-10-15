"""Schema-eight fact and finding persistence; promotion shares the registry transaction."""
from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Mapping, Sequence

from .debug import utc_now
from .errors import ReCTMError
from .fact_memory import ProjectFinding, VerifiedFact, compute_fact_id, normalize


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _conflict(message: str) -> ReCTMError:
    return ReCTMError("FACT_GRAPH_CONFLICT", message, category="conflict")


def _payload(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    for field in ("glossary_json", "external_refs_json", "links_json"):
        if field in value:
            value[field.removesuffix("_json")] = json.loads(value.pop(field))
    for field in ("verifiable", "revoked"):
        if field in value:
            value[field] = bool(value[field])
    return value


def _validate_fact(fact: VerifiedFact) -> None:
    if (not isinstance(fact, VerifiedFact) or not isinstance(fact.fact_id, str)
            or not re.fullmatch(r"[0-9a-f]{16}", fact.fact_id)
            or any(not isinstance(text, str) or not text.strip() or len(text.encode()) > 65_536
                   for text in (fact.statement_tex, fact.proof_tex))
            or not isinstance(fact.intuition, str) or len(fact.intuition.encode()) > 4096
            or not isinstance(fact.predecessors, (tuple, list)) or len(fact.predecessors) > 64
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{16}", value)
                   for value in fact.predecessors)
            or not isinstance(fact.glossary_introduces, Mapping) or len(fact.glossary_introduces) > 64
            or any(not isinstance(key, str) or len(key.encode()) > 256
                   or not isinstance(value, str) or len(value.encode()) > 4096
                   for key, value in fact.glossary_introduces.items())):
        raise _conflict("Fact batch contains invalid or oversized data.")


def insert_promoted_facts(connection: sqlite3.Connection, project_id: str, run_id: str,
                          facts: Sequence[VerifiedFact], now: str) -> str:
    """Called inside finalizer promotion's transaction, before the claim revision.

    No independent commit is allowed: a later revision/edge/status failure must
    roll back all fact inserts. The caller owns done/LaTeX/verifier checks.
    """
    if not connection.in_transaction:
        raise _conflict("Fact promotion requires the registry transaction.")
    if not 1 <= len(facts) <= 32:
        raise _conflict("A verified promotion needs a bounded fact batch.")
    batch_ids: set[str] = set()
    for fact in facts:
        _validate_fact(fact)
        if (len(set(fact.predecessors)) != len(fact.predecessors)
                or fact.fact_id in batch_ids or fact.fact_id in fact.predecessors):
            raise _conflict("Fact batch contains invalid or repeated data.")
        if compute_fact_id(project_id, fact.predecessors, fact.glossary_introduces,
                           fact.statement_tex, fact.proof_tex) != fact.fact_id:
            raise _conflict("Fact ID does not bind its immutable content.")
        batch_ids.add(fact.fact_id)
        for predecessor in fact.predecessors:
            row = connection.execute(
                "SELECT project_id FROM facts WHERE fact_id=? AND NOT EXISTS "
                "(SELECT 1 FROM fact_revocations r WHERE r.fact_id=facts.fact_id)",
                (predecessor,),
            ).fetchone()
            if row is None or row["project_id"] != project_id:
                raise _conflict("Fact predecessor is missing, revoked, or belongs to another project.")
        glossary = _json(dict(fact.glossary_introduces))
        prior = connection.execute("SELECT * FROM facts WHERE fact_id=?", (fact.fact_id,)).fetchone()
        if prior is not None:
            if (prior["project_id"] != project_id
                    or normalize(prior["statement_tex"]) != normalize(fact.statement_tex)
                    or normalize(prior["proof_tex"]) != normalize(fact.proof_tex)
                    or prior["glossary_json"] != glossary):
                raise _conflict("An existing fact ID has different immutable content.")
            edges = connection.execute("SELECT predecessor_id FROM fact_edges WHERE fact_id=?",
                                       (fact.fact_id,)).fetchall()
            if {row["predecessor_id"] for row in edges} != set(fact.predecessors):
                raise _conflict("An existing fact ID has different predecessors.")
            if connection.execute("SELECT 1 FROM fact_revocations WHERE fact_id=?",
                                  (fact.fact_id,)).fetchone() is not None:
                raise _conflict("A revoked fact cannot be promoted again.")
            continue
        connection.execute(
            "INSERT INTO facts(fact_id,project_id,source_run_id,statement_tex,proof_tex,intuition,"
            "glossary_json,external_refs_json,created_at) VALUES(?,?,?,?,?,?,?,'[]',?)",
            (fact.fact_id, project_id, run_id, fact.statement_tex, fact.proof_tex, fact.intuition, glossary, now),
        )
        connection.executemany("INSERT INTO fact_edges(fact_id,predecessor_id) VALUES(?,?)",
                               [(fact.fact_id, predecessor) for predecessor in fact.predecessors])
    return facts[-1].fact_id


def verify_matching_findings(connection: sqlite3.Connection, run_id: str,
                             facts: Sequence[VerifiedFact], now: str) -> None:
    if not connection.in_transaction:
        raise _conflict("Finding verification requires the registry transaction.")
    findings = connection.execute(
        "SELECT finding_id,claim FROM memory_findings WHERE run_id=? AND verifiable=1 "
        "AND kind IN ('conclusion','example','counterexample','proof_attempt') ORDER BY finding_id",
        (run_id,),
    ).fetchall()
    for finding in findings:
        fact = next((fact for fact in facts if normalize(fact.statement_tex) == normalize(finding["claim"])), None)
        if fact is None:
            continue
        previous = connection.execute(
            "SELECT status FROM memory_finding_status WHERE finding_id=? ORDER BY seq DESC LIMIT 1",
            (finding["finding_id"],),
        ).fetchone()
        if previous is None or previous["status"] != "verified":
            connection.execute(
                "INSERT INTO memory_finding_status(finding_id,seq,status,fact_id,created_at) "
                "VALUES(?,(SELECT COALESCE(MAX(seq),0)+1 FROM memory_finding_status WHERE finding_id=?),'verified',?,?)",
                (finding["finding_id"], finding["finding_id"], fact.fact_id, now),
            )


class FactStore:
    """Mixin for StateStore; authorization remains at each public project boundary."""

    def insert_project_findings(self, project_id: str, run_id: str, owner_id: str,
                                findings: Sequence[ProjectFinding]) -> None:
        if len(findings) > 8192:
            raise _conflict("Finding projection exceeds its fixed bound.")
        self.get_project(project_id, owner_id=owner_id)
        project_run = self.get_project_run(run_id, owner_id=owner_id)
        if project_run is None or project_run["project_id"] != project_id:
            raise _conflict("Finding run belongs to no project or another project.")
        now = utc_now()
        with self.transaction() as connection:
            for finding in findings:
                if (not isinstance(finding, ProjectFinding)
                        or not isinstance(finding.finding_id, str) or not re.fullmatch(r"[0-9a-f]{64}", finding.finding_id)
                        or not isinstance(finding.claim, str) or not finding.claim or len(finding.claim.encode()) > 8192
                        or not isinstance(finding.evidence, str) or len(finding.evidence.encode()) > 8192
                        or type(finding.verifiable) is not bool or not isinstance(finding.kind, str)
                        or finding.kind not in {"conclusion", "example", "counterexample", "proof_attempt",
                                                "plan", "dead_end", "direction", "obstacle"}):
                    raise _conflict("Finding data is invalid.")
                try:
                    links = json.loads(finding.links_json)
                except (TypeError, ValueError) as exc:
                    raise _conflict("Finding links must be JSON.") from exc
                if not isinstance(links, dict):
                    raise _conflict("Finding links must be an object.")
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO memory_findings(finding_id,project_id,run_id,kind,claim,evidence,"
                    "verifiable,links_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (finding.finding_id, project_id, run_id, finding.kind, finding.claim, finding.evidence,
                     int(finding.verifiable), finding.links_json, now),
                ).rowcount
                if inserted:
                    connection.execute("INSERT INTO memory_finding_status(finding_id,seq,status,created_at) "
                                       "VALUES(?,1,'active',?)", (finding.finding_id, now))
                else:
                    previous = connection.execute("SELECT * FROM memory_findings WHERE finding_id=?",
                                                  (finding.finding_id,)).fetchone()
                    expected = (project_id, run_id, finding.kind, finding.claim, finding.evidence,
                                int(finding.verifiable), links)
                    actual = (previous["project_id"], previous["run_id"], previous["kind"], previous["claim"],
                              previous["evidence"], previous["verifiable"], json.loads(previous["links_json"]))
                    if expected != actual:
                        raise _conflict("An existing finding ID has different immutable content.")

    def list_project_findings(self, project_id: str, *, owner_id: str) -> list[dict[str, Any]]:
        self.get_project(project_id, owner_id=owner_id)
        rows = self._fetch_all(
            "SELECT f.*,s.status,s.fact_id FROM memory_findings f JOIN memory_finding_status s "
            "ON s.finding_id=f.finding_id AND s.seq=(SELECT MAX(seq) FROM memory_finding_status "
            "WHERE finding_id=f.finding_id) WHERE f.project_id=? ORDER BY f.created_at DESC,f.finding_id LIMIT 1024",
            (project_id,),
        )
        return [_payload(row) for row in rows]

    def list_project_facts(self, project_id: str, *, owner_id: str) -> list[dict[str, Any]]:
        self.get_project(project_id, owner_id=owner_id)
        return [_payload(row) for row in self._fetch_all(_FACT_SUMMARY_SQL + " WHERE f.project_id=? ORDER BY f.fact_id",
                                                        (project_id,))]

    def active_project_fact_ids(self, project_id: str, *, owner_id: str) -> set[str]:
        return {row["fact_id"] for row in self.list_project_facts(project_id, owner_id=owner_id) if not row["revoked"]}

    def memory_fact_candidates(self, project_id: str, *, owner_id: str) -> list[dict[str, Any]]:
        self.get_project(project_id, owner_id=owner_id)
        return [dict(row) for row in self._fetch_all(
            "SELECT fact_id,substr(statement_tex,1,4096) AS statement_tex,substr(intuition,1,1024) AS intuition "
            "FROM facts f WHERE project_id=? AND NOT EXISTS(SELECT 1 FROM fact_revocations r WHERE r.fact_id=f.fact_id) "
            "ORDER BY created_at DESC,fact_id LIMIT 512", (project_id,),
        )]

    def memory_fact_summary(self, project_id: str, fact_id: str) -> dict[str, Any]:
        row = self._fetch_one(
            "SELECT fact_id,substr(statement_tex,1,4096) AS statement_tex,substr(intuition,1,1024) AS intuition "
            "FROM facts f WHERE project_id=? AND fact_id=? "
            "AND NOT EXISTS(SELECT 1 FROM fact_revocations r WHERE r.fact_id=f.fact_id)", (project_id, fact_id),
        )
        if row is None:
            raise _conflict("Selected fact predecessor is missing or revoked.")
        return dict(row)

    def memory_fact_predecessors(self, project_id: str, fact_id: str) -> list[str]:
        rows = self._fetch_all(
            "SELECT e.predecessor_id FROM fact_edges e JOIN facts f ON f.fact_id=e.fact_id "
            "WHERE f.project_id=? AND e.fact_id=? ORDER BY e.predecessor_id", (project_id, fact_id),
        )
        return [row["predecessor_id"] for row in rows]

    def project_fact_graph(self, project_id: str, *, owner_id: str) -> dict[str, Any]:
        self.get_project(project_id, owner_id=owner_id)
        return self.project_fact_graph_operator(project_id)

    def project_fact_graph_operator(self, project_id: str) -> dict[str, Any]:
        """Private local-operator graph export, with one coherent SQLite snapshot."""
        self.get_project(project_id)
        with self._lock:
            connection = self._connection
            connection.execute("BEGIN")
            try:
                facts = [_payload(row) for row in connection.execute(
                    _FACT_SUMMARY_SQL + " WHERE f.project_id=? ORDER BY f.fact_id", (project_id,),
                ).fetchall()]
                edges = connection.execute(
                    "SELECT e.fact_id,e.predecessor_id FROM fact_edges e JOIN facts f ON f.fact_id=e.fact_id "
                    "WHERE f.project_id=? ORDER BY e.fact_id,e.predecessor_id", (project_id,),
                ).fetchall()
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        nodes = {fact["fact_id"]: {"label": fact["statement_tex"], "metadata": {
            "source_run_id": fact["source_run_id"], "intuition": fact["intuition"],
            "glossary": fact["glossary"], "revoked": fact["revoked"]}} for fact in facts}
        return {"graph": {"id": project_id, "nodes": nodes,
                          "edges": [{"source": row["fact_id"], "target": row["predecessor_id"],
                                     "relation": "depends_on"} for row in edges]}}

    def revoke_project_fact(self, fact_id: str, actor: str, reason: str, *,
                             owner_id: str | None = None) -> dict[str, Any]:
        """Append a revocation and cascade to descendants; never rewrite facts."""
        if (not isinstance(actor, str) or not actor.strip() or not isinstance(reason, str)
                or not reason.strip() or len(reason.encode()) > 4096):
            raise ReCTMError("INVALID_FACT_REVOCATION", "Actor and a bounded reason are required.", category="validation")
        now = utc_now()
        with self.transaction() as connection:
            root = connection.execute("SELECT project_id FROM facts WHERE fact_id=?", (fact_id,)).fetchone()
            if root is None:
                raise ReCTMError("FACT_NOT_FOUND", "Unknown fact.", category="not_found")
            project_id = root["project_id"]
            if owner_id is not None:
                self.get_project(project_id, owner_id=owner_id)
            descendants = connection.execute(
                "WITH RECURSIVE descendants(fact_id) AS (SELECT ? UNION SELECT e.fact_id FROM fact_edges e "
                "JOIN descendants d ON e.predecessor_id=d.fact_id JOIN facts f ON f.fact_id=e.fact_id "
                "WHERE f.project_id=?) SELECT fact_id FROM descendants ORDER BY fact_id", (fact_id, project_id),
            ).fetchall()
            revoked = []
            for row in descendants:
                current = row["fact_id"]
                if connection.execute("SELECT 1 FROM fact_revocations WHERE fact_id=?", (current,)).fetchone():
                    continue
                connection.execute("INSERT INTO fact_revocations(fact_id,reason,actor,created_at) VALUES(?,?,?,?)",
                                   (current, reason, actor, now))
                linked = connection.execute(
                    "SELECT s.finding_id FROM memory_finding_status s WHERE s.fact_id=? AND s.status='verified' "
                    "AND s.seq=(SELECT MAX(seq) FROM memory_finding_status WHERE finding_id=s.finding_id) "
                    "ORDER BY s.finding_id", (current,),
                ).fetchall()
                for finding in linked:
                    connection.execute(
                        "INSERT INTO memory_finding_status(finding_id,seq,status,created_at) VALUES(?,"
                        "(SELECT COALESCE(MAX(seq),0)+1 FROM memory_finding_status WHERE finding_id=?),'superseded',?)",
                        (finding["finding_id"], finding["finding_id"], now),
                    )
                revoked.append(current)
            return {"project_id": project_id, "revoked_fact_ids": revoked}


_FACT_SUMMARY_SQL = (
    "SELECT f.fact_id,f.project_id,f.source_run_id,f.statement_tex,f.intuition,f.glossary_json,"
    "f.external_refs_json,f.created_at,EXISTS(SELECT 1 FROM fact_revocations r WHERE r.fact_id=f.fact_id) AS revoked FROM facts f"
)
