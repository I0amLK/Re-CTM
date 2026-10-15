from __future__ import annotations


SCHEMA_MIGRATIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);
"""


V1_WORKFLOW_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    problem_id TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    state TEXT NOT NULL,
    status TEXT NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 1,
    round_index INTEGER NOT NULL DEFAULT 0,
    transition_seq INTEGER NOT NULL DEFAULT 0,
    latex_passed INTEGER NOT NULL DEFAULT 0,
    verdict TEXT,
    sealed INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    domain_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    snapshot_id TEXT,
    order_index INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    sealed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_domains_run
    ON domains(run_id, role, status, order_index);

CREATE TABLE IF NOT EXISTS capabilities (
    nonce TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(domain_id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    issued_state TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    revoke_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_capabilities_run
    ON capabilities(run_id, domain_id, revoked);

CREATE TABLE IF NOT EXISTS branches (
    branch_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL,
    domain_id TEXT NOT NULL REFERENCES domains(domain_id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL,
    order_index INTEGER NOT NULL,
    status TEXT NOT NULL,
    result_path TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    sealed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_branches_run
    ON branches(run_id, status, order_index);

CREATE TABLE IF NOT EXISTS steering (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL,
    message TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    trace_id TEXT NOT NULL,
    before_state TEXT NOT NULL,
    after_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(run_id, sequence)
);
"""


V2_RESEARCH_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_owner
    ON projects(owner_id, status, updated_at);

CREATE TABLE IF NOT EXISTS claims (
    claim_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_claims_project
    ON claims(project_id, updated_at);

CREATE TABLE IF NOT EXISTS claim_revisions (
    revision_id TEXT PRIMARY KEY,
    claim_id TEXT NOT NULL REFERENCES claims(claim_id) ON DELETE CASCADE,
    revision_number INTEGER NOT NULL,
    statement_tex TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    lifecycle_status TEXT NOT NULL,
    source_run_id TEXT REFERENCES runs(run_id) ON DELETE SET NULL,
    proof_sha256 TEXT,
    conditions_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(claim_id, revision_number),
    UNIQUE(source_run_id)
);
CREATE INDEX IF NOT EXISTS idx_claim_revisions_claim
    ON claim_revisions(claim_id, revision_number DESC);

CREATE TABLE IF NOT EXISTS claim_edges (
    edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    from_revision_id TEXT NOT NULL REFERENCES claim_revisions(revision_id) ON DELETE CASCADE,
    to_revision_id TEXT NOT NULL REFERENCES claim_revisions(revision_id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(from_revision_id, to_revision_id, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_claim_edges_project
    ON claim_edges(project_id, edge_type);

CREATE TABLE IF NOT EXISTS project_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL,
    revisions_json TEXT NOT NULL DEFAULT '[]',
    snapshot_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_runs (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    project_snapshot_id TEXT NOT NULL REFERENCES project_snapshots(snapshot_id) ON DELETE RESTRICT,
    target_claim_id TEXT REFERENCES claims(claim_id) ON DELETE SET NULL,
    base_revision_id TEXT REFERENCES claim_revisions(revision_id) ON DELETE SET NULL,
    requested_workflow_mode TEXT NOT NULL DEFAULT 'auto',
    effective_workflow_mode TEXT NOT NULL DEFAULT 'full',
    register_result INTEGER NOT NULL DEFAULT 1,
    promotion_status TEXT NOT NULL DEFAULT 'pending',
    promoted_revision_id TEXT REFERENCES claim_revisions(revision_id) ON DELETE SET NULL,
    promotion_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_project_runs_project
    ON project_runs(project_id, created_at);

CREATE TABLE IF NOT EXISTS proof_manifests (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
    manifest_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS references_registry (
    reference_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
    identity_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    paper_id TEXT NOT NULL DEFAULT '',
    arxiv_id TEXT NOT NULL DEFAULT '',
    doi TEXT NOT NULL DEFAULT '',
    theorem_id TEXT NOT NULL DEFAULT '',
    source_uri TEXT NOT NULL DEFAULT '',
    source_state TEXT NOT NULL DEFAULT 'candidate',
    source_sha256 TEXT NOT NULL DEFAULT '',
    content_sha256 TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, identity_key)
);
CREATE INDEX IF NOT EXISTS idx_references_run
    ON references_registry(run_id, created_at);

CREATE TABLE IF NOT EXISTS source_snapshots (
    source_snapshot_id TEXT PRIMARY KEY,
    reference_id TEXT NOT NULL REFERENCES references_registry(reference_id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    source_uri TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'text/plain',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reference_audits (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    reference_id TEXT NOT NULL REFERENCES references_registry(reference_id) ON DELETE CASCADE,
    disposition TEXT NOT NULL,
    evidence_basis TEXT NOT NULL DEFAULT 'unresolved',
    evidence_locator TEXT NOT NULL DEFAULT '',
    verifier_domain_id TEXT NOT NULL DEFAULT '',
    proof_sha256 TEXT NOT NULL DEFAULT '',
    proof_manifest_sha256 TEXT NOT NULL DEFAULT '',
    material INTEGER NOT NULL DEFAULT 1,
    assumptions_checked INTEGER NOT NULL DEFAULT 0,
    notation_checked INTEGER NOT NULL DEFAULT 0,
    source_checked INTEGER NOT NULL DEFAULT 0,
    independently_rederived INTEGER NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, reference_id)
);
"""


V3_SUBMISSION_RECEIPTS_SQL = """
CREATE TABLE step_receipts (
    capability_sha256 TEXT PRIMARY KEY CHECK(length(capability_sha256)=64),
    owner_id TEXT NOT NULL,
    workspace_sha256 TEXT NOT NULL CHECK(length(workspace_sha256)=64),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    domain_id TEXT NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    role TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    issued_state TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','completed')),
    result_json TEXT CHECK(result_json IS NULL OR length(result_json)<=2048),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK((status='pending' AND result_json IS NULL AND completed_at IS NULL)
       OR (status='completed' AND result_json IS NOT NULL AND completed_at IS NOT NULL))
);
CREATE INDEX idx_step_receipts_run ON step_receipts(run_id);
CREATE UNIQUE INDEX idx_step_receipts_pending_run
    ON step_receipts(run_id) WHERE status='pending';
"""


V4_RECOVERY_SQL = """
CREATE TABLE creation_receipts (
    owner_id TEXT NOT NULL,
    key_sha256 TEXT NOT NULL CHECK(length(key_sha256)=64),
    workspace_sha256 TEXT NOT NULL CHECK(length(workspace_sha256)=64),
    request_sha256 TEXT NOT NULL CHECK(length(request_sha256)=64),
    run_id TEXT NOT NULL UNIQUE,
    execution_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('pending','completed')),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY(owner_id,key_sha256),
    CHECK((status='pending' AND completed_at IS NULL)
       OR (status='completed' AND completed_at IS NOT NULL))
);
CREATE TABLE step_checkpoints (
    capability_sha256 TEXT PRIMARY KEY REFERENCES step_receipts(capability_sha256) ON DELETE RESTRICT,
    execution_id TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL CHECK(phase IN ('prepared','running','commit_ready')),
    expected_writes INTEGER CHECK(expected_writes BETWEEN 0 AND 65536),
    accepted_writes INTEGER NOT NULL DEFAULT 0 CHECK(accepted_writes BETWEEN 0 AND 65536),
    CHECK((phase='prepared' AND expected_writes IS NULL AND accepted_writes=0)
       OR (phase='running' AND expected_writes IS NOT NULL AND accepted_writes<=expected_writes)
       OR (phase='commit_ready' AND expected_writes IS NOT NULL AND accepted_writes=expected_writes))
);
"""


V5_CREATION_INITIALIZATION_SQL = """
CREATE TABLE creation_initializations (
    run_id TEXT PRIMARY KEY REFERENCES creation_receipts(run_id) ON DELETE RESTRICT,
    material_sha256 TEXT CHECK(material_sha256 IS NULL OR length(material_sha256)=64),
    database_sha256 TEXT CHECK(database_sha256 IS NULL OR length(database_sha256)=64),
    CHECK((material_sha256 IS NULL)=(database_sha256 IS NULL))
);
"""


V6_CALLER_WRITE_JOURNAL_SQL = """
CREATE TABLE step_write_journals (
    capability_sha256 TEXT PRIMARY KEY REFERENCES step_checkpoints(capability_sha256) ON DELETE RESTRICT,
    marker_json TEXT NOT NULL CHECK(length(marker_json)<=4096)
);
"""


V7_ATOMIC_ACTION_SQL = """
ALTER TABLE step_checkpoints ADD COLUMN atomic_action TEXT
    CHECK(atomic_action IN ('assessment_complete','exploration_complete','proof_submitted','repair_submitted'));
"""


V8_FACT_MEMORY_SQL = """
CREATE TABLE facts (
    fact_id TEXT PRIMARY KEY CHECK(length(fact_id)=16),
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    source_run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    statement_tex TEXT NOT NULL,
    proof_tex TEXT NOT NULL,
    intuition TEXT NOT NULL DEFAULT '',
    glossary_json TEXT NOT NULL DEFAULT '[]',
    external_refs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_facts_project ON facts(project_id, created_at, fact_id);
ALTER TABLE claim_revisions ADD COLUMN fact_id TEXT REFERENCES facts(fact_id) ON DELETE RESTRICT;
CREATE TABLE fact_edges (
    fact_id TEXT NOT NULL REFERENCES facts(fact_id) ON DELETE RESTRICT,
    predecessor_id TEXT NOT NULL REFERENCES facts(fact_id) ON DELETE RESTRICT,
    PRIMARY KEY(fact_id, predecessor_id),
    CHECK(fact_id != predecessor_id)
);
CREATE TABLE fact_revocations (
    fact_id TEXT NOT NULL REFERENCES facts(fact_id) ON DELETE RESTRICT,
    reason TEXT NOT NULL CHECK(length(reason)>0),
    actor TEXT NOT NULL CHECK(length(actor)>0),
    created_at TEXT NOT NULL
);
CREATE INDEX idx_fact_revocations_fact ON fact_revocations(fact_id);
CREATE TABLE memory_findings (
    finding_id TEXT PRIMARY KEY CHECK(length(finding_id)=64),
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('conclusion','example','counterexample','proof_attempt','plan','dead_end','direction','obstacle')),
    claim TEXT NOT NULL,
    evidence TEXT NOT NULL,
    verifiable INTEGER NOT NULL CHECK(verifiable IN (0,1)),
    links_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_memory_findings_project ON memory_findings(project_id, kind, created_at);
CREATE TABLE memory_finding_status (
    finding_id TEXT NOT NULL REFERENCES memory_findings(finding_id) ON DELETE CASCADE,
    seq INTEGER NOT NULL CHECK(seq>0),
    status TEXT NOT NULL CHECK(status IN ('active','verified','superseded')),
    fact_id TEXT REFERENCES facts(fact_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL,
    PRIMARY KEY(finding_id, seq),
    CHECK((status='verified')=(fact_id IS NOT NULL))
);
"""
