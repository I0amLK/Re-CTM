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
