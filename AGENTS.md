# Re-CTM engineering rules

## Current target-host validation scope (2026-10-14)

The user subsequently authorized deployment and validation on the selected MTM
host, aiming for release readiness. OPT-022 covers the bounded release-harness
and documentation corrections plus isolated target testing. Use only the MTM
connector and workspace-relative paths for this task; do not launch Work, Codex,
a cloud task or an alternate local execution route.

This later authorization supersedes the earlier source-only/no-deployment
restriction below only for disposable deployment and testing on this host. It
does not authorize reading or migrating production private state, changing host
security/isolation settings, public ingress, commits, pushes or publication.
The user will handle GitHub publication. Keep the existing MTM service and its
private state untouched; use fresh, non-overlapping test roots. A nested-user-
namespace restriction is a blocker to report, not a reason to weaken isolation.
Preserve historical acceptance records and never convert missing target,
browser, LaTeX or mathematical evidence into a passing release claim.

## User-authorized MTM contract migration (2026-10-14)

The user explicitly approved migration to MTM's new tool, workflow and database
contracts after being told that they break the previous freeze. For OPT-018 through
OPT-021, the target is the actual MTM `b5dbd2577869d2aaf7b0933373df6671d104581c`
behavior: 19 Native plus six workflow tools, current v11 tool semantics, workflow
protocol 3 for new runs, additive state schemas 3–8, durable recovery receipts and
verified fact memory. The old 24-tool/schema-2/protocol-2/alias/Native-mode freeze
below is superseded only for this explicit migration; historical records remain
historical, and legacy persisted runs require a tested upgrade/resume path.

Do not claim completion by changing version constants. Preserve one production
authority, OAuth ownership, Native/private-root isolation, opaque signed capability
checks, role/state and verifier barriers, and mechanical finalizer-only promotion.
The earlier source-only phase authorized source changes and disposable test
migrations, and excluded live databases, security settings, installation,
deployment, commits and pushes. Its cloud-filesystem execution route is historical;
the current target-host scope above now governs this task. Keep the compatible
OPT-017 changes and their stricter Git/LaTeX safety boundaries intact.

Re-CTM combines a native CMT plane and a Rethlas workflow plane in one OAuth MCP package. Preserve the following invariants in every change.

## Authorization axioms

1. OAuth identity is L0 authority.
2. Public Native `dangerous` is L1 authority and governs native tools only. Public `safe`/`trusted` configuration is retired; retained internal isolation adapters do not restore those public profiles.
3. Signed run capabilities, role ACLs, and workflow state are L2 authority and govern only `rethlas_*` logical resources and transitions.
4. L1 `dangerous` never implies an L2 capability. Do not add `native_mode` to capability claims or workflow authorization decisions.
5. The native workspace and Re-CTM data/private roots must not overlap.
6. Native arbitrary execution fails closed unless a hard-isolation backend is available and attested. The built-in Linux Bubblewrap backend attests on every startup; external helpers require explicit operator attestation. The private vault must not be mounted in that worker.
7. Native toolchain exposure is application-agnostic. Build one canonical union of system roots, validated PATH/symlink discovery, and `RE_CTM_NATIVE_EXEC_ALLOW_ROOTS`; reject broad, missing, relative, workspace/data/private-overlapping roots and mount every accepted non-system root read-only. Do not add per-application Sage/Magma/Mathematica special cases.
8. OAuth authenticates a client but does not replace run ownership or workflow capability validation.
9. If `RE_CTM_OAUTH_PASSWORD` is unset for an interactive `serve`, generate a high-entropy authorization key at startup and reveal it only to the local operator terminal. Never write the raw generated key to structured debug events, project ledgers, validation reports, HTTP responses, or persistent state.
10. `RE_CTM_SERVER_URL` is a fixed OAuth-origin override, not a mandatory startup dependency. Without it, dynamic OAuth-origin discovery is allowed only on a loopback-bound HTTP server; forwarded proxy headers are trusted only from a loopback peer, and the resulting authorization code/token issuer/audience remain bound to that effective origin.
11. Research projects, claim revisions, project snapshots, proof manifests, reference provenance, and reference audits are private-state facts. Native `dangerous` never grants project registry authority and the registry must not be stored under the native workspace.
12. A model or owner-facing project action may create or revise OPEN claims, but only the mechanical finalizer may create VERIFIED/CONDITIONAL claim revisions from a completed run. Verified revisions are immutable.

## Workflow invariants

- Keep one fixed, truthful public MCP tool catalog: the exact 19 MTM Native tools followed by six Rethlas façade tools (25 public tools). Authorization is server-side, not `tools/list` filtering. Retired Rethlas aliases are documented historical names and are rejected, not callable hidden tools.
- Keep the concrete-mathematics routing rule in both MCP initialize instructions and `rethlas_start` metadata: proof, derivation, proof-repair, and rigorous verification tasks use Rethlas by default unless the user explicitly requests an informal bypass, and continue through `rethlas_step` until done.
- Every model-active Rethlas task must be zero-guess and self-describing: return a machine-readable `write_contract`, exact `commit_action`, `commit_payload_schema`, and at least one minimal/template/example submission. Memory writes are one JSON object per write unless the task explicitly declares another schema.
- New façade runs use workflow protocol 3. Existing persisted protocol-1 and protocol-2 runs remain resumable after upgrade with their original write contracts; a schema upgrade never silently changes a run protocol. The v0.2 protocol-2 and 24-tool freeze is historical and was explicitly superseded by the migration approval above.
- Compact mode reduces exploration cost only. It never skips the LaTeX gate, independent verifier, repair loop, or mechanical finalizer. The server owns the compact/full route decision; compact assembly and repeated verifier failure must have explicit full-workflow escalation paths.
- Do not make the model duplicate server-derived workflow facts. If commit payload is authoritative and the server creates the canonical memory record (for example decomposition plans, failure synthesis, or replanning decisions), expose an empty `write_contract` for that fact instead of also requiring a logical write.
- Direct-plan screening must use server-issued plan/subgoal identifiers. Coverage remains mandatory, but partial screening submissions are retained and report missing ids; plan status, overall branch-vs-solved outcome, and the all-active-plan branch set are server-derived rather than echoed by the model.
- When `rethlas_step` returns a fresh task capability after a recoverable validation/conflict correction, set `recoverable=true` and retryable semantics explicitly, revoke the superseded capability, identify whether successful writes were retained, and instruct the client not to replay retained records. Permission/security failures remain hard failures.
- Treat every workflow capability as an opaque, immutable server-issued handle. Clients must copy `run_id` and `capability` verbatim from the same current task envelope; they must never decode, edit, normalize, concatenate, synthesize, or pair a capability with another run id. The server must reject an envelope mismatch before any logical write, recovery action, or next-task issuance.
- Signed capability claims and the persisted capability registry are two independent integrity sources. Validation must fail closed if run/domain/role/epoch/state/permissions/issued-at/expiry facts in the signed handle disagree with the registered nonce record, even when the HMAC itself is valid.
- Branch domains read one frozen snapshot and their own branch only until every branch is sealed and the join barrier opens.
- Sealing a domain revokes its capabilities.
- Verifier domains cannot read generation memory, branch internals, steering history, join internals, or generator confidence.
- For project-linked protocol-2-or-newer runs, the verifier may see only proof-declared dependency revisions from the frozen project snapshot, not the wider project registry or target-claim lifecycle state.
- Protocol-2-or-newer proof submission includes a machine-readable `proof_manifest`. Dependency revisions must come from the frozen project snapshot; material references must belong to the run; conditional hypotheses and computational evidence remain explicit provenance rather than hidden prose-only assumptions.
- Each material protocol-2-or-newer reference must receive a server-tracked verifier disposition plus evidence basis/locator. `SOURCE_VERIFIED` requires actual source/assumption/notation checks and traceable source evidence; fixed-provider theorem/bibliographic discovery metadata is never sufficient by itself. Missing or unresolved reference-audit coverage is mechanically added to verification gaps before the server computes the verdict.
- The server computes `correct` iff both `critical_errors` and `gaps` are empty.
- Protocol-3 research events and action records carry server-owned record type/id, role, domain, round and timestamp; callers cannot forge these fields. Plans have typed local keys with server-issued canonical plan/node/subgoal ids and validated acyclic dependencies.
- Research state is advisory. `route_solved`, counterexample-search negative evidence and project-memory suggestions never confer VERIFIED status or bypass the verifier/finalizer. Only generator and repair task context may include the broad research projection; verifier, branch and join context must not construct or expose it.
- Bound research graphs to 256 nodes, 1,024 edges, 2,048 attempts and 256 decisions. Bound the base advisory task view to 16,384 UTF-8 bytes, five frontier/attempt/partial entries and three warnings; the view including project memory must stay within 24,576 bytes.
- Exact `rethlas_step` retries use durable submission receipts bound to the owner, workspace, run/domain/role/epoch, original capability and ordered request. Historical receipts provide no fresh task authority; changed content under a consumed capability fails closed. `recover_only` reconciles only explicitly enrolled evidenced work and never executes missing writes or actions.
- State schemas 3–8 add receipts, recovery checkpoints, creation initialization, caller-write journals, explicit action enrollment, immutable facts and append-only finding status. Use the same private SQLite authority and transaction boundary; unsupported future schemas fail closed.
- Protocol-2-or-newer reference dispositions are evidence-bearing, not labels: SOURCE_VERIFIED must identify an actual source inspection or an eligible stored source-body snapshot; theorem/paper discovery metadata alone is not original-source verification. Bind each structured audit to the verifier domain plus proof/proof-manifest hashes.
- Project registry promotion is a non-fatal second phase after mathematical `done`: promotion failure/conflict must never invalidate `proof_verified.tex`; retryable promotion errors remain pending and are retried idempotently on later terminal calls.
- Frozen project snapshots retain historical VERIFIED/CONDITIONAL revisions even after a newer OPEN revision becomes active, so lifecycle supersession does not erase mathematically valid dependency evidence.
- Only the mechanical finalization gate may create `proof_verified.tex`.
- Project promotion is downstream of mathematical finalization. It must be idempotent by source run, propagate dependency conditions mechanically, use optimistic concurrency against the run's frozen base revision, and record registry conflicts without invalidating an already-verified proof.
- On terminal MCP `rethlas_step`, export the mechanically finalized bytes through the controlled bridge to the run's workspace-relative path. The default is `rethlas-output/<run_id>/proof_verified.tex`; identical retries are idempotent and different content must never be overwritten automatically.
- The final artifact is self-contained LaTeX; Zola and Markdown delivery are out of scope.
- Portable project manifests must omit owner/OAuth/capability/private-reasoning material. Generated project-summary LaTeX must pass the same static external-file/shell-safety checks before export.

## Code quality and optimization governance

- Read and follow `docs/CODE_QUALITY.md` before cleanup, refactoring, deduplication, modularization, performance work, or broad naming/format changes.
- The governing sentence is: make only the smallest code improvement whose value can be demonstrated through functional correctness, security boundaries, reliability, maintainability, or measured performance.
- Do not optimize for aesthetics, line count, abstraction count, or novelty. A large function/module is a review signal, not an automatic command to split it.
- Every optimization must be represented in `code-optimization-graph.json` before implementation with evidence, functional outcome, scope, non-goals, acceptance criteria, validation commands, dependencies, risk, stop condition, and rollback.
- `approved` work changes to `in_progress` before code modification. `completed`, `rejected`, and `superseded` nodes require an append-only matching receipt; failed checks may leave work `in_progress` or `blocked`, never `completed`.
- Preserve unrelated history: do not mix a functional change with repository-wide formatting, mass renaming, or speculative cleanup.
- Run `python3 scripts/validate_code_optimization_graph.py` whenever the optimization graph or receipt ledger changes. The full local check also runs this validator.

## Debugging and evidence

- Every external request, authorization decision, and state transition must have a trace ID and structured event.
- Never log raw OAuth tokens, authorization codes, client secrets, passwords, capability handles, or secret environment values.
- Unexpected tool failures should write a redacted per-run `last_error.json` when a run id is available.
- Keep state snapshots and transition records replayable.
- State schema upgrades are versioned and additive. The runtime must migrate supported older schemas transactionally and fail closed on a database whose schema version is newer than the runtime understands.
- External research retrieval uses fixed/validated HTTPS providers with bounded timeout/response size/content type. Never turn `rethlas_retrieve` into an arbitrary caller-supplied URL fetcher.
- Native process termination provenance may add diagnostics but must not silently change the original CTM timeout/TERM/KILL lifecycle without a fresh reference-compatibility review.
- Use `scripts/collect_debug_bundle.py` for post-push evidence. It must not include problem/proof/private file contents.

## Validation boundary

Run before considering a local change complete:

```bash
python3 scripts/run_local_checks.py
```

This validates deterministic local behavior only. Never describe it as proof that the complete webpage/OAuth/MCP/mathematical workflow works on the target PC. Keep the active RC checklist in `manual-validation.json` pending until each check has candidate-specific evidence at its stated scope. Scripted/local evidence cannot replace actual target/browser or operator mathematical acceptance. Preserve superseded checklists and their evidence; pushing the repository is a separate user action, not a prerequisite for local qualification.

Update `project-progress.json` after material engineering changes. Do not mark hard native isolation, real browser compatibility, external retrieval quality, real LaTeX compilation, cognitive domain independence, or the 95-percent functional-equivalence target as validated solely from local unit tests.
