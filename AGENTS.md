# Re-CTM engineering rules

Re-CTM combines a native CMT plane and a Rethlas workflow plane in one OAuth MCP package. Preserve the following invariants in every change.

## Authorization axioms

1. OAuth identity is L0 authority.
2. Native `safe`, `trusted`, and `dangerous` are L1 authority and govern native tools only.
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

- Keep one fixed, truthful public MCP tool catalog: the exact 18 CTM native tools followed by six Rethlas façade tools. Authorization is server-side, not `tools/list` filtering. Superseded Rethlas protocol names may remain callable only as hidden compatibility aliases.
- Keep the concrete-mathematics routing rule in both MCP initialize instructions and `rethlas_start` metadata: proof, derivation, proof-repair, and rigorous verification tasks use Rethlas by default unless the user explicitly requests an informal bypass, and continue through `rethlas_step` until done.
- Every model-active Rethlas task must be zero-guess and self-describing: return a machine-readable `write_contract`, exact `commit_action`, `commit_payload_schema`, and at least one minimal/template/example submission. Memory writes are one JSON object per write unless the task explicitly declares another schema.
- New v0.2 runs use workflow protocol 2. Existing persisted protocol-1 runs must remain resumable after upgrade and must not suddenly acquire protocol-2 write requirements.
- Compact mode reduces exploration cost only. It never skips the LaTeX gate, independent verifier, repair loop, or mechanical finalizer. The server owns the compact/full route decision; compact assembly and repeated verifier failure must have explicit full-workflow escalation paths.
- Do not make the model duplicate server-derived workflow facts. If commit payload is authoritative and the server creates the canonical memory record (for example decomposition plans, failure synthesis, or replanning decisions), expose an empty `write_contract` for that fact instead of also requiring a logical write.
- Direct-plan screening must use server-issued plan/subgoal identifiers. Coverage remains mandatory, but partial screening submissions are retained and report missing ids; plan status, overall branch-vs-solved outcome, and the all-active-plan branch set are server-derived rather than echoed by the model.
- When `rethlas_step` returns a fresh task capability after a recoverable validation/conflict correction, set `recoverable=true` and retryable semantics explicitly, revoke the superseded capability, identify whether successful writes were retained, and instruct the client not to replay retained records. Permission/security failures remain hard failures.
- Branch domains read one frozen snapshot and their own branch only until every branch is sealed and the join barrier opens.
- Sealing a domain revokes its capabilities.
- Verifier domains cannot read generation memory, branch internals, steering history, join internals, or generator confidence.
- For project-linked protocol-2 runs, the verifier may see only proof-declared dependency revisions from the frozen project snapshot, not the wider project registry or target-claim lifecycle state.
- Protocol-2 proof submission includes a machine-readable `proof_manifest`. Dependency revisions must come from the frozen project snapshot; material references must belong to the run; conditional hypotheses and computational evidence remain explicit provenance rather than hidden prose-only assumptions.
- Each material protocol-2 reference must receive a server-tracked verifier disposition plus evidence basis/locator. `SOURCE_VERIFIED` requires actual source/assumption/notation checks and traceable source evidence; fixed-provider theorem/bibliographic discovery metadata is never sufficient by itself. Missing or unresolved reference-audit coverage is mechanically added to verification gaps before the server computes the verdict.
- The server computes `correct` iff both `critical_errors` and `gaps` are empty.
- Protocol-2 reference dispositions are evidence-bearing, not labels: SOURCE_VERIFIED must identify an actual source inspection or an eligible stored source-body snapshot; theorem/paper discovery metadata alone is not original-source verification. Bind each structured audit to the verifier domain plus proof/proof-manifest hashes.
- Project registry promotion is a non-fatal second phase after mathematical `done`: promotion failure/conflict must never invalidate `proof_verified.tex`; retryable promotion errors remain pending and are retried idempotently on later terminal calls.
- Frozen project snapshots retain historical VERIFIED/CONDITIONAL revisions even after a newer OPEN revision becomes active, so lifecycle supersession does not erase mathematically valid dependency evidence.
- Only the mechanical finalization gate may create `proof_verified.tex`.
- Project promotion is downstream of mathematical finalization. It must be idempotent by source run, propagate dependency conditions mechanically, use optimistic concurrency against the run's frozen base revision, and record registry conflicts without invalidating an already-verified proof.
- On terminal MCP `rethlas_next`, export the mechanically finalized bytes through the controlled bridge to the run's workspace-relative path. The default is `rethlas-output/<run_id>/proof_verified.tex`; identical retries are idempotent and different content must never be overwritten automatically.
- The final artifact is self-contained LaTeX; Zola and Markdown delivery are out of scope.
- Portable project manifests must omit owner/OAuth/capability/private-reasoning material. Generated project-summary LaTeX must pass the same static external-file/shell-safety checks before export.

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

This validates deterministic local behavior only. Never describe it as proof that the complete webpage/OAuth/MCP/mathematical workflow works on the target PC. Keep `manual-validation.json` pending until a human runs it after the repository is pushed.

Update `project-progress.json` after material engineering changes. Do not mark hard native isolation, real browser compatibility, external retrieval quality, real LaTeX compilation, cognitive domain independence, or the 95-percent functional-equivalence target as validated solely from local unit tests.
