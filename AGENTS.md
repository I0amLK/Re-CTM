# Re-CTM engineering rules

Re-CTM combines a native CMT plane and a Rethlas workflow plane in one OAuth MCP package. Preserve the following invariants in every change.

## Authorization axioms

1. OAuth identity is L0 authority.
2. Native `safe`, `trusted`, and `dangerous` are L1 authority and govern native tools only.
3. Signed run capabilities, role ACLs, and workflow state are L2 authority and govern only `rethlas_*` logical resources and transitions.
4. L1 `dangerous` never implies an L2 capability. Do not add `native_mode` to capability claims or workflow authorization decisions.
5. The native workspace and Re-CTM data/private roots must not overlap.
6. Native arbitrary execution fails closed unless an external hard-isolation backend is configured and attested. The private vault must not be mounted in that worker.
7. OAuth authenticates a client but does not replace run ownership or workflow capability validation.
8. If `RE_CTM_OAUTH_PASSWORD` is unset for an interactive `serve`, generate a high-entropy authorization key at startup and reveal it only to the local operator terminal. Never write the raw generated key to structured debug events, project ledgers, validation reports, HTTP responses, or persistent state.
9. `RE_CTM_SERVER_URL` is a fixed OAuth-origin override, not a mandatory startup dependency. Without it, dynamic OAuth-origin discovery is allowed only on a loopback-bound HTTP server; forwarded proxy headers are trusted only from a loopback peer, and the resulting authorization code/token issuer/audience remain bound to that effective origin.

## Workflow invariants

- Keep one fixed, truthful public MCP tool catalog: the exact 18 CTM native tools followed by six Rethlas façade tools. Authorization is server-side, not `tools/list` filtering. Superseded Rethlas protocol names may remain callable only as hidden compatibility aliases.
- Keep the concrete-mathematics routing rule in both MCP initialize instructions and `rethlas_start` metadata: proof, derivation, proof-repair, and rigorous verification tasks use Rethlas by default unless the user explicitly requests an informal bypass, and continue through `rethlas_step` until done.
- Direct-plan screening must use server-issued plan/subgoal identifiers. Coverage remains mandatory, but partial screening submissions are retained and report missing ids; plan status, overall branch-vs-solved outcome, and the all-active-plan branch set are server-derived rather than echoed by the model.
- When `rethlas_step` returns a fresh task capability after a submission (including a recoverable validation correction), revoke the capability used for that submission so the client has one current handle to continue with.
- Branch domains read one frozen snapshot and their own branch only until every branch is sealed and the join barrier opens.
- Sealing a domain revokes its capabilities.
- Verifier domains cannot read generation memory, branch internals, steering history, join internals, or generator confidence.
- The server computes `correct` iff both `critical_errors` and `gaps` are empty.
- Only the mechanical finalization gate may create `proof_verified.tex`.
- On terminal MCP `rethlas_next`, export the mechanically finalized bytes through the controlled bridge to the run's workspace-relative path. The default is `rethlas-output/<run_id>/proof_verified.tex`; identical retries are idempotent and different content must never be overwritten automatically.
- The final artifact is self-contained LaTeX; Zola and Markdown delivery are out of scope.

## Debugging and evidence

- Every external request, authorization decision, and state transition must have a trace ID and structured event.
- Never log raw OAuth tokens, authorization codes, client secrets, passwords, capability handles, or secret environment values.
- Unexpected tool failures should write a redacted per-run `last_error.json` when a run id is available.
- Keep state snapshots and transition records replayable.
- Use `scripts/collect_debug_bundle.py` for post-push evidence. It must not include problem/proof/private file contents.

## Validation boundary

Run before considering a local change complete:

```bash
python3 scripts/run_local_checks.py
```

This validates deterministic local behavior only. Never describe it as proof that the complete webpage/OAuth/MCP/mathematical workflow works on the target PC. Keep `manual-validation.json` pending until a human runs it after the repository is pushed.

Update `project-progress.json` after material engineering changes. Do not mark hard native isolation, real browser compatibility, external retrieval quality, real LaTeX compilation, cognitive domain independence, or the 95-percent functional-equivalence target as validated solely from local unit tests.
