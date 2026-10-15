# MTM contract migration: source integration

The user explicitly authorized migration to MTM's new contracts on 2026-10-14.
The reference is MTM commit `b5dbd2577869d2aaf7b0933373df6671d104581c`, including
`docs/MTM-018-CTM-050-INTEGRATION.md`. This is a source update, not installation,
deployment, a new release, or target-machine acceptance. The earlier compatible
OPT-017 changes remain in place; see [MTM_BACKPORT.md](MTM_BACKPORT.md).

Current public MCP contract: `mtm-tools-v11`, 19 Native tools followed by six
workflow façades, 25 total. Native declarations, specialized output schemas and
annotations come from `src/re_ctm/native_catalog.py`; the dispatcher consumes that
table. Retired workflow tool aliases are no longer callable through MCP. Existing
clients must use the six façades rather than relying on hidden alias dispatch.

## Native configuration and command migration

`dangerous` is the only public Native profile and the default. Existing
`RE_CTM_NATIVE_MODE=safe`/`trusted` configurations and those CLI choices are rejected;
operators must explicitly review the upgrade and use `dangerous`, or leave arbitrary
execution disabled with `RE_CTM_NATIVE_EXEC_BACKEND=disabled`. There is no restored
consent/grant ledger. `request_permissions` is a non-mutating compatibility response
and retains the eight historical permission names.

This does not relax OAuth, Native workspace/private-root separation, hard-isolation
attestation, signed workflow capabilities, role/state ACLs or finalizer authority.
Internal `SAFE`/`TRUSTED` enum values remain for compatibility tests and fixed
adapters, not public runtime configuration. The LaTeX adapter explicitly uses the
network-isolated internal mode; public `dangerous` must never change that setting.

`exec_command` requires exactly one of `argv` or `cmd`. Literal `argv` may contain
empty arguments after a nonempty executable. `cmd` runs non-login `/bin/sh -c`, so
login profiles do not silently reset the caller's PATH. The total lifetime default
is 300000 ms, maximum 600000 ms; yield remains 10000 ms by default, maximum 30000 ms.
Workdir is workspace-relative and must agree with `cwd` if both are supplied.

`native_exec.py` adapts MTM's `native_permission.rs`, `shell_candidates.rs` and
`shell_segments.rs`: exact requested `env.PATH`, empty/relative PATH entries relative
to invocation workdir, `/workspace` mapping, visible read-only toolchain roots,
executable metadata and immediate pre-start revalidation. Absolute host workspace
paths are not sandbox executable paths. Missing/dynamic executable targets fail
closed with bounded recovery information, without echoing command tokens or secrets.
The bounded shell collector follows MTM's literal-list/for-loop/query handling and
compatibility fallback; it is not a complete shell interpreter or a race-free
executable loader. No toolchain is installed or executed to perform the checks.

The built-in Bubblewrap lifecycle handles stdin, TTY and environment overrides.
External synchronous helpers retain their attested protocol but reject options they
cannot honor (nonempty env/stdin or TTY), rather than silently ignoring them.

Every observation distinguishes `running`, `exited_0`, `exited_nonzero`, `timeout`
and `signal` via `operation_outcome`. A nonzero child exit does not make a successful
MCP observation a transport failure. One locked snapshot supplies lifecycle fields;
the first terminal observation across exec, poll, kill and output paging emits one
terminal event. Polling bytes are not consumed by `read_output`. A command still
alive after a kill/timeout attempt remains running. Retention is 300 seconds with
32 retained commands; active-command capacity remains 16. Existing TERM/KILL
provenance is preserved.

## Revision-bound structured changes and current patches

`apply_changes` implements six actions: `create`, `write`, `edit`, `delete`, `move`
and `copy`. Read the file first and use its same-snapshot SHA-256 `revision` for any
existing source. `create` asserts absence; `write` may create an absent file without
a revision. Structured move/copy destinations must be absent. All normalized source
and destination paths are unique across the request; chained operations and path
aliases are rejected. Action-specific fields are validated at the typed runtime
boundary despite the intentionally flat input schema.

`native_changes.py` is the single transaction writer for structured changes,
current patches and controlled artifact exports. Preparation captures and validates
bytes without writes. Commit serializes in this runtime, uses descriptor-relative
no-follow traversal, stages files, revalidates all sources/dependencies and parent
bindings, and checks rollback backups before restoration. Copy sources and identical
writes remain read-only dependencies, retaining their inodes. A changed dependency
after an earlier mutation triggers rollback. An external replacement never becomes
rollback-owned merely because it was captured after installation. Uncertain rollback
preserves evidence and raises `NATIVE_PATCH_ROLLBACK_FAILED`; it does not claim that
the original files were restored. Created-directory cleanup uses the same no-follow
boundary. Completed writes with incomplete temporary-file cleanup return a warning.

Limits follow MTM: 1 MiB request, 100 actions/patch operations, 200 edits/hunks per
file, 64 MiB per captured source and aggregate captured source bytes. Structured
sources and the shared transaction writer reject symlinks, hardlinks and nonregular
files. Existing file mode is retained without setuid/setgid privilege bits. Revisions
and result evidence come from captured/staged bytes, not a post-commit reread.

Line editing numbers LF-delimited lines exactly like `read_file`. Existing bare CR
is content; replacement CRLF/CR is normalized, untouched endings remain byte-exact,
BOM/EOF behavior follows the MTM fixtures, and overlapping edits are rejected.
Evidence counts changed placements rather than unchanged context.

`native_patch.py` adapts the current MTM parser and detailed matcher: forward anchors
and cursor, missing-anchor refusal, EOF placement, exact/trailing-whitespace/
indentation matching, bounded repair hints, accurate ranges and line counts, and
conservative already-applied recognition. Matching has a 512 MiB comparison-work
budget. Add never overwrites. A single patch move preserves MTM's existing-destination
overwrite behavior; self/alias moves and interacting source/destination operations
are rejected. Proven unchanged edits preserve their inode. Legacy pure parsing
helpers in `ctm_compat.py` remain isolated from the production mutation path.

Neither the process-local commit lock nor baseline rechecks provide global atomicity
against hostile external writers or multiple server processes. There is no Native
crash journal or power-loss atomicity. Reconcile files after an interrupted or unknown
outcome; do not assume that a retry can safely recreate a transaction.

## Caller-scoped write replay

`apply_patch` and `apply_changes` share one `NativeReplay` instance per runtime.
Keys are optional, 1–128 UTF-8 bytes, scoped to the authenticated subject, client ID,
OAuth scope, tool and workspace/backend runtime instance. The dispatcher provides
that scope after authentication; a keyed direct invocation without authoritative
scope is rejected. Argument identity is canonical JSON excluding the key.

Changed arguments under the same key conflict. A concurrent duplicate returns
`NATIVE_WRITE_IN_PROGRESS` without a second execution. Dry runs do not reserve slots.
Only completed successes can be LRU-evicted from the 64-slot store. Runtime/internal
failures, malformed/failed result envelopes and results exceeding 1 MiB leave an
unknown slot, blocking automatic re-execution. The cache lock never spans filesystem
work. Historical successful replay does not reread or restore today's files.

This is not a durable workflow receipt or exactly-once guarantee across restart,
crash or eviction. A fresh key or restart does not make uncertain work safe to retry.
The upstream broad repeated-failure circuit breaker remains deliberately unported,
as in the pinned MTM integration: filesystem errors can become repairable after
external edits not visible to an in-memory failure cache.

## Other Native v11 adaptations and preserved stricter boundaries

- `read_file` exposes same-snapshot revision/algorithm alongside byte-exact UTF-8
  paging, partial-line offsets and digest-bound continuations. Parent and leaf opens
  are descriptor-relative/no-follow after alias validation, closing a parent-symlink
  race into private data.
- `search_text` accepts an explicit file with basename/full-path glob selection and
  preserves UTF-8 byte boundaries in previews. File reads use the same bounded
  snapshot boundary; context snippets are bounded as well.
- `git_diff` includes untracked files by default only in its unstaged pass. It uses
  complete UTF-8 NUL-record enumeration, known filenames, stable no-follow captured
  bytes, binary markers and no external diff/textconv helpers. Work is bounded to
  128 files, a 15-second processing window, 8 MiB per pre-read source and the aggregate
  requested output budget. `include_untracked=false` restores tracked-only selection.
- Protected Re-CTM Git restrictions remain stricter than generic upstream tooling:
  repositories with effective clean/smudge/process filters or promisor/partial-clone
  fetching are rejected; status/diff reject indexed submodules. Transport helpers,
  signature verification, external diff and textconv remain disabled.
- OPT-017 compatible schema extensions remain: case-insensitive read digest input,
  explicit `max_lines=500` default and optional `git_log.paths`. These are intentional
  differences from the pinned raw MTM table, not accidental parity claims.
- The stricter dual-view LaTeX scanner still rejects forbidden operations inside
  literal environments; the isolated compiler receives the original bytes. No
  verifier/finalizer or network-isolation gate is weakened.

## Native validation evidence and limits

Focused source tests cover structured actions/revisions, no-op/copy inode behavior,
dry runs, exact line editing, alias/link boundaries, injected commit failures,
backup/installed-target tampering, parent-symlink reads and cleanup, replay scope/
concurrency/eviction/unknown outcomes, current patch matching, requested PATH and
executable revalidation, command lifecycle, canonical schemas, untracked Git and the
existing Git restrictions. See `tests/test_native_changes_v11.py`,
`tests/test_native_exec_v11.py`, `tests/test_native_review_v11.py`,
`tests/test_command_v11.py`, `tests/test_native_catalog_v11.py`,
`tests/test_git_untracked_v11.py`, `tests/test_workspace_read.py` and
`tests/test_workspace_git.py`.

The current cloud environment denies Bubblewrap's NETLINK_ROUTE socket creation.
Real Bubblewrap/LaTeX qualification therefore remains blocked here; dedicated tests
are retained rather than skipped or weakened. Passing disposable deterministic tests
does not establish fresh target-host hard isolation, real scientific toolchains,
browser OAuth/MCP interoperability or mathematical/cognitive correctness. The final
full-gate outcome and any remaining issues are recorded separately by the integration
owner. No live user database, security setting, installation, commit or push was part
of this work.

## Workflow protocol 3: source parity and boundaries

The protocol implementation is anchored to `mtm-workflow/src/research_state/`
and `mtm-workflow/src/methodology.rs` at the revision above. It is a Python port
inside the existing `WorkflowEngine`; it does not introduce a second workflow
engine or a parallel database authority.

| Contract | Re-CTM implementation | Evidence / boundary |
| --- | --- | --- |
| New façade runs use protocol 3 | `ToolRuntime` default and creation metadata | Default-protocol-3 MCP example runs through independent verification, finalization and workspace export |
| Persisted protocol 1/2 retain original requirements | Runtime gates every research overlay and input normalizer by persisted protocol | `test_protocol3_workflow.py` reopens the database and resumes both legacy versions without adding typed writes |
| Typed assessment and exploration | Assessment, toy-example, retrieval assessment, candidate lemma, notation and counterexample records | Runtime validators reject unknown fields, invalid IDs, unregistered references, unsupported outcomes and oversized UTF-8 text |
| Server provenance | `record_type`, `record_id`, `actor_role`, `actor_domain_id`, `round_index`, `created_at` | Caller-supplied provenance is rejected; action-record identity is deterministic from run/epoch/state/action/slot |
| Structured decomposition | Typed local subgoal keys, statements, dependencies, kind and criticality | Canonical `plan-rN-I`, `sg-I`, `node:plan:subgoal` IDs; unknown/self/cyclic/duplicate local dependencies rejected before persistence |
| Direct screening | Canonical IDs, typed method/obstruction/evidence and retained partial coverage | Server derives plan status, missing IDs and the complete active-plan branch set; protocol 3 does not require a duplicate `proof_steps` write |
| Branch completion | Assigned canonical node IDs and typed obstruction records | Cross-plan node references, overlapping proved/unproved nodes and inconsistent solved/failure declarations rejected |
| Failure synthesis / replanning | Canonical affected/excluded/preserved IDs, obstruction class, constraints and focus | Replan requires a causal change: superseded plan, new constraint or selected focus |
| Research graph | Typed nodes, attempts, decisions, disjunctive plan routes, stable digest and deterministic advisory selection | Unknown references, duplicate IDs, cycles and resource-limit overflow fail closed; a solved alternative never requires every alternative to succeed |
| Model-active tasks | Exact write contract, commit action, payload schema and submission examples | All emitted protocol-3 examples are schema-checked; old protocol-1/2 catalogs remain unchanged |
| Private task context | Broad research view only for generator / repair | Branch, join, assembler, verifier and finalizer receive no broad research projection; sibling results stay behind the join barrier |

The graph admits at most 256 nodes, 1,024 edges, 2,048 attempts, 256 decisions,
64 active plans, 64 dependencies per node and 32 evidence locators per attempt.
The base task view is at most **16,384 UTF-8 JSON bytes**, with at most five
frontier nodes, five recent attempts, five preserved partial results, three
warnings and three evidence locators per displayed attempt. It omits actor-domain
identity and capability data. The base view plus project memory must fit within
**24,576 bytes**.

`route_solved` is a generator/branch route report, not VERIFIED evidence. A
counterexample `not_found_within_scope` records bounded negative evidence and is
not a proof. The existing independent verifier, LaTeX gate and mechanical
finalizer remain the only route to `proof_verified.tex`.

### Deliberate compatibility and correctness decisions

- The pinned source keeps candidate-lemma and toy-example events as typed history;
  its history projector derives graph attempts from screening, sealed branches,
  counterexamples, retrievals, failures and repair feedback. Re-CTM preserves
  this distinction rather than inventing verified candidate-node authority.
- Registered retrieval discovery and later typed assessment have separate
  novelty tracking. An initial assessment may use newly discovered material;
  repeating the same assessment cannot manufacture fresh progress.
- A legacy claimed counterexample without a meaningful witness, or one referring
  to an unknown node, cannot refute the target. Legacy prose does not silently
  become verified evidence.
- The source replan example contains only `reason`, while the source validator
  also requires a causal change. Re-CTM adds `selected_focus_node_id: target` to
  that example so following the emitted example is accepted by the real validator.
- Protocol-3 generation writes cannot forge server-reserved provenance even in
  otherwise freeform memory channels. Legacy protocol-1/2 records are not rewritten.

## Additive private database migration to schema 8

Migration changes `PRAGMA user_version` transactionally and records migration
history in the same private SQLite database. Supported older versions are
upgraded additively; a version newer than 8 fails closed. Schema migration is
independent of the workflow protocol stored on each run.

| Schema | Added source contract |
| --- | --- |
| 3 | `step_receipts`: capability/request/owner/workspace binding and one pending submission per run |
| 4 | `creation_receipts` and `step_checkpoints`: durable creation identity and prepared/running/commit-ready phases |
| 5 | `creation_initializations`: bound material and database fingerprints |
| 6 | `step_write_journals`: bounded caller-write recovery evidence |
| 7 | Explicit `atomic_action` enrollment on checkpoints |
| 8 | Immutable `facts`, `fact_edges`, append-only `fact_revocations`, `claim_revisions.fact_id`, typed `memory_findings` and append-only `memory_finding_status` |

Disposable-database tests cover every supported source version, preservation of
runs/receipts, repeatable initialization, a forced schema-8 rollback, future-version
rejection and transactional rollback of state/receipt/revocation changes. These
tests do not authorize opening or migrating the user's live database. Before a
real upgrade, an operator must retain a backup and run the target-machine checks.

### Durable step and creation semantics

The exact original capability, action, payload and ordered writes identify a step
request. An exact retry can return a historical receipt with zero new writes and
no fresh capability. Changed content under a consumed capability is
`IDEMPOTENCY_CONFLICT`. A historical state is not current task authority: fetch
`rethlas_step(run_id)` separately.

`recover_only=true` requires the original capability/action envelope and never
runs missing writes or the action. Only explicitly enrolled work with sufficient
private evidence may be reconciled. Unknown legacy actions, changed bytes,
opaque effects or an active execution fence cannot be guessed successful or
silently replayed. A retained-write prefix must be omitted from a corrected
submission. Fresh-capability correction responses remain explicitly retryable;
historical receipt replay is not new execution authority.

Creation deduplication requires the caller's original `creation_key`, bound to
owner, workspace and request. A key is not a general authorization token and does
not deduplicate unrelated control/retrieval calls.

Storage-level fault tests are in `test_storage_recovery.py`. Façade tests in
`test_mcp.py` independently check exact replay, changed-request rejection,
`dependentRequired`, and missing-receipt `recover_only` without side effects.
The process-level recovery integration matrix and its final acceptance remain
subject to the release validation record; do not infer comprehensive crash
recovery merely from a green graph or schema test.

## Verified fact memory

The fact implementation ports `mtm-workflow/src/memory.rs`, its `memory/` subtree
and `mtm-storage/src/fact_memory.rs` behavior into
`fact_memory.py`, `fact_graph.py` and `fact_store.py`, with integration through
the existing project finalizer transaction.

| Contract | Evidence / boundary |
| --- | --- |
| Content-addressed fact identity | Golden vectors bind normalized statement, proof, glossary, sorted predecessors and project identity |
| Proof provenance | Explicit facts must be present in the submitted proof; target matching and local dependency order are checked |
| Immutable graph | Missing, foreign-project, revoked, self or conflicting predecessors fail closed; replay preserves immutable content |
| Atomic promotion | Facts, edges, claim revision and finding status share the registry transaction downstream of mathematical DONE |
| Historical data | Adding schema 8 does not synthesize fact evidence for old `fact_id = NULL` revisions |
| Advisory project memory | Deterministic ranking, bounded predecessor closure, current-run exclusion and revoked-fact exclusion |
| Finding lifecycle | Typed finding IDs and append-only active/verified/superseded statuses; projected findings cannot independently mint verified facts |
| Ownership | Fact memory remains private to the project's OAuth owner; Native permission mode grants no registry authority |

Fact unit and disposable-store tests (`test_fact_memory.py`, `test_fact_store.py`)
cover identity vectors, target/proof provenance, graph limits, dependency closure,
ranking determinism, revocation, owner boundaries, idempotence and rollback.
Project-finalizer and project-memory task integration are tested separately;
consult the final local validation and manual-validation records rather than
assuming pure-helper tests establish target-machine correctness.

## Reproduction of the protocol / storage evidence

Run from the repository root, without installing or touching a live database:

```bash
PYTHONPATH=src:tests python3 -m unittest \
  test_research_state test_protocol3_workflow test_methodology \
  test_mcp test_workflow test_operator_outcomes \
  test_rethlas_contracts test_authorization_matrix -q
PYTHONPATH=src:tests python3 -m unittest \
  test_storage_recovery test_submission_recovery_integration \
  test_fact_memory test_fact_store -q
python3 scripts/validate_documentation_consistency.py
python3 scripts/run_local_checks.py
```

Local deterministic tests cannot establish real OAuth/browser interoperability,
real external source quality, actual sandbox isolation on the target machine,
LaTeX toolchain availability, cognitive independence, or the 95% mathematical
functional-equivalence target. These remain explicit manual acceptance work.


## Operator fact-graph commands

The following are source-supported operator commands. They were tested only on
disposable databases during this update; no live graph was exported or revoked.

```bash
re-ctm fact-graph export --project PROJECT_ID --out facts.json --state-db /operator/data/private/state.sqlite3
re-ctm fact-graph revoke FACT_ID --reason "operator-supplied reason" --state-db /operator/data/private/state.sqlite3
```

Export opens an existing schema-8 state database read-only, does not migrate an
older database, and does not overwrite any existing output file. Revocation is a
state-changing operator action: it appends a reasoned revocation for the fact and
its dependent descendants. Review the project and backup before invoking it.
It does not delete historical facts or grant Native tools project authority.

## Integrated recovery evidence

The public path is exercised by `test_submission_recovery_integration.py` and the
independent `test_workflow_review_v11.py`. Tested failure points include:

- keyed creation restart with exact no-clobber private files and atomic records;
- concurrent reservation, stale exact replay, changed-input and workspace denial;
- file replacement after enrollment but before accepted-write checkpoint;
- prepared, between-write, atomic-action and restartable-action reconciliation;
- refusal of equal-before/after ambiguity, opaque writes and missing legacy evidence;
- pending submissions blocking task issuance before mechanical side effects;
- successful transition followed by next-task generation failure;
- interrupted multi-file action reuse without duplicate appends;
- server-augmented verification report retry without duplicate reference gaps;
- changed action payload or missing original receipt refusing retained-effect adoption;
- observer delivery only after permanent private run locks have been released.

These are controlled exception/restart and transaction fixtures. They do not
establish arbitrary power-loss durability on every filesystem, malicious host
administrator resistance, or a comprehensive security audit. Durable façade
receipts do not make internal Python helper calls an alternate public protocol.

## Upgrade and rollback boundary

Stop the old server and retain a consistent pre-upgrade backup of the private
SQLite database, vault and signing keys before an operator starts 0.4.0 against
real data. Schema migration is additive but rolling back binaries alone is not a
supported downgrade: do not decrement `user_version`, delete receipt rows or
synthesize missing recovery evidence. Use the preserved pre-upgrade copy when
rolling back, with all writers stopped. Reusing retained signing keys preserves
signature continuity; receipts still require owner, run, workspace and exact
request binding and never grant execution authority.

Public `safe`/`trusted` configurations now fail explicitly instead of being silently
promoted. Select `dangerous` deliberately for a target deployment, retain private
root separation and a working attested execution backend, and keep the independent
LaTeX/verifier/finalizer barriers. New runs default to protocol 3; setting
`RE_CTM_WORKFLOW_PROTOCOL_VERSION=2` affects only subsequently created runs.
Persisted protocol-1/2 runs retain their original contracts.


## Final local checkpoint (2026-10-14)

- Re-CTM source version: **0.4.0**, uncommitted and unreleased.
- `python3 scripts/run_local_checks.py`: **459 tests, 453 passed, 1 failure,
  5 errors, no skips**. The six non-passing cases are dedicated real Bubblewrap
  Native isolation/lifecycle and required LaTeX tests; this cloud host rejects
  the Bubblewrap NETLINK_ROUTE probe. The full gate correctly returns nonzero.
- Compileall, engineering graph, optimization graph, error-contract audit,
  documentation consistency and `git diff --check` pass.
- The baseline had 3 failures and 5 errors. Two OAuth/UI-only CLI unit fixtures
  now explicitly select a disabled execution backend instead of accidentally
  requiring host attestation; dedicated real-isolation tests remain enabled.
- Offline sdist/wheel builds, sdist round trip, all 49 extracted-wheel module
  imports and eight CLI help/version probes pass without installation. All 53
  package source/resource files and final source fingerprints were verified.
- Independent review added 21 targeted regressions; its final 101-test slice
  passed. This is a scoped review, not a comprehensive security audit.

Exact current reports: [full gate](validation/MTM-0.4-local-validation.json) and
[package validation](validation/MTM-0.4-package-validation.json). The compatible
OPT-017 snapshot remains separate. No production database, security setting or
running service was changed, and nothing was installed, committed or pushed.
Target-host/browser/real-LaTeX and mathematical methodology acceptance remain
release blockers; current graph items are marked blocked rather than falsely
completed while the full gate is nonzero.
