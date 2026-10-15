# Re-CTM target-PC deployment and validation

This document is an operational guide, not evidence that a target has passed validation. The authoritative acceptance state remains in `manual-validation.json`.

Current source version: **Re-CTM v0.4.1**, a Native asynchronous-command lifetime repair candidate. It retains the 0.4.0 tool/protocol/schema contracts; this does not certify fresh target-PC acceptance.

## 1. Required software

- Python 3.11 or newer.
- Linux with user namespaces enabled for the packaged reference isolation backend.
- `bubblewrap` for native command execution and required LaTeX compilation.
- `latexmk` plus the required TeX Live packages when `RE_CTM_LATEX_POLICY=required`.
- An HTTPS reverse proxy or tunnel for non-loopback browser access.

The target does not need Codex and does not download Rethlas separately.

Re-CTM v0.2.0 stores the Verified Research Workspace registry, project snapshots, proof manifests, reference provenance, and audits under the private state root. They are server-owned research metadata and must never be moved into the native workspace merely for convenience.

## 2. Directory boundary

Use non-overlapping roots:

```text
/srv/re-ctm/workspace/       native CMT workspace
/var/lib/re-ctm/             server state
/var/lib/re-ctm/private/     private workflow vault
```

The workspace must not be `/`, the account home directory, the data root, or an ancestor/descendant of the private root.

Recommended ownership:

```bash
sudo install -d -m 0750 -o re-ctm -g re-ctm /srv/re-ctm/workspace
sudo install -d -m 0700 -o re-ctm -g re-ctm /var/lib/re-ctm
sudo install -d -m 0700 -o re-ctm -g re-ctm /var/lib/re-ctm/private
```

## 3. Install one package

From a checked-out release:

```bash
python3 -m venv /opt/re-ctm/venv
/opt/re-ctm/venv/bin/python -m pip install dist/re_ctm-*.whl
```

No second Rethlas checkout is required.

## 4. Configure OAuth and runtime secrets

Start from `config.example.env`. At minimum configure:

```bash
RE_CTM_WORKSPACE=/srv/re-ctm/workspace
RE_CTM_DATA_ROOT=/var/lib/re-ctm
RE_CTM_PRIVATE_ROOT=/var/lib/re-ctm/private
RE_CTM_ALLOWED_ORIGINS=https://the-real-web-client.example
RE_CTM_LATEX_POLICY=required
RE_CTM_NATIVE_MODE=dangerous
```

On Linux, if `bwrap` is installed and `RE_CTM_NATIVE_EXEC_BACKEND` is omitted, Re-CTM automatically selects the built-in Bubblewrap backend and performs mandatory startup attestation. Set `RE_CTM_NATIVE_EXEC_BACKEND=disabled` only when command execution should be intentionally unavailable.

Native scientific/computer tools are exposed by policy rather than by an application allowlist. The dangerous profile derives read-only toolchain roots from non-system PATH entries and executable symlink targets. For split or non-PATH installations, declare additional absolute directories with the platform path separator (`:` on Linux):

```bash
RE_CTM_NATIVE_EXEC_ALLOW_ROOTS=/opt/vendor-suite:/srv/shared-runtime
```

Every declared root must exist and is canonicalized before startup. Re-CMT rejects `/`, the complete service-account home, broad aggregate roots such as `/home`, `/var`, and `/opt`, workspace/data/private overlaps, and unsupported backends; declare a specific product/runtime subtree instead. Accepted roots are ancestor-collapsed and mounted read-only. `re-ctm check-config` prints the effective exposure plan; `check_exec_environment` reports the live plan after startup.

The current external-helper protocol does not promise operator-declared roots; configuring `RE_CTM_NATIVE_EXEC_ALLOW_ROOTS` with `RE_CTM_NATIVE_EXEC_BACKEND=external` fails closed instead of silently ignoring the roots.

`RE_CTM_OAUTH_PASSWORD` is optional for an interactive operator launch. If omitted, `re-ctm serve` and `re-ctm tui` generate a high-entropy authorization key and reveal it once to the local operator terminal after the HTTP bind succeeds. When a password is explicitly configured, the TUI reports `configured externally` and does not echo the configured secret. Set a stable password only when operator policy or automation requires it.

`RE_CTM_SERVER_URL` is optional. For a stable public hostname or named tunnel, set it explicitly:

```bash
RE_CTM_SERVER_URL=https://re-ctm.example.com
```

For a Cloudflare Quick Tunnel, leave it unset and bind Re-CTM to loopback. The request's validated public Host and loopback-trusted forwarding headers become the effective OAuth issuer/resource. Dynamic issuer mode is rejected on non-loopback binds.

Do not commit the real environment file. Re-CTM materializes server signing secrets under the data root with mode `0600` when they are not explicitly supplied.

### State database upgrade

v0.2.0 introduces a versioned state-schema migration framework. Existing unversioned v0.1/dev6 databases are recognized as the baseline workflow schema and migrated additively to the v0.2 research-registry schema; runs, domains, branches, capabilities, transitions, and old protocol-1 workflow metadata are preserved. The state store records `PRAGMA user_version` plus migration history and fails closed if a database was created by a newer runtime version. Back up the private state directory before the first production upgrade even though the migration is additive.

New MCP runs default to workflow protocol 3. `RE_CTM_WORKFLOW_PROTOCOL_VERSION=2` explicitly selects protocol 2 for new runs; only 2 or 3 is accepted. Persisted protocol-1/2 runs retain their original write contracts and remain resumable. The current additive state migration and durable recovery details are documented in [MTM_MIGRATION.md](MTM_MIGRATION.md); do not open live state merely to test an upgrade.

### Native/client contract upgrade

The public surface is now 19 Native plus six workflow tools (`mtm-tools-v11`), 25 total. Refresh cached client schemas. Public `safe` and `trusted` profiles are retired and rejected; review the change before selecting `dangerous`. The former hidden workflow MCP aliases are also rejected; use the six façades. Existing persisted runs are handled separately from public alias compatibility.

`exec_command` requires exactly one of `argv` or `cmd`; `cmd` runs non-login `/bin/sh -c`. The total lifetime default is 300000 ms (maximum 600000), while polling yield remains 10000 ms by default. Requested PATH/workdir executable facts are revalidated immediately before start. Native write keys are caller-scoped in-memory receipts, not durable exactly-once execution. Unknown results and rollback failures require file reconciliation, even after restart. See [Native migration details](MTM_MIGRATION.md).

## 5. Validate native isolation

The built-in Bubblewrap backend attests itself every time the service starts and fails closed if the required isolation properties are not proven. For release/target evidence, also probe it explicitly:

```bash
re-ctm attest-native \
  --backend bubblewrap \
  --workspace /srv/re-ctm/workspace \
  --data-root /var/lib/re-ctm \
  --private-root /var/lib/re-ctm/private \
  --allow-root /opt/vendor-suite
```

Omit or repeat `--allow-root` to match the configured explicit roots.

Then run the adversarial target harness from the repository:

```bash
python3 scripts/manual_native_isolation_test.py \
  --backend bubblewrap \
  --workspace /srv/re-ctm/workspace \
  --data-root /var/lib/re-ctm \
  --private-root /var/lib/re-ctm/private \
  --allow-root /opt/vendor-suite \
  --output native-isolation-validation.json
```

Omit `--allow-root` when none are configured; repeat it for every declared root. The report includes a target-specific read-only write probe for those roots.

Review the JSON before treating that target as accepted for production. `RE_CTM_NATIVE_ISOLATION_ATTESTED=1` remains required only for an operator-supplied external helper. `dangerous` still does not grant a workflow capability: it changes native-tool policy inside the attested namespace. Host-PATH discovery and explicit toolchain roots use one canonical, read-only mount plan while the configured workspace/data/private trust domains remain excluded.

Long-running command results include `operation_outcome` and additive `termination` provenance. The default lifetime is now 300000 ms; the existing timeout/TERM/KILL termination sequence is preserved. Review `source`, `requested_timeout_ms`, `elapsed_ms`, `observed_signal`, `term_sent_by_re_ctm`, and `kill_sent_by_re_ctm` before diagnosing a killed CAS computation. A signal observed without a matching Re-CTM action is reported as `external_or_unknown`, not guessed to be an OOM event.

### Asynchronous HTTP command lifetime (0.4.1)

Actual connected-client testing of 0.4.0 found that a Native command could return
`running` and then receive SIGKILL when its HTTP request thread exited.
Linux parent-death signaling follows the creating thread. The repair creates
each managed child in a dedicated owner thread which stays alive until the child
is terminal; it retains Bubblewrap's `--die-with-parent`, namespaces,
process-group signaling and the existing timeout/kill authority.

Keep the previously running installation and evidence intact. Qualify a fresh
0.4.1 candidate with `scripts/manual_native_http_lifecycle_test.py` on the
ordinary host, including async completion, stdin/PTY, explicit kill, timeout
and service-exit cleanup after each initiating HTTP request has finished.
Do not remove `--die-with-parent` or disable isolation to make this pass.
Direct in-process tests and old 0.4.0 acceptance cannot establish this repair.

Install the accepted wheel into a separate venv. Stop/restart a live service only
at an operator-approved point; do not overwrite its active venv, change existing
signing keys, or open its private database merely to test an upgrade. Protocol 3,
schema 8, the 25-tool catalog and persisted workflow contracts are unchanged.
A Quick Tunnel restart may assign a new public URL and the interactive OAuth
authorization key is generated anew; reconnect the intended client explicitly.

## 6. Start Re-CTM

For an operator who wants only OAuth and tool-call visibility, start the same server through the minimal terminal observer:

```bash
set -a
. /etc/re-ctm/re-ctm.env
set +a
/opt/re-ctm/venv/bin/re-ctm tui
```

The terminal observer is presentation-only. It consumes already-redacted runtime events through a bounded non-blocking in-memory queue, performs no database/JSONL polling and no extra network calls, and never receives the raw generated authorization key through the structured event path. Slow/broken terminal output is isolated from MCP tool execution. Model token usage is intentionally not estimated because the MCP server is not guaranteed to receive authoritative upstream model-usage metadata.

For the untouched standard stderr, terminal-observer output bypasses Python's buffered writer. A closed PTY or pipe disables further observer output without changing the intended server shutdown status; Re-CTM does not close or replace process-wide stderr. Explicit/custom streams retain their write/flush behavior. Source regressions use disabled Native execution and static-only LaTeX to isolate this I/O contract; release qualification still requires the rebuilt installed candidate on the ordinary host.

The default TUI prints each tool when it starts and preserves failures and rejected
logical submissions, without a second routine-success line. Add `--verbose` to
show completion lines and trace identifiers. Argument values, result bodies and
capabilities are never rendered in either mode. A returned fresh workflow task
does not mean its rejected submission succeeded; inspect its retained-write
instructions before correcting it.

The MTM-compatible source update also publishes
`/.well-known/oauth-protected-resource/mcp` and advertises it in the MCP bearer
challenge. This document identifies the exact `/mcp` resource while preserving
the origin-level issuer and legacy origin-resource audience. Keep reverse-proxy
origin validation and the existing single-writer deployment boundary intact.
First-start secret publication is now non-overwriting; do not delete or rotate an
existing secret to diagnose an authorization issue. See [the backport notes](MTM_BACKPORT.md)
for scope and fresh target-host/browser checks still required.

For the common disposable remote-client path, `tui` can explicitly own one Cloudflare Quick Tunnel:

```bash
/opt/re-ctm/venv/bin/re-ctm tui --quick-tunnel --native-mode dangerous
```

When neither `--port` nor `RE_CTM_PORT` is supplied, this mode binds Re-CTM to an OS-selected loopback port and starts `cloudflared tunnel --config /dev/null --no-autoupdate --url <local-origin>` only after that bind succeeds. The child process does not inherit Re-CTM OAuth/token/capability secrets or Cloudflare named-tunnel credential variables. The TUI accepts only HTTPS `*.trycloudflare.com` origins from the bounded cloudflared output stream. On shutdown it terminates only the `Popen` process it created, escalating to kill only if that owned process ignores TERM.

`--quick-tunnel` intentionally selects dynamic OAuth-origin mode for that session even if `RE_CTM_SERVER_URL` is present in the parent environment; it does not rewrite the environment or persisted configuration. Do not use this testing/development shortcut as a substitute for a stable named tunnel or production ingress policy.

Headless/service-style operation remains:

```bash
set -a
. /etc/re-ctm/re-ctm.env
set +a
/opt/re-ctm/venv/bin/re-ctm serve
```

For a disposable Cloudflare Quick Tunnel, the preferred interactive path is now:

```bash
/opt/re-ctm/venv/bin/re-ctm tui --quick-tunnel --native-mode dangerous
```

The same terminal prints the generated Re-CTM authorization key and, once Cloudflare assigns it, `Public MCP URL https://<random>.trycloudflare.com/mcp`. Enter the authorization key on the first OAuth page and use the public MCP URL in the client. If `cloudflared` is missing or fails, the local MCP service remains available and the TUI reports the degradation rather than killing the server.

Operators who intentionally want separate process supervision may still run `re-ctm serve`/`re-ctm tui` and `cloudflared tunnel --url ...` independently. Re-CTM never runs `fuser`, `pkill`, `killall`, or kills an unrelated tunnel process.

Expose the service only through HTTPS. Confirm:

```text
https://re-ctm.example.com/.well-known/oauth-authorization-server
https://re-ctm.example.com/.well-known/oauth-protected-resource
https://re-ctm.example.com/.well-known/mcp.json
https://re-ctm.example.com/mcp
```

## 7. Redacted protocol smoke

The script below performs DCR, PKCE authorization, token exchange, legacy MCP, modern MCP mirror headers, fixed catalog, and non-inheritance checks without writing the password, code, or token:

```bash
python3 scripts/smoke_oauth_mcp.py \
  --base-url https://re-ctm.example.com \
  --callback http://127.0.0.1/callback \
  --output oauth-mcp-smoke.json
```

This is not a substitute for connecting the actual webpage MCP host.

## 8. Manual acceptance

Execute the active RC-001 through RC-011 checks in `manual-validation.json` against the actual candidate. The complete previous MV checklist and its evidence are retained under `historical_checklists` as superseded history, not current acceptance. Repository publication is a separate operator action and is not required before local target qualification. Local host deployment/testing does not itself authorize public ingress, live private-state access or security-policy changes.

The active gates separate:

- RC-001/002: deterministic/package evidence and the 25-tool MTM v11 contract;
- RC-003/004: scripted loopback OAuth/MCP versus actual browser/client authorization, routing and resume;
- RC-005/006: target hard isolation and real required LaTeX compilation/final delivery;
- RC-007/008/009: protocol-3 role barriers, disposable schema-8/recovery tests, project facts and source-backed reference audits;
- RC-010/011: optional terminal/approved ingress behavior and operator mathematical-quality review.

All current checks begin pending. Record candidate hashes, target environment, exact commands/client actions, outcomes and redacted evidence before marking any passed. A failed nested-namespace probe is an execution blocker; disabling the backend or replacing required compilation with `static_only` does not satisfy the corresponding gate. Preserve the real-isolation tests and do not alter host security policy merely to pass them. Use only disposable state for qualification unless a separate live-state action is explicitly authorized. Keep evidence content-minimized:

- tool names, state names, hashes, trace IDs, status codes, and redacted reports are appropriate;
- OAuth passwords, access tokens, authorization codes, client secrets, capabilities, private problem statements, proof bodies, and reference bodies are not.

For a terminal run, create a debug bundle:

```bash
python3 scripts/collect_debug_bundle.py <run-id> \
  --data-root /var/lib/re-ctm \
  --output debug-bundle.json
```

## 9. Final artifact delivery

The MCP initialization instructions route concrete mathematical proof, derivation, proof-repair, and rigorous verification requests into `rethlas_start` by default. A particular webpage host may still ignore those instructions, so MV-008 must confirm ordinary-language routing on the real client.

When terminal `rethlas_step` reports `done`, the controlled private-to-native bridge automatically writes the mechanically finalized bytes to the run's `workspace_export_path`. The default is:

```text
rethlas-output/<run_id>/proof_verified.tex
```

The automatic operation is idempotent when the existing file has the same hash and refuses to overwrite different content. `rethlas_artifact` is the public artifact façade: `action=get` returns finalized LaTeX through MCP and `action=export` re-materializes the run's default `workspace_export_path` or writes an explicit alternate workspace-relative `.tex` destination. Overwriting an existing alternate path requires its current SHA-256 baseline. The older `rethlas_get_artifact` and `rethlas_export_final` names are retired and rejected; persisted-run compatibility does not restore retired tool aliases.

Protocol-2 runs may additionally expose `proof_manifest` and `reference_audit`. Project owners may retrieve/export a portable `project_manifest` or `project_summary_tex`. These project artifacts are generated from private registry facts and contain claim/revision/status/hash/dependency/condition/reference-audit information only; they must not include owner/OAuth binding data, generation memory, branch internals, verifier scratch memory, steering, or capability handles. `project_summary_tex` is subjected to the same static external-file/shell-operation checks as proof LaTeX before it can be returned/exported.

Project-linked finalization is two-phase by design. The mathematical run reaches `done` only after the existing LaTeX and independent verifier gates pass. Registry promotion then creates an immutable `VERIFIED` or `CONDITIONAL` claim revision if the frozen base revision still matches. A concurrent registry conflict is recorded separately and never changes an already-correct run into a failed proof. A transient promotion error is also non-fatal: it remains pending and is retried on a later terminal `rethlas_step`. Repeated terminal retries must not create duplicate revisions for the same source run.

Compact workflow mode never weakens the correctness gate. Protocol 2 can route a local self-contained lemma from `assess` directly to `assemble`, but still requires LaTeX validation, independent verification, repair, and mechanical finalization. A compact assembler may escalate to full exploration, and a second wrong compact verifier result automatically escalates to the full workflow.

External reference use is also mechanically gated in protocol 2. The assembler lists material `reference_id` values in `proof_manifest`; the verifier gives each one a tracked disposition plus `evidence_basis`/`evidence_locator`. `SOURCE_VERIFIED` requires source/assumption/notation checks and must point either to a stored source-body snapshot or to the external DOI/arXiv/source location actually inspected. A theorem-search or bibliographic discovery snapshot is not original-source evidence and cannot by itself establish `SOURCE_VERIFIED`. Missing or unresolved material-reference coverage is added to the verification gaps by the server even if the verifier model does not report it itself.

Paper-aware retrieval uses a fixed HTTPS OpenAlex trust domain; theorem retrieval uses the configured validated HTTPS theorem endpoint. Both initial and post-redirect response locations remain host-validated, so an external redirect cannot turn the research integration into a cross-host fetcher. `paper_search` may be driven by query, author, title, or keywords without requiring a dummy free-text query.

## 10. Claims boundary

Do not mark the full workflow validated until all manual checks have evidence. In particular, local unit tests do not prove:

- compatibility with the final webpage MCP host;
- hard isolation on a different target kernel/packaging;
- mathematical proof quality or 95-percent Rethlas equivalence;
- cognitive independence equivalent to truly fresh model contexts.


## Accepted local launcher

The accepted local 0.4.1 installation can be activated without reinstalling it,
changing runtime code, reading/migrating data, or restarting a running service.
This is a deployment-specific wrapper, not a change to package defaults. Review
`scripts/activate_release_launcher.py`, then run once in the ordinary host terminal:

```sh
cd '/home/lk/桌面/MTM/Re-CTM' &&
/home/lk/miniconda3/bin/python3 -I -B scripts/activate_release_launcher.py --activate &&
hash -r && re-ctm --version
```

The helper verifies the pinned accepted wheel SHA-256 and all 55 installed runtime
files, rejects another PATH entry shadowing `~/.local/bin/re-ctm`, preserves the
old launcher (including a symlink), and atomically replaces only that launcher.
Its JSON output names the activation receipt and reversible backup. A failed
version or receipt check restores the backup. Before activation, the same launcher
template starts a temporary loopback-only TUI with fresh disposable data/workspace
roots, checks OAuth discovery, then stops only that owned process. It never starts
a public Quick Tunnel or touches the existing running service. Run
`--check-only` for a read-only candidate check; it does not certify host activation.

After activation, the usual command is:

```sh
re-ctm tui --quick-tunnel --native-mode dangerous
```

It preserves the previously accepted launch settings regardless of current
directory: workspace `<checkout>/.local-install/workspace`, data
`~/.re-ctm-0.4-local`, private data beneath that root, Bubblewrap, required LaTeX,
loopback `127.0.0.1`, and port `0`. The wrapper clears inherited settings and
credentials just as the accepted `env -i` command did; it preserves only HOME,
PATH and TERM, then supplies those explicit settings. Ordinary CLI arguments
still pass through unchanged. It does not read the old 0.3 data root or move any
state. Keep the checkout and its accepted venv at their original host location.

For rollback, use the exact receipt path printed at activation:

```sh
python3 scripts/activate_release_launcher.py --rollback /path/to/activation.json
hash -r
```

Rollback refuses to overwrite a launcher changed since activation. It restores
only the prior command entry, never a database, private vault or running service.
Do not run an old runtime against newer state after rollback. Shell aliases or
functions named `re-ctm` are outside PATH lookup; use `type -a re-ctm` if the shell
still selects an unexpected command.

This helper is pinned to the accepted local 0.4.1 wheel. Later accepted releases
require a new reviewed pin; it intentionally never downloads or chooses an
unverified latest version. Machine acceptance, operator acceptance and public
publication remain separate release gates. Do not publish `.local-install*` or
`.release-validation`; use the package builder's explicit source allowlist.
