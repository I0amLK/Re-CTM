# Re-CTM target-PC deployment and validation

This document is an operational guide, not evidence that a target has passed validation. The authoritative acceptance state remains in `manual-validation.json`.

Current release: **Re-CTM v0.3.0**.

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
RE_CTM_NATIVE_MODE=safe
```

On Linux, if `bwrap` is installed and `RE_CTM_NATIVE_EXEC_BACKEND` is omitted, Re-CTM automatically selects the built-in Bubblewrap backend and performs mandatory startup attestation. Set `RE_CTM_NATIVE_EXEC_BACKEND=disabled` only when command execution should be intentionally unavailable.

Native scientific/computer tools are exposed by policy rather than by an application allowlist. Trusted/dangerous modes derive read-only toolchain roots from non-system PATH entries and executable symlink targets. For split or non-PATH installations, declare additional absolute directories with the platform path separator (`:` on Linux):

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

New MCP runs use workflow protocol 2. Existing persisted runs without a protocol marker continue as protocol 1, so an in-progress pre-v0.2 run does not suddenly acquire new proof-manifest requirements after upgrade.

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

Long-running command results include additive `termination` provenance without changing CTM lifecycle semantics. Review `source`, `requested_timeout_ms`, `elapsed_ms`, `observed_signal`, `term_sent_by_re_ctm`, and `kill_sent_by_re_ctm` before diagnosing a killed CAS computation. A signal observed without a matching Re-CTM action is reported as `external_or_unknown`, not guessed to be an OOM event.

## 6. Start Re-CTM

For an operator who wants only OAuth and tool-call visibility, start the same server through the minimal terminal observer:

```bash
set -a
. /etc/re-ctm/re-ctm.env
set +a
/opt/re-ctm/venv/bin/re-ctm tui
```

The terminal observer is presentation-only. It consumes already-redacted runtime events through a bounded non-blocking in-memory queue, performs no database/JSONL polling and no extra network calls, and never receives the raw generated authorization key through the structured event path. Slow/broken terminal output is isolated from MCP tool execution. Model token usage is intentionally not estimated because the MCP server is not guaranteed to receive authoritative upstream model-usage metadata.

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

Execute every pending item in `manual-validation.json`. Keep evidence content-minimized:

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

The automatic operation is idempotent when the existing file has the same hash and refuses to overwrite different content. `rethlas_artifact` is the public artifact façade: `action=get` returns finalized LaTeX through MCP and `action=export` re-materializes the run's default `workspace_export_path` or writes an explicit alternate workspace-relative `.tex` destination. Overwriting an existing alternate path requires its current SHA-256 baseline. The older `rethlas_get_artifact` and `rethlas_export_final` names remain hidden compatibility aliases.

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
