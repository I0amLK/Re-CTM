# Re-CTM target-PC deployment and validation

This document is an operational guide, not evidence that a target has passed validation. The authoritative acceptance state remains in `manual-validation.json`.

## 1. Required software

- Python 3.11 or newer.
- Linux with user namespaces enabled for the packaged reference isolation backend.
- `bubblewrap` for native command execution and required LaTeX compilation.
- `latexmk` plus the required TeX Live packages when `RE_CTM_LATEX_POLICY=required`.
- An HTTPS reverse proxy or tunnel for non-loopback browser access.

The target does not need Codex and does not download Rethlas separately.

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
RE_CTM_NATIVE_EXEC_BACKEND=disabled
```

`RE_CTM_OAUTH_PASSWORD` is optional for an interactive operator launch. If omitted, `re-ctm serve` generates a high-entropy authorization key and prints it once to the local terminal. Set it explicitly only when a stable operator password is preferred or automation must know it in advance.

`RE_CTM_SERVER_URL` is optional. For a stable public hostname or named tunnel, set it explicitly:

```bash
RE_CTM_SERVER_URL=https://re-ctm.example.com
```

For a Cloudflare Quick Tunnel, leave it unset and bind Re-CTM to loopback. The request's validated public Host and loopback-trusted forwarding headers become the effective OAuth issuer/resource. Dynamic issuer mode is rejected on non-loopback binds.

Do not commit the real environment file. Re-CTM materializes server signing secrets under the data root with mode `0600` when they are not explicitly supplied.

## 5. Validate native isolation before enabling it

The acknowledgement variable is intentionally separate from runtime attestation. First probe the backend:

```bash
re-ctm attest-native \
  --backend bubblewrap \
  --workspace /srv/re-ctm/workspace \
  --data-root /var/lib/re-ctm \
  --private-root /var/lib/re-ctm/private
```

Then run the adversarial target harness from the repository:

```bash
python3 scripts/manual_native_isolation_test.py \
  --backend bubblewrap \
  --workspace /srv/re-ctm/workspace \
  --data-root /var/lib/re-ctm \
  --private-root /var/lib/re-ctm/private \
  --output native-isolation-validation.json
```

Review the JSON. Only after all checks pass on that target:

```bash
RE_CTM_NATIVE_EXEC_BACKEND=bubblewrap
RE_CTM_NATIVE_ISOLATION_ATTESTED=1
```

`dangerous` still does not grant a workflow capability. It only changes native-tool policy inside a namespace that does not mount the private vault.

## 6. Start Re-CTM

```bash
set -a
. /etc/re-ctm/re-ctm.env
set +a
/opt/re-ctm/venv/bin/re-ctm serve
```

For a disposable Cloudflare Quick Tunnel, the convenient startup order is intentionally server first, tunnel second:

```bash
PORT=54567
fuser -k -9 ${PORT}/tcp 2>/dev/null || true

env -u RE_CTM_SERVER_URL -u RE_CTM_OAUTH_PASSWORD \
  /opt/re-ctm/venv/bin/re-ctm serve --host 127.0.0.1 --port ${PORT} &
MCP_PID=$!
sleep 2

cloudflared tunnel --url http://127.0.0.1:${PORT}
```

The Re-CTM terminal prints `Re-CTM OAuth authorization key: ...`. Enter that value on the first OAuth authorization page. It is a Re-CTM authorization credential, not a Cloudflare Tunnel Token.

Use the printed `https://<random>.trycloudflare.com/mcp` URL in the MCP client. No Re-CTM restart is required after Cloudflare assigns the random hostname.

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

When terminal `rethlas_next` reports `done`, the controlled private-to-native bridge automatically writes the mechanically finalized bytes to the run's `workspace_export_path`. The default is:

```text
rethlas-output/<run_id>/proof_verified.tex
```

The automatic operation is idempotent when the existing file has the same hash and refuses to overwrite different content. `rethlas_get_artifact(final_tex)` still returns the finalized LaTeX through MCP. `rethlas_export_final` with no path re-materializes the run's default `workspace_export_path`; with an explicit alternate workspace-relative `.tex` destination, overwriting an existing path requires its current SHA-256 baseline.

## 10. Claims boundary

Do not mark the full workflow validated until all manual checks have evidence. In particular, local unit tests do not prove:

- compatibility with the final webpage MCP host;
- hard isolation on a different target kernel/packaging;
- mathematical proof quality or 95-percent Rethlas equivalence;
- cognitive independence equivalent to truly fresh model contexts.
