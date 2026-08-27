# Re-CTM

Re-CTM is an engineering work in progress that combines two orthogonal planes in one OAuth MCP service:

1. a streamlined native CMT computer-tool plane with `safe`, `trusted`, and `dangerous` authority;
2. a Rethlas-derived mathematical workflow plane with signed run capabilities, role ACLs, branch barriers, a verifier firewall, and mechanical finalization gates.

The two planes do not inherit authority from one another. In particular, native `dangerous` mode never grants access to private Rethlas state or permission to publish `proof_verified.tex`.

The MCP catalog is fixed at 19 tools: six native tools and thirteen `rethlas_*` workflow tools. `rethlas_retrieve` exposes bounded HTTPS theorem search to generator, branch, verifier, and repair domains. Its results are persisted as external, unverified evidence and may not be used as black boxes without reading source context and checking definitions and applicability. `rethlas_export_final` is the only direct private-to-native artifact bridge: it can copy a mechanically finalized `proof_verified.tex` into a workspace-relative `.tex` path, and existing destinations require a SHA-256 baseline.

## Current validation boundary

The repository is designed so deterministic components can be tested locally: JSON-LD graph consistency, persistence, capabilities, role/state authorization, branch isolation, verifier isolation, isolated LaTeX compilation, JSON-RPC dispatch, native namespace isolation, and debug-event redaction.

The complete browser/OAuth/MCP/reasoning workflow cannot be claimed as locally validated here. After the project is pushed, a human operator must test the real webpage client, OAuth redirects, target-PC isolation, external retrieval, multi-turn reasoning quality, and the final LaTeX toolchain. See `engineering-graph.json` and `manual-validation.json` as they are implemented.

## Development checks

```bash
python3 scripts/validate_engineering_graph.py
python3 scripts/run_local_checks.py
```

The second command writes `local-validation.json`. It currently covers deterministic graph metrics, Python compilation, unit tests, loopback OAuth/PKCE/MCP mechanics, modern and handshake-era protocol dispatch, capability ownership, branch barriers, verifier isolation, mechanical verdict/finalization, native workspace boundaries, fail-closed command execution, the Linux bubblewrap reference helper when available, debug redaction, and isolated/static LaTeX validation.

`engineering-graph.json` is valid JSON-LD. Its directed guarded edges are authoritative for security; the undirected projection is used only for articulation-point, bridge, two-core, and cycle-rank analysis. The `implementation_snapshot` classifies every graph vertex as locally implemented, reference-implemented but target-validation-pending, partial/external, or manual-only.

## Local server configuration

Copy the variables from `config.example.env` into your service manager or shell environment. The OAuth-only server requires at least:

```bash
export RE_CTM_SERVER_URL=http://127.0.0.1:8765
export RE_CTM_OAUTH_PASSWORD='replace-me'
export RE_CTM_WORKSPACE=/path/to/a/dedicated/workspace
export RE_CTM_DATA_ROOT=/path/outside/the/workspace/re-ctm-data
PYTHONPATH=src python3 -m re_ctm serve --host 127.0.0.1 --port 8765
```

`RE_CTM_NATIVE_EXEC_BACKEND=disabled` is the safe default. Native file/search/patch tools still work, while `exec_command` returns `NATIVE_ISOLATION_REQUIRED`.

On Linux, Re-CTM contains a bubblewrap reference backend. Probe it without enabling execution:

```bash
PYTHONPATH=src python3 -m re_ctm attest-native \
  --backend bubblewrap \
  --workspace /path/to/native-workspace \
  --data-root /path/outside/workspace/re-ctm-data \
  --private-root /path/outside/workspace/re-ctm-data/private
```

Then run the target-specific adversarial harness:

```bash
python3 scripts/manual_native_isolation_test.py \
  --backend bubblewrap \
  --workspace /path/to/native-workspace \
  --data-root /path/outside/workspace/re-ctm-data \
  --private-root /path/outside/workspace/re-ctm-data/private \
  --output native-isolation-validation.json
```

Only after reviewing a passing report should an operator set:

```bash
RE_CTM_NATIVE_EXEC_BACKEND=bubblewrap
RE_CTM_NATIVE_ISOLATION_ATTESTED=1
```

The acknowledgement does not grant workflow authority. `dangerous` still affects only native computer tools, while the private workflow vault is absent from the native mount namespace.

Target-PC setup, the redacted OAuth/MCP smoke script, isolation attestation, debug evidence, and claim boundaries are documented in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## LaTeX compiler boundary

With `RE_CTM_LATEX_POLICY=required`, Re-CTM requires both `latexmk` and bubblewrap. A proof is copied into a fresh scratch workspace and compiled in a network-isolated namespace with `-no-shell-escape`. The original run directory and private vault are not mounted. If bubblewrap is unavailable, Re-CTM refuses to compile model-generated TeX on the host rather than weakening the gate.

## Debug bundle

After a run is created, an operator can build a content-minimized diagnostic bundle:

```bash
python3 scripts/collect_debug_bundle.py <run-id> \
  --data-root /path/to/re-ctm-data \
  --output debug-bundle.json
```

The bundle contains state, domains, branches, transition history, redacted events, and file hashes. It deliberately excludes problem text, proof text, private file contents, OAuth secrets, and capability handles.

## Manual validation after push

`manual-validation.json` is the authoritative checklist for the real webpage client and target PC. A green `local-validation.json` does **not** mark those checks complete. The repository must be pushed and manually exercised before claiming browser compatibility, hard dangerous-mode isolation, real retrieval quality, real LaTeX compilation, or 95-percent Rethlas functional equivalence.
