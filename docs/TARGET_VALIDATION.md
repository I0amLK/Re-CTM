# Target validation for Re-CTM 0.4.1

## Current status

The 0.4.1 runtime addresses OPT-024: actual 0.4.0 connected-client evidence
found asynchronous Native commands killed after their issuing HTTP request
returned. That failing evidence remains historical. The accepted 0.4.1 wheel
has passed the ordinary-host 528-source/178-installed baseline and the corrected
22-regression/13-group real HTTP/Bubblewrap supplement. Six current actual
connector lifecycle checks also passed. All 55 runtime package members remain
byte-identical to that accepted wheel; installer, tests and documentation changes
do not reuse the old whole-source fingerprint.

The sanitized [release evidence index](validation/release-0.4.1-evidence.json)
records hashes, exact scopes and limitations. The baseline was reused, not rerun.
Final source/package hashes and the new short-command launcher activation must
be recorded separately. The [launcher activation procedure](DEPLOYMENT.md#accepted-local-launcher)
includes its own disposable loopback start/shutdown rehearsal before changing the
PATH entry, and never restarts the existing service.


The MTM host has the required Python, Bubblewrap and LaTeX programs. MTM's
connector deliberately disables nested user namespaces. A nested Bubblewrap
probe fails with ENOSPC; this does not prove that the ordinary host terminal
cannot run Bubblewrap. No isolation setting has been changed or bypassed.

The bounded runtime machine scope is accepted; complete product acceptance is
**not claimed**. Scripted protocol and package
evidence is separate from real Native/LaTeX isolation, browser interaction,
external source quality and mathematical/operator acceptance. The active
checklist is [manual-validation.json](../manual-validation.json).
Historical reports in this repository do not certify this candidate.

## Ordinary host terminal command

Review the scripts first. Run this in the host's ordinary terminal, not through
MTM's exec tool or another nested sandbox:

```sh
cd '/home/lk/桌面/MTM/Re-CTM' &&
/home/lk/miniconda3/bin/python3 scripts/release_target_checks.py
```

The interpreter above was verified on this target. The portable alternative is
`python3 scripts/release_target_checks.py`, provided that interpreter already
has venv, pip, setuptools and wheel. The driver does not download dependencies.
If one is missing, stop and review the exact dependency needed before installing
anything. Do not add sudo or weaken namespace/network/security settings to make
a test pass.

The script:

- Creates a fresh evidence directory and a disposable source snapshot.
- Runs the full source suite, without skipping real isolation or LaTeX tests.
- Builds an sdist and wheel offline, installs the wheel into a fresh venv, and
  verifies actual installed commands, resources, contracts and recovery fixtures.
- Runs the real Bubblewrap adversarial isolation checks in disposable roots.
- Starts only its own temporary loopback HTTP server on a random free port.
  OAuth credentials exist only in the disposable fixture. Authenticated MCP
  exercises the current contract and a synthetic protocol-3 proof workflow.
- Requires actual isolated LaTeX compilation in strict mode before finalization.
- Stops only owned child processes and removes its own temporary state.
- Leaves the existing MTM service, production databases, credentials, host
  security configuration and Git remotes unchanged.

`--control-plane-only` is an explicitly incomplete diagnostic for constrained
environments. It uses disabled Native execution and static-only LaTeX in its
test fixture, marks the omitted physical gates pending, and cannot certify a
release. It does not change application defaults or any running service.

## Evidence and exit status

The terminal prints a new path of this form:

```text
/home/lk/桌面/MTM/Re-CTM/.release-validation/host-YYYYMMDDTHHMMSSZ-XXXXXXXX/report.json
```

That directory contains the candidate hash manifest, command logs and separate
package, OAuth/MCP, workflow and isolation reports. Check the named gates and
their exit codes. A successful build alone is insufficient.

- Exit 1: at least one machine check failed or was blocked. Preserve the evidence.
- Exit 2: manual acceptance or explicitly omitted checks remain pending.
- Exit 0: all requested recorded gates passed. The current driver intentionally
  leaves actual browser, live source quality and operator acceptance pending,
  so a machine-only run normally cannot return release approval.

Return the generated `report.json` here first. It lists the evidence paths needed
for a failed gate. Do not upload the venv, temporary databases, credential files,
browser profiles or an indiscriminate debug bundle. The reports are designed to
exclude credentials and private proofs; review any extra log before sharing it.

The venv uses its actual installation path. Do not move a venv created under the
connector's `/workspace` mount to the host path; rebuild/install on the host with
this driver instead.

## Remaining human/client acceptance

After the strict machine gates pass, complete the applicable current checklist:

- Actual intended browser/MCP-client OAuth callback, task routing, fresh-context
  verifier behavior and disconnect/resume.
- Real fixed-provider retrieval and substantive source-context review.
- Interactive terminal behavior and any separately approved public ingress.
- Mathematical corpus/repair/counterexample/reference quality and operator signoff.

The offline reflexivity proof checks server behavior, not mathematical quality or
95-percent methodology equivalence. Public ingress, production migration and
publication are separate actions. Before an authorized live migration, retain a
consistent database/vault/signing-key backup with writers stopped; never
downgrade by editing SQLite user_version.

GitHub publication remains the user's responsibility.
