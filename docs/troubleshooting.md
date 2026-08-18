# Troubleshooting

## Start With The Aggregate Gate

Open the failed `github-ci` run and inspect the `evidence` and `gate` jobs. The
evidence artifact contains the applicability plan, producer manifest, normalized
records, and native reports. A producer job can be green while the aggregate
gate rejects missing or mismatched evidence; use the gate finding rather than
rerunning blindly.

## `N/A` Is Rejected

The preflight detector owns applicability. Confirm that the file is tracked and
that `.github/github-ci.yaml` uses the intended profile and module paths. An
applicable scanner cannot be disabled by omitting a job or report.

## Generated Drift

Run:

```bash
make generate
make verify-generated
git diff --exit-code
```

Commit the template and all generated outputs together. Do not edit files with
the `Code generated` header directly.

## Tool Download Or Egress Failure

Compare the failed host with the explicit Harden Runner endpoint list. Verify
the upstream source and checksum before changing policy. Do not switch egress to
audit mode or replace an immutable pin with a mutable URL.

## Governance Drift

Generate a new plan from live state. Never reuse an old plan ID after any
repository setting changes. Apply stops deliberately when the remaining live
operations differ from the approved plan.

## Fork Pull Requests

Forks have no secrets and receive reduced token permissions. Local findings and
evidence remain blocking. If an optional GitHub report upload is unavailable,
confirm that the analyzer itself and aggregate gate completed; do not grant
secrets to untrusted pull-request code.
