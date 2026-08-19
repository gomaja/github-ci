# Troubleshooting

## Harden Runner Blocks Checkout

The generated workflows use a folded `allowed-endpoints: >-` scalar so Harden
Runner receives a space-delimited allowlist. Do not change it to a literal
newline-delimited scalar. If checkout cannot reach `github.com`, regenerate the
workflow and verify the live Harden Runner log retained every configured
endpoint rather than only the first entry.

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

## CodeQL Empty Diagnostic Messages

CodeQL 4.37.7 can emit an empty diagnostic `message.text`, although
[OASIS SARIF 2.1.0 plus Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
section 3.11.8 requires a non-empty string when that property is present. The
evidence recorder archives the original SARIF and the producer-aware parser
replaces only this empty CodeQL diagnostic text in memory. The generic SARIF
parser remains strict, and an error-level diagnostic still fails the run.
Inspect the archived native report when this compatibility path is involved.

## Governance Drift

Generate a new plan from live state. Never reuse an old plan ID after any
repository setting changes. Apply stops deliberately when the remaining live
operations differ from the approved plan.

## Fork Pull Requests

Forks have no secrets and receive reduced token permissions. Local findings and
evidence remain blocking. If an optional GitHub report upload is unavailable,
confirm that the analyzer itself and aggregate gate completed; do not grant
secrets to untrusted pull-request code.

## Generated Source Is Repository-Specific

The central workflow classifies configured generated paths but does not guess a
generator. Copy `templates/preparation/generated-source.yml.tmpl`, replace the
example command with the repository's deterministic entrypoint, and keep both
`git diff --exit-code` and the untracked-file check. Require the observed
`generated / verify` context only after a real run proves its name.

## PostgreSQL Or Redis Integration

The deep reusable workflow intentionally starts no services. Copy the matching
template from `templates/preparation`, retain the digest-pinned image, and
replace the example command with the repository's migrations, fixtures, tags,
and integration suite. Keep that workflow independently required; do not add a
consumer command input to the reusable workflow.

## Private Go Modules

Use the private-module preparation template only for trusted events or
same-repository pull requests. Set a least-privilege `PRIVATE_MODULE_TOKEN`,
replace the `GOPRIVATE` scope and repository command, and verify the job's fork
condition remains intact. A fork cannot receive the token. Do not use
`pull_request_target` to run untrusted code with credentials; use a reviewed
vendored or otherwise credential-free path if fork builds must resolve the
private dependency.
