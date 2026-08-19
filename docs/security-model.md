# Security Model

## Protected Assets

The system protects source integrity, pull-request decisions, analyzer policy,
workflow implementation, native reports, normalized evidence, release assets,
and repository settings. A green job without complete validated evidence is not
accepted as a successful gate.

External native reports are copied into the evidence artifact before parsing.
Producer compatibility handling never replaces this raw copy or changes the
digest bound into the evidence record.

OpenSSF Scorecard is evaluated through the dedicated `scorecard-sarif/v1`
policy. The complete native SARIF remains in evidence, while three repository
governance indicators do not count as blocking code or configuration findings:

- `CodeReviewID` measures approvals on historical changesets; current review
  enforcement is controlled independently by the managed repository ruleset.
- `MaintainedID` cannot pass for a repository younger than 90 days, and the
  [Scorecard check documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained)
  defines no project remediation for a low score.
- `CIIBestPracticesID` measures an external, self-attested badge rather than a
  source, dependency, workflow, or repository-setting defect.

All other Scorecard rules are blocking. An error-level result remains blocking
even when it uses one of these three rule identifiers. This classification is
part of the versioned parser policy, not an evidence exception.

## Trust Boundaries

Consumer source and pull-request content are untrusted. Parsers reject unknown
fields, duplicate identities, malformed reports, oversized inputs, and trailing
documents. Evidence binds the repository tree and subject SHA to a policy and
parser version. Producer conclusions and evidence are checked independently.
Paths selected by the caller are opened through traversal-resistant filesystem
roots. Evidence and release artifacts expected beneath a trusted directory
cannot escape it through `..`, absolute paths, or symbolic links; release
digests are calculated from the same verified regular file that is read.

Reusable workflows are public code, but callers execute only a reviewed commit
SHA. Actions, downloadable tools, Go modules, and containers are pinned and
verified through separate immutable controls. Harden Runner uses block-mode
egress with explicit endpoints on jobs that install or execute external tools.

## Permissions

The default workflow token is `contents: read` and cannot approve pull
requests. CodeQL alone receives `security-events: write` to publish the same
results evaluated by the local zero-finding gate. Release evidence receives
`id-token: write` and `attestations: write`; it does not receive release-write
permission. Workflows do not use repository secrets for pull requests.

## Failure Behavior

All applicable findings, analyzer execution failures, report parse errors,
missing reports, skipped required jobs, stale policy, unverified downloads, and
unexpected applicability fail closed. Network access is not a reason to pass a
scanner without evidence. Approved exceptions remain exact, reviewed, and
time-limited.

## Residual Platform Limits

GitHub plan-dependent features may be unavailable on personal public
repositories. Governance reports those limits rather than claiming them as
enabled. The portable scanners continue to enforce equivalent source-level
checks where possible. GitHub-hosted runners and GitHub's own action execution
service remain external trust dependencies.
