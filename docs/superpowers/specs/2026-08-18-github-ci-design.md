# github-ci Design

- Status: Draft for specification review
- Date: 2026-08-18
- Target repository: `gomaja/github-ci`
- License: Apache-2.0

## 1. Purpose

`github-ci` centralizes strict CI, security scanning, supply-chain assurance,
release evidence, and repository governance for gomaja's public repositories.
The same interfaces are public for external GitHub users.

The governing rule is simple: an applicable check passes only when it ran to
completion, produced valid evidence, and reported zero open findings. Missing
evidence, scanner errors, malformed reports, timeouts, cancellations, and
unexpected skips are failures.

This design targets GitHub.com. GitHub Enterprise Server is outside the first
release because the workflow identity properties used to retrieve co-located
helpers are not currently available there.

## 2. Goals

- Provide reusable workflows for pull requests, main branches, schedules, and
  releases.
- Preserve every relevant assurance capability from the existing CI baseline.
- Add current GitHub-native and ecosystem security controls where they improve
  coverage.
- Make all applicable findings blocking, independent of severity.
- Give each consumer one stable aggregate required check.
- Keep consumers pinned to immutable workflow commits.
- Make repository settings auditable and reproducible under personal ownership
  today and organization ownership later.
- Support public external consumers without gomaja credentials.
- Produce deterministic, reviewable, machine-readable evidence.
- Keep release artifacts verifiable and traceable to source and tool versions.

## 3. Non-Goals

- Running deployment or product-specific release logic for consumers.
- Accepting arbitrary consumer shell commands in privileged central jobs.
- Providing secrets to untrusted fork pull requests.
- Hiding findings behind severity thresholds, baselines, or permissive exits.
- Replacing repository-owned protocol, integration, or wire-level tests.
- Supporting moving major-version workflow tags in the strict profile.
- Supporting GitHub Enterprise Server in `v1`.

## 4. Trust Model

Pull-request source, repository build scripts, tool configuration, generated
files, dependencies, archives, and uploaded artifacts are untrusted inputs.
Workflow definitions, central helper code, pinned tool distributions, and the
governance manifest are trusted only after review and immutable pinning.

The design follows these boundaries:

1. Untrusted pull-request code runs only under `pull_request` or `merge_group`.
2. Pull-request jobs use a read-only token and receive no repository secrets.
3. `pull_request_target` never checks out or executes contributor-controlled
   code.
4. Reusable workflows do not inherit secrets. A future capability that needs a
   secret must declare a named secret and restrict it to trusted events.
5. Third-party actions use full commit SHAs. Tool binaries use immutable
   versions plus checksums or signed provenance. Container images use digests.
6. Runner egress is denied except for reviewed endpoints needed by the job.
7. Reports from untrusted jobs are parsed as data and never executed.
8. The final gate verifies evidence rather than trusting a green upstream job.

## 5. Repository Architecture

The planned repository layout is:

```text
.github/
  workflows/
    go.yml
    deep.yml
    release.yml
    self-test.yml
  dependabot.yml
actions/
  preflight/
  run-tool/
cmd/
  github-ci/
  github-ci-govern/
internal/
  applicability/
  evidence/
  exceptions/
  githubapi/
  manifest/
  policy/
  reports/
policies/
  default/
schemas/
  evidence.schema.json
  governance.schema.json
templates/
  callers/
  workflows/
testdata/
  fixtures/
  reports/
governance/
  gomaja.yaml
docs/
```

Reusable workflows check out two repositories into separate directories:

- the caller repository at the event commit; and
- `job.workflow_repository` at `job.workflow_sha` for central helpers and
  policies.

This binds helper code to the exact workflow commit selected by the caller. No
central helper is taken from `main`, and no caller must copy central scripts.
Generated workflow files are committed artifacts. CI regenerates them from
their templates and fails on any diff.

### 5.1 GitLab-To-GitHub Equivalence

The implementation preserves assurance behavior while using GitHub-native
interfaces:

- GitLab Catalog components become public reusable workflows plus narrowly
  scoped composite actions.
- GitLab SAST and Code Quality reports become SARIF uploads, GitHub check
  annotations, normalized evidence, and retained native analyzer reports.
- Checkstyle, JUnit, Cobertura, native staticcheck JSON, native govulncheck JSON,
  and ShellCheck JSON remain parser fixtures and supported report inputs.
- GitLab security-policy ownership becomes a versioned policy bundle plus
  repository rulesets applied by the governance CLI.
- GitLab `allow_failure` has no equivalent in the strict profile; findings and
  infrastructure failures are blocking.
- GitLab generic release assets become GitHub release assets with checksums,
  SBOMs, attestations, and a deterministic release manifest.
- Renovate's tool-modernity function becomes a scheduled pin inventory and
  compatibility audit. Dependabot is the default update producer on GitHub,
  while Renovate configuration remains validated for consumers that use it.

This is a clean implementation from requirements and public interfaces. It does
not copy private source or private repository history.

## 6. Consumer Interface

Every consumer receives a required caller and a scheduled caller.

The required caller:

- has the workflow name `github-ci`;
- triggers on `pull_request`, `merge_group`, pushes to the default branch, and
  `workflow_dispatch`;
- has no workflow-level path or branch filter that could suppress the required
  pull-request or merge-group run;
- grants only named minimum permissions;
- calls `gomaja/github-ci/.github/workflows/go.yml@<full-commit-sha>`; and
- exposes one stable final job named `gate`.

The scheduled caller:

- invokes `deep.yml` on a governance-selected schedule;
- supports `workflow_dispatch` for remediation and verification;
- has concurrency that prevents overlapping deep scans; and
- does not cancel an in-progress release workflow.

The release caller invokes `release.yml` only for immutable semantic-version
tags or an explicit trusted dispatch. Repository-specific publishing remains in
the consumer repository and depends on the central release gate.

Inputs are typed and bounded. Supported inputs describe policy, not arbitrary
commands. Examples include module roots, build tags, predefined service
profiles, generated-code policy, minimum coverage, and private-module mode.

## 7. Execution Profiles

### 7.1 Pull Requests

Every applicable correctness and security check runs. The profile includes the
race detector and does not use a reduced security suite. Full-history secret
scanning, sustained fuzzing, mutation testing, and portability matrices remain
scheduled because their runtime is not bounded enough for every pull request.

### 7.2 Main And Tags

This profile repeats pull-request assurance against the landed commit and adds
full portability, SBOM generation, SARIF upload, long-lived report retention,
and release-readiness evidence.

### 7.3 Scheduled Deep Assurance

This profile adds sustained fuzzing, mutation testing, benchmark execution,
full-history secret scanning, dependency refresh checks, current/previous Go
compatibility, minimum-version checks where valid, generated-code regeneration,
repository posture drift, and complete supply-chain inventory.

### 7.4 Releases

This profile requires the strict main profile and additionally produces
checksums, release manifests, SBOMs, source and build attestations, and
provenance verification. It verifies that the release tag points to the
approved commit and that no release asset is mutable or missing.

## 8. Assurance Inventory

### 8.1 Go Correctness And Quality

The Go contract includes:

- `gofmt` and `goimports` with a clean-diff check;
- `git diff --check`;
- `go mod tidy -diff` for every detected module;
- `go mod verify`;
- `go build ./...`;
- `go test ./... -count=1`;
- `go test -race ./... -count=1`;
- `go vet ./...`;
- direct `staticcheck ./...`;
- `golangci-lint run ./...`;
- `gopls check` for changed and policy-selected Go files;
- JUnit output through `gotestsum`;
- Go coverage profiles and Cobertura conversion;
- real Go fuzzing with corpus and crasher retention;
- benchmark execution and optional reviewed regression policy;
- scheduled mutation testing, blocking surviving non-equivalent mutants;
- public API compatibility checks against the latest stable release;
- license policy and dependency-license inventory;
- current and previous supported Go versions;
- module-declared minimum Go version where the dependency graph permits it;
- Linux, macOS, and Windows portability where the package is applicable;
- multi-module repositories, build tags, module modes, generated code, and
  predefined PostgreSQL and Redis service profiles; and
- an explicit trusted-event profile for consumers with private Go modules.

Tool versions are immutable release inputs. The release manifest records the
exact Go toolchain, `golangci-lint`, `govulncheck`, `goimports`, `staticcheck`,
`gotestsum`, and `gocover-cobertura` versions. Version upgrades are reviewed as
normal pull requests and validated against clean and deliberately failing
fixtures before adoption.

### 8.2 Golangci-Lint Policy

The initial policy carries all 74 baseline linters. During implementation, each
name is validated against the selected golangci-lint version; a renamed or
removed analyzer is a migration finding, not a reason to silently reduce the
set.

#### Common (28)

`errcheck`, `gosec`, `govet`, `ineffassign`, `misspell`, `revive`,
`staticcheck`, `unused`, `bodyclose`, `errorlint`, `nilerr`, `nolintlint`,
`unconvert`, `wastedassign`, `asasalint`, `asciicheck`, `bidichk`,
`durationcheck`, `errchkjson`, `forcetypeassert`,
`gocheckcompilerdirectives`, `gochecksumtype`, `iotamixing`, `makezero`,
`nilnesserr`, `nosprintfhostport`, `reassign`, `recvcheck`.

#### Service (9)

`errname`, `noctx`, `exhaustive`, `nilnil`, `unparam`, `gocritic`,
`contextcheck`, `containedctx`, `fatcontext`.

#### Database (3)

`rowserrcheck`, `sqlclosecheck`, `unqueryvet`.

#### Tests (5)

`testableexamples`, `testifylint`, `thelper`, `tparallel`, `usetesting`.

#### Serialization (2)

`musttag`, `protogetter`.

#### Observability (5)

`loggercheck`, `sloglint`, `spancheck`, `zerologlint`, `promlinter`.

#### Modernization (6)

`modernize`, `exptostd`, `intrange`, `mirror`, `perfsprint`,
`usestdlibvars`.

#### Style (6)

`goconst`, `godoclint`, `godot`, `godox`, `goprintffuncname`, `predeclared`.

#### Repository Policy (6)

`depguard`, `gomodguard_v2`, `gomoddirectives`, `importas`, `forbidigo`,
`goheader`.

#### Maintainability (4)

`cyclop`, `dupl`, `gocognit`, `maintidx`.

No global analyzer exclusion is accepted merely to make adoption green.
Analyzer-specific false positives follow the exception contract in section 11.

### 8.3 Security And Supply Chain

The security contract includes:

- CodeQL for Go and GitHub Actions with security-extended and quality queries;
- `govulncheck`;
- GitHub dependency review and dependency graph validation;
- GitHub secret scanning, push protection, and supported validity checks;
- Gitleaks on pull-request content and full history on schedule;
- OSV-Scanner;
- Trivy filesystem, configuration, and dependency scanning;
- Syft SPDX and CycloneDX SBOM generation;
- Grype vulnerability scanning of the generated inventory;
- Semgrep with pinned, reviewed rules;
- OpenSSF Scorecard;
- scheduled tool-modernity and pin coverage, including Renovate configuration
  validation;
- GitHub artifact attestations and provenance verification;
- checksummed or signed tool acquisition;
- immutable action SHAs and container digests; and
- runner hardening with blocking egress policy.

Native GitHub code-scanning merge protection is enabled for all alert levels,
but it is defense in depth. Its documented merge-queue and Dependabot
limitations mean the central gate must independently parse and enforce scanner
results.

### 8.4 Workflow, Shell, Configuration, And Documentation

The contract includes:

- `actionlint` and `zizmor` for GitHub Actions;
- Bash syntax checks and ShellCheck JSON output;
- `shfmt`;
- Checkov for infrastructure and workflow configuration;
- Hadolint for Dockerfiles;
- `yamllint` and strict YAML parsing;
- `markdownlint`;
- strict JSON parsing and JSON Schema validation;
- manifest validation for tracked files, symlinks, traversal, duplicates,
  control characters, and unsafe values;
- generated-file freshness; and
- repository hygiene checks for forbidden artifacts and unexpected binaries.

### 8.5 Compatibility And Self-Verification

The project tests each analyzer with a clean fixture and at least one fixture
that must fail for the expected rule. It also verifies:

- tool installation and version output;
- parser behavior for valid, empty, malformed, truncated, and oversized reports;
- deprecated and removed tool/configuration inventory;
- deterministic generation of workflows, schemas, release manifests, and
  checksums;
- report conversion and provenance logic;
- multi-module, generated-code, build-tag, private-module, PostgreSQL, and Redis
  fixtures;
- fork pull-request permissions;
- merge-group triggering;
- scheduled execution; and
- the exact required-check context observed in a real consumer repository.

## 9. Applicability

Preflight discovers repository capabilities from tracked content and a strict
consumer manifest. It emits an immutable applicability plan consumed by all
jobs and the final gate.

An `N/A` result is valid only when:

- the detector version and input tree hash are recorded;
- a specific policy rule explains non-applicability;
- no contradictory tracked file exists; and
- the expected evidence record is present.

Examples include no `go.mod` for Go analyzers, no Dockerfile for Hadolint, and no
shell file for ShellCheck. A missing tool, missing configuration, failed setup,
or empty report is never `N/A`.

Consumer overrides may add scope but cannot silently disable a mandatory
applicable analyzer. Exclusions are exact path patterns validated against
tracked files and the exception policy.

## 10. Evidence Contract

Every analyzer writes one normalized JSON record. The initial schema contains:

```json
{
  "schema_version": "1",
  "tool": "example",
  "tool_version": "1.2.3",
  "policy_version": "sha256:...",
  "subject_sha": "...",
  "applicability": "applicable",
  "command_id": "example/default",
  "exit_code": 0,
  "finding_count": 0,
  "suppressed_count": 0,
  "report_sha256": "...",
  "outcome": "pass"
}
```

The schema rejects unknown outcome and applicability states. Evidence contains
no secrets and uses repository-relative paths. Large native reports remain
separate artifacts referenced by hash.

The gate runs with `if: always()` after all expected jobs. It validates:

1. the preflight plan and tree identity;
2. the complete expected evidence set;
3. every evidence record against the schema;
4. native report hashes and parser versions;
5. upstream job conclusions, including cancellation and skip handling;
6. exception validity; and
7. zero open findings.

The gate fails closed. GitHub job success is necessary but not sufficient.

## 11. Findings And Exceptions

All applicable findings block regardless of severity. A finding is open until
the code or configuration is fixed, the dependency or tool is upgraded, or the
finding is proven to be a false positive under this exception contract.

An exception must include:

- tool and rule identifier;
- stable finding fingerprint;
- exact path and smallest possible scope;
- technical false-positive or equivalent-mutant rationale;
- owner and approval reference;
- creation and expiry dates; and
- a verification test where one can prevent recurrence.

Exceptions live in a reviewed repository manifest. Expired, unused, duplicate,
overbroad, undocumented, or unmatched exceptions fail the gate. Inline
suppressions and tool ignore files are inventoried and must map one-to-one to a
valid exception. Severity-only waivers and permanent blanket baselines are not
supported.

## 12. Permissions And Fork Pull Requests

The caller grants `contents: read` by default. Individual trusted jobs may add
the narrow permission they require, such as `security-events: write` for SARIF
upload or `id-token: write` for attestations. Permissions can be reduced by a
caller but cannot be elevated by a called workflow.

Fork and Dependabot pull requests run with a read-only token and no secrets.
Their scanner reports still block through local exit status and normalized
evidence. Upload operations that need write permission are not part of the
pull-request pass condition; trusted main or scheduled runs upload the same
report types.

No workflow uses `secrets: inherit`. Any future named secret is unavailable to
untrusted events and its absence must not turn a required security check into a
false pass.

## 13. Repository Governance

`github-ci-govern` applies a versioned desired-state manifest. Its commands are:

- `audit`: read-only by default, with human and JSON output;
- `plan`: produce an ordered, reviewable change set;
- `apply --confirm`: apply an exact plan idempotently;
- `verify`: re-read live state and prove convergence; and
- `render-callers`: render consumer caller files at an approved workflow SHA.

The client uses structured GitHub APIs, strict response parsing, pagination,
bounded retries, and a centrally pinned GitHub API version. The implementation
starts with API version `2026-03-10`, which was accepted by the repository
ruleset endpoint during design validation. API drift is a hard audit finding.

The manifest defaults to public, owned, non-fork, non-archived repositories. It
refuses private, forked, archived, transferred, or unexpected-owner targets
unless an explicit policy permits them. Apply operations require administration
write permission; routine scheduled audits use administration read permission.

### 13.1 Default-Branch Ruleset

The gomaja policy requires:

- changes through pull requests;
- dismissal of stale reviews after new commits;
- resolution of all review conversations;
- no required human approval count for a single-maintainer personal account;
- Copilot review where the feature is available, without treating it as a
  replacement for scanner enforcement;
- strict required status checks against the latest base branch;
- the observed stable aggregate `github-ci / gate` check from GitHub Actions;
- linear history;
- protection from deletion and non-fast-forward updates;
- protection of default-branch creation semantics; and
- no bypass actors.

The exact aggregate check context is promoted into enforcement only after a
real canary run reports it. The governance tool will not guess a check name.

### 13.2 Merge And Branch Settings

Repositories allow squash merges only, automatically delete merged head
branches, and reject merge commits and rebase merges. Branches with merged pull
requests are audited and removed when they contain no unmerged commits and are
not protected or otherwise retained by policy.

Signed commits are an audit-only phase-two control until canary testing proves
that GitHub squash commits and all approved automation remain usable. It will
not be silently enabled across repositories.

### 13.3 Tag Ruleset

Semantic-version tags are immutable. The tag ruleset blocks deletion and
non-fast-forward updates for `v*` tags. Release creation remains a separately
authorized operation and is never performed by a routine governance apply.

### 13.4 Actions Settings

The policy requires:

- Actions enabled;
- default workflow permission `read`;
- workflows unable to create or approve pull requests;
- mandatory full-SHA action pinning;
- GitHub-owned actions plus an explicit repository allowlist only;
- every selected third-party action pinned and justified; and
- fork-contributor approval policy recorded and audited.

Direct tool downloads and containers receive equivalent version, checksum,
signature, digest, and source controls.

### 13.5 Security Features

Where GitHub exposes the feature for a public personal repository, policy
enables and audits:

- dependency graph;
- Dependabot alerts, security updates, and version updates;
- secret scanning and push protection;
- non-provider secret patterns and validity checks;
- private vulnerability reporting;
- CodeQL and third-party SARIF uploads;
- code-scanning merge protection for all alert levels; and
- security policy presence.

Unavailable plan-dependent settings are reported as unsupported, not silently
passed. The report distinguishes unsupported, disabled, misconfigured, and
drifted states.

## 14. Governance Manifest

The manifest is strict YAML with a published JSON Schema. Its conceptual form
is:

```yaml
schema-version: 1
owners:
  - name: gomaja
    type: user
defaults:
  profile: go-strict
  default-branch: main
  required-check: github-ci / gate
repositories:
  - name: sctp-portkill
    profile: go-strict
  - name: go-sctp
    profile: go-strict
```

Repository entries may add predefined service, build-tag, generated-code, and
platform applicability. They cannot weaken mandatory zero-finding behavior.
External users maintain their own manifest and authentication; public workflow
calls do not need access to gomaja settings or secrets.

## 15. Release Model

Releases use immutable `vX.Y.Z` tags. Consumers pin the release commit SHA and
retain the semantic version in a comment so automated dependency updates can
propose reviewed changes. Moving `v1` aliases are not published in the strict
distribution model.

Compatibility rules are:

- patch: fixes that preserve workflow inputs, evidence schema, job names, and
  failure policy;
- minor: backward-compatible inputs, tools, reports, or policy capabilities;
- major: breaking workflow, schema, required-check, permission, or policy
  behavior.

Each release includes:

- deterministic source archive checksums;
- a release manifest with workflow hashes, action SHAs, tool versions, Go
  versions, linter inventory, schemas, and policy hashes;
- SPDX and CycloneDX SBOMs;
- GitHub artifact attestations and provenance verification instructions;
- generated caller templates pinned to the release commit; and
- compatibility and migration notes.

Release publication is not automatic. It requires successful self-tests, a
cross-repository canary, verified tag protection, reviewed evidence, and a
separate explicit authorization.

## 16. Self-Test Strategy

The project validates itself with:

- unit tests for applicability, manifest, policy, exceptions, API decoding, and
  report parsers;
- table-driven boundary and malformed-input tests;
- fuzz tests for every parser and manifest boundary;
- golden tests for generated workflows, callers, schemas, and evidence;
- mutation tests for policy and parser decisions;
- fixture tests proving every scanner both passes clean input and rejects a
  known finding;
- integration tests against a temporary local Git repository;
- GitHub Actions tests for fork permissions, merge-group events, cancellations,
  expected skips, missing reports, and aggregate-gate behavior; and
- a real public canary pull request before release or broad rollout.

All Go changes run `gopls`, build, uncached tests, vet, direct staticcheck, and
golangci-lint. Race, fuzz, and mutation coverage scale with the affected
contract but are mandatory for shared parsing, policy, and gate behavior.

## 17. Migration Plan

Migration must not remove a currently required check before its replacement has
reported successfully.

For each repository:

1. Audit current workflows, rulesets, security features, open alerts, branch
   state, and merge settings.
2. Remediate existing findings under the new tools.
3. Add SHA-pinned callers while retaining existing CI.
4. Open a real pull request and verify all jobs, reports, fork-safe permissions,
   SARIF behavior, and the exact aggregate check context.
5. Add the observed aggregate check to the ruleset and verify strict behavior.
6. Remove duplicated legacy workflows and obsolete required-check names.
7. Apply merge, branch-deletion, Actions, security, and tag policies.
8. Re-audit live state and retain the convergence report.

`sctp-portkill` is the first canary. The remaining public, gomaja-owned,
non-fork, non-archived repositories follow in small batches. Private,
archived, and forked repositories are outside this rollout unless separately
approved.

## 18. Personal Ownership And Future Organization Migration

Personal ownership meets workflow reuse and external-consumer needs. Public
reusable workflows can be called across repositories at immutable SHAs.

The cost is duplicated repository-level governance because personal accounts
do not provide one organization policy surface. The manifest and governance CLI
remove most operational duplication by treating all repository settings as one
desired state.

If repositories later move to an organization, the workflow interface and
consumer SHAs remain valid only while the permanent `gomaja/github-ci` owner and
repository path remain unchanged. Organization-level rulesets, teams, security
roles, variables, and secrets can then replace eligible per-repository settings
without changing the evidence or gate contracts.

## 19. Failure Handling

- Scanner outage: fail and identify acquisition or execution failure.
- Unsupported repository shape: fail preflight with the exact unsupported
  capability.
- Report parse error: fail the analyzer and aggregate gate.
- Job cancellation or timeout: fail the aggregate gate.
- Expected analyzer skip: require detector-backed `N/A` evidence.
- GitHub API rate limit: bounded retry, then fail audit without partial apply.
- Partial governance apply: stop, report completed operations, and require a new
  live plan before retry.
- API or schema drift: fail closed and require a reviewed compatibility update.
- Tool removal or rename: fail compatibility fixtures; do not drop coverage.
- Release evidence mismatch: reject release publication.
- Ruleset deadlock risk: retain old required checks until the new real check is
  observed and green.

## 20. Acceptance Criteria

The first stable release is ready only when:

1. Apache-2.0 has been present since the root commit.
2. Every inventory item in section 8 is implemented or is explicitly marked
   unsupported with an approved pre-release decision.
3. Every scanner has clean and failing fixtures.
4. All parsers have unit, boundary, and fuzz coverage.
5. The aggregate gate fails for findings, missing evidence, malformed evidence,
   cancellations, timeouts, and unexpected skips.
6. A fork pull request passes without secrets or write permission and cannot
   access privileged jobs.
7. A merge-group run produces the required aggregate check.
8. Generated workflow and release artifacts are deterministic.
9. Governance audit and apply are idempotent and verified against a canary.
10. The canary repository has converged rules, Actions settings, security
    features, merge policy, and automatic branch deletion.
11. SBOM, checksums, attestations, and release manifest verify successfully.
12. Documentation lets an external public repository adopt the workflows with
    thin SHA-pinned callers and no gomaja credentials.

## 21. Authoritative GitHub References

- [Reuse workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
- [Workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [Contexts reference](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)
- [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [Troubleshooting required status checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
- [Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [Code scanning merge protection](https://docs.github.com/en/code-security/concepts/code-scanning/merge-protection)
- [Repository rules API](https://docs.github.com/en/rest/repos/rules)
- [GitHub Actions permissions API](https://docs.github.com/en/rest/actions/permissions)
- [Uploading SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

These references are rechecked during implementation and each significant
policy revisit because GitHub capabilities and API versions change.
