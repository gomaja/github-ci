# github-ci Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, publish, and live-validate a public, fail-closed GitHub CI and
repository-governance system for gomaja and external public repositories.

**Architecture:** A small Go binary owns strict configuration, applicability,
report parsing, evidence, aggregate gating, deterministic generation, and
GitHub governance. Public reusable workflows check out their own helper source
at `job.workflow_sha`, run pinned tools against the caller repository, and feed
normalized records to one stable gate.

**Tech Stack:** Go 1.26.6 with Go 1.25.13 compatibility, standard library,
`gopkg.in/yaml.v3`, GitHub Actions, SARIF 2.1.0, JSON Schema, Apache-2.0.

**Spec:**
`docs/superpowers/specs/2026-08-18-github-ci-design.md`

## Global Constraints

- The module path is `github.com/gomaja/github-ci`.
- `go.mod` declares `go 1.25.0` and `toolchain go1.26.6`.
- `gopkg.in/yaml.v3 v3.0.1` is the only runtime dependency.
- All configuration rejects unknown fields, duplicate keys, and trailing YAML
  documents.
- Every applicable finding blocks regardless of severity.
- Missing, malformed, cancelled, timed-out, or unexpectedly skipped evidence
  fails the gate.
- An `N/A` result requires detector-produced evidence.
- Public pull requests use `pull_request`, read-only permissions, and no
  secrets.
- No workflow executes contributor code under `pull_request_target`.
- All actions use full commit SHAs, tools use immutable versions, and containers
  use digests.
- Consumer inputs select predefined policy only; they never contain executable
  command strings.
- All files are ASCII unless a test fixture explicitly verifies Unicode input.
- Commits use `gomaja <marwanjdid@gmail.com>` with no attribution trailers.
- Each Go task follows test-first red, green, refactor, and deliberate mutation
  verification.
- After every Go change require clean `gofmt -l` and `~/go/bin/goimports -l`
  output on changed Go directories, then run `go mod tidy -diff`,
  `go mod verify`, `gopls check` on changed Go files, `go build ./...`,
  `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`,
  `~/go/bin/staticcheck ./...`, and `~/go/bin/golangci-lint run ./...`.
- A release or semantic-version tag is outside this plan and requires separate
  authorization.

---

### Task 1: Bootstrap The Go Module And Strict Configuration

**Files:**

- Create: `go.mod`
- Create: `go.sum`
- Create: `internal/config/consumer.go`
- Create: `internal/config/consumer_test.go`
- Create: `internal/config/governance.go`
- Create: `internal/config/governance_test.go`
- Create: `schemas/consumer.schema.json`
- Create: `schemas/governance.schema.json`
- Create: `testdata/config/consumer-valid.yaml`
- Create: `testdata/config/governance-valid.yaml`

**Interfaces:**

- Produces `config.DecodeConsumer(io.Reader) (config.Consumer, error)`.
- Produces `config.DecodeGovernance(io.Reader) (config.Governance, error)`.
- Produces `config.Consumer.Validate() error` and
  `config.Governance.Validate() error`.
- Later tasks consume exact profile names `go-strict`, `go-library`, and
  `repository-only`.

- [ ] **Step 1: Write strict consumer configuration tests**

Cover valid input, empty input, unknown fields, duplicate keys, two documents,
invalid schema version, traversal paths, absolute paths, duplicate modules,
unknown profiles, unsupported services, and control characters.

```go
func TestDecodeConsumerRejectsUnknownField(t *testing.T) {
    _, err := DecodeConsumer(strings.NewReader(
        "schema-version: 1\nprofile: go-strict\nunknown: true\n",
    ))
    if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
        t.Fatalf("DecodeConsumer() error = %v", err)
    }
}
```

- [ ] **Step 2: Run the configuration tests and confirm the missing package**

Run: `go test ./internal/config -count=1`

Expected: FAIL because `DecodeConsumer` and the configuration types do not
exist.

- [ ] **Step 3: Implement strict decoding and validation**

Use `yaml.NewDecoder`, `KnownFields(true)`, one successful decode followed by an
`io.EOF` check, and explicit semantic validation. Decode through `yaml.Node`
first so duplicate mapping keys are rejected consistently before struct
decoding.

```go
type Consumer struct {
    SchemaVersion int       `yaml:"schema-version"`
    Profile       Profile   `yaml:"profile"`
    Modules       []Module  `yaml:"modules,omitempty"`
    BuildTags     []string  `yaml:"build-tags,omitempty"`
    Services      []Service `yaml:"services,omitempty"`
    Generated     []string  `yaml:"generated,omitempty"`
    Exceptions    string    `yaml:"exceptions,omitempty"`
}
```

- [ ] **Step 4: Add governance configuration and schema tests**

Governance validation covers owner type, public-only defaults, unique
repositories, API version, and refusal flags for forks, archived repositories,
private repositories, and unexpected owners. A repository with
`enforce-caller: true` must also have an immutable 40-character workflow SHA
and an observed required check; bootstrap entries may omit both only while
`enforce-caller: false`.

- [ ] **Step 5: Run focused and full Go validation**

Run the Global Constraints Go sequence. Deliberately remove `KnownFields(true)`
and confirm `TestDecodeConsumerRejectsUnknownField` fails, then restore it and
rerun the sequence.

- [ ] **Step 6: Commit the configuration contract**

```bash
git add go.mod go.sum internal/config schemas testdata/config
git commit -m "feat: add strict configuration contracts"
```

### Task 2: Add Evidence Types And Native Report Parsers

**Files:**

- Create: `internal/evidence/model.go`
- Create: `internal/evidence/model_test.go`
- Create: `internal/evidence/io.go`
- Create: `internal/evidence/io_test.go`
- Create: `internal/reports/reports.go`
- Create: `internal/reports/reports_test.go`
- Create: `internal/reports/sarif.go`
- Create: `internal/reports/json.go`
- Create: `schemas/evidence.schema.json`
- Create: `testdata/reports/clean/*`
- Create: `testdata/reports/findings/*`
- Create: `testdata/reports/malformed/*`

**Interfaces:**

- Consumes strict relative-path validation from Task 1.
- Produces `evidence.Record`, `evidence.Plan`, and `evidence.Expected`.
- Produces `evidence.Read`, `evidence.WriteAtomic`, and
  `evidence.ValidateRecord`.
- Produces `reports.Count(tool string, io.Reader) (reports.Result, error)`.

- [ ] **Step 1: Write evidence invariant tests**

Test valid pass, valid finding, valid `N/A`, invalid schema, unknown outcome,
negative finding count, pass with findings, missing report hash, mismatched
subject SHA, absolute path, duplicate record identity, and non-atomic write
failure.

```go
func TestValidateRecordRejectsPassWithFindings(t *testing.T) {
    r := validRecord()
    r.Outcome = OutcomePass
    r.FindingCount = 1
    if err := ValidateRecord(r); err == nil {
        t.Fatal("ValidateRecord() accepted a passing record with findings")
    }
}
```

- [ ] **Step 2: Run evidence tests and confirm expected failure**

Run: `go test ./internal/evidence -count=1`

Expected: FAIL because `Record` and `ValidateRecord` do not exist.

- [ ] **Step 3: Implement the evidence model**

Use explicit string enums and deterministic JSON. Identity is
`tool/command_id`. Atomic writes use a same-directory temporary file, `Sync`,
`Close`, and `Rename`.

```go
type Record struct {
    SchemaVersion  string        `json:"schema_version"`
    Tool           string        `json:"tool"`
    ToolVersion    string        `json:"tool_version"`
    PolicyVersion  string        `json:"policy_version"`
    SubjectSHA     string        `json:"subject_sha"`
    Applicability Applicability `json:"applicability"`
    CommandID      string        `json:"command_id"`
    ExitCode       int           `json:"exit_code"`
    FindingCount   int           `json:"finding_count"`
    Suppressed     int           `json:"suppressed_count"`
    ReportSHA256   string        `json:"report_sha256,omitempty"`
    Outcome        Outcome       `json:"outcome"`
}
```

- [ ] **Step 4: Write clean, finding, and malformed parser tests**

Add fixtures for SARIF, golangci-lint JSON, govulncheck JSON streams,
staticcheck JSON lines, ShellCheck JSON1, Gitleaks JSON, OSV JSON, Trivy JSON,
Grype JSON, Semgrep JSON, and Checkov JSON. Test empty, truncated, unknown-field,
oversized, duplicate-result, and multi-run SARIF cases.

- [ ] **Step 5: Implement bounded structured parsers**

Limit input to 64 MiB, use `json.Decoder.DisallowUnknownFields` where schemas
are stable, count all result levels, and return parser errors separately from
finding counts. SBOM and checksum artifacts use validators, not finding parsers.

- [ ] **Step 6: Fuzz and mutation-test parser boundaries**

Seed each parser from clean, finding, and malformed fixtures. Run every fuzz
target for at least 30 seconds. Remove the SARIF result-count increment and
confirm the finding fixture test fails before restoring it.

- [ ] **Step 7: Run full Go validation and commit**

```bash
git add internal/evidence internal/reports schemas testdata/reports
git commit -m "feat: add fail-closed evidence parsing"
```

### Task 3: Implement Applicability, Exceptions, And Aggregate Gating

**Files:**

- Modify: `internal/evidence/model.go`
- Modify: `internal/evidence/model_test.go`
- Create: `internal/applicability/catalog.go`
- Create: `internal/applicability/catalog_test.go`
- Create: `internal/applicability/detect.go`
- Create: `internal/applicability/detect_test.go`
- Create: `internal/exceptions/exceptions.go`
- Create: `internal/exceptions/exceptions_test.go`
- Create: `internal/gate/gate.go`
- Create: `internal/gate/gate_test.go`
- Create: `testdata/repositories/*`
- Create: `testdata/exceptions/*`

**Interfaces:**

- Consumes `config.Consumer`, `evidence.Plan`, and `evidence.Record`.
- Produces
  `applicability.Detect(fs.FS, applicability.Input) (evidence.Plan, error)`.
- `applicability.Input` carries the validated consumer, subject SHA, policy
  digest, and one typed catalog of tool, parser, profile, and reason-code
  identities. Task 4 acquisition locks extend this catalog and are drift-tested
  against it instead of creating a second applicability inventory.
- Extends `evidence.Plan` with policy identity and deterministic validation and
  digest functions. Expected entries carry the parser contract required by the
  gate.
- Produces `exceptions.LoadDetailed(io.Reader, time.Time) (LoadResult, error)`;
  syntax failures are fatal while sorted semantic issues remain available to
  the aggregate gate. A strict `Load` convenience wrapper may reject any issue.
- Produces `gate.Evaluate(gate.Input) gate.Result`.
- `gate.Input` carries the plan, normalized records, independently observed
  subject/tree identities, context keyed by every expected identity, valid
  exceptions, and exception issues. Context binds each producer to the plan,
  tree, detector, execution conclusion, observed report hash/parser, and typed
  finding or suppression observations.

- [ ] **Step 1: Write repository-shape detection tests**

Use fixture file systems for Go single-module, Go multi-module, generated Go,
shell-only, Docker, workflow-only, Terraform, Markdown-only, mixed, symlink,
untracked manifest path, and contradictory explicit configuration.

```go
func TestDetectMarksHadolintNotApplicableWithoutDockerfile(t *testing.T) {
    plan := detectFixture(t, "go-library")
    want := Expected{Tool: "hadolint", Applicability: NotApplicable}
    assertExpected(t, plan, want)
}
```

- [ ] **Step 2: Confirm applicability tests fail before implementation**

Run: `go test ./internal/applicability -count=1`

Expected: FAIL because `Detect` does not exist.

- [ ] **Step 3: Implement deterministic applicability**

Walk tracked paths supplied by `git ls-files -z`; never infer from untracked
files. Sort all paths and expected records. Each `N/A` entry records detector
version, tree hash, policy digest, parser identity, and one exact reason code.
Compute a deterministic plan digest and validate all plan invariants before any
job consumes it.

- [ ] **Step 4: Write exception lifecycle tests**

Cover valid fingerprint, expired date, future creation date, empty rationale,
unknown tool, wildcard scope, duplicate fingerprint, unused exception, missing
owner, invalid path, equivalent mutant, and inline suppression without a
matching entry.

- [ ] **Step 5: Implement strict exception matching**

Match tool, rule, fingerprint, and exact repository-relative scope. Gate output
lists every unused, expired, invalid, duplicate, or unmatched exception as a
finding. Aggregate counts without stable observations cannot consume an
exception.

- [ ] **Step 6: Write aggregate gate truth-table tests**

Cover all pass, one finding, non-zero exit, missing record, duplicate record,
malformed record, cancellation, timeout, unexpected skip, valid `N/A`, invalid
`N/A`, report hash mismatch, policy mismatch, subject mismatch, and unused
exception. Supply independent observed report and tree hashes in the typed gate
input; never compare one untrusted claim with itself.

- [ ] **Step 7: Implement and mutation-test the gate**

```go
type Result struct {
    Pass     bool
    Findings []Finding
}
```

Define GitHub-neutral execution states for completed, failed, cancelled,
timed-out, and skipped producers. Only detector-backed `N/A` is an expected
skip. Sort findings by tool, command, code, and stable detail. Delete the
missing-record branch and confirm its dedicated test fails, then restore it.

Typed observations carry tool, command, rule, fingerprint, exact scope,
suppression state, and source (`analyzer`, `inline`, or `ignore-file`). Match
them one-to-one to exceptions. Missing identities, nonzero count mismatches,
unmatched suppressions, and unused exceptions are findings.

- [ ] **Step 8: Run full Go validation and commit**

```bash
git add internal/evidence internal/applicability internal/exceptions
git add internal/gate testdata
git commit -m "feat: add applicability and aggregate gate"
```

### Task 4: Add The CLI And Deterministic Generators

**Files:**

- Create: `cmd/github-ci/main.go`
- Create: `internal/command/command.go`
- Create: `internal/command/command_test.go`
- Create: `internal/generate/generate.go`
- Create: `internal/generate/generate_test.go`
- Create: `policies/tools.yaml`
- Create: `policies/linters.yaml`
- Create: `templates/workflows/go.yml.tmpl`
- Create: `templates/workflows/deep.yml.tmpl`
- Create: `templates/workflows/release.yml.tmpl`
- Create: `templates/callers/github-ci.yml.tmpl`
- Create: `templates/callers/github-ci-deep.yml.tmpl`
- Create: `templates/callers/github-ci-release.yml.tmpl`
- Create: `scripts/generate.sh`

**Interfaces:**

- Consumes all Task 1 through Task 3 packages.
- Builds the tracked-only file system, computes independent current tree and
  report digests, and assembles the complete typed `gate.Input`.
- Produces CLI subcommands `preflight`, `parse`, `record`, `gate`, `generate`,
  and `verify-generated`.
- Produces deterministic files under `.github/workflows/` and
  `templates/callers/generated/`.

- [ ] **Step 1: Write command parsing and exit-code tests**

Test unknown command, missing flags, path validation, parser error exit `2`,
finding exit `1`, success exit `0`, deterministic diagnostics, and no secret
values in errors.

- [ ] **Step 2: Confirm CLI tests fail before implementation**

Run: `go test ./internal/command -count=1`

Expected: FAIL because `command.Run` does not exist.

- [ ] **Step 3: Implement the CLI with dependency injection**

```go
func Run(ctx context.Context, args []string, stdin io.Reader,
    stdout, stderr io.Writer, now func() time.Time) int
```

Use `flag.FlagSet` per subcommand, write only deterministic output, and never
print environment variables or tokens.

- [ ] **Step 4: Write generator golden and drift tests**

Test byte-identical repeated generation, sorted tool and linter inventory,
exactly 74 unique linters, no symbolic action refs, no mutable container tags,
no `continue-on-error`, no `pull_request_target`, and no workflow-level path
filters on required callers.

- [ ] **Step 5: Implement strict tool locks and generation**

`policies/tools.yaml` records tool id, immutable version, source URL, SHA-256 or
container digest, report parser, profiles, and acquisition mode. Action entries
record repository, semantic release label, and full 40-character commit SHA.
The generator refuses incomplete or duplicate locks.

- [ ] **Step 6: Resolve and verify current pins**

Resolve action release tags through the GitHub API, dereference annotated tags,
and record commit SHAs. Resolve tool releases from official release APIs or Go
module proxies, verify published checksums or signatures, and run every
`--version` command. Store the resolved immutable values in `policies/tools.yaml`.

- [ ] **Step 7: Generate initial artifacts and run drift verification**

Run: `go run ./cmd/github-ci generate`

Run: `go run ./cmd/github-ci verify-generated`

Expected: both exit `0`, and a second generation creates no diff.

- [ ] **Step 8: Run full Go validation and commit**

```bash
git add cmd internal/command internal/generate policies templates scripts
git add .github/workflows
git commit -m "feat: add ci policy CLI and generators"
```

### Task 5: Implement The Reusable Go Correctness Workflow

**Files:**

- Modify: `templates/workflows/go.yml.tmpl`
- Modify: `.github/workflows/go.yml`
- Create: `actions/bootstrap/action.yml`
- Create: `actions/record/action.yml`
- Create: `testdata/workflows/go-caller.yaml`
- Create: `internal/generate/workflow_test.go`

**Interfaces:**

- Consumes `github-ci preflight`, `record`, and `gate` from Task 4.
- Maps every `needs` job conclusion into the GitHub-neutral execution states,
  downloads native artifacts under `if: always()`, and never manufactures
  completed evidence for a cancelled, timed-out, or skipped producer.
- Produces reusable workflow inputs `profile`, `config-path`, `go-version`, and
  `previous-go-version`.
- Produces final job id and name `gate` and supports the literal
  `merge_group` event in its generated required caller.

- [ ] **Step 1: Write structural workflow tests**

Parse generated YAML and assert `workflow_call`, minimum permissions, caller
checkout, helper checkout at `job.workflow_sha`, `fail-fast: false`, bounded
timeouts, artifact retention, `if: always()` on evidence and gate jobs, and no
untrusted expression interpolation in `run` blocks.

- [ ] **Step 2: Confirm the structural test fails**

Run: `go test ./internal/generate -run TestGoWorkflow -count=1`

Expected: FAIL because the workflow lacks required jobs.

- [ ] **Step 3: Add preflight and Go module jobs**

Generate jobs for `gofmt`, goimports, `go mod tidy -diff`, `go mod verify`,
build, uncached test, race, vet, direct staticcheck, gopls, golangci-lint,
govulncheck, JUnit through `gotestsum`, coverage, and Cobertura. Multi-module
jobs consume only the preflight plan and never construct shell commands from
consumer strings.

- [ ] **Step 4: Add the exact 74-linter policy**

Generate golangci-lint configuration from `policies/linters.yaml`. Fail
generation if the count is not 74 or if the selected golangci-lint binary does
not recognize every name.

- [ ] **Step 5: Add evidence collection and final gating**

Each analyzer uploads native report plus one evidence record. A separate
`evidence` job downloads all artifacts and the final `gate` job runs even when
dependencies fail or skip.

- [ ] **Step 6: Exercise clean and failing local workflow fixtures**

Use a local workflow validator plus the fixture command harness to prove clean
Go passes and each of formatting, build, test, race, vet, staticcheck,
golangci-lint, govulncheck, and gopls failures produces a blocking record.

- [ ] **Step 7: Regenerate, run full validation, and commit**

```bash
git add templates .github/workflows actions testdata internal/generate
git commit -m "feat: add reusable Go correctness workflow"
```

### Task 6: Add Security, Supply-Chain, And Repository Scanners

**Files:**

- Modify: `templates/workflows/go.yml.tmpl`
- Modify: `.github/workflows/go.yml`
- Create: `policies/semgrep.yaml`
- Create: `policies/licenses.yaml`
- Create: `testdata/scanners/*`
- Modify: `internal/reports/json.go`
- Modify: `internal/reports/reports_test.go`
- Modify: `internal/generate/workflow_test.go`

**Interfaces:**

- Consumes report parsers and immutable tool locks.
- Extends native adapters to emit stable typed finding and suppression
  observations for one-to-one exception matching. Aggregate counts without
  those identities remain blocking.
- Produces evidence ids `codeql`, `dependency-review`, `gitleaks`, `osv`,
  `trivy`, `syft`, `grype`, `semgrep`, `actionlint`, `zizmor`, `scorecard`,
  `checkov`, `hadolint`, `shellcheck`, `shfmt`, `yamllint`, `markdownlint`,
  `json`, `license`, and `api-compat`.

- [ ] **Step 1: Add failing structural tests for every scanner id**

Assert each applicable scanner is present, pinned, has a timeout, emits native
output, records evidence, and appears in the gate plan. Assert CodeQL uses Go,
Actions, security-extended, and quality coverage.

- [ ] **Step 2: Confirm scanner inventory tests fail**

Run: `go test ./internal/generate -run TestScannerInventory -count=1`

Expected: FAIL listing absent scanner ids.

- [ ] **Step 3: Implement secret, dependency, and static-analysis jobs**

Add Gitleaks, OSV-Scanner, Trivy, Grype, Semgrep, CodeQL, GitHub dependency
review, and license/API compatibility jobs. The `dependency-review` evidence
id maps exactly to the GitHub dependency review job. PR enforcement parses
local output;
SARIF upload is conditional on trusted write permission and never determines
the gate result.

- [ ] **Step 4: Implement SBOM and provenance inputs**

Generate SPDX and CycloneDX SBOMs with Syft, validate non-empty subjects and
hashes, then scan the same inventory with Grype. Retain SBOMs on main, tags,
schedule, and manual runs.

- [ ] **Step 5: Implement workflow, shell, config, and documentation jobs**

Add actionlint, zizmor, ShellCheck JSON1, Bash syntax, shfmt, Checkov, Hadolint,
yamllint, markdownlint, strict JSON/YAML parsing, manifest-safety, generated-file
drift, and repository-hygiene checks.

- [ ] **Step 6: Add clean and deliberately failing scanner fixtures**

Each scanner receives one clean fixture and one smallest possible finding. Run
its real pinned binary and assert the normalized count and blocking exit.

- [ ] **Step 7: Add runner hardening and permission tests**

Use the pinned harden-runner action with blocking egress and explicit endpoints.
Assert fork PR jobs have no secrets, no write token, and no privileged follow-up
that executes untrusted artifacts.

- [ ] **Step 8: Regenerate, run full validation, and commit**

```bash
git add templates .github/workflows policies testdata internal
git commit -m "feat: add security and supply-chain scanners"
```

### Task 7: Add Deep Assurance And Release Evidence Workflows

**Files:**

- Modify: `templates/workflows/deep.yml.tmpl`
- Modify: `templates/workflows/release.yml.tmpl`
- Modify: `.github/workflows/deep.yml`
- Modify: `.github/workflows/release.yml`
- Create: `internal/release/manifest.go`
- Create: `internal/release/manifest_test.go`
- Create: `internal/release/checksums.go`
- Create: `internal/release/checksums_test.go`
- Create: `testdata/release/*`

**Interfaces:**

- Consumes strict Go and scanner workflows.
- Produces deterministic `release-manifest.json` and `SHA256SUMS`.
- Produces reusable deep and release workflows with final `gate` jobs.

- [ ] **Step 1: Write deterministic release evidence tests**

Test sorted assets, duplicate names, path traversal, changed bytes, missing
asset, wrong checksum, non-release tag, tag/SHA mismatch, repeated generation,
and source-date normalization.

- [ ] **Step 2: Confirm release tests fail before implementation**

Run: `go test ./internal/release -count=1`

Expected: FAIL because release manifest generation does not exist.

- [ ] **Step 3: Implement release manifest and checksum generation**

Manifest fields include subject SHA, workflow hashes, action SHAs, tool
versions, Go lines, all 74 linters, policy hashes, schema hashes, SBOM hashes,
and artifact hashes. JSON output is stable and newline-terminated.

- [ ] **Step 4: Implement scheduled deep assurance**

Add real bounded Go fuzzing, parser fuzzing, mutation testing, benchmarks,
full-history secret scanning, current/previous/minimum Go compatibility,
Linux/macOS/Windows portability, generated-code regeneration, PostgreSQL and
Redis service profiles, dependency refresh, Renovate validation, and governance
drift audit.

- [ ] **Step 5: Implement release evidence without publishing**

The release workflow builds checksums, SPDX and CycloneDX SBOMs, release
manifest, and GitHub attestations. It validates a semantic-version tag but does
not create a tag, GitHub release, or mutable alias.

- [ ] **Step 6: Mutation-test release validation**

Remove one asset hash comparison and confirm its test fails, restore it, then
run full Go validation.

- [ ] **Step 7: Regenerate and commit**

```bash
git add templates .github/workflows internal/release testdata/release
git commit -m "feat: add deep and release assurance"
```

### Task 8: Implement Repository Governance Audit And Apply

**Files:**

- Create: `cmd/github-ci-govern/main.go`
- Create: `internal/githubapi/client.go`
- Create: `internal/githubapi/client_test.go`
- Create: `internal/governance/state.go`
- Create: `internal/governance/diff.go`
- Create: `internal/governance/apply.go`
- Create: `internal/governance/governance_test.go`
- Create: `governance/gomaja.yaml`
- Create: `testdata/githubapi/*`

**Interfaces:**

- Consumes `config.Governance` and caller renderer.
- Produces commands `audit`, `plan`, `apply --confirm`, `verify`, and
  `render-callers`.
- Uses GitHub REST API version `2026-03-10` through an injected `http.Client`.

- [ ] **Step 1: Write HTTP client contract tests**

Use `httptest.Server` to cover pagination, API-version header, authentication,
404, 403, 422, rate limits, bounded retry, malformed JSON, unexpected content
type, and token redaction.

- [ ] **Step 2: Confirm client tests fail before implementation**

Run: `go test ./internal/githubapi -count=1`

Expected: FAIL because `Client` does not exist.

- [ ] **Step 3: Implement structured GitHub API access**

Use standard-library HTTP only. Decode explicit response structs. Preserve
ETags for read operations. Retries apply only to idempotent requests unless an
apply operation supplies an idempotency-safe live precondition.

- [ ] **Step 4: Write desired-state diff tests**

Cover public owned repository, fork, archived, private, transferred owner,
missing caller, wrong workflow SHA, ruleset drift, unknown required check,
merge methods, branch deletion, Actions permissions, SHA pinning, action
allowlist, Dependabot, secret scanning, push protection, CodeQL, private
vulnerability reporting, and immutable tag rules.

- [ ] **Step 5: Implement deterministic plan and apply**

Plans have a SHA-256 id over desired and observed state. `apply --confirm`
requires that exact id, re-reads live state before every mutation, applies in a
deadlock-safe order, and stops after the first mismatch. Release creation and
tag creation are absent from apply operations.

- [ ] **Step 6: Add the live gomaja manifest**

Generate entries from `gh repo list gomaja`, then keep only public, owned,
non-fork, non-archived repositories. `github-ci` is included. Each entry records
profile, default branch, repository-specific services or build tags, and
`enforce-caller: false` until Task 10 supplies a live validated workflow SHA and
required-check context.

- [ ] **Step 7: Fuzz API and manifest response decoding**

Seed malformed, truncated, duplicated, and oversized JSON responses. Confirm no
panic and deterministic error classification.

- [ ] **Step 8: Run full Go validation and commit**

```bash
git add cmd/github-ci-govern internal/githubapi internal/governance governance
git add testdata/githubapi
git commit -m "feat: add repository governance automation"
```

### Task 9: Complete Self-Tests, Documentation, And Consumer Templates

**Files:**

- Create: `.github/workflows/self-test.yml`
- Create: `.github/dependabot.yml`
- Create: `.markdownlint-cli2.yaml`
- Create: `.golangci.yml`
- Create: `Makefile`
- Modify: `README.md`
- Modify: `CONTRIBUTING.md`
- Modify: `SECURITY.md`
- Create: `docs/adoption.md`
- Create: `docs/policy.md`
- Create: `docs/governance.md`
- Create: `docs/releases.md`
- Create: `docs/troubleshooting.md`
- Create: `testdata/canary/*`

**Interfaces:**

- Consumes every prior command, workflow, schema, and template.
- Produces documented SHA-pinned adoption for gomaja and external users.
- Produces one self-test workflow whose aggregate job is `gate`.

- [ ] **Step 1: Write repository contract tests**

Assert required docs, license, security policy, CODEOWNERS, action pinning,
generated freshness, scanner inventory, no forbidden workflow patterns, caller
SHA comments, and links.

- [ ] **Step 2: Confirm repository tests expose missing files**

Run: `go test ./... -run Repository -count=1`

Expected: FAIL listing missing self-test and adoption documents.

- [ ] **Step 3: Add self-test CI and update automation**

Self-test runs generation drift, unit tests, race, vet, gopls, staticcheck,
golangci-lint, parser fuzz seeds, actionlint, zizmor, Markdown, YAML, JSON,
license, secret, dependency, SBOM, and provenance fixtures. Dependabot updates
Go modules and GitHub Actions weekly with grouped pull requests.

- [ ] **Step 4: Write complete adoption and governance documentation**

Document personal ownership, external callers, immutable SHA updates, fork
behavior, expected `N/A`, exceptions, ruleset migration, scheduled scans,
report locations, token permissions, audit/apply, and no-release-yet status.

- [ ] **Step 5: Run all local validation**

Run the Global Constraints sequence, generation drift, Markdown validation,
actionlint, zizmor, ShellCheck, YAML/JSON parsing, secret scanning, and all
clean/failing fixtures. Run every fuzz target for at least 30 seconds and the
full race suite.

- [ ] **Step 6: Perform hostile self-review and mutation checks**

Temporarily remove one scanner from the generated workflow, replace one action
SHA with `main`, omit one evidence artifact, and accept one malformed report.
Each mutation must fail the exact contract test. Restore and prove a clean tree.

- [ ] **Step 7: Commit the ready-to-publish repository**

```bash
git add .github .golangci.yml .markdownlint-cli2.yaml Makefile
git add README.md CONTRIBUTING.md SECURITY.md docs testdata
git commit -m "docs: complete github-ci adoption and self-test"
```

### Task 10: Publish, Harden, And Live-Validate The Public Repository

**Files:**

- Modify only when live validation identifies a reproducible defect.
- Render temporary canary caller files outside the `github-ci` repository.

**Interfaces:**

- Consumes the verified implementation branch and governance CLI.
- Produces public repository `gomaja/github-ci` with protected `main`.
- Produces a live cross-repository canary result pinned to the published commit.

- [ ] **Step 1: Finish the implementation branch locally**

Run every Task 9 validation fresh, inspect the full diff from root commit, and
fast-forward local `main` only after the finishing-development-branch review.

- [ ] **Step 2: Create and push the public GitHub repository**

Create `gomaja/github-ci` as public with issues, vulnerability reporting, and
the description from `README.md`. Push local `main` so commit `07f85da` remains
the root and therefore contains Apache-2.0 from repository creation.

- [ ] **Step 3: Validate live GitHub Actions**

Inspect every initial workflow run and log. Fix only reproduced defects through
focused tests and commits. Require all self-test jobs and the aggregate gate to
complete successfully on the exact pushed SHA.

- [ ] **Step 4: Apply repository security and merge settings**

Use `github-ci-govern plan`, inspect the exact plan, apply it, and verify live
convergence. Require squash-only merges, automatic branch deletion, read-only
workflow token, full action SHA pinning, explicit action allowlist, secret
scanning, push protection, Dependabot, CodeQL, private vulnerability reporting,
immutable version tags, and a no-bypass default-branch ruleset.

- [ ] **Step 5: Run a temporary public cross-repository canary**

Create a temporary branch in `gomaja/sctp-portkill` containing the generated
caller pinned to the exact `github-ci` SHA. Open a pull request, observe all
called workflow jobs and the exact aggregate check name, and record logs and
artifacts. Do not merge the canary; close it and delete the branch after the
evidence is retained.

- [ ] **Step 6: Verify cleanup and final public state**

Confirm `github-ci` has no open findings, failed runs, stale branches, unmerged
commits, untracked local files, or settings drift. Confirm the temporary canary
branch is deleted and `sctp-portkill` main is unchanged.

- [ ] **Step 7: Record the ready commit without publishing a release**

Update the manifest and adoption documentation with the validated workflow SHA
and observed check context. A governance-only metadata commit may follow that
workflow commit; it does not replace the canary-validated SHA as the immutable
caller reference. Commit through the protected workflow and verify all final
checks. Do not create a semantic-version tag or GitHub release.
