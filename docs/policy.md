# Assurance Policy

## Gate Contract

Preflight derives applicability from tracked files and the strict consumer
configuration. Every applicable producer must emit schema-valid evidence for
the exact subject SHA, command identity, parser version, and policy digest.
Missing, duplicate, malformed, stale, skipped, cancelled, or mismatched
evidence fails closed. An analyzer finding blocks regardless of severity.

`N/A` is allowed only when the detector proves that the required tracked-file
capability is absent. A workflow cannot mark its own scanner not applicable.

## Standard Assurance

| Area | Tools and checks |
| --- | --- |
| Go correctness | `go build`, `go test`, race detector, `go vet`, current and previous Go |
| Go analysis | gopls, staticcheck, golangci-lint with 74 linters, gofmt, goimports |
| Go security | govulncheck, OSV-Scanner, CodeQL extended security and quality queries |
| Source security | Gitleaks, Semgrep, Trivy filesystem scanning |
| Dependencies | GitHub dependency review, module integrity, update automation |
| Supply chain | Syft SPDX SBOM, Grype, go-licenses, apidiff |
| Workflows | Actionlint, Zizmor, OpenSSF Scorecard actionable findings, immutable action references |
| Repository files | Hadolint, Bash syntax, ShellCheck, shfmt, Yamllint, Markdownlint, JSON parsing |
| Infrastructure | Checkov for Terraform and other supported infrastructure files |
| Integrity | generated-file drift, repository hygiene, complete evidence aggregation |

Tools downloaded directly are version-locked and checksum-verified. Container
images use SHA-256 digests. GitHub Actions use full commit SHAs. The canonical
inventory is `policies/tools.yaml`; linter membership is
`policies/linters.yaml`.

The Go linter policy caps cyclomatic complexity at 20 and reports cognitive
complexity from 30. Dependency policy rejects obsolete compatibility packages
while remaining reusable across repositories. Repeated test-fixture literals
are excluded from `goconst`; test files are excluded only from `gosec`, whose
production-oriented rules otherwise generate false positives for deliberate
adversarial fixtures. Generated code is detected in strict mode, unused
exclusion rules fail configuration review, and issue reporting is unlimited.

## Scanner Ownership Matrix

Primary ownership identifies the result used to classify and route a finding;
it does not make overlapping results advisory. Every applicable scanner must
produce its native report and normalized evidence, and every finding or
execution error remains blocking.

| Scanner | Primary purpose | Why the overlap remains | Native report and gate behavior | Triage owner |
| --- | --- | --- | --- | --- |
| CodeQL | Compiled semantic dataflow for Go and GitHub Actions | Finds cross-function flows that portable pattern rules and Go lint rules do not model | SARIF 2.1.0 through `sarif/v1`; every result, diagnostic error, missing report, or failed analysis blocks | Application security |
| Semgrep | Portable source-pattern policy across supported languages | Covers repository source without a successful compiled database and expresses project-wide patterns | Semgrep JSON through `semgrep-json/v1`; every result or execution error blocks | Source-security policy maintainers |
| gosec in golangci-lint | Go-specific unsafe APIs and source idioms | Complements semantic dataflow with fast compiler-aware Go checks in the common lint pass | golangci-lint JSON through `golangci-lint-json/v1`; every issue or execution error blocks | Go maintainers |
| govulncheck | Reachable vulnerabilities in Go call graphs | Reachability prioritizes executable exposure but does not replace complete dependency matching | Govulncheck JSON through `govulncheck-json/v1`; every reachable finding, malformed stream, or execution error blocks | Go dependency owners |
| OSV-Scanner | Vulnerabilities matched to manifests and lockfiles | Detects declared packages regardless of whether current static analysis proves reachability | OSV JSON through `osv-json/v1`; every vulnerability or execution error blocks | Dependency security |
| Trivy | Broad filesystem vulnerability, misconfiguration, and secret inventory | Cross-checks language-specific and dedicated scanners while also covering operating-system and repository artifacts | Trivy JSON through `trivy-json/v1`; every vulnerability, misconfiguration, secret, or execution error blocks | Repository security |
| Grype | Vulnerability matching against the generated SBOM | Independently checks the inventory emitted by Syft and can expose inventory or matcher disagreement | Grype JSON through `grype-json/v1`; every match at any severity or execution error blocks | Supply-chain maintainers |
| GitHub secret scanning | Provider-side alert lifecycle, validity, and push protection | Platform history and push controls are unavailable to a checkout-only scanner | GitHub platform alerts and governance state; enabled controls are mandatory, and any platform alert is handled independently | Repository administrators and security |
| Gitleaks | Blocking checkout content and scheduled full-history secret detection | Gives deterministic local evidence on pull requests and finds historical material outside the checked-out tree | Gitleaks JSON through `gitleaks-json/v1`; every finding or execution error blocks | Source-security policy maintainers |
| Dependency Review | Pull-request dependency additions and version deltas | Owns the change boundary while SBOM tools inspect the complete resolved repository inventory | Action conclusion normalized as `command-status/v1`; a finding, action failure, or missing evidence blocks | Dependency owners |
| Syft | Authoritative complete software inventory for downstream SBOM analysis | Inventory is distinct from vulnerability matching; Grype consumes a second Syft-native representation | SPDX JSON through `spdx-json/v1`, with Syft JSON retained for Grype; missing or malformed inventory blocks | Supply-chain maintainers |
| OpenSSF Scorecard | Repository posture signals not already enforced by central jobs or managed governance | Preserves an independent view of consumer hygiene while reusable-workflow opacity prevents it from observing central CodeQL and deep fuzz execution | Native SARIF through `scorecard-sarif/v1`; SAST and fuzzing posture signals are nonblocking only because CodeQL and selected deep fuzz evidence are authoritative, while actionable consumer findings still block | Repository administrators and security |

The overlap policy is additive: one scanner never suppresses, downgrades, or
closes another scanner's finding. Duplicate-looking results are linked during
triage while their original tool identities and evidence remain intact.

## Deep Assurance

The weekly deep workflow runs every configured module on Linux, macOS, and
Windows against the current and previous Go releases. It also runs every fuzz
target separately, benchmarks the configured package scope, requires Gremlins
mutation testing at 100 percent efficacy and mutant coverage, scans full Git
history with Gitleaks, and checks direct dependency freshness.

Generated-source verification, PostgreSQL or Redis integration, private-module
authentication, protocol testing, and system topology remain independently
required consumer-owned jobs. The central workflow neither starts those
services nor accepts their credentials or shell commands.

Every configured module runs all eleven mutators available in pinned Gremlins
v0.6.0. A normal report is bound to the exact Go module and accepted only when
every mutation is killed or not viable. When a module has no mutation points,
the validator requires Gremlins' exact terminal no-results marker and emits
module-bound evidence. A missing report without that marker fails closed.

## Release Assurance

The release workflow accepts an existing immutable `vX.Y.Z` tag, verifies that
it resolves to the event SHA, creates a deterministic source archive, emits SPDX
and CycloneDX SBOMs, records a release manifest and `SHA256SUMS`, and generates
build provenance. It uploads evidence only and never creates or moves a tag or
release.
