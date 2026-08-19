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

## Deep Assurance

The weekly deep workflow runs Linux, macOS, and Windows against the current and
previous Go releases; every fuzz target; benchmarks; Gremlins mutation testing
at 100 percent efficacy and mutant coverage; full-history Gitleaks; dependency
freshness; generated drift; and PostgreSQL and Redis integration-tagged tests.

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
