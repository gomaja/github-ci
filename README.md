# github-ci

`github-ci` is a public, reusable GitHub Actions assurance system for Go and
mixed-source repositories. Every applicable analyzer is blocking. A pull
request passes only when the aggregate gate receives complete, valid evidence
and reports zero findings.

## Assurance

The standard workflow combines correctness, race and compatibility testing,
CodeQL, dependency review, secret and vulnerability scanning, SAST,
infrastructure and workflow analysis, SBOM and license checks, API compatibility,
repository hygiene, and an evidence-completeness gate. Scheduled deep assurance
adds multi-platform testing, fuzzing, mutation testing, full-history secret
scanning, dependency freshness, benchmarks, and service integration tests.

See [policy](docs/policy.md) for the complete scanner inventory and
[security model](docs/security-model.md) for trust and permission boundaries.

## Adoption

Consumers commit a strict `.github/github-ci.yaml` file and caller workflows
that reference a reviewed 40-character commit SHA. Mutable branches and tags
are not accepted as trust anchors.

```bash
go run github.com/gomaja/github-ci/cmd/github-ci-govern@<commit-sha> \
  render-callers \
  --manifest governance/gomaja.yaml \
  --repository sctp-portkill \
  --workflow-sha <commit-sha> \
  --output ./rendered
```

`v1.0.0` is the first stable release. Resolve its immutable tag to a full commit
SHA and pin that SHA in every reusable workflow call. Release evidence
automation validates existing tags but never creates a tag or GitHub release.

## Documentation

- [Adoption](docs/adoption.md)
- [Policy and scanner inventory](docs/policy.md)
- [Governance](docs/governance.md)
- [Security model](docs/security-model.md)
- [Exceptions](docs/exceptions.md)
- [Release model](docs/releases.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
