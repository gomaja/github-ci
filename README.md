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
scanning, dependency freshness, and benchmarks. Repository-specific generation,
services, private dependencies, protocols, and system topology stay in
consumer-owned preparation workflows.

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

Do not adopt `v1.0.0`: its linked external canary failed and exercised only the
`repository-only` profile. `v1.1.0` introduced the intentional one-time schema
2 compatibility reset, but its release evidence failed closed before complete
consumer proof. `v1.1.1` completed that proof and remains valid. `v1.1.2`
repeated the complete acceptance chain with a signed tag and remains a valid
exact-SHA adoption anchor, but its `SHA256SUMS` uses repository-relative
`dist/` paths that do not match flat GitHub Release downloads. `v1.1.3`
corrects that packaging contract without changing schema 2 and becomes the
preferred adoption target only after its release-acceptance gate succeeds.
Release evidence automation validates existing tags but never creates, moves,
deletes, or publishes a tag or GitHub Release.

## Documentation

- [Adoption](docs/adoption.md)
- [Migration from v1.0.0 to v1.1.x](docs/migration-v1.1.md)
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
