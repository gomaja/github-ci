# Adoption

## Trust Anchor

Adopt only a commit that completed the repository self-test and a real
cross-repository canary. Pin all reusable workflow calls to that exact
40-character SHA. A version comment may describe the commit, but a branch,
moving major tag, or mutable release tag is not an acceptable reference.

For a published release, fetch its tag and resolve the peeled commit before
rendering callers:

```bash
git fetch origin tag v1.0.0
git rev-parse 'v1.0.0^{commit}'
```

The pre-release canary workflow SHA was
`3dc64d2ab02b3d5ce3f2eacacfdc1eec9a9e78f7`. It completed the
[standard gate](https://github.com/gomaja/github-ci/actions/runs/32243207234),
[deep assurance](https://github.com/gomaja/github-ci/actions/runs/32243204063),
and a real [cross-repository canary](https://github.com/gomaja/sctp-portkill/pull/3)
whose [run](https://github.com/gomaja/sctp-portkill/actions/runs/32243265290)
observed the aggregate check as `gate / gate`.

## Consumer Configuration

Create `.github/github-ci.yaml`:

```yaml
schema-version: 1
profile: go-strict
```

The supported profiles are `go-strict`, `go-library`, and `repository-only`.
Modules are discovered from tracked `go.mod` files when `modules` is omitted.
Use explicit repository-relative module paths when the repository intentionally
excludes fixtures or examples. Optional fields configure build tags, PostgreSQL
or Redis integration, generated paths, and the exception manifest.

Render caller files with the governance CLI, or start from the templates in
`templates/callers/generated` and replace the zero SHA with the validated
commit. Commit the standard caller and consumer configuration together. The
deep and release callers are separate because they have different triggers and
permissions.

## External Repositories

The workflows are public and do not depend on the gomaja governance manifest.
An external repository keeps its own config, branch rules, and authentication.
No gomaja token or organization membership is required. The workflow checks
out its helper implementation at the called workflow commit, so the consumer
reviews one immutable source identity.

Fork pull requests receive no repository secrets and a read-only token. Local
scanner exit status and normalized evidence remain blocking even when GitHub
does not permit an optional report upload from an untrusted fork.

## Updating

Treat an update as a source-code change:

1. Review the complete commit range and policy-lock changes.
2. Render callers at the proposed SHA.
3. Open a pull request and require the old protected gate plus the candidate run.
4. Merge only after the candidate aggregate gate is successful.
5. Update the ruleset check context only when a real run proves that it changed.
