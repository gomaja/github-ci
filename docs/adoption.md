# Adoption

## Trust Anchor

Adopt only a commit that completed the repository self-test and a real
cross-repository canary. Pin all reusable workflow calls to that exact
40-character SHA. A version comment may describe the commit, but a branch,
moving major tag, or mutable release tag is not an acceptable reference.

After v1.1.2 passes release acceptance and is published, fetch its immutable tag
and resolve the peeled commit before rendering callers:

```bash
git fetch origin tag v1.1.2
git rev-parse 'v1.1.2^{commit}'
```

Do not adopt v1.0.0. Its pre-release self-test SHA
`3dc64d2ab02b3d5ce3f2eacacfdc1eec9a9e78f7` completed the
[standard gate](https://github.com/gomaja/github-ci/actions/runs/32243207234)
and [deep assurance](https://github.com/gomaja/github-ci/actions/runs/32243204063),
but the linked [cross-repository canary](https://github.com/gomaja/sctp-portkill/pull/3)
[run](https://github.com/gomaja/sctp-portkill/actions/runs/32243265290)
failed. That consumer used schema 1 with `repository-only`, and every Go job was
skipped. It proved fail-closed aggregate enforcement but did not prove a
successful Go consumer adoption.

`v1.1.0` introduced the intentional compatibility reset to schema 2, but its
untrusted-fork canary was incomplete and its
[tag evidence](https://github.com/gomaja/github-ci/actions/runs/32328609432)
failed closed. It is not an adoption target. `v1.1.1` subsequently completed
the standard, deep, external Go consumer, untrusted-fork, exact-commit candidate,
and tag-evidence checks at commit
`9016be300245e6046b8b572a8bca63d445b50620`; its
[exact-commit candidate](https://github.com/gomaja/github-ci/actions/runs/32382404153)
and [tag evidence and provenance](https://github.com/gomaja/github-ci/actions/runs/32384592414)
remain valid.

`v1.1.2` preserves the accepted schema 2 behavior and supersedes `v1.1.1` only
to correct the versioned documentation and use a verified signed tag. Its exact
release commit becomes the current adoption target only after the complete
acceptance chain passes again at that commit.

Repositories with schema-1 configuration must follow the complete
[v1.1 migration guide](migration-v1.1.md). Unknown and removed fields fail
strict parsing; there is no compatibility translation.

## Consumer Configuration

Create `.github/github-ci.yaml`:

```yaml
schema-version: 2
profile: go-strict
go:
  defaults:
    packages: [./...]
    module-mode: readonly
    build-tags: []
    test-timeout: 10m
    package-parallelism: 4
    race-parallelism: 1
    coverage-packages: [./...]
```

The supported profiles are `go-strict`, `go-library`, and `repository-only`.
Modules are discovered from tracked `go.mod` files when `go.modules` is
omitted. If `go.modules` is present, it must be nonempty and name every tracked
module exactly; each module entry replaces omitted default fields independently. Package scope,
module mode, build tags, test timeout, package parallelism, race parallelism,
and coverage scope are applied through a typed argument plan. Generated paths
are classification only, and `exceptions` selects the reviewed exception
manifest. Test timeouts use whole seconds from `1s` through `2700s` or whole
minutes from `1m` through `45m` so runtime and published-schema validation are
identical.
YAML `null` is rejected; omit an optional field or provide an explicit value.

Render caller files with the governance CLI, or start from the templates in
`templates/callers/generated` and replace the zero SHA with the validated
commit. Commit the standard caller and consumer configuration together. The
deep and release callers are separate because they have different triggers and
permissions.

## Consumer-Owned Preparation

Reusable workflow jobs cannot inherit a caller job's modified checkout,
running service containers, or private credentials. Keep preparation and
repository-specific integration in independent caller-owned workflows, then
require their observed check names in the repository ruleset.

Copy and review the examples in `templates/preparation`:

- `generated-source.yml.tmpl` runs the repository's explicit generator and
  fails on tracked or untracked drift;
- `postgresql.yml.tmpl` and `redis.yml.tmpl` provide digest-pinned services but
  leave migrations, fixtures, tags, and the test command to the repository;
- `private-modules.yml.tmpl` configures credentials only for trusted events and
  same-repository pull requests; and
- protocol, wire, privileged, or multi-container tests remain ordinary
  repository-owned workflows because their topology is part of the consumer.

Replace every documented example command before committing a copied template.
Do not pass a shell command, service password, or private-module token into the
central reusable workflow.

## External Repositories

The workflows are public and do not depend on the gomaja governance manifest.
An external repository keeps its own config, branch rules, and authentication.
No gomaja token or organization membership is required. The workflow checks
out its helper implementation at the called workflow commit, so the consumer
reviews one immutable source identity.

Fork pull requests receive no repository secrets and a read-only token. Local
scanner exit status and normalized evidence remain blocking even when GitHub
does not permit an optional report upload from an untrusted fork.

A repository whose build requires private modules must choose an explicit fork
policy. The private-module preparation job is skipped for forks and cannot make
credentials available to them. If external fork contributions must pass the
main Go gate, provide a credential-free dependency path such as reviewed
vendoring; never switch to `pull_request_target` to execute fork code with a
secret.

The copyable seed in `testdata/repositories/go-canary` is the minimum release
acceptance topology: two tracked modules, two simultaneous build tags,
committed generated Go, explicit package and coverage scopes, distinct module
modes, and explicit timeout and concurrency controls. The public canary must
add standard and deep callers pinned to the exact candidate SHA; a local copy
of the seed is test evidence, not a substitute for the public and
untrusted-fork runs.

## Updating

Treat an update as a source-code change:

1. Review the complete commit range and policy-lock changes.
2. Render callers at the proposed SHA.
3. Open a pull request and require the old protected gate plus the candidate run.
4. Merge only after the candidate aggregate gate is successful.
5. Update the ruleset check context only when a real run proves that it changed.
