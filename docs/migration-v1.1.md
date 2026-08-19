# Migrating from v1.0.0 to v1.1.0

`v1.1.0` is an intentional compatibility reset. No repository successfully
adopted the v1.0.0 Go workflow, so this release uses schema 2 and does not
preserve ineffective schema-1 fields. `v1.0.0` remains immutable historical
evidence and must not be deleted, moved, or used as an adoption target.

## Consumer configuration

The following table covers every schema-1 consumer field.

| Schema 1 | Schema 2 | Migration |
| --- | --- | --- |
| `schema-version: 1` | `schema-version: 2` | Required. Schema 1 is rejected. |
| `profile` | `profile` | The field is unchanged. `go-strict` and `go-library` now select different fixed analyzer policies. |
| `modules: [path]` | `go.modules: [{path: path}]` | Each entry is now an object that can replace execution defaults. If present, the list must exactly match every tracked `go.mod`. |
| `build-tags` | `go.defaults.build-tags` or `go.modules[].build-tags` | Tags are applied to package build, test, vet, gopls, Staticcheck, golangci-lint, govulncheck, portability, fuzz, benchmark, and mutation contexts. |
| `services` | Removed | PostgreSQL and Redis topology is consumer-owned. Copy a digest-pinned preparation template and require its observed check separately. |
| `generated` | `generated-paths` | The central workflow classifies these paths but never runs a repository-specific generator. |
| `exceptions` | `exceptions` | The field and reviewed-manifest behavior are unchanged. |

Schema 2 adds execution controls that schema 1 could not express:

- `packages` selects the exact package patterns for every Go analyzer;
- `module-mode` is `readonly`, `vendor`, or `mod`;
- `test-timeout` is whole seconds from `1s` through `2700s` or whole minutes
  from `1m` through `45m`;
- `package-parallelism` controls ordinary Go package concurrency;
- `race-parallelism` controls both `go test -race -p` and `-parallel`; and
- `coverage-packages` selects `-coverpkg`; an explicit empty array enables
  coverage without adding `-coverpkg`.

Defaults apply first. A field present on a module replaces that field rather
than merging lists. Omitted `go.modules` means all tracked modules are
discovered. An explicit module list is closed-world and must name all of them.

For example:

```yaml
schema-version: 2
profile: go-library
go:
  defaults:
    packages: [., ./generated]
    module-mode: readonly
    build-tags: [canary_a, canary_b]
    test-timeout: 12m
    package-parallelism: 3
    race-parallelism: 1
    coverage-packages: [.]
  modules:
    - path: .
    - path: tools
      packages: [.]
      module-mode: mod
      coverage-packages: []
generated-paths:
  - generated
```

The complete copyable example is in `testdata/repositories/go-canary`. Its
tagged files compile only when both configured tags are applied, and
`scripts/check-generated.sh` demonstrates a consumer-owned freshness check.

## Governance manifest

The governance manifest also moves to schema 2. Every schema-1 governance
field not listed below is unchanged.

| Schema 1 | Schema 2 | Migration |
| --- | --- | --- |
| `defaults.required-check` | `defaults.required-checks` | Wrap the exact check name in a nonempty array. |
| `repositories[].modules` | `repositories[].go.modules[].path` | Use the same closed-world module objects as consumer configuration. |
| `repositories[].build-tags` | `repositories[].go.defaults.build-tags` | Move tags into the typed Go settings. |
| `repositories[].services` | Removed | Keep service workflows and their required checks consumer-owned. |
| `repositories[].generated` | `repositories[].generated-paths` | Rename without changing classification semantics. |
| `repositories[].observed-required-check` | `repositories[].observed-required-checks` | Use an array containing every baseline check before enforcement. |

`api-version`, owners, default profile and branch, refusal controls,
repository owner/profile, `exceptions`, `enforce-caller`, and `workflow-sha`
retain their names. Plans and applies reject duplicates, empty required-check
arrays, unobserved baseline checks, stale observed-state hashes, or concurrent
ruleset drift.

## Consumer-owned preparation

Do not translate schema-1 `services` into central inputs. Use the PostgreSQL or
Redis preparation template and supply the repository's own migrations,
fixtures, tags, and test command. Private dependency authentication,
repository-specific generation, protocol tests, and system topology follow the
same rule. The reusable workflow receives none of their commands or secrets.

## Upgrade sequence

1. Convert the consumer and governance YAML to schema 2 on a branch.
2. Run the repository generator and commit all rendered callers together.
3. Pin callers to the exact accepted v1.1.0 commit, never to `v1.1.0`, `v1`, or
   a branch in executable YAML.
4. Run consumer-owned generation, service, private-dependency, protocol, and
   system jobs independently.
5. Require both the existing protected check and the candidate `gate / gate`
   until the new real run is observed.
6. Remove an obsolete check only after the replacement has passed on the
   protected branch and merge queue where applicable.

The release commit is adoptable only when its standard workflow, deep
workflow, public multi-module Go canary, and untrusted-fork canary pass and the
canonical acceptance record is included in checksummed, attested release
evidence.
