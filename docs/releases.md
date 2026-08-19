# Releases

Releases use immutable `vX.Y.Z` tags. Consumers pin the tag's exact commit SHA
and retain the semantic version only as review context. Moving major tags such
as `v1` are not part of the strict distribution model.

`v1.0.0` remains immutable historical evidence but is not an adoption target.
Its linked external canary failed and used `repository-only`, so it proved the
aggregate gate failed closed without proving Go adoption. `v1.1.0` is the
intentional one-time compatibility reset to schema 2 because no consumer
successfully adopted v1.0.0. It becomes an adoption target only after standard,
deep, external Go consumer, and untrusted-fork acceptance all pass at its exact
commit.

The `github-ci-release` workflow validates an existing tag and produces a
deterministic source archive, SPDX and CycloneDX SBOMs, a release manifest,
checksums, and GitHub build provenance. It does not create a tag, publish a
release, or upload release assets. Those are separately authorized operations
performed only after the tag workflow succeeds.

A manual validation must be dispatched with the immutable tag itself as the
workflow ref, not from a branch with only the `tag` input populated. The event
SHA, checked-out tag commit, and self-release reusable-workflow SHA must agree;
otherwise evidence generation fails before any artifact is accepted.

Before building that evidence, the repository release workflow finds the most
recent successful `github-ci-release-candidate` run whose `head_sha` is the
tagged commit. It downloads `github-ci-release-acceptance`, revalidates its
canonical JSON and candidate SHA without network trust, and uploads it into the
current run. A missing, expired, malformed, noncanonical, or different-commit
record fails release evidence.

The release evidence includes the validated acceptance record, a default
strict consumer configuration, and standard, deep, and release caller
workflows pinned to the tagged commit. It also includes the source archive,
SPDX and CycloneDX SBOMs, release manifest, and `SHA256SUMS`; GitHub records
build provenance for every evidence file.

The v1.1.0 release keeps the historical v1.0.0 tag and release unchanged. It is
allowed to break the unadopted v1.0.0 API by explicit project decision; future
incompatible changes to workflow inputs, configuration or evidence schemas,
job names, required checks, permissions, or policy behavior require a new major
version and a reviewed consumer update.

The manually dispatched release-candidate workflow never creates a tag or
release. Its final gate requires this repository's local standard and deep
reusable workflows plus verified external standard, deep, and cross-repository
fork runs. Run IDs are API identities, not assertions: the verifier fetches all
job pages, checks exact aggregate jobs, reads callers and schema-2 config at
immutable run heads, and proves tracked modules and generated Go source.
