# Releases

No semantic-version tag or GitHub release has been published for `github-ci`.
Until the first supported release, consumers must use the live-canary-validated
commit listed in [adoption.md](adoption.md).

Future releases use immutable `vX.Y.Z` tags. Consumers continue to pin the tag's
exact commit SHA and retain the semantic version only as review context. Moving
major tags such as `v1` are not part of the strict distribution model.

The `github-ci-release` workflow validates an existing tag and produces a
deterministic source archive, SPDX and CycloneDX SBOMs, a release manifest,
checksums, and GitHub build provenance. It does not create a tag, publish a
release, or upload release assets. Those are separately authorized operations
performed only after the tag workflow succeeds.

Compatibility promises begin with `v1.0.0`. Before that release, workflow
inputs, evidence schemas, job names, and policy behavior may change at any
commit and require a reviewed consumer update.
