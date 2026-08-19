# Releases

`v1.0.0` defines the first supported compatibility line. Releases use immutable
`vX.Y.Z` tags. Consumers pin the tag's exact commit SHA and retain the semantic
version only as review context. Moving major tags such as `v1` are not part of
the strict distribution model.

The `github-ci-release` workflow validates an existing tag and produces a
deterministic source archive, SPDX and CycloneDX SBOMs, a release manifest,
checksums, and GitHub build provenance. It does not create a tag, publish a
release, or upload release assets. Those are separately authorized operations
performed only after the tag workflow succeeds.

The release evidence includes a default strict consumer configuration and
standard, deep, and release caller workflows pinned to the tagged commit. It
also includes the source archive, SPDX and CycloneDX SBOMs, release manifest,
and `SHA256SUMS`; GitHub records build provenance for every evidence file.

Compatibility promises begin with `v1.0.0`. Changes to workflow inputs,
evidence schemas, job names, and policy behavior follow the semantic-versioning
rules in the project design and always require a reviewed consumer update.
