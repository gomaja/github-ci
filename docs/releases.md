# Releases

Releases use immutable `vX.Y.Z` tags. Consumers pin the tag's exact commit SHA
and retain the semantic version only as review context. Moving major tags such
as `v1` are not part of the strict distribution model.

Release-specific annotated tags from `v1.1.2` onward must be signed. Before a
draft release is created, the tag must pass local signature verification and
GitHub must report the tag signature as verified. Tag signing adds author
identity to the existing exact-SHA, protected-tag, immutable-release,
checksummed evidence, and provenance controls; it does not replace any of them.

## Release History

- `v1.0.0` remains immutable historical evidence but is not an adoption target.
  Its linked external canary failed and used `repository-only`, proving the
  aggregate gate failed closed without proving Go adoption.
- `v1.1.0` introduced the intentional one-time schema 2 compatibility reset,
  but the untrusted-fork canary was incomplete and the tag-triggered evidence
  workflow failed closed. It is not an adoption target.
- `v1.1.1` is the first fully accepted schema 2 release. Its standard, deep,
  external Go consumer, untrusted-fork, exact-commit candidate, tag evidence,
  and provenance all passed at commit
  `9016be300245e6046b8b572a8bca63d445b50620`. Its
  [candidate](https://github.com/gomaja/github-ci/actions/runs/32382404153)
  and [tag evidence](https://github.com/gomaja/github-ci/actions/runs/32384592414)
  remain valid.
- `v1.1.2` preserves the accepted `v1.1.1` behavior and completed the full
  acceptance chain at commit `f10be1183b42364176a7d3f1ebfd789aad8aba30` with a
  verified signed tag. Its
  [candidate](https://github.com/gomaja/github-ci/actions/runs/32393221746)
  and [tag evidence](https://github.com/gomaja/github-ci/actions/runs/32395259085)
  remain valid. Its exact-SHA workflows remain adoptable, but its `SHA256SUMS`
  records repository-relative `dist/` paths while GitHub Release assets
  download flat. The individual digests and provenance remain valid, but the
  checksum file is not directly runnable from the download directory.
- `v1.1.3` corrects the checksum file to use published asset names and preserves
  the schema 2 workflow contract. It becomes the preferred adoption target only
  after the complete acceptance chain passes at its exact commit.

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
build provenance for every evidence file. New checksum files use the published
asset names, reject basename collisions, and are checked from the flat release
directory before attestation. Verification continues to accept a complete
legacy repository-relative checksum file for historical releases but rejects a
mixture of the two formats.

The v1.1 line keeps the historical v1.0.0 tag and release unchanged. The
v1.1.0 reset was allowed to break the unadopted v1.0.0 API by explicit project
decision. Future incompatible changes to workflow inputs, configuration or
evidence schemas, job names, required checks, permissions, or policy behavior
require a new major version and a reviewed consumer update.

The manually dispatched release-candidate workflow never creates a tag or
release. Its final gate requires this repository's local standard and deep
reusable workflows plus verified external standard, deep, and cross-repository
fork runs. Run IDs are API identities, not assertions: the verifier fetches all
job pages, checks exact aggregate jobs, reads callers and schema-2 config at
immutable run heads, and proves tracked modules and generated Go source.
