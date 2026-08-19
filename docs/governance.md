# Repository Governance

`github-ci-govern` keeps public owned repositories converged on one review,
merge, Actions, security, and tag policy. The gomaja manifest is
`governance/gomaja.yaml`. Personal ownership does not provide an organization
policy surface, so this explicit manifest and API client provide the shared
control plane without requiring migration to an organization.

## Audit And Apply

Authenticate with `GITHUB_TOKEN` or `GH_TOKEN`. Read-only audits need repository
administration read access; apply needs administration write access.

```bash
go run ./cmd/github-ci-govern audit --manifest governance/gomaja.yaml
go run ./cmd/github-ci-govern plan --manifest governance/gomaja.yaml --output plan.json
go run ./cmd/github-ci-govern apply \
  --manifest governance/gomaja.yaml \
  --plan plan.json \
  --confirm <plan-id>
go run ./cmd/github-ci-govern verify --manifest governance/gomaja.yaml
```

Use `--repository <name>` with `audit`, `plan`, `apply`, or `verify` for a
staged rollout. The selected name must exist in the manifest, and both the plan
identity and apply-time drift check are restricted to that repository.

The plan ID covers the desired operations and observed state. Apply requires
the exact ID, rebuilds the remaining plan before every mutation, and stops on
concurrent drift. Release and tag creation are not governance operations.

## Enforced State

- public, owned, non-fork, non-archived repositories with default branch `main`;
- squash-only merging, linear history, automatic branch deletion, and update branches;
- pull requests, stale-review dismissal, conversation resolution, code-owner review, and no bypass actors;
- CodeQL code-scanning protection at all alert and security severity levels;
- immutable `v*` tags;
- read-only default workflow tokens and no workflow approval permission;
- full-SHA action pinning, GitHub-owned actions, and an explicit third-party allowlist;
- Dependabot alerts and security updates;
- secret scanning and push protection; and
- private vulnerability reporting.

Required status checks are enabled only after a real canary records the stable
aggregate context. The manifest will not guess the check name.

The live self-test records the aggregate context as `gate / gate`. Consumer
repositories record their observed context in their own manifest entry before
caller enforcement is enabled.

Secret scanning for non-provider patterns and validity checks requires GitHub
Secret Protection for Team or Enterprise repositories. It is unavailable to
the current personal-account public repositories and is recorded as an
unsupported platform capability, not treated as enabled. Base secret scanning,
push protection, and the repository-independent Gitleaks scan remain mandatory.

## Scope Refusal

Planning stops if a target is private, forked, archived, transferred to an
unexpected owner, renamed, or using an unexpected default branch. The tool does
not silently broaden its scope. Legacy rulesets with the same exact branch or
tag scope are updated in place, and overlapping duplicates are removed only
after the managed ruleset exists.
