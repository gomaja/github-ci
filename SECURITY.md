# Security Policy

## Reporting A Vulnerability

Do not disclose suspected vulnerabilities in a public issue. Use GitHub private
[vulnerability reporting](https://github.com/gomaja/github-ci/security/advisories/new)
for this repository. Include the affected component and commit, impact,
reproduction steps, and any known mitigation.

The maintainer will acknowledge a complete report within 3 business days,
provide a remediation assessment within 10 business days, and target a fix
within 90 days. The actual timeline may be shorter for actively exploited or
critical vulnerabilities. Public disclosure will be coordinated with the
reporter after a fix is available, or sooner when users need immediate
mitigation guidance.

If private vulnerability reporting is temporarily unavailable, contact the
maintainer through the security contact shown on the `gomaja` GitHub profile
without including exploit details in the first message. Public reports can use
the repository's [issue tracker](https://github.com/gomaja/github-ci/issues) only
for security-process questions that contain no vulnerability or exploit details.

## Supported Versions

Stable releases beginning with `v1.0.0` are supported. The latest stable minor
release receives security fixes.

## Supply Chain

Consumers must pin reusable workflows to a reviewed full commit SHA. The
repository pins actions, tool distributions, and container images to immutable
identities and verifies checksums or digests before execution. See
[docs/security-model.md](docs/security-model.md).
