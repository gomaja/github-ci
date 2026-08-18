# Security Policy

## Reporting A Vulnerability

Do not disclose suspected vulnerabilities in a public issue. Use GitHub private
vulnerability reporting for this repository. Include the affected component and
commit, impact, reproduction steps, and any known mitigation.

If private vulnerability reporting is temporarily unavailable, contact the
maintainer through the security contact shown on the `gomaja` GitHub profile
without including exploit details in the first message.

## Supported Versions

Until the first stable release, only the current `main` branch is supported.
After `v1.0.0`, the latest stable minor release will receive security fixes.

## Supply Chain

Consumers must pin reusable workflows to a reviewed full commit SHA. The
repository pins actions, tool distributions, and container images to immutable
identities and verifies checksums or digests before execution. See
[docs/security-model.md](docs/security-model.md).
