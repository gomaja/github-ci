# Contributing

Changes are made through pull requests against `main`. Run `make verify` before
opening a pull request. Changes to templates must include regenerated artifacts
from `make generate`.

Contributions must include focused tests and pass every applicable check with
zero open findings. New parsers and other untrusted input boundaries require
malformed-input tests and fuzz coverage. Workflow changes must keep every
third-party action pinned to a full commit SHA and preserve least-privilege
permissions.

The `go-library` profile is the complete `go-strict` policy plus the blocking
`apidiff/public-api` command. Changes to profile membership require an explicit
policy-lock update and the exact membership tests. Scanner overlap remains
additive: a finding from one tool cannot be suppressed because another tool
covers a similar category.

`v1.1.0` is the approved one-time compatibility reset from the unadopted
v1.0.0 contract. Future incompatible workflow inputs, configuration schemas,
evidence contracts, required check names, permissions, or policy behavior must
use a new major version.

Suppressions and policy exceptions are not routine fixes. A proven false
positive may use the reviewed, scoped, expiring contract in
[docs/exceptions.md](docs/exceptions.md). Blanket baselines, severity waivers,
and permanent exceptions are rejected.

Security vulnerabilities must be reported according to [SECURITY.md](SECURITY.md).
By submitting a contribution, you agree that it is licensed under Apache-2.0.
