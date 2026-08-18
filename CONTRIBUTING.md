# Contributing

Changes are made through pull requests against `main`. Run `make verify` before
opening a pull request. Changes to templates must include regenerated artifacts
from `make generate`.

Contributions must include focused tests and pass every applicable check with
zero open findings. New parsers and other untrusted input boundaries require
malformed-input tests and fuzz coverage. Workflow changes must keep every
third-party action pinned to a full commit SHA and preserve least-privilege
permissions.

Suppressions and policy exceptions are not routine fixes. A proven false
positive may use the reviewed, scoped, expiring contract in
[docs/exceptions.md](docs/exceptions.md). Blanket baselines, severity waivers,
and permanent exceptions are rejected.

Security vulnerabilities must be reported according to [SECURITY.md](SECURITY.md).
By submitting a contribution, you agree that it is licensed under Apache-2.0.
