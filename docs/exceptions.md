# Finding Exceptions

Fixing the finding is the default. An exception is valid only for a proven
false positive or equivalent mutation that cannot be represented accurately by
the originating tool. Severity, effort, age, and an existing baseline are not
acceptable reasons.

An exception manifest is strict YAML:

```yaml
schema-version: 1
exceptions:
  - tool: staticcheck
    rule: SA1000
    fingerprint: sha256:0123456789abcdef
    scope: internal/parser.go
    rationale: Parser input is validated before this unreachable branch.
    owner: gomaja
    approval: gomaja/example#12
    created: 2026-08-01
    expires: 2026-08-18
    verification-tests:
      - internal/parser_test.go
```

Set the consumer `exceptions` field to the repository-relative manifest path.
The maximum lifetime is 90 days. Tool, rule, fingerprint, and smallest exact
scope form a one-to-one identity. Duplicate fingerprints, unused entries,
expired entries, future dates, missing approvals, broad scopes, or unmatched
inline suppressions fail the gate.

Renewal requires a new review of the current finding and a new expiry. Do not
extend an exception automatically during dependency updates.
