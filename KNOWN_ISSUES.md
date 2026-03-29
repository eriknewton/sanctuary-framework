# Known Issues

This file summarizes open items tracked from the security review conducted in March 2026.
All items are logged in detail in `REMEDIATION_PLAN.md` on the `security-review` branch.

## Security Posture

All Critical and High security findings from the March 2026 audit have been resolved and
independently evaluated. The merge gate was passed with 310/310 tests passing (+74 regression
tests added during the review).

## Open Items

### Functional Bugs (REMEDIATION_PLAN.md Section 2, HP-03 through HP-15)

Sixteen functional correctness issues identified during the audit are deferred to post-merge
development. These include cache staleness edge cases, bridge protocol incompleteness, and
off-by-one errors in boundary conditions. None create exploitable security vulnerabilities.
All are tracked with reproduction steps in BUG_REPORT.md on the `security-review` branch.

### Hardening Items (REMEDIATION_PLAN.md Section 4)

Ten Medium/Low security findings (SEC-004, SEC-006, SEC-013, SEC-015, SEC-017, SEC-018,
SEC-021, SEC-022, SEC-023, SEC-024) are deferred as defense-in-depth improvements. Notable items:

- **Dashboard rate limiting** — no rate limiting on approval endpoints
- **`reputation_export` tier asymmetry** — Tier 3 while `state_export` is Tier 1
- **Two dead config values** — `withhold-all` and `service-mediated` accepted but unimplemented
- **Bridge tool auth gaps** — `sanctuary_bridge_configure`, `sanctuary_bridge_commit`,
  `sanctuary_bridge_attest` missing auth gates (H-19 through H-21)

## Contributing

If you discover a security issue not listed here, please open a private security advisory
on GitHub rather than a public issue.
