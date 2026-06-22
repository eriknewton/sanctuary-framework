# Test Coverage

Sanctuary's primary trust signal is the [Assurance Matrix](../ASSURANCE_MATRIX.md),
which maps each capability claim to evidence, a known gap, and the next proof
needed. Line/statement coverage is a complementary, quantitative signal: it
tells you how much of the server source the test suite executes, not whether the
security-critical paths are proven (the matrix answers that).

## How to measure

From `server/`:

```bash
npm run test:coverage
```

This runs the full vitest suite with the v8 coverage provider and writes:

- a human-readable summary to the terminal (text reporter),
- `server/coverage/coverage-summary.json` (machine-readable totals), and
- `server/coverage/lcov.info` + `server/coverage/lcov-report/` (standard lcov,
  for coverage viewers and uploaders).

Coverage scope is `src/**/*.ts`, excluding `src/cli.ts` (the thin CLI entry
shim). See `server/vitest.config.ts`.

No coverage threshold is enforced as a CI gate yet. Coverage is a reported
number, not a hard merge gate; adding a failing threshold is deferred so that a
flaky threshold cannot block CI. The hard gate today is the non-regressing
test-count guard (`.test-baseline`).

## Captured baseline (2026-06-15)

Measured locally on macOS against `main` at the pre-outreach-hygiene branch
point, with four test groups manually excluded from the run: the
`server/test/cli` directory (excluded wholesale as a flake-isolation
convenience: roughly a quarter of those tests shell out to the installed
`sanctuary` CLI or touch the live Castle Wall app on the measuring host; the
rest import `src` in-process), plus the MCP-child, template-tarball, and
transparency auditor-pack tests. All of these run green in Linux CI.

Because the capture excluded those groups, the plain `npm run test:coverage`
command above does **not** reproduce this exact table (a full run includes the
excluded groups, and on a macOS host with the Castle Wall app some of them
flake). Treat the numbers below as a point-in-time macOS-local **lower bound**
for orientation, not an exact whole-suite figure. The authoritative whole-suite
coverage should be regenerated in Linux CI.

| Metric | Coverage (macOS-local lower bound; 4 groups excluded) |
|---|---|
| Lines | 79.83% (90,675 / 113,577) |
| Statements | 79.83% (90,675 / 113,577) |
| Functions | 87.71% (4,713 / 5,373) |
| Branches | 78.93% (19,507 / 24,714) |

This is a point-in-time macOS-local capture for orientation, not a live or
authoritative figure. Regenerate the whole-suite number in Linux CI; do not
trust this table as current.
