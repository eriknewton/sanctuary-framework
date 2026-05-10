# Test concurrency discipline (Sigma-6, Part B)

vitest runs test files in a worker pool. Tests that assert
wall-clock bounds (p50, p99, ReDoS deadlines) calibrate against an
isolated run, but a worker scheduled at the same instant as a heavy
file (crypto suites, ZK proofs, sidecar JSON-RPC harness) sees CPU
contention that can push the observed bound above the threshold.
Two flake classes have surfaced in production:

- `server/test/composition/production-pipeline.test.ts` — D5
  gate-check perf bound (`p99 < 5ms`, calibrated against isolated
  local at ~0.5ms; CI Linux headroom is generous). Fires roughly
  half of recent commits under vitest concurrency.
- `server/test/security/injection-detector.test.ts` — SEC-031 ReDoS
  bound (`elapsed < 2000ms` on a 20KB pathological input;
  algorithmic regex completes in single-digit ms in isolation).
  Same firing pattern.

Both bounds are correctly calibrated against the underlying
algorithm. The flakes are scheduling artifacts, not regressions.

## The rule

A test whose assertion includes a wall-clock bound (`expect(elapsed)
.toBeLessThan(...)`, `expect(p99).toBeLessThan(...)`, etc.) must do
one of:

1. **`{ retry: 2 }`** — vitest's per-test option. The runner retries
   the test up to two extra times on failure; a true regression
   (algorithm broken) will fail all three attempts, while a
   scheduling flake (transient contention) will pass on the retry.
   This is the established pattern in the codebase (see
   `dashboard.test.ts` `/v1.0` and `/dashboard` rate-limit tests).

2. **Generous bound** — pick a threshold ~10× the calibrated value
   so transient contention can't possibly cross it. Use this when
   the underlying property is "doesn't hang for tens of seconds"
   (e.g. catching ReDoS regressions) rather than "fast enough to
   meet user-visible latency targets."

3. **Sequential isolation** — for tests where contention is the
   primary source of flake, wrap the suite in `describe.sequential`
   so all `it`s in the block run one-at-a-time. Doesn't fix
   cross-file contention (the main concurrency source) but is
   cheap when within-file is the culprit.

Combine 1 and 2 when in doubt. Sigma-6 added `{ retry: 2 }` to D5
production-pipeline and SEC-031 ReDoS specifically.

## Cross-references

- `server/docs/test-port-discipline.md` — sibling discipline for
  port-collision flakes.
- `server/docs/perf-calibration.md` — Sigma-4 perf-calibration
  methodology + the source of the p50<1ms / p99<5ms bounds.
- vitest test options:
  https://vitest.dev/api/#test-options (the `retry` option lives
  here).

## Anti-patterns

- **Don't loosen the bound.** If a calibrated 5ms bound flakes
  under concurrency, the right fix is `{ retry: 2 }`, not
  `toBeLessThan(50)`. Loosening hides the calibration signal and
  lets real perf regressions slip through.
- **Don't disable concurrency globally.** vitest worker
  parallelism is the right default for the bulk of the suite (~
  300+ test files). Don't set `fileParallelism: false` in
  `vitest.config.ts` — fix the specific flaking tests instead.
- **Don't suppress with `.skip` or `.todo`.** A skipped perf-bound
  test stops catching the regression it was written to catch.

## Adding a new perf-bound test

Calibrate the bound in isolation, document the calibration in
`server/docs/perf-calibration.md`, then ship the test with
`{ retry: 2 }`:

```ts
it("operation X completes within calibrated bound", { retry: 2 }, () => {
  // Calibrated isolated: p99 ≈ 0.5ms; bound 5ms = 10× headroom.
  // Under vitest cross-file worker concurrency the bound can be
  // pressed; { retry: 2 } absorbs that without loosening the
  // calibration signal.
  const start = performance.now();
  doExpensiveThing();
  const elapsed = performance.now() - start;
  expect(elapsed).toBeLessThan(5);
});
```
