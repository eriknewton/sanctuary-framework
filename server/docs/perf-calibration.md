# Perf calibration: gate-check (evaluateCommitmentBoundary)

This document explains how the perf bound at
`server/test/composition/production-pipeline.test.ts` (A6 default-off
invariant, "gate-check alone" test) was derived, what runs informed it,
and how to recalibrate when the test environment changes.

## What the test guards

The test exercises `evaluateCommitmentBoundary()` 10,000 times in a tight
loop and asserts that the per-call latency stays "negligible": that is,
that adding the gate-check to a cold tool invocation does not add
meaningful latency. The gate is on the hot path of every commitment
emission, so a regression of order 10x would meaningfully degrade the
agent contract surface.

The bound is a **regression guard, not a perf target**. A gate-check that
takes 1ms instead of 0.2ms is still negligible against a 10-100ms loaded
tool invocation. The bound exists to trap pathological slowdowns
(missing memoization, accidental quadratic behavior, repeated parsing of
the policy on every call, etc.).

## Harness shape

The test runs **10 outer batches of 1000 inner iterations each** and
computes the per-batch p50 and p99 latencies. It then takes the **best 8
of the 10** per-batch numbers, sorting ascending and asserting that
batch index 7 (the 8th-best) passes the bound. The 2 worst batches are
discarded.

This shape was chosen over the prior single-batch-of-1000 harness because
a single GC pause or scheduler preemption inside one batch puts a stray
multi-millisecond entry into the sorted samples and lands it at or near
the p99 slot, which is what produced the original CI flakes (Tau-1,
Upsilon-1, Tau-3, Upsilon-3 all hit `SKIP_TEST_BASELINE=1` overrides
because the same assertion fired non-deterministically across PR runs).

The best-of-8-of-10 pattern absorbs up to 2 noisy batches per test run
without weakening the regression signal. A real regression manifests as
a shift in the entire batch distribution, not as a one-off outlier; the
8th-best batch tracks distributional shifts faithfully because 8 of 10
batches still have to clear the bound.

## Calibrated bounds

| Bound | Value | Calibration basis |
|---|---|---|
| best-of-8-of-10 p50 | < 1 ms | Local p50 measured 0.23-0.25 ms across all conditions, stdev 0.003 ms. 1 ms is ~4x the observed worst-case median; tightens to a meaningful regression guard. |
| best-of-8-of-10 p99 | < 5 ms | Local p99 measured 0.40-0.74 ms across all conditions and pooled 40 batches, stdev ~0.07 ms. 5 ms is ~7-12x the observed worst p99 locally; preserves substantial CI headroom for slower runners and shared-tenant noise without inviting flakes. |

## Observed distributions

Calibration ran 2026-05-09 on Apple Silicon (Darwin arm64, Node v24.14.0)
with the harness in `server/scripts/calibrate-d5-perf.ts`. 10 batches per
condition, 4 conditions:

| Condition | p50 mean | p99 mean | p99 max | max mean | max worst |
|---|---|---|---|---|---|
| A: cold start, idle host | 0.234 ms | 0.470 ms | 0.568 ms | 0.819 ms | 1.391 ms |
| B: warmed, idle host | 0.236 ms | 0.502 ms | 0.712 ms | 1.004 ms | 2.478 ms |
| C: idle host (re-run) | 0.235 ms | 0.498 ms | 0.705 ms | 1.000 ms | 2.194 ms |
| D: 2x background CPU spinners | 0.247 ms | 0.531 ms | 0.745 ms | 1.394 ms | 5.313 ms |

p50 was rock-solid stable across all four conditions (stdev 0.003 ms).
p99 widened slightly under load (stdev rose from 0.045 ms to 0.076 ms).
Max showed the strongest sensitivity: a single 5.3 ms outlier appeared
under contention and is exactly the failure mode that the harness change
is designed to absorb.

## How to recalibrate

When the host environment changes (new CI runner image, new Node.js
version, hardware refresh, sustained perf complaint), re-run the
calibration:

```bash
cd server
npx vite-node scripts/calibrate-d5-perf.ts
```

The script prints per-batch p50/p90/p99/max plus a summary of variation
across batches per condition. To exercise the loaded condition, launch
2 background CPU spinners before running the script:

```bash
node -e 'function spin(){let x=0;for(let i=0;i<1e7;i++)x+=Math.sqrt(i);return x};while(true)spin();' &
node -e 'function spin(){let x=0;for(let i=0;i<1e7;i++)x+=Math.sqrt(i);return x};while(true)spin();' &
cd server && npx vite-node scripts/calibrate-d5-perf.ts
kill %1 %2
```

Update the bounds in
`server/test/composition/production-pipeline.test.ts` (A6 "gate-check
alone" test) and the table in this document if the calibrated worst-case
shifts by more than 50 percent.

## Audit trail

- 2026-05-09: initial calibration (Sigma-4 build) following four CI
  flakes on the original single-batch p99 < 5ms assertion. Switched
  harness to best-of-8-of-10 batches, kept numerical bounds.
- v1.0.2 backlog item (e) closed by this work.
