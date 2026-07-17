/**
 * D5 perf calibration runner.
 *
 * Replicates the inner loop of the gate-check perf assertion in
 * test/composition/production-pipeline.test.ts (A6: default-off invariant)
 * and runs it 10 times to characterize the latency distribution of
 * evaluateCommitmentBoundary() on the current host.
 *
 * Used to derive the calibrated p50 + p99 bounds documented in
 * server/docs/perf-calibration.md and pinned in the test.
 *
 * Run:
 *   cd server && npx tsx scripts/calibrate-d5-perf.ts
 */

import {
  evaluateCommitmentBoundary,
  type CommitmentBoundaryRequest,
  type CommitmentBoundaryCtx,
} from "../src/policy-engine/commitment-boundary.js";
import { compileFixturePolicy } from "../src/policy-engine/compiler-fixture.js";
import type { CompiledPolicy } from "../src/policy-engine/types.js";
import { buildTestFortress } from "../test/agent-contract/fixture.js";

const AGENT_ID = "agent-alpha";
const COUNTERPARTY = "agent-beta";
const COMMITMENT_CLASS = "task-delegate";
const FORTRESS_ID = "fortress-pipeline-test";

function buildPolicy(): CompiledPolicy {
  return compileFixturePolicy({
    agent_id: AGENT_ID,
    fortress_id: FORTRESS_ID,
    policy_version: 1,
    source_english: `Agent ${AGENT_ID} may emit commitments of class ${COMMITMENT_CLASS}.`,
  });
}

function commitmentRequest(): CommitmentBoundaryRequest {
  return {
    agent_id: AGENT_ID,
    delegates_or_accepts: false, // matches the perf-test sample
    counterparty: COUNTERPARTY,
    bounded_scope: {
      deliverable: "writes a report",
      deadline_or_terminal: "2026-05-01T00:00:00Z",
      budget_ref: "budget-alpha",
    },
    commitment_class: COMMITMENT_CLASS,
  };
}

interface BatchStats {
  batch: number;
  p50: number;
  p90: number;
  p99: number;
  max: number;
  mean: number;
}

function runBatch(batchIndex: number): BatchStats {
  const f = buildTestFortress();
  const policy = buildPolicy();
  const ctx: CommitmentBoundaryCtx = {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: FORTRESS_ID,
  };
  const req = commitmentRequest();
  const samples: number[] = [];
  for (let i = 0; i < 1000; i++) {
    const t0 = performance.now();
    evaluateCommitmentBoundary(ctx, req);
    samples.push(performance.now() - t0);
  }
  samples.sort((a, b) => a - b);
  const p50 = samples[Math.floor(0.5 * samples.length)]!;
  const p90 = samples[Math.floor(0.9 * samples.length)]!;
  const p99 = samples[Math.floor(0.99 * samples.length)]!;
  const max = samples[samples.length - 1]!;
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  return { batch: batchIndex, p50, p90, p99, max, mean };
}

function summarize(label: string, batches: BatchStats[]): void {
  console.log(`\n=== ${label} ===`);
  console.log("batch  p50(ms)  p90(ms)  p99(ms)  max(ms)  mean(ms)");
  for (const b of batches) {
    console.log(
      `${String(b.batch).padStart(5)}  ${b.p50.toFixed(4).padStart(7)}  ${b.p90
        .toFixed(4)
        .padStart(7)}  ${b.p99.toFixed(4).padStart(7)}  ${b.max
        .toFixed(4)
        .padStart(7)}  ${b.mean.toFixed(4).padStart(8)}`
    );
  }
  const p50s = batches.map((b) => b.p50).sort((a, b) => a - b);
  const p99s = batches.map((b) => b.p99).sort((a, b) => a - b);
  const maxs = batches.map((b) => b.max).sort((a, b) => a - b);
  const stat = (arr: number[]) => ({
    min: arr[0]!,
    median: arr[Math.floor(arr.length / 2)]!,
    max: arr[arr.length - 1]!,
    mean: arr.reduce((a, b) => a + b, 0) / arr.length,
    stdev: Math.sqrt(
      arr.reduce(
        (acc, v) =>
          acc + Math.pow(v - arr.reduce((a, b) => a + b, 0) / arr.length, 2),
        0
      ) / arr.length
    ),
  });
  const sp50 = stat(p50s);
  const sp99 = stat(p99s);
  const smax = stat(maxs);
  console.log(
    `\n  Across ${batches.length} batches:`
  );
  console.log(
    `  p50  min=${sp50.min.toFixed(4)} median=${sp50.median.toFixed(
      4
    )} max=${sp50.max.toFixed(4)} mean=${sp50.mean.toFixed(
      4
    )} stdev=${sp50.stdev.toFixed(4)}`
  );
  console.log(
    `  p99  min=${sp99.min.toFixed(4)} median=${sp99.median.toFixed(
      4
    )} max=${sp99.max.toFixed(4)} mean=${sp99.mean.toFixed(
      4
    )} stdev=${sp99.stdev.toFixed(4)}`
  );
  console.log(
    `  max  min=${smax.min.toFixed(4)} median=${smax.median.toFixed(
      4
    )} max=${smax.max.toFixed(4)} mean=${smax.mean.toFixed(
      4
    )} stdev=${smax.stdev.toFixed(4)}`
  );
}

function runCondition(label: string): BatchStats[] {
  const batches: BatchStats[] = [];
  for (let i = 1; i <= 10; i++) {
    batches.push(runBatch(i));
  }
  summarize(label, batches);
  return batches;
}

console.log("D5 perf calibration: evaluateCommitmentBoundary()");
console.log("=================================================");
console.log(`Node ${process.version}`);
console.log(`Platform ${process.platform} ${process.arch}`);
console.log(`Date ${new Date().toISOString()}`);

// Condition (a): cold start + idle. Just runs.
runCondition("Condition A: cold start, idle host");

// Condition (b): warmed (re-run with cached optimizations).
runCondition("Condition B: warmed, idle host");

// Condition (c): under simulated CPU load. The caller must launch
// background CPU competition; this script just runs and reports.
runCondition("Condition C: caller-supplied CPU load");
