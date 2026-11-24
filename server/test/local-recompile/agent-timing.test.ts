// fail-before-exempt: acceptance over a tool absent on base
/**
 * The agent's other calls stay within the timing bound while a local job
 * runs. Two in-process servers, one idle and one in the world under test,
 * are called alternately (ABAB, each call kind alternating which world goes
 * first) over a fixed mix of calls; the absolute difference of per-kind
 * medians must stay at or under the bound for the kind's class. Calls that
 * write to disk and calls that do not have separate bounds and separate
 * positive controls. A class whose control does not trip is unmeasured, and
 * its comparisons fail.
 */
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, describe, expect, it, vi } from "vitest";
import { openWorld, type World, type WorldOptions } from "./helpers/armed-world.js";

vi.mock("../../src/intelligence/model-manifest.js", async (original) => {
  // Must match Q5E_PRIVATE_KEY in test/intelligence/q5e-fixtures.ts, which imports this module and so cannot be imported here.
  const { ed25519 } = await import("@noble/curves/ed25519");
  const key = ed25519.getPublicKey(new Uint8Array(32).fill(41));
  return { ...await original<typeof import("../../src/intelligence/model-manifest.js")>(), loadPinnedModelManifestKey: () => Uint8Array.from(key) };
});

/** Calls that do not write to disk: design 3.3's proposal (open question 3). */
export const TIMING_BOUND_MS = 0.5;
/** Twice the bound, so a working harness separates the control by construction. */
export const TIMING_CONTROL_SPIN_MS = 1.0;
/**
 * Calls that write to disk: about 2.8 times the largest idle-against-idle
 * difference measured on box 1 (1.77 ms, `timing-idle-vs-idle.log`, run 2 of LR-1b).
 */
export const TIMING_BOUND_DURABLE_MS = 5;
/** Twice the durable bound. */
export const TIMING_CONTROL_SPIN_DURABLE_MS = 10;
const WARM_UP_CALLS = 40;
const MEASURED_PAIRS = 200;
const HOUR_MS = 60 * 60 * 1_000;
// Boots, warm-up and 400 measured calls per comparison on a loaded machine.
const COMPARISON_TIMEOUT_MS = 600_000;

const RECORD = { namespace: "notes", key: "one", value: "short note about the plan" };
type Kind = "local_task" | "state_read" | "recall" | "recall_refused_by_schema";
type TimingClass = "durable" | "non_durable";
const MIX: Kind[] = ["local_task", "state_read", "recall", "recall_refused_by_schema"];
const CALLS: Record<Kind, [string, Record<string, unknown>]> = {
  local_task: ["sanctuary_local_task", { kind: "summarize", sources: { refs: [{ namespace: "notes", key: "one" }] }, instruction: "Summarize." }],
  state_read: ["state_read", { namespace: "notes", key: "one" }],
  // Answered by the handler in this world, with an audit row.
  recall: ["sanctuary_recall", { key: "one", opts: { namespace: "notes" } }],
  // An unknown field: the router's schema check answers before any audit row.
  recall_refused_by_schema: ["sanctuary_recall", { query: "plan" }],
};
const CLASS_OF: Record<Kind, TimingClass> = {
  local_task: "durable",
  state_read: "durable",
  recall: "durable",
  recall_refused_by_schema: "non_durable",
};
const BOUND: Record<TimingClass, number> = { durable: TIMING_BOUND_DURABLE_MS, non_durable: TIMING_BOUND_MS };

interface Timed {
  world: World;
  clock: { now: number };
}

const opened: World[] = [];
afterAll(async () => {
  for (const world of opened.splice(0).reverse()) await world.close();
});

async function open(options: WorldOptions, durableSpin = false): Promise<Timed> {
  const clock = { now: 1_800_000_000_000 };
  const world = await openWorld({
    ...options,
    seams: {
      ...options.seams,
      // Every local task call is admitted: the rate window moves two hours per call.
      clock: () => clock.now,
      ...(durableSpin ? { callHook: (state: string) => { if (state === "state_ACK") busyWait(TIMING_CONTROL_SPIN_DURABLE_MS); } } : {}),
    },
  });
  opened.push(world);
  return { world, clock };
}

function busyWait(ms: number): void {
  const until = process.hrtime.bigint() + BigInt(Math.round(ms * 1e6));
  while (process.hrtime.bigint() < until) { /* synchronous spin, on the server's event loop */ }
}

async function timeCall(timed: Timed, kind: Kind): Promise<number> {
  if (kind === "local_task") timed.clock.now += 2 * HOUR_MS;
  const [name, args] = CALLS[kind];
  const start = process.hrtime.bigint();
  await timed.world.server.callTool(name, args);
  return Number(process.hrtime.bigint() - start) / 1e6;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

type Comparison = Record<Kind, { a: number; b: number; diff: number }>;

/** Per call kind: median in world b minus median in world a, in milliseconds. */
async function compare(a: Timed, b: Timed): Promise<Comparison> {
  for (let i = 0; i < WARM_UP_CALLS; i += 1) {
    await timeCall(a, MIX[i % MIX.length]!);
    await timeCall(b, MIX[i % MIX.length]!);
  }
  const samples = Object.fromEntries(MIX.map((kind) => [kind, { a: [] as number[], b: [] as number[] }])) as Record<Kind, { a: number[]; b: number[] }>;
  for (let i = 0; i < MEASURED_PAIRS; i += 1) {
    const kind = MIX[i % MIX.length]!;
    // Each kind alternates which world goes first.
    if (Math.floor(i / MIX.length) % 2 === 0) {
      samples[kind].a.push(await timeCall(a, kind));
      samples[kind].b.push(await timeCall(b, kind));
    } else {
      samples[kind].b.push(await timeCall(b, kind));
      samples[kind].a.push(await timeCall(a, kind));
    }
  }
  const out = {} as Comparison;
  for (const kind of MIX) {
    const ma = median(samples[kind].a);
    const mb = median(samples[kind].b);
    out[kind] = { a: ma, b: mb, diff: mb - ma };
  }
  return out;
}

const report: Record<string, unknown> = {};
const controlTripped: Record<TimingClass, boolean> = { durable: false, non_durable: false };
afterAll(() => {
  // The result file records these medians and both controls' measured differences.
  process.stdout.write(`local-task timing medians (ms): ${JSON.stringify(report)}\n`);
});

describe.sequential("the agent's other calls while a local job runs", () => {
  it("the control for calls that write to disk trips: a spin of its size in one world is measured above its bound", async () => {
    const idle = await open({ records: [RECORD] });
    const spun = await open({ records: [RECORD] }, true);
    const result = await compare(idle, spun);
    report.durable_control = result;
    controlTripped.durable = Math.abs(result.local_task.diff) > TIMING_BOUND_DURABLE_MS;
    expect(Math.abs(result.local_task.diff), JSON.stringify(result)).toBeGreaterThan(TIMING_BOUND_DURABLE_MS);
  }, COMPARISON_TIMEOUT_MS);

  it("the control for calls that do not write to disk trips: a spin of its size in one world is measured above its bound", async () => {
    const idle = await open({ records: [RECORD] });
    const spun = await open({ records: [RECORD] });
    // Test-only: the spin runs only on the control world's own server transport, then the real send.
    const target = spun.world.server.runtime.server.transport;
    const send = InMemoryTransport.prototype.send;
    const spy = vi.spyOn(InMemoryTransport.prototype, "send").mockImplementation(function (this: InMemoryTransport, ...args: Parameters<typeof send>) {
      if (this === target) busyWait(TIMING_CONTROL_SPIN_MS);
      return send.apply(this, args);
    });
    try {
      const result = await compare(idle, spun);
      report.non_durable_control = result;
      controlTripped.non_durable = Math.abs(result.recall_refused_by_schema.diff) > TIMING_BOUND_MS;
      expect(Math.abs(result.recall_refused_by_schema.diff), JSON.stringify(result)).toBeGreaterThan(TIMING_BOUND_MS);
    } finally {
      spy.mockRestore();
    }
  }, COMPARISON_TIMEOUT_MS);

  it.each([
    ["a job streaming from the model", { records: [RECORD], fakeScript: { mode: "slow", delay_ms: 100, reply: "x".repeat(4_000) } }],
    ["a job refused at authority", { records: [RECORD], unarmed: true }],
  ] as Array<[string, WorldOptions]>)("with %s, each call kind stays within its bound", async (name, options) => {
    const idle = await open({ records: [RECORD] });
    const busy = await open(options);
    const result = await compare(idle, busy);
    report[name] = result;
    for (const kind of MIX) {
      const timingClass = CLASS_OF[kind];
      // A class whose control did not trip is unmeasured, never passed.
      expect.soft(controlTripped[timingClass], `${timingClass} control did not trip: unmeasured`).toBe(true);
      expect.soft(Math.abs(result[kind].diff), `${kind}: ${JSON.stringify(result)}`).toBeLessThanOrEqual(BOUND[timingClass]);
    }
  }, COMPARISON_TIMEOUT_MS);
});
