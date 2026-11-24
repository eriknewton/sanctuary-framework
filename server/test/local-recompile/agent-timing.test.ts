// fail-before-exempt: acceptance over a tool absent on base
/**
 * The agent's other calls stay within the timing bound while a local job
 * runs. Two in-process servers are called alternately (ABAB, each call kind
 * alternating which world goes first); the absolute difference of per-kind
 * medians must stay at or under the bound for the kind's class. Calls that
 * write to disk and calls refused before their handler have separate bounds
 * and separate positive controls. A class whose control does not trip is
 * unmeasured, and its comparisons fail.
 *
 * The two worlds of a comparison differ only in the hidden fact. With a job
 * streaming, the other world is idle and never runs a local job, and the
 * acknowledgement is compared against a world whose worker is stopped, so its
 * acknowledged calls start no job. With a job refused at authority, the other
 * world submits at the same cadence and its jobs are accepted and run to
 * commit, so the refusal is the only difference. Each comparison opens its own
 * worlds and closes them before the next.
 *
 * The latency comparisons run only in the serial timing gate (`npm run
 * test:timing`); the harness checks below them run in the default suite.
 */
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import type { OplogRow } from "../../src/local-recompile/oplog.js";
import { WORKER_QUEUE_PER_SEAT_MAX } from "../../src/local-recompile/limits.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { openWorld, operatorRows, type World, type WorldOptions } from "./helpers/armed-world.js";
import { isAlive, localTaskPid } from "./helpers/local-task-server.js";

vi.mock("../../src/intelligence/model-manifest.js", async (original) => {
  // Must match Q5E_PRIVATE_KEY in test/intelligence/q5e-fixtures.ts, which imports this module and so cannot be imported here.
  const { ed25519 } = await import("@noble/curves/ed25519");
  const key = ed25519.getPublicKey(new Uint8Array(32).fill(41));
  return { ...await original<typeof import("../../src/intelligence/model-manifest.js")>(), loadPinnedModelManifestKey: () => Uint8Array.from(key) };
});

/** Calls refused before their handler, which write nothing: design 3.3's proposal (open question 3). */
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
// The streaming acknowledgement comparison boots ACK_WORLD_PAIRS world pairs.
const AGGREGATE_TIMEOUT_MS = 1_200_000;

/** The serial timing gate's switch; set only by `npm run test:timing` in server/package.json. */
const TIMING_GATE = process.env.SANCTUARY_TIMING_GATE === "1";

const RECORD = { namespace: "notes", key: "one", value: "short note about the plan" };
type Kind = "local_task" | "state_read" | "recall" | "recall_refused_by_schema";
type TimingClass = "durable" | "non_durable";
/** The calls compared between two worlds; the local task's acknowledgement has its own comparison. */
const OTHER_KINDS: Kind[] = ["state_read", "recall", "recall_refused_by_schema"];
/**
 * Calls that write nothing. No call on this base reaches its handler without a write (the probe test
 * records the candidates), so the class holds a call refused before its handler only.
 */
const NON_DURABLE_KINDS: Kind[] = ["recall_refused_by_schema"];
/** Handler-reaching candidates for the class; each writes at least one row, so each is durable. */
const NON_DURABLE_CANDIDATES: Array<[string, Record<string, unknown>]> = [
  ["sanctuary_help", { intent: "save my timezone" }],
  ["sanctuary_capabilities", {}],
];
const CALLS: Record<Kind, [string, Record<string, unknown>]> = {
  local_task: ["sanctuary_local_task", { kind: "summarize", sources: { refs: [{ namespace: "notes", key: "one" }] }, instruction: "Summarize." }],
  state_read: ["state_read", { namespace: "notes", key: "one" }],
  // Answered by the handler in this world, with an audit row.
  recall: ["sanctuary_recall", { key: "one", opts: { namespace: "notes" } }],
  // An unknown field: the router's schema check answers before the handler and before any write.
  recall_refused_by_schema: ["sanctuary_recall", { query: "plan" }],
};
const CLASS_OF: Record<Kind, TimingClass> = {
  local_task: "durable",
  state_read: "durable",
  recall: "durable",
  recall_refused_by_schema: "non_durable",
};
const BOUND: Record<TimingClass, number> = { durable: TIMING_BOUND_DURABLE_MS, non_durable: TIMING_BOUND_MS };
/**
 * The streaming world's seat holds at most WORKER_QUEUE_PER_SEAT_MAX jobs, the streaming one included,
 * so one world pair makes that many calls in all: the starting call, one warm-up and the rest measured.
 * None is dropped as seat-full. The comparison is aggregated over fresh world pairs until each side
 * has at least ACK_MIN_SAMPLES.
 */
const ACK_WARM_UP_PAIRS = 1;
const ACK_MEASURED_PAIRS = WORKER_QUEUE_PER_SEAT_MAX - 1 - ACK_WARM_UP_PAIRS;
const ACK_MIN_SAMPLES = 24;
const ACK_WORLD_PAIRS = Math.ceil(ACK_MIN_SAMPLES / ACK_MEASURED_PAIRS);
// The refused comparison settles each world's jobs before each submission, so it is not seat-bound.
const REFUSED_ACK_MEASURED_PAIRS = ACK_MIN_SAMPLES;
// One submission per OTHER_KINDS.length + 1 calls, in both worlds of the refused comparison. The period
// is coprime with the number of kinds, so the job's work overlaps each kind's samples equally.
const SUBMIT_PERIOD = OTHER_KINDS.length + 1;
// The harness checks make a short run at the same cadence.
const HARNESS_CALLS = 3 * SUBMIT_PERIOD;
// One streaming call: 600 frames of 64 characters, one every 200 ms, is 120 s, longer than any measured
// window here and inside the per-call timeout's 120 s only at the very end.
const STREAM_FRAMES = 600;
const STREAM_FRAME_CHARS = 64;
const STREAM_DELAY_MS = 200;
const STREAMING: Record<string, unknown> = { mode: "slow", delay_ms: STREAM_DELAY_MS, reply: "x".repeat(STREAM_FRAMES * STREAM_FRAME_CHARS) };
const JOB_END_KINDS = new Set(["job_committed", "job_refused", "job_failed", "job_dropped", "job_indeterminate"]);
const JOB_WAIT_MS = 60_000;
const POLL_MS = 25;

interface Timed {
  world: World;
  clock: { now: number };
  /** Local task calls this world has made. */
  submitted: number;
  /** Before each call in this world, given the call's index in the run. */
  beforeCall?: (index: number) => Promise<unknown>;
}

let opened: World[] = [];
const stoppedPids = new Set<number>();

/** Close one world: a stopped worker is killed outright (its exit releases its jobs as dropped); no pid survives. */
async function closeWorld(world: World, failures: unknown[]): Promise<void> {
  const index = opened.indexOf(world);
  if (index >= 0) opened.splice(index, 1);
  const workerPid = localTaskPid(world.server.runtime);
  try {
    if (workerPid !== undefined && stoppedPids.has(workerPid) && isAlive(workerPid)) process.kill(workerPid, "SIGKILL");
    await world.close();
  } catch (error) {
    failures.push(error);
  }
  try {
    expect(isAlive(workerPid)).toBe(false);
    expect(isAlive(world.fake.pid)).toBe(false);
  } catch (error) {
    failures.push(error);
  }
}

async function closeAll(worlds: World[]): Promise<void> {
  const failures: unknown[] = [];
  for (const world of [...worlds].reverse()) await closeWorld(world, failures);
  if (failures.length > 0) throw failures[0];
}

afterEach(async () => {
  vi.restoreAllMocks();
  try {
    await closeAll([...opened]);
  } finally {
    opened = [];
    stoppedPids.clear();
  }
});

async function open(options: WorldOptions, control: { durableSpin?: boolean; stopWorker?: boolean } = {}): Promise<Timed> {
  const clock = { now: 1_800_000_000_000 };
  const world = await openWorld({
    ...options,
    seams: {
      ...options.seams,
      // Every local task call is admitted: the rate window moves two hours per call.
      clock: () => clock.now,
      ...(control.durableSpin ? { callHook: (state: string) => { if (state === "state_ACK") busyWait(TIMING_CONTROL_SPIN_DURABLE_MS); } } : {}),
    },
  });
  opened.push(world);
  // A stopped worker reads nothing: every acknowledged job stays in the channel and none starts.
  if (control.stopWorker) {
    const pid = localTaskPid(world.server.runtime)!;
    stoppedPids.add(pid);
    process.kill(pid, "SIGSTOP");
  }
  return { world, clock, submitted: 0 };
}

function busyWait(ms: number): void {
  const until = process.hrtime.bigint() + BigInt(Math.round(ms * 1e6));
  while (process.hrtime.bigint() < until) { /* synchronous spin, on the server's event loop */ }
}

async function call(timed: Timed, kind: Kind): Promise<string> {
  if (kind === "local_task") {
    timed.clock.now += 2 * HOUR_MS;
    timed.submitted += 1;
  }
  const [name, args] = CALLS[kind];
  return (await timed.world.server.callTool(name, args)).text;
}

async function timeCall(timed: Timed, kind: Kind, index: number): Promise<number> {
  await timed.beforeCall?.(index);
  const start = process.hrtime.bigint();
  await call(timed, kind);
  return Number(process.hrtime.bigint() - start) / 1e6;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
}

type Samples = Partial<Record<Kind, { a: number[]; b: number[] }>>;
type Comparison = Partial<Record<Kind, { a: number; b: number; diff: number; samples: number }>>;

/** Per call kind: every sample in world a and in world b, in milliseconds. */
async function sample(a: Timed, b: Timed, kinds: Kind[], warmUp = WARM_UP_CALLS, pairs = MEASURED_PAIRS): Promise<Samples> {
  for (let i = 0; i < warmUp; i += 1) {
    await timeCall(a, kinds[i % kinds.length]!, i);
    await timeCall(b, kinds[i % kinds.length]!, i);
  }
  const samples: Samples = Object.fromEntries(kinds.map((kind) => [kind, { a: [] as number[], b: [] as number[] }]));
  for (let i = 0; i < pairs; i += 1) {
    const kind = kinds[i % kinds.length]!;
    const slot = samples[kind]!;
    // Each kind alternates which world goes first.
    if (Math.floor(i / kinds.length) % 2 === 0) {
      slot.a.push(await timeCall(a, kind, warmUp + i));
      slot.b.push(await timeCall(b, kind, warmUp + i));
    } else {
      slot.b.push(await timeCall(b, kind, warmUp + i));
      slot.a.push(await timeCall(a, kind, warmUp + i));
    }
  }
  return samples;
}

/** Per call kind: median in world b minus median in world a. */
function summarize(samples: Samples): Comparison {
  const out: Comparison = {};
  for (const [kind, slot] of Object.entries(samples) as Array<[Kind, { a: number[]; b: number[] }]>) {
    const ma = median(slot.a);
    const mb = median(slot.b);
    out[kind] = { a: ma, b: mb, diff: mb - ma, samples: slot.a.length };
  }
  return out;
}

async function compare(a: Timed, b: Timed, kinds: Kind[], warmUp = WARM_UP_CALLS, pairs = MEASURED_PAIRS): Promise<Comparison> {
  return summarize(await sample(a, b, kinds, warmUp, pairs));
}

function sameRequest(row: OplogRow, id: string): boolean {
  return "request_id" in row.body && row.body.request_id === id;
}

async function jobRows(world: World): Promise<OplogRow[]> {
  return (await operatorRows(world)).filter((row) => row.kind.startsWith("job_"));
}

async function waitFor(world: World, predicate: (rows: OplogRow[]) => boolean, what: string): Promise<OplogRow[]> {
  const deadline = Date.now() + JOB_WAIT_MS;
  for (;;) {
    const rows = await operatorRows(world);
    if (predicate(rows)) return rows;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

/** Every job this world submitted has its end row; untimed, before the next call. */
async function settle(timed: Timed): Promise<void> {
  await waitFor(timed.world, (rows) => rows.filter((row) => JOB_END_KINDS.has(row.kind)).length >= timed.submitted, "every submitted job to end");
}

/** Before every SUBMIT_PERIOD-th call: settle this world's jobs, then submit one more. */
function submitAtCadence(timed: Timed): (index: number) => Promise<unknown> {
  return async (index) => {
    if (index % SUBMIT_PERIOD !== 0) return;
    await settle(timed);
    await call(timed, "local_task");
  };
}

/** Start the busy world's one job and wait until it is generating. */
async function startStreamingJob(busy: Timed): Promise<string> {
  const id = (JSON.parse(await call(busy, "local_task")) as { request_id: string }).request_id;
  await waitFor(busy.world, (rows) => rows.some((row) => row.kind === "result_pending" && sameRequest(row, id)), "the job to start generating");
  return id;
}

/** The streaming job is still generating: its results object is pending and it has no end row. */
async function expectStillGenerating(busy: Timed, id: string): Promise<void> {
  const rows = await operatorRows(busy.world);
  expect(rows.some((row) => row.kind === "result_pending" && sameRequest(row, id))).toBe(true);
  expect(rows.filter((row) => JOB_END_KINDS.has(row.kind) && sameRequest(row, id))).toEqual([]);
}

/** The streaming world dropped nothing as seat-full and only its one job ever started. */
async function expectOnlyTheStreamingJob(busy: Timed, id: string): Promise<void> {
  const rows = await jobRows(busy.world);
  expect(rows.filter((row) => row.kind === "job_dropped")).toEqual([]);
  expect(rows.filter((row) => row.kind === "job_started").map((row) => ("request_id" in row.body ? row.body.request_id : null))).toEqual([id]);
}

/** Every job in the control world committed and every job in the refused world was refused; none dropped. */
async function expectCadenceOutcomes(control: Timed, refused: Timed): Promise<void> {
  await settle(control);
  await settle(refused);
  const controlRows = await jobRows(control.world);
  const refusedRows = await jobRows(refused.world);
  expect(controlRows.filter((row) => row.kind === "job_committed").length).toBe(control.submitted);
  expect(refusedRows.filter((row) => row.kind === "job_refused").length).toBe(refused.submitted);
  expect([...controlRows, ...refusedRows].filter((row) => row.kind === "job_dropped")).toEqual([]);
}

/** Every write path the fortress storage has; a call that reaches none of them writes nothing. */
function storageWrites(): { count(): number } {
  const prototype = FilesystemStorage.prototype as unknown as Record<string, (...args: unknown[]) => unknown>;
  let writes = 0;
  for (const name of ["write", "writeStrict", "writeIfAbsentStrict", "delete"]) {
    const original = prototype[name];
    if (typeof original !== "function") continue;
    vi.spyOn(prototype, name).mockImplementation(function (this: unknown, ...args: unknown[]) {
      writes += 1;
      return original.apply(this, args);
    });
  }
  return { count: () => writes };
}

describe.sequential("the timing harness", () => {
  it("each call in the class that writes nothing reaches no storage write, and each handler-reaching candidate writes", async () => {
    const world = await open({ records: [RECORD] });
    const writes = storageWrites();
    for (const kind of NON_DURABLE_KINDS) {
      const before = writes.count();
      await world.world.server.callTool(...CALLS[kind]);
      expect(writes.count() - before, kind).toBe(0);
    }
    for (const [name, args] of NON_DURABLE_CANDIDATES) {
      const before = writes.count();
      const answer = await world.world.server.callTool(name, args);
      expect(answer.isError, name).toBe(false);
      expect(writes.count() - before, name).toBeGreaterThan(0);
    }
  }, COMPARISON_TIMEOUT_MS);

  it("with a job streaming, the idle world runs no job and the streaming world's seat holds every acknowledgement", async () => {
    const busy = await open({ records: [RECORD], fakeScript: STREAMING });
    const id = await startStreamingJob(busy);
    const idle = await open({ records: [RECORD] });
    for (let i = 0; i < HARNESS_CALLS; i += 1) {
      await call(idle, OTHER_KINDS[i % OTHER_KINDS.length]!);
      await call(busy, OTHER_KINDS[i % OTHER_KINDS.length]!);
    }
    expect(await jobRows(idle.world)).toEqual([]);
    const stopped = await open({ records: [RECORD] }, { stopWorker: true });
    for (let i = 0; i < WORKER_QUEUE_PER_SEAT_MAX - 1; i += 1) {
      await call(stopped, "local_task");
      await call(busy, "local_task");
    }
    expect((await jobRows(stopped.world)).filter((row) => row.kind === "job_started")).toEqual([]);
    await expectStillGenerating(busy, id);
    await expectOnlyTheStreamingJob(busy, id);
    await closeAll([busy, idle, stopped].map((timed) => timed.world));
  }, COMPARISON_TIMEOUT_MS);

  it("with a job refused at authority, the other world submits at the same cadence and its jobs commit", async () => {
    const refused = await open({ records: [RECORD], unarmed: true });
    const control = await open({ records: [RECORD] });
    refused.beforeCall = submitAtCadence(refused);
    control.beforeCall = submitAtCadence(control);
    for (let i = 0; i < HARNESS_CALLS; i += 1) {
      await timeCall(control, OTHER_KINDS[i % OTHER_KINDS.length]!, i);
      await timeCall(refused, OTHER_KINDS[i % OTHER_KINDS.length]!, i);
    }
    expect(control.submitted).toBe(refused.submitted);
    expect(control.submitted).toBe(HARNESS_CALLS / SUBMIT_PERIOD);
    await expectCadenceOutcomes(control, refused);
    await closeAll([refused, control].map((timed) => timed.world));
  }, COMPARISON_TIMEOUT_MS);
});

const report: Record<string, unknown> = {};
const controlTripped: Record<TimingClass, boolean> = { durable: false, non_durable: false };
afterAll(() => {
  // The result file records these medians and both controls' measured differences.
  if (TIMING_GATE) process.stdout.write(`local-task timing medians (ms): ${JSON.stringify(report)}\n`);
});

function expectWithinBounds(result: Comparison): void {
  for (const [kind, measured] of Object.entries(result) as Array<[Kind, { diff: number }]>) {
    const timingClass = CLASS_OF[kind];
    // A class whose control did not trip is unmeasured, never passed.
    expect.soft(controlTripped[timingClass], `${timingClass} control did not trip: unmeasured`).toBe(true);
    expect.soft(Math.abs(measured.diff), `${kind}: ${JSON.stringify(result)}`).toBeLessThanOrEqual(BOUND[timingClass]);
  }
}

// The default suite cannot measure latency under its own load (some 280 files share four CPUs, here and
// in CI), so these comparisons run only in the serial gate; the claim's evidence is the recorded serial
// runs on box 1. DEBT(LOCAL-TIMING-GATE-NOT-IN-CI)
describe.runIf(TIMING_GATE).sequential("the agent's other calls while a local job runs", () => {
  it("the control for calls that write to disk trips: a spin of its size in one world is measured above its bound", async () => {
    // Both workers are stopped, so neither world runs a job while the control is measured.
    const idle = await open({ records: [RECORD] }, { stopWorker: true });
    const spun = await open({ records: [RECORD] }, { durableSpin: true, stopWorker: true });
    const result = await compare(idle, spun, ["local_task"], 4, 20);
    report.durable_control = result;
    controlTripped.durable = Math.abs(result.local_task!.diff) > TIMING_BOUND_DURABLE_MS;
    expect(Math.abs(result.local_task!.diff), JSON.stringify(result)).toBeGreaterThan(TIMING_BOUND_DURABLE_MS);
  }, COMPARISON_TIMEOUT_MS);

  it("the control for calls that write nothing trips: a spin of its size in one world is measured above its bound", async () => {
    const idle = await open({ records: [RECORD] });
    const spun = await open({ records: [RECORD] });
    // Test-only: the spin runs only on the control world's own server transport, then the real send.
    const target = spun.world.server.runtime.server.transport;
    const send = InMemoryTransport.prototype.send;
    vi.spyOn(InMemoryTransport.prototype, "send").mockImplementation(function (this: InMemoryTransport, ...args: Parameters<typeof send>) {
      if (this === target) busyWait(TIMING_CONTROL_SPIN_MS);
      return send.apply(this, args);
    });
    const result = await compare(idle, spun, NON_DURABLE_KINDS);
    report.non_durable_control = result;
    controlTripped.non_durable = NON_DURABLE_KINDS.every((kind) => Math.abs(result[kind]!.diff) > TIMING_BOUND_MS);
    for (const kind of NON_DURABLE_KINDS) expect(Math.abs(result[kind]!.diff), JSON.stringify(result)).toBeGreaterThan(TIMING_BOUND_MS);
  }, COMPARISON_TIMEOUT_MS);

  it("with a job streaming from the model, each call kind stays within its bound", async () => {
    const busy = await open({ records: [RECORD], fakeScript: STREAMING });
    const id = await startStreamingJob(busy);
    const idle = await open({ records: [RECORD] });
    expect(await jobRows(idle.world)).toEqual([]);
    const others = await compare(idle, busy, OTHER_KINDS);
    // The idle world ran no job, and the busy world's one job streamed through the whole window.
    expect(await jobRows(idle.world)).toEqual([]);
    await expectStillGenerating(busy, id);
    await expectOnlyTheStreamingJob(busy, id);
    await closeAll([idle, busy].map((timed) => timed.world));

    // The acknowledgement itself, against a world whose acknowledged calls start no job, over fresh
    // world pairs: each streaming world's seat allows ACK_MEASURED_PAIRS samples a side.
    const acks: { a: number[]; b: number[] } = { a: [], b: [] };
    for (let pair = 0; pair < ACK_WORLD_PAIRS; pair += 1) {
      const streaming = await open({ records: [RECORD], fakeScript: STREAMING });
      const streamId = await startStreamingJob(streaming);
      const stopped = await open({ records: [RECORD] }, { stopWorker: true });
      const measured = (await sample(stopped, streaming, ["local_task"], ACK_WARM_UP_PAIRS, ACK_MEASURED_PAIRS)).local_task!;
      acks.a.push(...measured.a);
      acks.b.push(...measured.b);
      expect((await jobRows(stopped.world)).filter((row) => row.kind === "job_started")).toEqual([]);
      await expectStillGenerating(streaming, streamId);
      // No warm-up or measured call was dropped as seat-full.
      await expectOnlyTheStreamingJob(streaming, streamId);
      await closeAll([stopped, streaming].map((timed) => timed.world));
    }
    expect(acks.a.length).toBeGreaterThanOrEqual(ACK_MIN_SAMPLES);
    const ackComparison = summarize({ local_task: acks });
    report["a job streaming from the model"] = { ...others, ...ackComparison };
    expectWithinBounds({ ...others, ...ackComparison });
  }, AGGREGATE_TIMEOUT_MS);

  it("with a job refused at authority, each call kind stays within its bound", async () => {
    const refused = await open({ records: [RECORD], unarmed: true });
    const control = await open({ records: [RECORD] });
    refused.beforeCall = submitAtCadence(refused);
    control.beforeCall = submitAtCadence(control);
    const others = await compare(control, refused, OTHER_KINDS);
    expect(control.submitted).toBe(refused.submitted);
    await expectCadenceOutcomes(control, refused);

    // The acknowledgement itself: every call submits, after each world's previous job has ended.
    refused.beforeCall = () => settle(refused);
    control.beforeCall = () => settle(control);
    const acks = await compare(control, refused, ["local_task"], ACK_WARM_UP_PAIRS, REFUSED_ACK_MEASURED_PAIRS);
    expect(control.submitted).toBe(refused.submitted);
    await expectCadenceOutcomes(control, refused);
    report["a job refused at authority"] = { ...others, ...acks };
    expectWithinBounds({ ...others, ...acks });
  }, COMPARISON_TIMEOUT_MS);
});
