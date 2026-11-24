// fail-before-exempt: acceptance over a tool absent on base
/**
 * Paired worlds through the real server and router. Two fortresses built the
 * same way, with the same id source, clock and seat, differ in one hidden
 * fact. The same calls in both must leave identical responses and identical
 * shared-log rows (count, operations, stored sizes, decrypted rows with the
 * timestamp masked, and the rows retention keeps), while each world's
 * operator log does differ, which shows the hidden fact reached the operator.
 */
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FORTRESS_STATE_DIRECTORY } from "../../src/core/custody-markers.js";
import type { OplogRow } from "../../src/local-recompile/oplog.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { isAlive } from "./helpers/local-task-server.js";
import { openWorld, waitForJobEnds, type World, type WorldOptions } from "./helpers/armed-world.js";

vi.mock("../../src/intelligence/model-manifest.js", async (original) => {
  // Must match Q5E_PRIVATE_KEY in test/intelligence/q5e-fixtures.ts, which imports this module and so cannot be imported here.
  const { ed25519 } = await import("@noble/curves/ed25519");
  const key = ed25519.getPublicKey(new Uint8Array(32).fill(41));
  return { ...await original<typeof import("../../src/intelligence/model-manifest.js")>(), loadPinnedModelManifestKey: () => Uint8Array.from(key) };
});

// Must match the four response literals in src/local-recompile/responses.ts (tool-responses.test.ts pins them).
const BUSY = '{"status":"busy"}';
const INVALID = '{"status":"invalid_input"}';
const UNAVAILABLE = '{"status":"unavailable"}';
const MINUTE_MS = 60_000;
const T0 = 1_800_000_000_000;
// A world boot, a few calls and the job ends, on a loaded machine.
const PAIR_TIMEOUT_MS = 240_000;
// Stored audit keys are `entry-<20-digit sequence>-...`.
const AUDIT_SEQ = /^entry-(\d{20})-/;

const RECORD = { namespace: "notes", key: "one", value: "short note about the plan" };
const VALID = { kind: "summarize", sources: { refs: [{ namespace: "notes", key: "one" }] }, instruction: "Summarize the main points." };
// Passes the router's schema (sources is an object) and fails the handler's strict check.
const HANDLER_INVALID = { kind: "summarize", sources: { refs: [{ namespace: "notes", key: "one", extra: "x" }] }, instruction: "Summarize." };
type Shape = "A1" | "A2";
const ARGS: Record<Shape, Record<string, unknown>> = { A1: VALID, A2: HANDLER_INVALID };
// Four admitted calls fill the minute, so the last A1 is answered busy.
const SCRIPT: Shape[] = ["A1", "A2", "A1", "A1", "A1", "A1"];

const opened: World[] = [];
afterEach(async () => {
  const failures: unknown[] = [];
  // Reverse order: each world restores the environment the one before it saw.
  for (const world of opened.splice(0).reverse()) {
    try { await world.close(); } catch (error) { failures.push(error); }
  }
  if (failures.length > 0) throw failures[0];
});

interface Clocked {
  world: World;
  clock: { now: number };
}

async function open(options: WorldOptions): Promise<Clocked> {
  const clock = { now: T0 };
  let ids = 0;
  const world = await openWorld({
    ...options,
    recordTime: T0,
    seams: {
      ...options.seams,
      clock: () => clock.now,
      idSource: () => (ids += 1).toString(16).padStart(32, "0"),
    },
  });
  opened.push(world);
  return { world, clock };
}

interface AuditRow { seq: number; size: number }

async function auditRows(world: World): Promise<AuditRow[]> {
  await world.server.runtime.auditLog.flush();
  const storage = new FilesystemStorage(join(world.storagePath, FORTRESS_STATE_DIRECTORY));
  return (await storage.list("_audit"))
    .map((entry) => ({ seq: Number(AUDIT_SEQ.exec(entry.key)?.[1] ?? Number.NaN), size: entry.size_bytes }))
    .sort((a, b) => a.seq - b.seq);
}

interface Measure {
  text: string;
  isError: boolean;
  items: number;
  added: number;
  operations: string[];
  sizes: number[];
  rows: unknown[];
  retained: number[];
}

/** One call and everything it left in the shared log, read with the server's own AuditLog after flush. */
async function measure(world: World, args: Record<string, unknown>): Promise<Measure> {
  const before = new Set((await auditRows(world)).map((row) => row.seq));
  const response = await world.server.call(args);
  const after = await auditRows(world);
  const added = after.filter((row) => !before.has(row.seq));
  const { entries } = await world.server.runtime.auditLog.query({ limit: 1_000 });
  const fresh = added.length === 0 ? [] : entries.slice(-added.length);
  return {
    text: response.text,
    isError: response.isError,
    items: response.items,
    added: added.length,
    operations: fresh.map((entry) => entry.operation),
    sizes: added.map((row) => row.size),
    // The timestamp is the one masked field: a persisted clock reading, not world state.
    rows: fresh.map((entry) => ({ ...entry, timestamp: "<masked>" })),
    retained: after.map((row) => row.seq),
  };
}

async function runScript(a: Clocked, b: Clocked, script: Shape[]): Promise<Array<[Measure, Measure]>> {
  const pairs: Array<[Measure, Measure]> = [];
  for (const shape of script) pairs.push([await measure(a.world, ARGS[shape]), await measure(b.world, ARGS[shape])]);
  return pairs;
}

// Must match LOCAL_REQUEST_SUBMITTED_OPERATION in src/local-recompile/tool.ts.
const SUBMITTED_OPERATION = "local_request_submitted";

function expectSameSharedView(pairs: Array<[Measure, Measure]>): void {
  pairs.forEach(([a, b], index) => {
    expect(b, `call ${index + 1}`).toEqual(a);
    expect(a.items, `call ${index + 1}`).toBe(1);
    expect(a.isError, `call ${index + 1}`).toBe(false);
    // Every added row is the gate's row for this tool, then the submission row on an acknowledgement;
    // none carries a denial cause.
    const submitted = a.text.startsWith('{"status":"submitted"');
    expect(a.operations, `call ${index + 1}`).toEqual(submitted ? [GATE_OPERATION, SUBMITTED_OPERATION] : [GATE_OPERATION]);
    for (const row of a.rows) expect(JSON.stringify(row), `call ${index + 1}`).not.toContain("denial_cause");
  });
}

// The gate's row for every call of this tool; must match the gate's audit operation in principal-policy/gate.ts.
const GATE_OPERATION = "gate_allow:sanctuary_local_task";

/**
 * The rest of the agent-visible tools that report counts, sizes or names, called in both worlds after
 * the script. Only the documented live presentation clocks are masked.
 */
const READ_TOOLS: Array<[string, Record<string, unknown>]> = [
  ["monitor_health", {}],
  ["state_list", { namespace: "notes" }],
  ["state_list", {}],
  ["sanctuary_help", { intent: "summarize my stored notes" }],
  ["sanctuary_capabilities", {}],
  ["identity_list", {}],
  ["castle_wall_liveness", {}],
];

/** Tools whose answers report the agent's own stored records: sizes and names. */
const RECORD_DEPENDENT = new Set(["monitor_health", "state_list"]);
/** Tools whose answers name per-fortress random identities; compared within each world only. */
const FORTRESS_SPECIFIC = new Set(["identity_list"]);
// The paired worlds are two fortresses, and each names its own fortress id (16 hex digits) in the
// Castle Wall socket path. The id is fixed for the fortress and set before any call, so it is masked.
const FORTRESS_ID = /fortress-[0-9a-f]{16}/g;

function maskLiveClocks(name: string, text: string): string {
  let value: unknown;
  try {
    value = JSON.parse(text.replace(FORTRESS_ID, "fortress-<masked>"));
  } catch {
    return text;
  }
  const walk = (node: unknown, inLiveness: boolean, top: boolean): unknown => {
    if (Array.isArray(node)) return node.map((item) => walk(item, inLiveness, false));
    if (node === null || typeof node !== "object") return node;
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const liveness = inLiveness || key === "castle_wall_liveness" || name === "castle_wall_liveness";
      if (name === "monitor_health" && top && key === "checked_at") out[key] = "<masked>";
      // Eight random bytes minted per call (cooperative-surface.ts audit()); it carries no world state.
      else if (key === "audit_ref" && typeof child === "string") out[key] = child.replace(/:[0-9a-f]{16}$/, ":<masked>");
      else if (liveness && (key === "evaluated_at" || key === "served_age_ms")) out[key] = "<masked>";
      else out[key] = walk(child, liveness, false);
    }
    return out;
  };
  return JSON.stringify(walk(value, name === "castle_wall_liveness", true));
}

async function readTools(world: Clocked, names: (name: string) => boolean): Promise<Array<{ tool: string; isError: boolean; text: string }>> {
  const out: Array<{ tool: string; isError: boolean; text: string }> = [];
  for (const [name, args] of READ_TOOLS) {
    if (!names(name)) continue;
    const answer = await world.world.server.callTool(name, args);
    out.push({ tool: `${name} ${JSON.stringify(args)}`, isError: answer.isError, text: maskLiveClocks(name, answer.text) });
  }
  return out;
}

/**
 * The rest of the agent's tools answer the same in both worlds. When the hidden fact is the agent's
 * own stored data, the tools that report those records are compared within each world instead
 * (before the script and after its jobs end), so the job's work shows in neither.
 */
async function expectSameReadTools(a: Clocked, b: Clocked, storedDataDiffers = false): Promise<void> {
  for (const [name, args] of READ_TOOLS) {
    if (FORTRESS_SPECIFIC.has(name) || (storedDataDiffers && RECORD_DEPENDENT.has(name))) continue;
    const left = await a.world.server.callTool(name, args);
    const right = await b.world.server.callTool(name, args);
    expect({ isError: right.isError, text: maskLiveClocks(name, right.text) }, `${name} ${JSON.stringify(args)}`)
      .toEqual({ isError: left.isError, text: maskLiveClocks(name, left.text) });
  }
}

/** Kind and body of each job row, with clocks and durations masked; the hidden fact shows up here. */
function operatorView(rows: OplogRow[]): unknown[] {
  return rows
    .filter((row) => row.kind.startsWith("job_") || row.kind.startsWith("result_"))
    .map((row) => ({ kind: row.kind, body: { ...row.body, ...("duration_ms" in row.body ? { duration_ms: 0 } : {}) } }));
}

async function killWorker(world: World): Promise<void> {
  const pid = world.server.runtime.localTask.workerPid();
  if (pid === undefined) throw new Error("no worker to kill");
  process.kill(pid, "SIGKILL");
  for (let i = 0; i < 100 && isAlive(pid); i += 1) await new Promise((resolve) => setTimeout(resolve, 20));
  expect(isAlive(pid)).toBe(false);
}

// Moves state_read from Tier 3 to Tier 1, so the record's namespace is not covered.
const stateReadTier1 = (text: string) =>
  text.replace("tier3_always_allow:\n  - state_read\n", "tier3_always_allow:\n").replace("tier1_always_approve:\n", "tier1_always_approve:\n  - state_read\n");

interface Pair {
  name: string;
  a: WorldOptions;
  b: WorldOptions;
  /** Runs in both worlds before the script; `world` is "a" or "b". */
  before?: (world: Clocked, which: "a" | "b") => Promise<void>;
  /** Jobs each world's operator log must show ended before the control compares them. */
  jobs: number;
  /** The hidden fact is the agent's own stored data, which its record tools report by design. */
  storedDataDiffers?: true;
}

const PAIRS: Pair[] = [
  { name: "record content", a: { records: [RECORD] }, b: { records: [{ ...RECORD, value: "a different and much longer note, ".repeat(40) }] }, jobs: 4, storedDataDiffers: true },
  { name: "record existence", a: { records: [RECORD] }, b: { records: [{ ...RECORD, key: "two" }] }, jobs: 4, storedDataDiffers: true },
  { name: "coverage", a: { records: [RECORD] }, b: { records: [RECORD], policy: stateReadTier1 }, jobs: 4 },
  { name: "model availability", a: { records: [RECORD] }, b: { records: [RECORD], fakeScript: { mode: "bad_digest" } }, jobs: 4 },
  {
    name: "worker alive or killed",
    a: { records: [RECORD] },
    b: { records: [RECORD] },
    before: async (world, which) => {
      if (which === "b") await killWorker(world.world);
    },
    jobs: 1,
  },
  {
    name: "a job running or idle",
    a: { records: [RECORD], fakeScript: { mode: "slow", delay_ms: 2_000 } },
    b: { records: [RECORD] },
    before: async (world, which) => {
      // The same earlier call in both worlds; only world b waits for its job to end.
      expect((await world.world.server.call(VALID)).text).toContain('"status":"submitted"');
      if (which === "b") await waitForJobEnds(world.world, 1);
      world.clock.now += 2 * MINUTE_MS;
    },
    jobs: 5,
  },
];

describe("the agent's view does not depend on a hidden fact", () => {
  it.each(PAIRS)("$name: same responses and shared log, different operator log", async (pair) => {
    const a = await open(pair.a);
    const b = await open(pair.b);
    const every = () => true;
    // Every read tool's answer in each world before anything else runs there.
    const toolsBefore = [await readTools(a, every), await readTools(b, every)];
    if (pair.before) {
      await pair.before(a, "a");
      await pair.before(b, "b");
    }
    const pairs = await runScript(a, b, SCRIPT);
    expectSameSharedView(pairs);
    expect(pairs.map(([m]) => m.text.startsWith('{"status":"submitted"') ? "A1" : m.text)).toEqual(["A1", INVALID, "A1", "A1", "A1", BUSY]);
    expect(pairs.map(([m]) => m.operations.length)).toEqual([2, 1, 2, 2, 2, 1]);
    await expectSameReadTools(a, b, pair.storedDataDiffers);

    // Control: the hidden fact did reach the operator side.
    const rowsA = await waitForJobEnds(a.world, pair.jobs);
    const rowsB = await waitForJobEnds(b.world, pair.jobs);
    // In each world, every read tool answers after its jobs ended exactly as before them.
    expect(await readTools(a, every)).toEqual(toolsBefore[0]);
    expect(await readTools(b, every)).toEqual(toolsBefore[1]);
    expect(operatorView(rowsB)).not.toEqual(operatorView(rowsA));
    // World a is the armed baseline: its jobs reach the model and commit.
    expect(rowsA.some((row) => row.kind === "job_committed")).toBe(true);
  }, PAIR_TIMEOUT_MS);

  // Every pair whose hidden fact is not about the worker, disarmed in both worlds.
  it.each(PAIRS.filter((pair) => pair.before === undefined))("disarmed, $name: the unavailable response and its rows do not depend on it", async (pair) => {
    const a = await open({ ...pair.a, seams: { ...pair.a.seams, spawnWorker: false } });
    const b = await open({ ...pair.b, seams: { ...pair.b.seams, spawnWorker: false } });
    const pairs = await runScript(a, b, SCRIPT);
    expectSameSharedView(pairs);
    expect(pairs.map(([m]) => m.text)).toEqual([UNAVAILABLE, INVALID, UNAVAILABLE, UNAVAILABLE, UNAVAILABLE, UNAVAILABLE]);
    expect(pairs.map(([m]) => m.operations.length)).toEqual([1, 1, 1, 1, 1, 1]);
    await expectSameReadTools(a, b, pair.storedDataDiffers);
  }, PAIR_TIMEOUT_MS);

  it.each([
    ["the entry cap", { maxEntries: 12 }],
    // The probe of this script measured about 10.7 KiB retained after two calls and 12.2 KiB after three.
    ["the size cap", { maxTotalSizeBytes: 11 * 1_024 }],
  ])("at %s both worlds prune the same rows", async (_name, auditLogConfig) => {
    const a = await open({ records: [RECORD], seams: { auditLogConfig } });
    const b = await open({ records: [{ ...RECORD, value: "a different and much longer note, ".repeat(40) }], seams: { auditLogConfig } });
    const before = await auditRows(a.world);
    const pairs = await runScript(a, b, SCRIPT);
    expectSameSharedView(pairs);
    const last = pairs.at(-1)![0].retained;
    // The threshold was crossed: rows retained before the script are gone.
    expect(before.some((row) => !last.includes(row.seq))).toBe(true);
  }, PAIR_TIMEOUT_MS);

  it("twenty interleaved calls leave the same shared log row for row", async () => {
    const a = await open({ records: [RECORD] });
    const b = await open({ records: [{ ...RECORD, value: "a different and much longer note, ".repeat(40) }] });
    const all: Array<[Measure, Measure]> = [];
    // Blocks of six (four admitted, one invalid, one busy), a new minute between blocks; 20 calls, 14 admitted, under the hourly 20.
    const calls: Shape[] = [...SCRIPT, ...SCRIPT, ...SCRIPT, "A1", "A2"];
    for (let i = 0; i < calls.length; i += SCRIPT.length) {
      all.push(...await runScript(a, b, calls.slice(i, i + SCRIPT.length)));
      a.clock.now += 2 * MINUTE_MS;
      b.clock.now += 2 * MINUTE_MS;
    }
    expect(all).toHaveLength(20);
    expectSameSharedView(all);
    const texts = new Set(all.map(([m]) => (m.text.startsWith('{"status":"submitted"') ? "A1" : m.text)));
    expect(texts).toEqual(new Set(["A1", INVALID, BUSY]));
  }, PAIR_TIMEOUT_MS);
});
