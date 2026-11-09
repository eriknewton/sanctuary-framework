/**
 * The liveness observer cycle: record assembly and parity with the schema,
 * recovery and fault tracking judged by the shared evaluator, availability
 * deadlines, full-service and session fields, evidence failures, canary
 * integrity per cycle, and allow-sighting retention with its instance seed.
 */
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CANARY_WINDOW_BASE,
  EVIDENCE_FAILURES_MAX,
  HISTORY_WINDOW,
  IPC_DEADLINE,
  OBSERVER_PERIOD,
  RECOVERY_GAP,
  SECOND,
} from "../../../src/castle-wall/liveness/constants.js";
import { CensusSampler, CensusSeries } from "../../../src/castle-wall/liveness/census-sampler.js";
import { evaluateLiveness, type LivenessEnvelope } from "../../../src/castle-wall/liveness/evaluate.js";
import { generateCanaryPlist, parseSystemJobPrint } from "../../../src/castle-wall/liveness/launchd-plists.js";
import {
  EvidenceFailureSet,
  LivenessObserver,
  agentCycleClean,
  resolvedSeedRead,
  wallCycleClean,
  type AvailabilityStatus,
  type ObserverCollectors,
} from "../../../src/castle-wall/liveness/observer.js";
import { parseProcessRead, type ProcessRow } from "../../../src/castle-wall/liveness/process-census.js";
import { OBSERVER_AGENT_RAW, OBSERVER_WALL_RAW, parseObserverRecord } from "../../../src/castle-wall/liveness/schema.js";
import * as fullAgent from "../../../src/cli/castle-wall-full-agent.js";
import { BoundedChildRunner, createWatchCollectors, type WatchChild, type WatchSpawn } from "../../../src/cli/castle-wall-watch-collectors.js";

vi.mock("../../../src/cli/castle-wall-full-agent.js", async importOriginal => {
  const original = await importOriginal<typeof import("../../../src/cli/castle-wall-full-agent.js")>();
  return { ...original, observeJob: vi.fn(original.observeJob) };
});

// ---------------------------------------------------------------------------
// World harness: fixture values only.
// ---------------------------------------------------------------------------
const FIX = join(__dirname, "fixtures");
const STATES = JSON.parse(readFileSync(join(FIX, "states.json"), "utf8"));
const PRINTS = JSON.parse(readFileSync(join(FIX, "launchctl-print.json"), "utf8")).entries;
const NETSTAT = readFileSync(join(FIX, "census", "netstat-anv-macos26.txt"), "utf8");
const PS_TEXT = (JSON.parse(readFileSync(join(FIX, "process-census.json"), "utf8")) as { text: string }).text;
const BASE_NOW: number = STATES.base.nowMs;
const BASE_UP: number = STATES.base.host.uptimeMs;
const FORTRESS_ID: string = STATES.base.local.fortress_id;
const OPERATOR: number = STATES.base.local.operator_uid;
const AGENT_UID = 502;
const ACCOUNT = "sanctuary-agent-fixture";
const iso = (ms: number) => new Date(ms).toISOString();
const psRows = (text = PS_TEXT): ProcessRow[] => { const p = parseProcessRead(text); if (p.status !== "ok") throw new Error("fixture"); return p.rows; };
const passingFacts = () => ({
  plistStat: { status: "ok" as const, value: { isFile: true, isSymbolicLink: false, uid: 0, gid: 0, mode: 0o100644, size: Buffer.byteLength(generateCanaryPlist(ACCOUNT)) } },
  plistBytes: { status: "ok" as const, value: Buffer.from(generateCanaryPlist(ACCOUNT)) },
  account: { status: "ok" as const, value: { name: ACCOUNT, reverseUid: AGENT_UID } },
  print: { status: "ok" as const, value: parseSystemJobPrint(PRINTS.canary_system.stdout) },
});

type CollectorName = keyof ObserverCollectors;
class World {
  now = BASE_NOW;
  uptime = BASE_UP;
  boot = "boot-fixture-current";
  canaryAt: number | null = null;
  allowed: { captured_at_ms: number; principal: string } | null = null;
  daemonInstance = "daemon-fixture-1";
  daemonPresent = true;
  daemonSequence = 100;
  config: Record<string, unknown> = structuredClone(STATES.base.config.value);
  observerRecord: unknown = null;
  availability: AvailabilityStatus | "reject" | "hang" = "live";
  fail = new Set<CollectorName>();
  facts = passingFacts();
  fullState: { latched: boolean; charges_ms: number[] } | null = null;
  fullPid: number | null = 4242;
  fullLoaded = true;
  processes: [ProcessRow[], ProcessRow[]] = [psRows(), psRows()];
  published: Record<string, unknown>[] = [];
  publishFailNext = false;
  /** The shared reader hit its deadline: every record reads custody_invalid read_deadline. */
  recordsDeadline = false;

  constructor() { (this.config.commissioning as Record<string, unknown>).agent = false; }
  advance(ms: number): void { this.now += ms; this.uptime += ms; }

  daemonRecord(): Record<string, unknown> {
    const d = structuredClone(STATES.base.daemon.value);
    const at = this.now - SECOND;
    d.daemon_instance = this.daemonInstance;
    d.sequence = this.daemonSequence++;
    d.boot_id = this.boot;
    d.observed_at = iso(at);
    d.observed_uptime_ms = this.uptime - SECOND;
    d.collection = { started_at_ms: at, ended_at_ms: at };
    d.raw.detector.last_evaluate_at_ms = at;
    d.raw.heartbeat.last_durable_flush_at_ms = at;
    d.raw.canary.last_confirmation = this.canaryAt === null ? null : { ...d.raw.canary.last_confirmation, captured_at_ms: this.canaryAt, confirmed_at_ms: this.canaryAt + SECOND };
    d.raw.canary.last_destination_allowed = this.allowed;
    return d;
  }

  private gate<T>(name: CollectorName, value: () => T): Promise<T> {
    return this.fail.has(name) ? Promise.reject(new Error(`${name} failed`)) : Promise.resolve(value());
  }

  collectors(): ObserverCollectors {
    return {
      readRecords: () => this.gate("readRecords", () => this.recordsDeadline ? {
        directory: { status: "ok" as const },
        daemon: { status: "custody_invalid" as const, cause: "read_deadline" as const },
        observer: { status: "custody_invalid" as const, cause: "read_deadline" as const },
        config: { status: "custody_invalid" as const, cause: "read_deadline" as const },
        readDeadlineHit: true,
      } : {
        directory: { status: "ok" as const },
        daemon: this.daemonPresent ? { status: "present" as const, value: this.daemonRecord() } : { status: "absent" as const },
        observer: this.observerRecord === null ? { status: "absent" as const } : { status: "present" as const, value: structuredClone(this.observerRecord) },
        config: { status: "present" as const, value: structuredClone(this.config) },
        readDeadlineHit: false,
      }),
      readBootId: () => this.gate("readBootId", () => this.boot),
      queryAvailability: () => {
        if (this.availability === "reject") return Promise.reject(new Error("socket"));
        if (this.availability === "hang") return new Promise<AvailabilityStatus>(resolve => { setTimeout(() => resolve("live"), IPC_DEADLINE * 10); });
        return Promise.resolve(this.availability);
      },
      printFullAgent: () => this.gate("printFullAgent", () => ({ loaded: this.fullLoaded, pid: this.fullPid })),
      readFullAgentState: () => this.gate("readFullAgentState", () => this.fullState),
      readProcesses: () => this.gate("readProcesses", () => this.processes),
      printHarness: () => this.gate("printHarness", () => 75400),
      collectCanaryFacts: () => this.gate("collectCanaryFacts", () => structuredClone(this.facts)),
    };
  }

  envelope(record: unknown = this.observerRecord): LivenessEnvelope {
    return evaluateLiveness({
      nowMs: this.now, platform: "darwin", host: { ok: true, bootId: this.boot, uptimeMs: this.uptime },
      local: { fortress_id: FORTRESS_ID, platform: "darwin", operator_uid: OPERATOR }, directory: { status: "ok" },
      daemon: this.daemonPresent ? { status: "present", value: this.daemonRecord() } : { status: "absent" },
      observer: record === null ? { status: "absent" } : { status: "present", value: record },
      config: { status: "present", value: this.config },
    });
  }
}

const realTimers = {
  setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms),
  clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout),
  setInterval: (fire: () => void, ms: number) => setInterval(fire, ms),
  clearInterval: (h: unknown) => clearInterval(h as NodeJS.Timeout),
};

function observerFor(
  world: World, collectors: ObserverCollectors = world.collectors(), instance = "observer-test-1",
  runNetstat: () => Promise<{ status: "ok"; stdout: string } | { status: "failed" }> = async () => ({ status: "failed" }), samplers: CensusSampler[] = [],
) {
  const series = new CensusSeries();
  let observer: LivenessObserver | null = null;
  const sampler = new CensusSampler({
    series, runNetstat, context: () => observer!.samplingContext(),
    clock: { nowMs: () => world.now, uptimeMs: () => world.uptime }, timers: realTimers,
  });
  samplers.push(sampler);
  observer = new LivenessObserver({
    fortressId: FORTRESS_ID, hostId: "host-fixture", operatorUid: OPERATOR, collectors, sampler, series,
    publisher: {
      publish: async record => {
        if (world.publishFailNext) { world.publishFailNext = false; throw new Error("custody refused"); }
        const copy = JSON.parse(JSON.stringify(record));
        world.observerRecord = copy;
        world.published.push(copy);
      },
    },
    clock: { nowMs: () => world.now, uptimeMs: () => world.uptime }, timers: realTimers, instance,
  });
  return observer;
}

/** Run one cycle and let the handed-off publish settle. */
async function cycle(observer: LivenessObserver): Promise<Record<string, unknown>> {
  await observer.tick();
  await new Promise(resolve => setImmediate(resolve));
  return observer.latestRecord()!;
}
const wallRec = (r: Record<string, unknown>) => (r.recovery as { wall: { samples: unknown[]; fault_uptime_ms: number | null } }).wall;
const agentRec = (r: Record<string, unknown>) => (r.recovery as { agent: { samples: unknown[]; fault_uptime_ms: number | null } }).agent;
const raw = (r: Record<string, unknown>) => r.raw as Record<string, unknown>;
const failuresOf = (r: Record<string, unknown>) => r.evidence_failures as Array<{ component: string; reason: string }>;

/** First cycle, then a canary captured after it and clean cycles until the pair spans RECOVERY_GAP. */
async function recoverToOk(world: World, observer: LivenessObserver): Promise<void> {
  await cycle(observer);
  world.advance(OBSERVER_PERIOD);
  world.canaryAt = world.now - SECOND;
  for (let elapsed = 0; elapsed <= RECOVERY_GAP; elapsed += OBSERVER_PERIOD) {
    await cycle(observer);
    world.advance(OBSERVER_PERIOD);
  }
  world.advance(-OBSERVER_PERIOD);
}

afterEach(() => { vi.useRealTimers(); });

// ---------------------------------------------------------------------------
describe("record production", () => {
  it("publishes records the parser accepts, with the schema's raw key set, and reaches wall OK after the first-cycle fault", async () => {
    const world = new World();
    const observer = observerFor(world);
    await recoverToOk(world, observer);
    expect(world.published.length).toBeGreaterThanOrEqual(3);
    world.published.forEach((record, i) => {
      const parsed = parseObserverRecord(record);
      expect(parsed.ok && parsed.wall.ok && parsed.agent.ok, `record ${i}`).toBe(true);
      expect(record.observer_period_ms).toBe(OBSERVER_PERIOD);
      expect(record.sequence).toBe(i + 1);
      expect(Object.keys(raw(record)).sort()).toEqual([...OBSERVER_WALL_RAW, ...OBSERVER_AGENT_RAW].sort());
      expect(Object.keys(record.recovery as object).sort()).toEqual(["agent", "wall"]);
      expect(raw(record).session).toBe("full");
      expect(raw(record).optional_reply).toBeNull();
    });
    const env = world.envelope();
    expect(env.wall.state.startsWith("wall_OK_"), env.wall.reasons.join(",")).toBe(true);
  });

  it("consumes the sequence number of a failed publish, so the next published record skips it", async () => {
    const world = new World();
    const observer = observerFor(world);
    await cycle(observer);
    world.publishFailNext = true;
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    expect(world.published.map(r => r.sequence)).toEqual([1, 3]);
    expect(observer.stats().publishFailures).toBe(1);
  });

  it("publishes with no valid config: agent_uid null, integrity null, census unavailable, wall DOWN with canary_unprovisioned", async () => {
    const world = new World();
    world.config = { schema_version: 1, record: "nonsense" };
    const observer = observerFor(world);
    const record = await cycle(observer);
    expect((record.subject as { agent_uid: unknown }).agent_uid).toBeNull();
    expect(raw(record).canary_integrity).toBeNull();
    expect(raw(record).census).toEqual({ status: "unavailable", samples: [] });
    const env = world.envelope();
    expect(env.wall.state).toBe("wall_DOWN");
    expect(env.coverage.state).not.toBe("coverage_COMPLETE");
  });
});

describe("recovery and fault tracking", () => {
  it("stores no sample on the first cycle, one after it, a second only at RECOVERY_GAP, and clears on a fault", async () => {
    const world = new World();
    const observer = observerFor(world);
    const first = await cycle(observer);
    expect(wallRec(first)).toEqual({ samples: [], fault_uptime_ms: world.uptime });
    expect(agentRec(first)).toEqual({ samples: [], fault_uptime_ms: world.uptime });
    const faultAt = world.uptime;
    world.advance(OBSERVER_PERIOD);
    world.canaryAt = world.now - SECOND;
    const firstSampleUptime = world.uptime;
    expect(wallRec(await cycle(observer)).samples).toHaveLength(1);
    world.advance(RECOVERY_GAP - 1);
    expect(wallRec(await cycle(observer)).samples).toHaveLength(1);
    world.advance(1);
    const paired = await cycle(observer);
    expect(wallRec(paired)).toEqual({ samples: [{ sequence: 2, observed_uptime_ms: firstSampleUptime }, { sequence: 4, observed_uptime_ms: world.uptime }], fault_uptime_ms: faultAt });
    expect(world.envelope().wall.state.startsWith("wall_OK_")).toBe(true);
    world.advance(OBSERVER_PERIOD);
    world.fullLoaded = false;
    const faulted = await cycle(observer);
    expect(wallRec(faulted)).toEqual({ samples: [], fault_uptime_ms: world.uptime });
    world.fullLoaded = true;
    world.advance(OBSERVER_PERIOD);
    world.canaryAt = world.now - SECOND;
    await cycle(observer);
    expect(world.envelope().wall.state).toBe("wall_RECOVERING");
    world.advance(RECOVERY_GAP);
    await cycle(observer);
    expect(world.envelope().wall.state.startsWith("wall_OK_")).toBe(true);
  });

  it("an observer restart during a fault reads RECOVERING until a canary captured after the restart, even with an older one inside the window", async () => {
    const world = new World();
    await recoverToOk(world, observerFor(world));
    expect(world.envelope().wall.state.startsWith("wall_OK_")).toBe(true);
    const restarted = observerFor(world, world.collectors(), "observer-test-2");
    world.advance(OBSERVER_PERIOD);
    await cycle(restarted);
    for (let i = 0; i < 4; i++) {
      world.advance(OBSERVER_PERIOD);
      await cycle(restarted);
      expect(world.now - world.canaryAt!).toBeLessThan(CANARY_WINDOW_BASE);
      expect(world.envelope().wall.state).toBe("wall_RECOVERING");
    }
    world.canaryAt = world.now - SECOND;
    world.advance(RECOVERY_GAP);
    await cycle(restarted);
    expect(world.envelope().wall.state.startsWith("wall_OK_")).toBe(true);
  });

  it("applies the same rules to the agent component", async () => {
    const world = new World();
    (world.config.commissioning as Record<string, unknown>).agent = true;
    const samplers: CensusSampler[] = [];
    const observer = observerFor(world, world.collectors(), "observer-test-1", async () => ({ status: "ok", stdout: NETSTAT }), samplers);
    // Each cycle refreshes the census context, then one sampler attempt lands before the next cycle reads it.
    const step = async (ms: number) => { await samplers[0]!.tick(); world.advance(ms); return cycle(observer); };
    await cycle(observer);
    const faulted = await step(OBSERVER_PERIOD);
    expect(raw(faulted).census).toMatchObject({ status: "ok" });
    expect(agentRec(faulted)).toEqual({ samples: [], fault_uptime_ms: world.uptime });
    expect(agentCycleClean(world.envelope())).toBe(false);
    (world.config.commissioning as Record<string, unknown>).agent = false;
    expect(agentRec(await step(OBSERVER_PERIOD)).samples).toHaveLength(1);
    expect(agentRec(await step(RECOVERY_GAP - 1)).samples).toHaveLength(1);
    const paired = await step(1);
    expect(agentRec(paired).samples).toHaveLength(2);
    expect(agentRec(paired).fault_uptime_ms).not.toBeNull();
    (world.config.commissioning as Record<string, unknown>).agent = true;
    expect(agentRec(await step(OBSERVER_PERIOD))).toEqual({ samples: [], fault_uptime_ms: world.uptime });
  });
});

describe("clean predicate", () => {
  const env = (wall: string[], agent: string[]) => ({ wall: { reasons: wall }, agent: { reasons: agent } }) as unknown as LivenessEnvelope;
  it("counts exactly none or exactly recovering as wall-clean", () => {
    expect(wallCycleClean(env(["none"], []))).toBe(true);
    expect(wallCycleClean(env(["recovering"], []))).toBe(true);
    expect(wallCycleClean(env(["recovering", "canary_failed"], []))).toBe(false);
    expect(wallCycleClean(env(["initializing"], []))).toBe(false);
    expect(wallCycleClean(env(["canary_failed"], []))).toBe(false);
  });
  it("counts agent_unmonitored as agent-clean", () => {
    expect(agentCycleClean(env([], ["agent_unmonitored"]))).toBe(true);
    expect(agentCycleClean(env([], ["none"]))).toBe(true);
    expect(agentCycleClean(env([], ["initializing"]))).toBe(false);
    expect(agentCycleClean(env([], ["agent_unmonitored", "census_unavailable"]))).toBe(false);
  });
});

describe("availability", () => {
  it.each<[AvailabilityStatus | "reject", string]>([["live", "live"], ["non_green", "not_live"], ["undetermined", "not_live"], ["reject", "unresponsive"]])(
    "maps %s to %s", async (status, expected) => {
      const world = new World();
      world.availability = status;
      const record = await cycle(observerFor(world));
      expect((raw(record).availability as { status: string }).status).toBe(expected);
      if (expected === "unresponsive") expect((raw(record).availability as { resolved_at_ms: unknown }).resolved_at_ms).toBeNull();
    });

  it("reads an IPC_DEADLINE lapse as unresponsive and never lets the late resolution change the record", async () => {
    vi.useFakeTimers();
    const world = new World();
    world.availability = "hang";
    const timers = {
      setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout),
      setInterval: (fire: () => void, ms: number) => setInterval(fire, ms), clearInterval: (h: unknown) => clearInterval(h as NodeJS.Timeout),
    };
    const series = new CensusSeries();
    let observer: LivenessObserver | null = null;
    const sampler = new CensusSampler({ series, runNetstat: async () => ({ status: "failed" }), context: () => observer!.samplingContext(), clock: { nowMs: () => world.now, uptimeMs: () => world.uptime }, timers });
    observer = new LivenessObserver({
      fortressId: FORTRESS_ID, hostId: "h", operatorUid: OPERATOR, collectors: world.collectors(), sampler, series,
      publisher: { publish: async r => { world.published.push(JSON.parse(JSON.stringify(r))); } }, clock: { nowMs: () => world.now, uptimeMs: () => world.uptime }, timers,
    });
    const done = observer.tick();
    await vi.advanceTimersByTimeAsync(IPC_DEADLINE);
    await done;
    expect((raw(world.published[0]!).availability as { status: string }).status).toBe("unresponsive");
    const before = JSON.stringify(world.published);
    await vi.advanceTimersByTimeAsync(IPC_DEADLINE * 10);
    expect(JSON.stringify(world.published)).toBe(before);
  });
});

describe("full service and session", () => {
  function spawnFor(answers: Record<string, { code: number; stdout: string; stderr?: string }>, argv: string[][]): WatchSpawn {
    return (file, args) => {
      argv.push([file, ...args]);
      const child = Object.assign(new EventEmitter(), { pid: 3000 + argv.length, stdout: new EventEmitter(), stderr: new EventEmitter() }) as unknown as WatchChild & EventEmitter & { stdout: EventEmitter };
      child.kill = () => true;
      const a = answers[file] ?? { code: 1, stdout: "" };
      queueMicrotask(() => { child.stdout.emit("data", Buffer.from(a.stdout)); child.emit("exit", a.code, null); child.emit("close", a.code, null); });
      return child;
    };
  }

  it("reads loaded and pid through the runner and parseFullAgentPrint, latched and the maximum charge from the state, start identity from ps, and never observeJob", async () => {
    const argv: string[][] = [];
    const runner = new BoundedChildRunner({ spawn: spawnFor({ "/bin/launchctl": PRINTS.full_agent_gui, "/usr/sbin/sysctl": { code: 0, stdout: "boot-fixture-current\n" } }, argv), timers: realTimers });
    const real = createWatchCollectors({ runner, timers: realTimers, fortressPath: "/nonexistent-fixture", operatorUid: OPERATOR });
    expect(await real.printFullAgent()).toEqual({ loaded: true, pid: 4242 });
    expect(await real.readBootId()).toBe("boot-fixture-current");
    expect(argv).toContainEqual(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"]);
    expect(argv).toContainEqual(["/bin/launchctl", "print", `gui/${OPERATOR}/${fullAgent.FULL_AGENT_LABEL}`]);
    const world = new World();
    world.fullState = { latched: true, charges_ms: [BASE_NOW - 3000, BASE_NOW - 1000, BASE_NOW - 2000] };
    const record = await cycle(observerFor(world, { ...world.collectors(), printFullAgent: () => real.printFullAgent(), readBootId: () => real.readBootId() }));
    expect(raw(record).full_service).toEqual({ loaded: true, latched: true, pid: 4242, start_identity: "Sun Nov 9 07:45:10 2026", last_charge_at_ms: BASE_NOW - 1000 });
    expect(vi.mocked(fullAgent.observeJob)).not.toHaveBeenCalled();
  });

  it("treats a printable sysctl boot that the publication claim cannot carry as a failed boot read", async () => {
    // A boot the claim grammar rejects would otherwise reach the publisher and become a null-boot claim.
    for (const stdout of ["boot invalid\n", "boot/slash\n", "boot:colon\n"]) {
      const runner = new BoundedChildRunner({ spawn: spawnFor({ "/usr/sbin/sysctl": { code: 0, stdout } }, []), timers: realTimers });
      const real = createWatchCollectors({ runner, timers: realTimers, fortressPath: "/nonexistent-fixture", operatorUid: OPERATOR });
      await expect(real.readBootId(), stdout).rejects.toThrow(/boot id read failed/);
    }
    const runner = new BoundedChildRunner({ spawn: spawnFor({ "/usr/sbin/sysctl": { code: 0, stdout: "6F3A1C2E-9B4D-4E7A-8C21-0D5E6F7A8B9C\n" } }, []), timers: realTimers });
    const real = createWatchCollectors({ runner, timers: realTimers, fortressPath: "/nonexistent-fixture", operatorUid: OPERATOR });
    expect(await real.readBootId()).toBe("6F3A1C2E-9B4D-4E7A-8C21-0D5E6F7A8B9C");
  });

  it("gives start_identity null for a pid absent from ps, which reads process_identity_unknown", async () => {
    const world = new World();
    world.processes = [psRows().filter(r => r.pid !== 4242), psRows().filter(r => r.pid !== 4242)];
    const record = await cycle(observerFor(world));
    expect((raw(record).full_service as { start_identity: unknown }).start_identity).toBeNull();
    expect(world.envelope().wall.reasons).toContain("process_identity_unknown");
  });

  it("always publishes session full; the full service unloaded reads wall DOWN daemon_missing, never OK", async () => {
    const world = new World();
    const observer = observerFor(world);
    await recoverToOk(world, observer);
    world.fullLoaded = false;
    world.fullPid = null;
    world.advance(OBSERVER_PERIOD);
    const record = await cycle(observer);
    expect(raw(record).session).toBe("full");
    const env = world.envelope();
    expect(env.wall.state).toBe("wall_DOWN");
    expect(env.wall.reasons).toContain("daemon_missing");
  });
});

describe("evidence failures", () => {
  it.each<[CollectorName, string, string]>([
    ["readRecords", "wall", "observation_invalid"],
    ["readBootId", "wall", "time_untrusted"],
    ["printFullAgent", "wall", "observation_invalid"],
    ["readFullAgentState", "wall", "observation_invalid"],
    ["readProcesses", "wall", "process_identity_unknown"],
    ["collectCanaryFacts", "wall", "canary_unprovisioned"],
  ])("a %s failure gives %s %s and still publishes once the instance start has resolved", async (name, component, reason) => {
    const world = new World();
    const observer = observerFor(world);
    await cycle(observer);
    world.fail.add(name);
    world.advance(OBSERVER_PERIOD);
    const record = await cycle(observer);
    expect(failuresOf(record)).toContainEqual({ component, reason });
    expect(world.published).toHaveLength(2);
  });

  it("an availability failure gives one daemon_unresponsive entry and a harness failure an agent observation_invalid", async () => {
    const world = new World();
    world.availability = "reject";
    world.config.mcp = { harness_label: "ai.sanctuaryprotocol.agent-harness", script_paths: ["/opt/agent-fixture/mcp/server.js"] };
    world.fail.add("printHarness");
    const record = await cycle(observerFor(world));
    expect(failuresOf(record).filter(f => f.reason === "daemon_unresponsive")).toEqual([{ component: "wall", reason: "daemon_unresponsive" }]);
    expect(failuresOf(record)).toContainEqual({ component: "agent", reason: "observation_invalid" });
    expect(raw(record).mcp).toBeNull();
  });

  it("keeps 1000 all-failure cycles bounded, deduplicated and published", async () => {
    const world = new World();
    const observer = observerFor(world);
    // The instance start resolves first; from then on every cycle publishes whatever fails.
    await cycle(observer);
    world.advance(OBSERVER_PERIOD);
    for (const name of ["readRecords", "readBootId", "printFullAgent", "readFullAgentState", "readProcesses", "collectCanaryFacts", "printHarness"] as const) world.fail.add(name);
    world.availability = "reject";
    for (let i = 0; i < 1000; i++) {
      const record = await cycle(observer);
      const failures = failuresOf(record);
      expect(failures.length).toBeLessThanOrEqual(EVIDENCE_FAILURES_MAX);
      expect(new Set(failures.map(f => `${f.component}:${f.reason}`)).size).toBe(failures.length);
      world.advance(OBSERVER_PERIOD);
    }
    expect(world.published).toHaveLength(1001);
  });

  it("saturates overflow into one observation_invalid entry per component", () => {
    const set = new EvidenceFailureSet();
    for (let i = 0; i < EVIDENCE_FAILURES_MAX * 3; i++) { set.add("wall", `reason_${i}`); set.add("agent", `reason_${i}`); }
    set.add("wall", "reason_0");
    const list = set.list();
    expect(list.length).toBe(EVIDENCE_FAILURES_MAX);
    expect(list.filter(f => f.component === "wall" && f.reason === "observation_invalid")).toHaveLength(1);
    expect(list.filter(f => f.component === "agent" && f.reason === "observation_invalid")).toHaveLength(1);
  });
});

describe("canary integrity through the observer and the evaluator", () => {
  it("reads integrity false with a fresh accepted drop as wall DOWN canary_unprovisioned and coverage UNAVAILABLE, never canary_failed", async () => {
    const world = new World();
    const observer = observerFor(world);
    await recoverToOk(world, observer);
    world.facts.plistStat.value.mode = 0o100664;
    world.advance(OBSERVER_PERIOD);
    world.canaryAt = world.now - SECOND;
    const record = await cycle(observer);
    expect(raw(record).canary_integrity).toEqual({ passed: false, checked_at_ms: world.now });
    const env = world.envelope();
    expect(env.wall.state).toBe("wall_DOWN");
    expect(env.wall.reasons).toContain("canary_unprovisioned");
    expect(env.wall.reasons).not.toContain("canary_failed");
    expect(env.coverage.state).toBe("coverage_UNAVAILABLE");
  });

  it("uses each cycle's own facts: a plist changed between two cycles is passed false in the next record", async () => {
    const world = new World();
    const observer = observerFor(world);
    expect((raw(await cycle(observer)).canary_integrity as { passed: boolean }).passed).toBe(true);
    world.facts.plistBytes.value = Buffer.from(generateCanaryPlist("other-agent"));
    world.advance(OBSERVER_PERIOD);
    const next = await cycle(observer);
    expect(raw(next).canary_integrity).toEqual({ passed: false, checked_at_ms: world.now });
  });
});

describe("allow-sighting retention", () => {
  it("keeps an allow seen by daemon instance A after instance B reports none, until HISTORY_WINDOW, and drops it on a boot change", async () => {
    const world = new World();
    const observer = observerFor(world);
    await recoverToOk(world, observer);
    const t = world.now - SECOND;
    world.allowed = { captured_at_ms: t, principal: "agent" };
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    world.daemonInstance = "daemon-fixture-2";
    world.allowed = null;
    world.advance(OBSERVER_PERIOD);
    const record = await cycle(observer);
    expect(raw(record).canary_allow_sighting).toEqual({ captured_at_ms: t, principal: "agent", daemon_instance: "daemon-fixture-1" });
    expect(world.envelope().wall.reasons).toContain("canary_destination_allowed");
    expect(world.envelope().wall.state).toBe("wall_DOWN");
    world.advance(t + HISTORY_WINDOW - world.now);
    await cycle(observer);
    expect(world.envelope().wall.reasons).toContain("canary_destination_allowed");
    world.advance(1);
    const aged = await cycle(observer);
    expect(raw(aged).canary_allow_sighting).toBeNull();
    expect(world.envelope().wall.reasons).not.toContain("canary_destination_allowed");
    world.allowed = { captured_at_ms: world.now - SECOND, principal: "gate" };
    world.advance(OBSERVER_PERIOD);
    expect(raw(await cycle(observer)).canary_allow_sighting).not.toBeNull();
    world.allowed = null;
    world.boot = "boot-fixture-next";
    world.advance(OBSERVER_PERIOD);
    expect(raw(await cycle(observer)).canary_allow_sighting).toBeNull();
  });

  it("keeps the sighting across a restart of both the daemon and the observer, seeded from the observer's own record", async () => {
    const world = new World();
    const observer = observerFor(world);
    await recoverToOk(world, observer);
    world.allowed = { captured_at_ms: world.now - SECOND, principal: "agent" };
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    world.daemonInstance = "daemon-fixture-2";
    world.allowed = null;
    const restarted = observerFor(world, world.collectors(), "observer-test-2");
    world.advance(OBSERVER_PERIOD);
    const record = await cycle(restarted);
    expect(raw(record).canary_allow_sighting).toMatchObject({ principal: "agent", daemon_instance: "daemon-fixture-1" });
    expect(world.envelope().wall.reasons).toContain("canary_destination_allowed");
  });

  it("seeds nothing from another boot's record or an aged-out sighting", async () => {
    for (const variant of ["other-boot", "aged"] as const) {
      const world = new World();
      const observer = observerFor(world);
      await cycle(observer);
      const seeded = structuredClone(world.observerRecord) as Record<string, unknown>;
      raw(seeded).canary_allow_sighting = { captured_at_ms: variant === "aged" ? world.now - HISTORY_WINDOW - 1 : world.now - SECOND, principal: "agent", daemon_instance: "daemon-fixture-1" };
      if (variant === "other-boot") seeded.boot_id = "boot-fixture-previous";
      world.observerRecord = seeded;
      const restarted = observerFor(world, world.collectors(), "observer-test-2");
      world.advance(OBSERVER_PERIOD);
      expect(raw(await cycle(restarted)).canary_allow_sighting, variant).toBeNull();
    }
  });

  it("refuses an observer record without the sighting key or with a principal other than agent or gate", async () => {
    const world = new World();
    const record = structuredClone(await cycle(observerFor(world))) as Record<string, unknown>;
    const missing = structuredClone(record);
    delete raw(missing).canary_allow_sighting;
    const parsedMissing = parseObserverRecord(missing);
    expect(parsedMissing.ok).toBe(false);
    if (!parsedMissing.ok) expect(parsedMissing.failures).toContain("raw.canary_allow_sighting");
    for (const principal of ["operator", "other", ""]) {
      const bad = structuredClone(record);
      raw(bad).canary_allow_sighting = { captured_at_ms: 1, principal, daemon_instance: "d" };
      const parsed = parseObserverRecord(bad);
      expect(parsed.ok && parsed.wall.ok, principal).toBe(false);
      if (parsed.ok && !parsed.wall.ok) expect(parsed.wall.failures).toContain("raw.canary_allow_sighting.principal");
    }
  });
});

describe("faults and sightings across a failed publish and a future stamp", () => {
  it("carries a fault and an allow sighting from a cycle whose publish failed into the next published record", async () => {
    const world = new World();
    const observer = observerFor(world);
    await recoverToOk(world, observer);
    // A wall fault on a cycle whose publish fails: the next, clean cycle's file still names that fault and holds one sample.
    world.advance(OBSERVER_PERIOD);
    world.fullLoaded = false;
    world.publishFailNext = true;
    const faultUptime = world.uptime;
    let publishedBefore = world.published.length;
    await cycle(observer);
    expect(world.published).toHaveLength(publishedBefore);
    world.fullLoaded = true;
    world.advance(OBSERVER_PERIOD);
    world.canaryAt = world.now - SECOND;
    await cycle(observer);
    let onDisk = world.published[world.published.length - 1]!;
    expect(onDisk).toBe(world.observerRecord);
    expect(wallRec(onDisk).fault_uptime_ms).toBe(faultUptime);
    expect(wallRec(onDisk).samples).toHaveLength(1);
    expect(world.envelope(onDisk).wall.state).toBe("wall_RECOVERING");
    // An allow sighting on a cycle whose publish fails, then a new daemon instance that saw none: the file still holds it.
    world.advance(OBSERVER_PERIOD);
    world.allowed = { captured_at_ms: world.now - SECOND, principal: "agent" };
    const sightedAt = world.allowed.captured_at_ms;
    world.publishFailNext = true;
    publishedBefore = world.published.length;
    await cycle(observer);
    expect(world.published).toHaveLength(publishedBefore);
    world.daemonInstance = "daemon-fixture-2";
    world.allowed = null;
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    onDisk = world.published[world.published.length - 1]!;
    expect(onDisk).toBe(world.observerRecord);
    expect(raw(onDisk).canary_allow_sighting).toEqual({ captured_at_ms: sightedAt, principal: "agent", daemon_instance: "daemon-fixture-1" });
    const env = world.envelope(onDisk);
    expect(env.wall.reasons).toContain("canary_destination_allowed");
    expect(env.wall.state).toBe("wall_DOWN");
  });

  it("retains a future-stamped allow as seen now, so it still faults the wall and ages out HISTORY_WINDOW later instead of never", async () => {
    const world = new World();
    const observer = observerFor(world);
    await recoverToOk(world, observer);
    world.allowed = { captured_at_ms: world.now + 10 * HISTORY_WINDOW, principal: "agent" };
    world.advance(OBSERVER_PERIOD);
    const seenAt = world.now;
    const record = await cycle(observer);
    expect(raw(record).canary_allow_sighting).toEqual({ captured_at_ms: seenAt, principal: "agent", daemon_instance: "daemon-fixture-1" });
    world.daemonInstance = "daemon-fixture-2";
    world.allowed = null;
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    expect(world.envelope().wall.reasons).toContain("canary_destination_allowed");
    world.advance(seenAt + HISTORY_WINDOW - world.now);
    expect(raw(await cycle(observer)).canary_allow_sighting).not.toBeNull();
    world.advance(1);
    expect(raw(await cycle(observer)).canary_allow_sighting).toBeNull();
  });

  it("seeds a future-stamped sighting from its own record as seen at the seed, never as a stamp that cannot age", async () => {
    const world = new World();
    await cycle(observerFor(world));
    const seeded = structuredClone(world.observerRecord) as Record<string, unknown>;
    raw(seeded).canary_allow_sighting = { captured_at_ms: world.now + 10 * HISTORY_WINDOW, principal: "gate", daemon_instance: "daemon-fixture-1" };
    world.observerRecord = seeded;
    const restarted = observerFor(world, world.collectors(), "observer-test-2");
    world.advance(OBSERVER_PERIOD);
    const seedAt = world.now;
    expect(raw(await cycle(restarted)).canary_allow_sighting).toEqual({ captured_at_ms: seedAt, principal: "gate", daemon_instance: "daemon-fixture-1" });
  });
});

describe("a failed boot or seed read never loses a published allow sighting", () => {
  /** Publish an agent allow, then restart the daemon so only the observer record still carries it. */
  async function sightingOnlyInObserverRecord(world: World, observer: LivenessObserver): Promise<number> {
    await recoverToOk(world, observer);
    const t = world.now - SECOND;
    world.allowed = { captured_at_ms: t, principal: "agent" };
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    world.daemonInstance = "daemon-fixture-2";
    world.allowed = null;
    world.advance(OBSERVER_PERIOD);
    await cycle(observer);
    expect(raw(world.observerRecord as Record<string, unknown>).canary_allow_sighting).not.toBeNull();
    return t;
  }
  /** Drive a healthy observer across the sighting's HISTORY_WINDOW and require the wall fault at every step, then its expiry. */
  async function faultedAcrossWindow(world: World, observer: LivenessObserver, t: number): Promise<void> {
    const steps = 6;
    for (let i = 0; i <= steps; i++) {
      const at = Math.min(t + HISTORY_WINDOW, world.now + (i === 0 ? OBSERVER_PERIOD : HISTORY_WINDOW / steps));
      world.advance(at - world.now);
      await cycle(observer);
      expect(world.envelope().wall.reasons, `at sighting age ${world.now - t}`).toContain("canary_destination_allowed");
      if (world.now >= t + HISTORY_WINDOW) break;
    }
    world.advance(1);
    await cycle(observer);
    expect(world.envelope().wall.reasons).not.toContain("canary_destination_allowed");
  }

  it("a failure record keeps the last validated boot, so a restarted observer still seeds the sighting", async () => {
    const world = new World();
    const t = await sightingOnlyInObserverRecord(world, observerFor(world));
    const running = observerFor(world, world.collectors(), "observer-test-1b");
    await cycle(running);
    world.advance(OBSERVER_PERIOD);
    world.fail.add("readBootId");
    await cycle(running);
    const failed = world.observerRecord as Record<string, unknown>;
    expect(failed.boot_id).toBe(world.boot);
    expect(raw(failed).canary_allow_sighting).not.toBeNull();
    expect(failuresOf(failed)).toContainEqual({ component: "wall", reason: "time_untrusted" });
    expect(failuresOf(failed)).toContainEqual({ component: "agent", reason: "time_untrusted" });
    world.fail.delete("readBootId");
    const restarted = observerFor(world, world.collectors(), "observer-test-2");
    await faultedAcrossWindow(world, restarted, t);
  });

  it("an instance whose first boot read fails publishes nothing, so a later restart still seeds the sighting", async () => {
    const world = new World();
    const t = await sightingOnlyInObserverRecord(world, observerFor(world));
    const predecessor = world.observerRecord;
    const published = world.published.length;
    const second = observerFor(world, world.collectors(), "observer-test-2");
    world.fail.add("readBootId");
    for (let i = 0; i < 3; i++) { world.advance(OBSERVER_PERIOD); await cycle(second); }
    expect(world.published).toHaveLength(published);
    expect(world.observerRecord).toBe(predecessor);
    world.fail.delete("readBootId");
    const third = observerFor(world, world.collectors(), "observer-test-3");
    await faultedAcrossWindow(world, third, t);
  });

  it("an instance whose boot read recovers seeds from the predecessor record it never overwrote", async () => {
    const world = new World();
    const t = await sightingOnlyInObserverRecord(world, observerFor(world));
    const predecessor = world.observerRecord;
    const published = world.published.length;
    const second = observerFor(world, world.collectors(), "observer-test-2");
    world.fail.add("readBootId");
    world.advance(OBSERVER_PERIOD);
    await cycle(second);
    expect(world.published, "the unresolved start publishes nothing").toHaveLength(published);
    expect(world.observerRecord).toBe(predecessor);
    world.fail.delete("readBootId");
    await faultedAcrossWindow(world, second, t);
  });

  it.each(["collector failure", "read deadline"] as const)("a seed read that fails by %s is not proof of no seed: nothing publishes until it resolves", async variant => {
    const world = new World();
    const t = await sightingOnlyInObserverRecord(world, observerFor(world));
    const published = world.published.length;
    const second = observerFor(world, world.collectors(), "observer-test-2");
    if (variant === "collector failure") world.fail.add("readRecords"); else world.recordsDeadline = true;
    for (let i = 0; i < 3; i++) { world.advance(OBSERVER_PERIOD); await cycle(second); }
    expect(world.published).toHaveLength(published);
    expect(second.stats().sequence).toBe(0);
    world.fail.delete("readRecords");
    world.recordsDeadline = false;
    await faultedAcrossWindow(world, second, t);
  });

  it("a valid boot, a failed read, then the same boot again: the fault is recorded, recovery is re-earned and the sighting survives", async () => {
    for (const withSighting of [false, true]) {
      const world = new World();
      const observer = observerFor(world);
      await recoverToOk(world, observer);
      if (withSighting) {
        world.allowed = { captured_at_ms: world.now - SECOND, principal: "gate" };
        world.advance(OBSERVER_PERIOD);
        await cycle(observer);
        world.daemonInstance = "daemon-fixture-2";
        world.allowed = null;
      } else {
        expect(world.envelope().wall.state.startsWith("wall_OK_")).toBe(true);
      }
      const sighting = raw(observer.latestRecord()!).canary_allow_sighting;
      expect(sighting === null).toBe(!withSighting);
      world.advance(OBSERVER_PERIOD);
      world.fail.add("readBootId");
      const failedUptime = world.uptime;
      const failed = await cycle(observer);
      expect(failed.boot_id, "the last validated boot").toBe(world.boot);
      expect(wallRec(failed)).toEqual({ samples: [], fault_uptime_ms: failedUptime });
      expect(agentRec(failed)).toEqual({ samples: [], fault_uptime_ms: failedUptime });
      expect(raw(failed).canary_allow_sighting).toEqual(sighting);
      world.fail.delete("readBootId");
      world.advance(OBSERVER_PERIOD);
      world.canaryAt = world.now - SECOND;
      const resumed = await cycle(observer);
      expect(raw(resumed).canary_allow_sighting).toEqual(sighting);
      if (withSighting) {
        // The retained sighting keeps the wall faulted through the failed read and after it, inside its window.
        expect(world.envelope(failed).wall.reasons).toContain("canary_destination_allowed");
        expect(world.envelope(resumed).wall.reasons).toContain("canary_destination_allowed");
        world.advance(RECOVERY_GAP);
        expect(raw(await cycle(observer)).canary_allow_sighting).toEqual(sighting);
        expect(world.envelope().wall.reasons).toContain("canary_destination_allowed");
        continue;
      }
      // Without one, the same boot keeps the failed cycle's fault and recovery is re-earned after it.
      expect(wallRec(resumed).fault_uptime_ms, "the same boot keeps the fault").toBe(failedUptime);
      expect(wallRec(resumed).samples).toHaveLength(1);
      expect(world.envelope().wall.state).toBe("wall_RECOVERING");
      world.advance(RECOVERY_GAP);
      const paired = await cycle(observer);
      expect(wallRec(paired).samples).toHaveLength(2);
      expect(wallRec(paired).fault_uptime_ms).toBe(failedUptime);
      expect(world.envelope().wall.state.startsWith("wall_OK_"), world.envelope().wall.reasons.join(",")).toBe(true);
    }
  });
});

describe("instance-start seed read resolution", () => {
  const base = { directory: { status: "ok" as const }, daemon: { status: "absent" as const }, config: { status: "absent" as const }, readDeadlineHit: false };
  it("resolves only a read that reached a verdict, and never reads a refused or unfinished read as no seed", () => {
    expect(resolvedSeedRead({ ...base, observer: { status: "absent" } })).toEqual({ status: "absent" });
    expect(resolvedSeedRead({ ...base, observer: { status: "unparsable" } })).toEqual({ status: "unparsable" });
    expect(resolvedSeedRead({ ...base, observer: { status: "present", value: { a: 1 } } })).toEqual({ status: "present", value: { a: 1 } });
    expect(resolvedSeedRead({ ...base, directory: { status: "absent" }, observer: { status: "absent" } })).toEqual({ status: "absent" });
    for (const cause of ["owner", "mode", "size", "not_regular_file", "read_deadline"] as const) {
      expect(resolvedSeedRead({ ...base, observer: { status: "custody_invalid", cause } }), cause).toBeNull();
    }
    expect(resolvedSeedRead({ ...base, directory: { status: "custody_invalid", cause: "owner" }, observer: { status: "absent" } })).toBeNull();
    expect(resolvedSeedRead({ ...base, observer: { status: "absent" }, readDeadlineHit: true })).toBeNull();
  });
});
