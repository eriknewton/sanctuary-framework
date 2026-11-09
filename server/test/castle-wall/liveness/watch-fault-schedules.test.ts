/**
 * Adversarial schedules for the observer process: a single-flight cycle under
 * slow collectors, the bounded child runner under timeout, late completion,
 * ignored signals and repeated admission waves, and record publication when a
 * write is paused while newer cycles complete.
 */
import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { COUNTER_MAX, KILL_REAP_GRACE, MAX_COLLECTION_CHILDREN, TERM_GRACE } from "../../../src/castle-wall/liveness/constants.js";
import { CensusSampler, CensusSeries } from "../../../src/castle-wall/liveness/census-sampler.js";
import { LivenessObserver, type ObserverCollectors, type ObserverPublisher } from "../../../src/castle-wall/liveness/observer.js";
import { LivenessRecordPublisher, nodePublisherFs, type PublisherFileHandle, type PublisherFs } from "../../../src/castle-wall/liveness/record-store.js";
import type { ReaderFileHandle, ReaderFs } from "../../../src/castle-wall/liveness/read-status.js";
import {
  BoundedChildRunner,
  createWatchCollectors,
  RecordReadSlotHeld,
  WATCH_CHILD_ENV,
  WATCH_COMMANDS,
  watchCommandArgv,
  type WatchChild,
  type WatchCommandOperand,
  type WatchSpawn,
} from "../../../src/cli/castle-wall-watch-collectors.js";

const OPERATOR = 501;
afterEach(() => { vi.useRealTimers(); });

/** Timers that never fire on their own, so a cycle ends only when its collectors settle. */
const inertTimers = {
  setTimeout: () => 0, clearTimeout: () => undefined, setInterval: () => 0, clearInterval: () => undefined,
};

/** Collectors that settle fast with absent records, except `readRecords`, which each test may hold. */
function quietCollectors(readRecords: ObserverCollectors["readRecords"]): ObserverCollectors {
  const refuse = () => Promise.reject(new Error("fixture collector refused"));
  return {
    readRecords, readBootId: () => Promise.resolve("boot-fixture-current"), queryAvailability: () => Promise.resolve("live"),
    printFullAgent: refuse, readFullAgentState: refuse, readProcesses: refuse, printHarness: refuse, collectCanaryFacts: refuse,
  };
}
const absentRecords = () => ({
  directory: { status: "ok" as const }, daemon: { status: "absent" as const }, observer: { status: "absent" as const },
  config: { status: "absent" as const }, readDeadlineHit: false,
});

function observerWith(collectors: ObserverCollectors, publisher: ObserverPublisher, now: { ms: number } = { ms: 1_794_225_600_000 }): LivenessObserver {
  const series = new CensusSeries();
  let observer: LivenessObserver | null = null;
  const sampler = new CensusSampler({ series, runNetstat: async () => ({ status: "failed" }), context: () => observer!.samplingContext(), clock: { nowMs: () => now.ms, uptimeMs: () => now.ms }, timers: inertTimers });
  observer = new LivenessObserver({
    fortressId: "fortress-0123456789abcdef", hostId: "host-fixture", operatorUid: OPERATOR, collectors, sampler, series, publisher,
    clock: { nowMs: () => now.ms, uptimeMs: () => now.ms }, timers: inertTimers, instance: "observer-schedule-1",
  });
  return observer;
}
const flush = () => new Promise<void>(resolve => setImmediate(resolve));

// ---------------------------------------------------------------------------
describe("single-flight cycle", () => {
  it("skips and counts ticks during an in-flight cycle, never queues them, across 1000 slow cycles", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    let calls = 0;
    let release: () => void = () => undefined;
    const observer = observerWith(quietCollectors(() => {
      calls++;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      return new Promise(resolve => { release = () => { inFlight--; resolve(absentRecords()); }; });
    }), { publish: async () => undefined });
    for (let wave = 0; wave < 1000; wave++) {
      const cycle = observer.tick();
      for (let i = 0; i < 3; i++) expect(observer.tick()).toBe(cycle);
      release();
      await cycle;
    }
    await flush();
    expect(maxInFlight).toBe(1);
    expect(calls).toBe(1000);
    expect(observer.stats().cycles).toBe(1000);
    expect(observer.stats().skipped).toBe(3000);
  });

  it("saturates the skipped counter at COUNTER_MAX and never publishes it", async () => {
    const published: unknown[] = [];
    let release: () => void = () => undefined;
    const observer = observerWith(quietCollectors(() => new Promise(resolve => { release = () => resolve(absentRecords()); })), { publish: async record => { published.push(record); } });
    observer.primeSkippedForTest(COUNTER_MAX - 1);
    const cycle = observer.tick();
    for (let i = 0; i < 5; i++) void observer.tick();
    expect(observer.stats().skipped).toBe(COUNTER_MAX);
    release();
    await cycle;
    await flush();
    const text = JSON.stringify(published);
    expect(published).toHaveLength(1);
    expect(text).not.toContain("skipped");
    expect(text).not.toContain(String(COUNTER_MAX));
  });
});

// ---------------------------------------------------------------------------
type FakeChild = WatchChild & EventEmitter & { stdout: EventEmitter; stderr: EventEmitter; signals: string[]; exitNow(code?: number): void; ignoreTerm: boolean; ignoreKill: boolean };
function fakeSpawner(): { spawn: WatchSpawn; children: FakeChild[]; calls: Array<{ file: string; args: readonly string[]; env: Record<string, string> }> } {
  const children: FakeChild[] = [];
  const calls: Array<{ file: string; args: readonly string[]; env: Record<string, string> }> = [];
  const spawn: WatchSpawn = (file, args, options) => {
    calls.push({ file, args, env: options.env });
    const child = Object.assign(new EventEmitter(), { pid: 6000 + children.length, stdout: new EventEmitter(), stderr: new EventEmitter(), signals: [] as string[], ignoreTerm: false, ignoreKill: false }) as FakeChild;
    child.exitNow = (code = 0) => { child.emit("exit", code, null); child.emit("close", code, null); };
    child.kill = signal => {
      child.signals.push(signal);
      if ((signal === "SIGTERM" && !child.ignoreTerm) || (signal === "SIGKILL" && !child.ignoreKill)) queueMicrotask(() => { child.emit("exit", null, signal); child.emit("close", null, signal); });
      return true;
    };
    children.push(child);
    return child;
  };
  return { spawn, children, calls };
}
const fakeRunnerTimers = { setTimeout: (fire: () => void, ms: number) => setTimeout(fire, ms), clearTimeout: (h: unknown) => clearTimeout(h as NodeJS.Timeout) };
const DEADLINE = 1000;

describe("bounded child runner", () => {
  it("discards a late success after the deadline and frees the slot only on an observed exit", async () => {
    vi.useFakeTimers();
    const { spawn, children } = fakeSpawner();
    const runner = new BoundedChildRunner({ spawn, timers: fakeRunnerTimers });
    const result = runner.run({ command: "ps" }, DEADLINE);
    children[0]!.ignoreTerm = true;
    await vi.advanceTimersByTimeAsync(DEADLINE);
    expect(await result).toEqual({ status: "failed", reason: "deadline" });
    expect(children[0]!.signals).toEqual(["SIGTERM"]);
    expect(runner.slotStates()[0]).toBe("slot_TERMINATING");
    children[0]!.stdout.emit("data", Buffer.from("late output\n"));
    expect(runner.liveChildren()).toBe(1);
    children[0]!.exitNow(0);
    expect(runner.slotStates()[0]).toBe("slot_IDLE");
    expect(await result).toEqual({ status: "failed", reason: "deadline" });
  });

  it("never lets a late close from a released child settle, release or poison the next child on the same slot", async () => {
    vi.useFakeTimers();
    const { spawn, children } = fakeSpawner();
    const runner = new BoundedChildRunner({ spawn, timers: fakeRunnerTimers, maxSlots: 1 });
    // The first child exits but its pipes stay open past the deadline, so the slot is released on the observed exit.
    const first = runner.run({ command: "ps" }, DEADLINE);
    children[0]!.emit("exit", 0, null);
    await vi.advanceTimersByTimeAsync(DEADLINE);
    expect(await first).toEqual({ status: "failed", reason: "deadline" });
    expect(runner.slotStates()).toEqual(["slot_IDLE"]);
    let secondResult: unknown = null;
    const second = runner.run({ command: "netstat" }, DEADLINE).then(result => { secondResult = result; return result; });
    expect(runner.slotStates()).toEqual(["slot_RUNNING"]);
    // The first child's pipes close now, while the second child owns the slot.
    children[0]!.stdout.emit("data", Buffer.from("late output\n"));
    children[0]!.emit("close", 0, null);
    expect(runner.slotStates()).toEqual(["slot_RUNNING"]);
    expect(runner.liveChildren()).toBe(1);
    expect(await runner.run({ command: "ps" }, DEADLINE)).toEqual({ status: "failed", reason: "no_slot" });
    children[1]!.stdout.emit("data", Buffer.from("second output\n"));
    children[1]!.exitNow(0);
    await vi.advanceTimersByTimeAsync(0);
    expect(secondResult).toEqual({ status: "ok", code: 0, signal: null, stdout: "second output\n", stderr: "" });
    expect(await second).toEqual(secondResult);
    expect(runner.slotStates()).toEqual(["slot_IDLE"]);
    expect(children).toHaveLength(2);
  });

  it("sends SIGKILL at TERM_GRACE to a child ignoring SIGTERM, and returns the slot when the exit is seen", async () => {
    vi.useFakeTimers();
    const { spawn, children } = fakeSpawner();
    const runner = new BoundedChildRunner({ spawn, timers: fakeRunnerTimers });
    void runner.run({ command: "netstat" }, DEADLINE);
    children[0]!.ignoreTerm = true;
    await vi.advanceTimersByTimeAsync(DEADLINE + TERM_GRACE - 1);
    expect(children[0]!.signals).toEqual(["SIGTERM"]);
    await vi.advanceTimersByTimeAsync(1);
    expect(children[0]!.signals).toEqual(["SIGTERM", "SIGKILL"]);
    expect(runner.slotStates()[0]).toBe("slot_IDLE");
  });

  it("poisons a slot whose SIGKILL brings no exit by KILL_REAP_GRACE and never replaces it, across 1000 admission and timeout waves", async () => {
    vi.useFakeTimers();
    const { spawn, children, calls } = fakeSpawner();
    const runner = new BoundedChildRunner({ spawn, timers: fakeRunnerTimers });
    let maxLive = 0;
    for (let wave = 0; wave < 1000; wave++) {
      const before = children.length;
      const results = Array.from({ length: MAX_COLLECTION_CHILDREN + 2 }, () => runner.run({ command: "sysctl_boot" }, DEADLINE));
      for (const child of children.slice(before)) { child.ignoreTerm = true; child.ignoreKill = true; }
      maxLive = Math.max(maxLive, runner.liveChildren());
      // Each wave admits at most the idle slots; the rest fail now with no_slot and never queue.
      const settled = await Promise.all(results.map(async (p, i) => {
        if (i < children.length - before) return null;
        return p;
      }));
      for (const r of settled.filter(r => r !== null)) expect(r).toEqual({ status: "failed", reason: "no_slot" });
      await vi.advanceTimersByTimeAsync(DEADLINE + TERM_GRACE + KILL_REAP_GRACE);
      maxLive = Math.max(maxLive, runner.liveChildren());
      expect(runner.liveChildren()).toBeLessThanOrEqual(MAX_COLLECTION_CHILDREN);
    }
    expect(maxLive).toBe(MAX_COLLECTION_CHILDREN);
    expect(runner.slotStates()).toEqual(Array(MAX_COLLECTION_CHILDREN).fill("slot_POISONED"));
    expect(children).toHaveLength(MAX_COLLECTION_CHILDREN);
    expect(await runner.run({ command: "ps" }, DEADLINE)).toEqual({ status: "failed", reason: "no_slot" });
    expect(calls).toHaveLength(MAX_COLLECTION_CHILDREN);
    for (const child of children) expect(child.signals).toEqual(["SIGTERM", "SIGKILL"]);
  });

  it("spawns only closed-enum argv with exactly the fixed environment, and refuses operands that would widen it", async () => {
    const { spawn, calls, children } = fakeSpawner();
    const runner = new BoundedChildRunner({ spawn, timers: fakeRunnerTimers });
    const operands: WatchCommandOperand[] = [
      { command: "launchctl_print_gui", uid: OPERATOR, label: "ai.sanctuaryprotocol.watch" },
      { command: "launchctl_print_system", label: "ai.sanctuaryprotocol.castle-wall.canary" },
      { command: "launchctl_bootstrap_gui", uid: OPERATOR, plistPath: "/Users/operator-fixture/Library/LaunchAgents/x.plist" },
      { command: "launchctl_bootout_gui", uid: OPERATOR, label: "ai.sanctuaryprotocol.watch" },
      { command: "ps" }, { command: "id_name", uid: 502 }, { command: "id_uid", name: "sanctuary-agent-fixture" },
      { command: "sysctl_boot" }, { command: "netstat" },
    ];
    expect(operands.map(o => o.command).sort()).toEqual([...WATCH_COMMANDS].sort());
    for (const operand of operands) {
      const result = runner.run(operand, DEADLINE);
      children[children.length - 1]!.exitNow(0);
      expect((await result).status).toBe("ok");
    }
    const files = new Set(calls.map(c => c.file));
    expect([...files].sort()).toEqual(["/bin/launchctl", "/bin/ps", "/usr/bin/id", "/usr/sbin/netstat", "/usr/sbin/sysctl"]);
    for (const call of calls) {
      expect(call.env).toEqual({ PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL: "C" });
      expect(call.env).toEqual({ ...WATCH_CHILD_ENV });
      for (const arg of call.args) expect(arg).not.toMatch(/sudo|osascript|^su$|[;&|`$]/);
    }
    const refused: WatchCommandOperand[] = [
      { command: "launchctl_print_system", label: "x; rm" },
      { command: "launchctl_print_gui", uid: -1, label: "a" },
      { command: "launchctl_bootstrap_gui", uid: OPERATOR, plistPath: "relative.plist" },
      { command: "id_uid", name: "-o" },
      { command: "unknown" } as unknown as WatchCommandOperand,
    ];
    for (const operand of refused) {
      expect(await runner.run(operand, DEADLINE)).toEqual({ status: "failed", reason: "spawn_error" });
    }
    expect(calls).toHaveLength(operands.length);
    expect(() => watchCommandArgv({ command: "id_name", uid: 2 ** 33 })).toThrow();
  });
});

// ---------------------------------------------------------------------------
describe("publication under the observer", () => {
  /** An in-memory publisher filesystem whose first rename of each wave can be paused. */
  class MemoryFs implements PublisherFs {
    files = new Map<string, string>();
    dirs = new Set<string>();
    openTemps = 0;
    maxOpenTemps = 0;
    renamedSequences: number[] = [];
    hold: Promise<void> | null = null;
    async mkdir(path: string): Promise<unknown> {
      if (this.dirs.has(path)) throw Object.assign(new Error("exists"), { code: "EEXIST" });
      this.dirs.add(path);
      return undefined;
    }
    async lstat(): Promise<{ uid: number; mode: number; isDirectory(): boolean }> { return { uid: OPERATOR, mode: 0o40700, isDirectory: () => true }; }
    /** Record temps only; the lock and claim temps the publication fence writes are not record writes. */
    private isRecordTemp(path: string): boolean {
      return path.endsWith(".tmp") && !path.endsWith(".lock.tmp") && !path.endsWith(".publisher.tmp");
    }
    async open(path: string): Promise<PublisherFileHandle> {
      if (this.files.has(path)) throw Object.assign(new Error("exists"), { code: "EEXIST" });
      if (this.isRecordTemp(path)) {
        this.openTemps++;
        this.maxOpenTemps = Math.max(this.maxOpenTemps, this.openTemps);
      }
      let data = "";
      this.files.set(path, "");
      return {
        stat: async () => ({ uid: OPERATOR, mode: 0o100600, isFile: () => true }),
        writeFile: async text => { data = text; },
        sync: async () => undefined,
        close: async () => { if (this.files.has(path)) this.files.set(path, data); },
      };
    }
    async rename(from: string, to: string): Promise<void> {
      const record = this.isRecordTemp(from);
      if (record) {
        const hold = this.hold;
        this.hold = null;
        if (hold !== null) await hold;
      }
      const text = this.files.get(from)!;
      this.files.delete(from);
      this.files.set(to, text);
      if (!record) return;
      this.openTemps--;
      this.renamedSequences.push((JSON.parse(text) as { sequence: number }).sequence);
    }
    async unlink(path: string): Promise<void> {
      if (!this.files.delete(path)) throw Object.assign(new Error("absent"), { code: "ENOENT" });
      if (this.isRecordTemp(path)) this.openTemps--;
    }
    async readdir(): Promise<string[]> { return []; }
    async link(existing: string, newPath: string): Promise<void> {
      if (this.files.has(newPath)) throw Object.assign(new Error("exists"), { code: "EEXIST" });
      const text = this.files.get(existing);
      if (text === undefined) throw Object.assign(new Error("absent"), { code: "ENOENT" });
      this.files.set(newPath, text);
    }
    async readFile(path: string): Promise<string> {
      const text = this.files.get(path);
      if (text === undefined) throw Object.assign(new Error("absent"), { code: "ENOENT" });
      return text;
    }
  }

  it("never lets an older record overwrite a newer one, and keeps one write in flight with one waiting, over 1000 waves", async () => {
    const fs = new MemoryFs();
    const publisher = new LivenessRecordPublisher({ fortressPath: "/fortress-fixture", fileName: "observer.json", instance: "observer-schedule-1", operatorUid: OPERATOR, fs });
    const now = { ms: 1_794_225_600_000 };
    const observer = observerWith(quietCollectors(() => Promise.resolve(absentRecords())), publisher, now);
    const target = "/fortress-fixture/liveness/observer.json";
    let lastSequence = 0;
    for (let wave = 0; wave < 1000; wave++) {
      let release!: () => void;
      fs.hold = new Promise<void>(resolve => { release = resolve; });
      const renamesBefore = fs.renamedSequences.length;
      // Cycle A starts its write and pauses before rename; B and C complete while it is paused.
      for (let k = 0; k < 3; k++) { await observer.tick(); now.ms += 10_000; }
      lastSequence = observer.stats().sequence;
      expect(fs.renamedSequences.length).toBe(renamesBefore);
      release();
      for (let i = 0; i < 50 && fs.renamedSequences.length < renamesBefore + 2; i++) await flush();
      const wrote = fs.renamedSequences.slice(renamesBefore);
      // One in flight and only the newest waiting: A then C, never B.
      expect(wrote).toEqual([lastSequence - 2, lastSequence]);
      expect((JSON.parse(fs.files.get(target)!) as { sequence: number }).sequence).toBe(lastSequence);
    }
    for (let i = 1; i < fs.renamedSequences.length; i++) expect(fs.renamedSequences[i]!).toBeGreaterThan(fs.renamedSequences[i - 1]!);
    expect(fs.maxOpenTemps).toBe(1);
    await observer.stop();
  });
});

// ---------------------------------------------------------------------------
describe("a publication stalled indefinitely under the observer", () => {
  it("keeps one handled continuation on the stalled drain over 1000 cycles, then settles it once on rejection", async () => {
    // The publisher's first filesystem step never settles until the test rejects it; every later attempt is refused at once.
    let rejectHeld!: (error: Error) => void;
    let mkdirCalls = 0;
    const fs: PublisherFs = {
      ...nodePublisherFs,
      mkdir: () => {
        mkdirCalls++;
        if (mkdirCalls === 1) return new Promise((_resolve, reject) => { rejectHeld = reject; });
        return Promise.reject(Object.assign(new Error("fixture refusal"), { code: "EACCES" }));
      },
    };
    const real = new LivenessRecordPublisher({ fortressPath: "/fortress-fixture-never-created", fileName: "observer.json", instance: "observer-stall-1", operatorUid: OPERATOR, fs });
    // Count every reaction attached to each distinct drain the publisher returns, without changing the drain's identity.
    const reactions = new Map<Promise<void>, number>();
    const publisher: ObserverPublisher = {
      publish: record => {
        const drain = real.publish(record);
        if (!reactions.has(drain)) {
          reactions.set(drain, 0);
          const then = drain.then.bind(drain);
          drain.then = ((onFulfilled, onRejected) => { reactions.set(drain, reactions.get(drain)! + 1); return then(onFulfilled, onRejected); }) as typeof drain.then;
        }
        return drain;
      },
    };
    const observer = observerWith(quietCollectors(() => Promise.resolve(absentRecords())), publisher);
    for (let i = 0; i < 1000; i++) {
      await observer.tick();
      expect([...reactions.values()], `after cycle ${i + 1}`).toEqual([1]);
    }
    expect(observer.stats().sequence).toBe(1000);
    expect(real.stats()).toEqual({ published: 0, failures: 0 });
    rejectHeld(Object.assign(new Error("fixture stall released"), { code: "EIO" }));
    for (let i = 0; i < 20 && observer.stats().publishFailures === 0; i++) await flush();
    // One drain rejected: one failure counted, by the one continuation; the stalled drain gained no handler meanwhile.
    expect(observer.stats().publishFailures).toBe(1);
    expect([...reactions.values()]).toEqual([1]);
    // The next cycle starts a new drain with its own single continuation, and its refusal is counted once.
    await observer.tick();
    for (let i = 0; i < 20 && observer.stats().publishFailures === 1; i++) await flush();
    expect([...reactions.values()]).toEqual([1, 1]);
    expect(observer.stats().publishFailures).toBe(2);
    await observer.stop();
  });
});

// ---------------------------------------------------------------------------
describe("the observer's record read under repeated read deadlines", () => {
  it("issues no new read while a timed-out read's operations or late cleanup are outstanding, then readmits", async () => {
    // A filesystem whose every open is held until the test releases it; once `healthy`, opens fail ENOENT at once.
    let opens = 0;
    let healthy = false;
    const heldOpens: Array<(handle: ReaderFileHandle) => void> = [];
    const readerFs: ReaderFs = {
      open: () => {
        opens++;
        if (healthy) return Promise.reject(Object.assign(new Error("absent"), { code: "ENOENT" }));
        return new Promise(resolve => { heldOpens.push(resolve); });
      },
    };
    // The reader's deadline fires only when the test says so.
    const deadlines: Array<() => void> = [];
    const readerDeadline = { after: (_ms: number, fire: () => void) => { deadlines.push(fire); return { cancel: () => undefined }; } };
    const runner = new BoundedChildRunner({ spawn: () => { throw new Error("no child in this schedule"); }, timers: fakeRunnerTimers });
    const production = createWatchCollectors({ runner, timers: fakeRunnerTimers, fortressPath: "/fortress-fixture-never-created", operatorUid: OPERATOR, readerFs, readerDeadline });
    // Each cycle's record evidence: the read completed, hit its deadline, or was refused because the slot is held.
    const outcomes: string[] = [];
    const observer = observerWith(quietCollectors(() => production.readRecords().then(
      read => { outcomes.push(read.readDeadlineHit ? "deadline" : "read"); return read; },
      (error: unknown) => { outcomes.push(error instanceof RecordReadSlotHeld ? "held" : "error"); throw error; },
    )), { publish: async () => undefined });
    const last = () => outcomes[outcomes.length - 1];

    // Wave 1 opens the fortress directory and stalls; its deadline fires and the cycle completes with failed evidence.
    const first = observer.tick();
    await flush();
    expect(opens).toBe(1);
    deadlines.shift()!();
    await first;
    expect(last()).toBe("deadline");
    // 999 more deadline waves: every cycle completes with failed record evidence and none issues another read.
    for (let wave = 1; wave < 1000; wave++) {
      const cycle = observer.tick();
      await flush();
      // Checked before the cycle is awaited: a read admitted here would stall on the held filesystem.
      expect(opens, `wave ${wave + 1}`).toBe(1);
      await cycle;
      expect(last()).toBe("held");
    }
    expect(deadlines).toHaveLength(0);
    // The stalled open completes late with a handle whose close is itself slow: the slot stays held until that close settles.
    let closeCalls = 0;
    let finishClose!: () => void;
    heldOpens.shift()!({
      stat: () => Promise.resolve({ uid: OPERATOR, mode: 0o40700, size: 0, isFile: () => false, isDirectory: () => true }),
      read: () => Promise.resolve({ bytesRead: 0 }),
      close: () => { closeCalls++; return new Promise<void>(resolve => { finishClose = resolve; }); },
    });
    await flush();
    expect(closeCalls, "the late handle goes to the cleanup owner").toBe(1);
    const whileClosing = observer.tick();
    await flush();
    expect(opens, "held by the late close").toBe(1);
    await whileClosing;
    expect(last()).toBe("held");
    // Once the late close settles the slot is free, and the next cycle starts a fresh read that completes.
    healthy = true;
    finishClose();
    await flush();
    await observer.tick();
    expect(opens).toBe(2);
    expect(last()).toBe("read");
    expect(outcomes).toHaveLength(1002);
    expect(heldOpens).toHaveLength(0);
    await observer.stop();
  });
});
