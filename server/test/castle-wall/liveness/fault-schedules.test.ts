/** Rule 8 and rule 12 fault schedules: slot waves, saturation, spam caps, paused publication, hostile record files and record budgets. */
import { execFileSync } from "node:child_process";
import { closeSync, constants as fsConstants, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import {
  CANARY_IP,
  CANARY_PORT,
  CANARY_PRIMARY_CAP_PER_DAY,
  CANARY_PROTOCOL,
  CANARY_SETTLE,
  CANARY_SLOT_REARM,
  CENSUS_INPUT_ROWS,
  CENSUS_PID_ROWS,
  CENSUS_SAMPLES_MAX,
  COUNTER_MAX,
  DAY,
  EVIDENCE_FAILURES_MAX,
  LABEL_BYTES,
  RECOVERY_SAMPLES_PER_COMPONENT,
  SECOND,
  STATUS_BYTES,
  STATUS_READ_DEADLINE,
} from "../../../src/castle-wall/liveness/constants.js";
import { parseCensus } from "../../../src/castle-wall/liveness/census.js";
import { evaluateLiveness, type LivenessInput } from "../../../src/castle-wall/liveness/evaluate.js";
import { nodeReaderFs, readLivenessRecords, type DeadlineClock, type ReaderFs } from "../../../src/castle-wall/liveness/read-status.js";
import { LivenessRecordPublisher, nodePublisherFs, type PublisherFs } from "../../../src/castle-wall/liveness/record-store.js";
import { CanaryRecordingSlot, saturatingIncrement, type CanaryOriginSubjects } from "../../../src/castle-wall/liveness/recorder.js";
import { parseDaemonRecord, parseObserverRecord } from "../../../src/castle-wall/liveness/schema.js";
import { evaluateFortressLiveness, livenessFortressId, runLivenessStatus, wallOnlyStatusExit } from "../../../src/cli/castle-wall-liveness-status.js";

const UID = process.getuid?.() ?? 0;
const START = Date.parse("2026-11-09T12:00:00.000Z");
const ORIGIN: CanaryOriginSubjects = { adapter: "uid", agentUid: 502, gateUid: null, agentSubject: "fixture/uid-502", gateSubject: null };
const STATES = JSON.parse(readFileSync(join(__dirname, "fixtures", "states.json"), "utf8")) as { base: any }; // Untyped fixture JSON, patched by path.
const candidate = (seq: number) => ({ seq, capturedAtMs: START, subjectUid: 502, destIp: CANARY_IP, destPort: CANARY_PORT, destProtocol: CANARY_PROTOCOL } as const);
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fortress(): string {
  const root = mkdtempSync(join(tmpdir(), "lv-fault-"));
  roots.push(root);
  mkdirSync(join(root, "liveness"), { mode: 0o700 });
  return root;
}
const withCanary = (canary: unknown): LivenessInput => {
  const input = structuredClone(STATES.base);
  input.daemon.value.raw.canary = canary;
  return input;
};

/** A deadline clock the test fires by hand, recording whether it ever ran. */
function manualDeadline() {
  let fire: (() => void) | null = null;
  let fired = false;
  const clock: DeadlineClock = { after: (_ms, callback) => { fire = callback; return { cancel: () => { fire = null; } }; } };
  return { clock, fired: () => fired, fire: () => { if (fire) { fired = true; fire(); } }, scheduled: () => fire !== null };
}

describe("slot waves", () => {
  it("1000 admission, timeout and late-settle waves keep one owned slot and never record a late confirmation", () => {
    let now = START;
    const slot = new CanaryRecordingSlot(() => ORIGIN, () => now);
    const waves = 1000;
    for (let wave = 0; wave < waves; wave++) {
      expect(slot.admit(candidate(wave))).toBe(true);
      now += CANARY_SETTLE + 1;
      // The deadline passed, but the slot stays owned until settlement; a replacement is refused.
      expect(slot.admit(candidate(wave + waves))).toBe(false);
      slot.settled(true);
      expect(slot.evidence().last_confirmation).toBeNull();
      now += CANARY_SLOT_REARM;
    }
    expect(slot.admissionCount()).toBe(waves);
    expect(slot.evidence()).toMatchObject({ last_confirmation: null, late_count: waves, last_late: { seq: waves - 1 } });
  });

  it("consumer stop while PENDING settles the slot as a failure", () => {
    const slot = new CanaryRecordingSlot(() => ORIGIN, () => START);
    slot.admit(candidate(1));
    expect(slot.currentState()).toBe("canary_PENDING");
    slot.stop();
    expect(slot.evidence()).toMatchObject({ failure_count: 1, last_failure: { seq: 1 } });
  });

  it("a slot never settled stays EXPIRED, keeps one record of each kind, and reads canary_failed", () => {
    let now = START;
    const slot = new CanaryRecordingSlot(() => ORIGIN, () => now);
    slot.admit(candidate(1)); now += SECOND; slot.settled(true);
    now += CANARY_SLOT_REARM; slot.admit(candidate(2)); slot.settled(false);
    now += CANARY_SLOT_REARM; slot.admit(candidate(3)); now += CANARY_SETTLE + 1; slot.settled(true);
    now += CANARY_SLOT_REARM; slot.admit(candidate(4));
    now += DAY;
    expect(slot.currentState()).toBe("canary_EXPIRED");
    const evidence = slot.evidence();
    for (const kind of ["last_confirmation", "last_failure", "last_late"] as const) {
      expect(Array.isArray(evidence[kind])).toBe(false);
      expect(evidence[kind]).not.toBeNull();
    }
    // Read the slot's evidence a day later through fresh records, so only the canary evidence is old.
    const input = withCanary(evidence) as any; // Untyped fixture JSON.
    const uptime = input.host.uptimeMs + (now - input.nowMs);
    for (const record of [input.daemon.value, input.observer.value]) {
      record.observed_at = new Date(now - SECOND).toISOString();
      record.observed_uptime_ms = uptime - SECOND;
    }
    const envelope = evaluateLiveness({ ...input, nowMs: now, host: { ok: true, bootId: input.host.bootId, uptimeMs: uptime } });
    expect(envelope.wall.reasons).toContain("canary_failed");
    expect(envelope.wall.reasons).not.toContain("time_untrusted");
  });

  it("a failure or late count driven to COUNTER_MAX saturates and reads observation_invalid, with bounded memory", () => {
    let count = COUNTER_MAX - 2;
    for (let i = 0; i < 10; i++) count = saturatingIncrement(count);
    expect(count).toBe(COUNTER_MAX);
    for (const field of ["failure_count", "late_count"]) {
      const canary = { ...STATES.base.daemon.value.raw.canary, [field]: count };
      expect(evaluateLiveness(withCanary(canary)).wall.reasons).toContain("observation_invalid");
    }
    let now = START;
    const slot = new CanaryRecordingSlot(() => ORIGIN, () => now);
    const sizes: number[] = [];
    for (let wave = 0; wave < 10_000; wave++) {
      slot.admit(candidate(wave)); slot.settled(wave % 2 === 0); now += CANARY_SLOT_REARM;
      if (wave % 1000 === 999) sizes.push(JSON.stringify(slot.evidence()).length);
    }
    expect(Math.max(...sizes) - Math.min(...sizes)).toBeLessThan(16);
  });

  it("agent spam of the canary tuple at 10 per second for a day forces exactly CANARY_PRIMARY_CAP_PER_DAY primaries", () => {
    let now = START;
    const slot = new CanaryRecordingSlot(() => ORIGIN, () => now);
    const interval = SECOND / 10;
    let forced = 0;
    // Half-open day [START, START + DAY).
    for (; now < START + DAY; now += interval) {
      if (slot.admit(candidate(forced))) { forced++; slot.settled(true); }
    }
    expect(forced).toBe(CANARY_PRIMARY_CAP_PER_DAY);
    expect(forced).toBe(960);
  });
});

describe("publication paused, then restart", () => {
  const OLD = "1111111111111111";
  const NEW = "2222222222222222";
  type Step = "open" | "write" | "rename";
  const recordAt = (root: string) => JSON.parse(readFileSync(join(root, "liveness", "daemon.json"), "utf8")) as unknown;
  /** Pause the old publisher's second record write at one step, after its first publish has claimed the target. */
  function pausedAt(root: string, step: Step) {
    const recordTemp = join(root, "liveness", `daemon.json.${OLD}.tmp`);
    const target = join(root, "liveness", "daemon.json");
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let reached!: () => void;
    const atStep = new Promise<void>(resolve => { reached = resolve; });
    let armed = false;
    const pause = async () => { reached(); await gate; };
    const fs: PublisherFs = {
      ...nodePublisherFs,
      open: async (path, flags, mode) => {
        if (armed && step === "open" && path === recordTemp) { armed = false; await pause(); }
        const handle = await nodePublisherFs.open(path, flags, mode);
        if (path !== recordTemp) return handle;
        return {
          stat: () => handle.stat(), sync: () => handle.sync(), close: () => handle.close(),
          writeFile: async data => { if (armed && step === "write") { armed = false; await pause(); } return handle.writeFile(data); },
        };
      },
      rename: async (from, to) => {
        if (armed && step === "rename" && to === target) { armed = false; await pause(); }
        return nodePublisherFs.rename(from, to);
      },
    };
    return { fs, arm: () => { armed = true; }, atStep, release };
  }

  it.each(["open", "write", "rename"] as const)("a queued old snapshot and a late %s completion never overwrite the newer instance's record", async step => {
    const root = fortress();
    const paused = pausedAt(root, step);
    const old = new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: OLD, operatorUid: UID, fs: paused.fs });
    await old.publish({ sequence: 1 });
    paused.arm();
    const late = old.publish({ sequence: 2 });
    late.catch(() => undefined);
    await paused.atStep;
    // A legitimate later tick queues behind the paused write.
    const queued = old.publish({ sequence: 3 });
    queued.catch(() => undefined);
    const restarted = new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: NEW, operatorUid: UID });
    const newer = restarted.publish({ sequence: 5 });
    if (step !== "rename") {
      // Before the rename the old instance holds no lock, so the newer instance commits at once.
      await newer;
      expect(recordAt(root)).toEqual({ sequence: 5 });
    }
    paused.release();
    await Promise.allSettled([late, queued]);
    await newer;
    // The paused rename was already inside the lock with a valid claim, so it may land, but only before the newer record.
    expect(recordAt(root)).toEqual({ sequence: 5 });
    // The old instance is superseded: its next snapshot is refused and the newer record stays.
    await expect(old.publish({ sequence: 4 })).rejects.toThrow();
    expect(old.isRetired()).toBe(true);
    expect(recordAt(root)).toEqual({ sequence: 5 });
    expect(readdirSync(join(root, "liveness")).sort()).toEqual(["daemon.json", "daemon.json.publisher"]);
    expect(readFileSync(join(root, "liveness", "daemon.json.publisher"), "utf8")).toBe(`${NEW}\n`);
  });

  it("a retired publisher drops its waiting snapshot and creates nothing more", async () => {
    const root = fortress();
    const paused = pausedAt(root, "write");
    const recordTemp = join(root, "liveness", `daemon.json.${OLD}.tmp`);
    let tempOpens = 0;
    const counting: PublisherFs = { ...paused.fs, open: (path, flags, mode) => { if (path === recordTemp) tempOpens++; return paused.fs.open(path, flags, mode); } };
    const p = new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: OLD, operatorUid: UID, fs: counting });
    await p.publish({ sequence: 1 });
    paused.arm();
    const inFlight = p.publish({ sequence: 2 });
    inFlight.catch(() => undefined);
    await paused.atStep;
    const waiting = p.publish({ sequence: 3 });
    waiting.catch(() => undefined);
    const opensAtRetire = tempOpens;
    p.retire();
    paused.release();
    await Promise.allSettled([inFlight, waiting]);
    expect(recordAt(root)).toEqual({ sequence: 1 });
    expect(tempOpens, "no snapshot is created after retirement").toBe(opensAtRetire);
    await expect(p.publish({ sequence: 4 })).rejects.toThrow("retired");
    expect(readdirSync(join(root, "liveness")).sort()).toEqual(["daemon.json", "daemon.json.publisher"]);
  });

  it("an old instance cannot check its claim while the newer instance holds the lock to establish its own", async () => {
    const root = fortress();
    const ownerPath = join(root, "liveness", "daemon.json.publisher");
    const oldPaused = pausedAt(root, "rename");
    const old = new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: OLD, operatorUid: UID, fs: oldPaused.fs });
    await old.publish({ sequence: 1 });
    // Hold the newer instance inside its startup critical section, after its sweep and before its claim lands.
    let releaseClaim!: () => void;
    const claimGate = new Promise<void>(resolve => { releaseClaim = resolve; });
    let atClaim!: () => void;
    const claimReached = new Promise<void>(resolve => { atClaim = resolve; });
    const newFs: PublisherFs = { ...nodePublisherFs, rename: async (from, to) => { if (to === ownerPath) { atClaim(); await claimGate; } return nodePublisherFs.rename(from, to); } };
    const restarted = new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: NEW, operatorUid: UID, fs: newFs });
    const newer = restarted.publish({ sequence: 5 });
    await claimReached;
    oldPaused.arm();
    const late = old.publish({ sequence: 2 });
    late.catch(() => undefined);
    // Give the old publisher time to reach its rename if anything let it past the held lock.
    await new Promise(resolve => setTimeout(resolve, 100));
    releaseClaim();
    await newer;
    oldPaused.release();
    await late.catch(() => undefined);
    expect(recordAt(root)).toEqual({ sequence: 5 });
    expect(old.isRetired()).toBe(true);
  });

  it("a lock left by a holder whose process has exited is taken over", async () => {
    const root = fortress();
    const lock = join(root, "liveness", "daemon.json.lock");
    const deadPid = 2_000_000_000;
    writeFileSync(lock, `${JSON.stringify({ pid: deadPid, instance: OLD })}\n`, { mode: 0o600 });
    const checked: number[] = [];
    const p = new LivenessRecordPublisher({
      fortressPath: root, fileName: "daemon.json", instance: NEW, operatorUid: UID,
      processExists: pid => { checked.push(pid); return pid !== deadPid; },
    });
    await p.publish({ sequence: 1 });
    expect(checked).toContain(deadPid);
    expect(recordAt(root)).toEqual({ sequence: 1 });
    expect(readdirSync(join(root, "liveness")).sort()).toEqual(["daemon.json", "daemon.json.publisher"]);
  });
});

describe("hostile record files", () => {
  it("a FIFO with no writer is custody_invalid not_regular_file, returned before the deadline fires", async () => {
    const root = fortress();
    const fifo = join(root, "liveness", "daemon.json");
    execFileSync("mkfifo", ["-m", "600", fifo]);
    const deadline = manualDeadline();
    let settled = false;
    const reading = readLivenessRecords({ fortressPath: root, operatorUid: UID, deadline: deadline.clock }).finally(() => { settled = true; });
    // Give a blocking open a fair chance to show itself, then fire the deadline so a blocked open fails the assertion instead of hanging.
    for (let i = 0; i < 50 && !settled; i++) await new Promise(resolve => setTimeout(resolve, 10));
    const firedBeforeResult = !settled;
    deadline.fire();
    const result = await reading;
    expect(firedBeforeResult, "the read finished before the deadline callback had to run").toBe(false);
    expect(result.daemon).toEqual({ status: "custody_invalid", cause: "not_regular_file" });
    expect(result.readDeadlineHit).toBe(false);
    // Opening the write end only now, non-blocking, releases any reader a mutant left blocked.
    try { closeSync(openSync(fifo, fsConstants.O_WRONLY | fsConstants.O_NONBLOCK)); } catch { /* no reader: ENXIO */ }
  });

  it("a FIFO whose writer already left a valid record is refused by fstat before any read", async () => {
    const root = fortress();
    const record = Buffer.from(JSON.stringify(STATES.base.daemon.value));
    let reads = 0;
    const fifoFs: ReaderFs = {
      open: async (path, flags) => {
        if (!path.endsWith("daemon.json")) return nodeReaderFs.open(path, flags);
        let offset = 0;
        return {
          stat: async () => ({ uid: UID, mode: 0o010600, size: 0, isFile: () => false, isDirectory: () => false }),
          read: async (buffer, at, length) => { reads++; const n = Math.min(length, record.length - offset); record.copy(buffer, at, offset, offset + n); offset += n; return { bytesRead: n }; },
          close: async () => undefined,
        };
      },
    };
    const result = await readLivenessRecords({ fortressPath: root, operatorUid: UID, fs: fifoFs });
    expect(result.daemon).toEqual({ status: "custody_invalid", cause: "not_regular_file" });
    expect(reads).toBe(0);
  });

  it("a directory in place of daemon.json is custody_invalid not_regular_file", async () => {
    const root = fortress();
    mkdirSync(join(root, "liveness", "daemon.json"), { mode: 0o700 });
    const result = await readLivenessRecords({ fortressPath: root, operatorUid: UID });
    expect(result.daemon).toEqual({ status: "custody_invalid", cause: "not_regular_file" });
  });

  function stalledFs() {
    let abort: (() => void) | null = null;
    let readStarted = false;
    const fs: ReaderFs = {
      open: async (path, flags) => {
        if (!path.endsWith("daemon.json")) return nodeReaderFs.open(path, flags);
        return {
          stat: async () => ({ uid: UID, mode: 0o100600, size: 2, isFile: () => true, isDirectory: () => false }),
          read: () => { readStarted = true; return new Promise((_resolve, reject) => { abort = () => reject(new Error("aborted by the test")); }); },
          close: async () => undefined,
        };
      },
    };
    return { fs, started: () => readStarted, abort: () => abort?.() };
  }

  it("a stalled read is custody_invalid read_deadline once STATUS_READ_DEADLINE elapses on the injected clock", async () => {
    const root = fortress();
    writeFileSync(join(root, "liveness", "daemon.json"), "{}", { mode: 0o600 });
    const stalled = stalledFs();
    let scheduledMs = 0;
    let fire: () => void = () => undefined;
    const clock: DeadlineClock = { after: (ms, callback) => { scheduledMs = ms; fire = callback; return { cancel: () => undefined }; } };
    try {
      const reading = readLivenessRecords({ fortressPath: root, operatorUid: UID, fs: stalled.fs, deadline: clock });
      for (let i = 0; i < 100 && !stalled.started(); i++) await new Promise(resolve => setTimeout(resolve, 5));
      expect(scheduledMs).toBe(STATUS_READ_DEADLINE);
      fire();
      const result = await reading;
      expect(result.readDeadlineHit).toBe(true);
      expect(result.daemon).toEqual({ status: "custody_invalid", cause: "read_deadline" });
    } finally {
      stalled.abort();
    }
  });

  it("liveness-status exits 70 on a read deadline and prints an envelope whose exit_code is 70", async () => {
    const root = fortress();
    writeFileSync(join(root, "liveness", "daemon.json"), "{}", { mode: 0o600 });
    const stalled = stalledFs();
    let fire: () => void = () => undefined;
    const clock: DeadlineClock = { after: (_ms, callback) => { fire = callback; return { cancel: () => undefined }; } };
    let out = "";
    const sink = new Writable({ write(chunk, _encoding, done) { out += String(chunk); done(); } });
    try {
      const running = runLivenessStatus(["--json", "--fortress", root], {
        platform: "darwin", getuid: () => UID, now: () => START, out: sink, err: sink, env: {},
        hostClock: { read: async () => ({ ok: true, bootId: "boot-fixture", uptimeMs: 1_000_000 }), uptimeMs: () => 1_000_000 },
        readerFs: stalled.fs, deadline: clock,
      });
      for (let i = 0; i < 100 && !stalled.started(); i++) await new Promise(resolve => setTimeout(resolve, 5));
      fire();
      expect(await running).toBe(70);
      const envelope = JSON.parse(out);
      expect(envelope.exit_code).toBe(70);
      expect(envelope.wall.reasons).toContain("custody_invalid");
      expect(envelope.wall.evidence.cause).toBe("read_deadline");
      expect(envelope.subject.fortress_id).toBe(livenessFortressId(root));
    } finally {
      stalled.abort();
    }
  });
});

describe("a stalled operation or cleanup never outlives the read deadline", () => {
  type Stall = "stat" | "read" | "close";
  /**
   * A daemon.json handle that holds one operation open until the test releases it. Close waits for any
   * outstanding operation of the same handle, as a Node FileHandle does, so a stalled stat or read also stalls close.
   */
  function stallingFs(stall: Stall) {
    const releases: Array<() => void> = [];
    let reached = false;
    const hold = <T>(value: T): Promise<T> => { reached = true; return new Promise<T>(resolve => { releases.push(() => resolve(value)); }); };
    const record = Buffer.from("{}");
    const info = { uid: UID, mode: 0o100600, size: record.length, isFile: () => true, isDirectory: () => false };
    const fs: ReaderFs = {
      open: async (path, flags) => {
        if (!path.endsWith("daemon.json")) return nodeReaderFs.open(path, flags);
        let outstanding: Promise<unknown> = Promise.resolve();
        let served = false;
        return {
          stat: () => { const op = stall === "stat" ? hold(info) : Promise.resolve(info); outstanding = op; return op; },
          read: (buffer, at) => {
            if (stall === "read") { const op = hold({ bytesRead: 0 }); outstanding = op; return op; }
            if (served) return Promise.resolve({ bytesRead: 0 });
            served = true;
            record.copy(buffer, at);
            return Promise.resolve({ bytesRead: record.length });
          },
          close: () => stall === "close" ? hold(undefined) : outstanding.then(() => undefined),
        };
      },
    };
    return { fs, reached: () => reached, release: () => { for (const release of releases.splice(0)) release(); } };
  }
  /** Fail fast, rather than hang, when the reader is still waiting on the stalled operation. */
  const settlesWithoutRelease = <T>(pending: Promise<T>): Promise<T> => Promise.race([
    pending,
    new Promise<never>((_resolve, reject) => { setTimeout(() => reject(new Error("still waiting on the stalled operation")), 2 * SECOND).unref(); }),
  ]);
  async function untilReached(stalled: { reached(): boolean }): Promise<void> {
    for (let i = 0; i < 200 && !stalled.reached(); i++) await new Promise(resolve => setTimeout(resolve, 5));
    expect(stalled.reached(), "the schedule reached its stall point").toBe(true);
  }
  const schedules: Stall[] = ["stat", "read", "close"];
  const host = { read: async () => ({ ok: true as const, bootId: "boot-fixture", uptimeMs: 1_000_000 }), uptimeMs: () => 1_000_000 };

  it.each(schedules)("a pending %s returns read_deadline once the deadline fires, before the stall is released", async stall => {
    const root = fortress();
    writeFileSync(join(root, "liveness", "daemon.json"), "{}", { mode: 0o600 });
    const stalled = stallingFs(stall);
    const deadline = manualDeadline();
    try {
      const reading = readLivenessRecords({ fortressPath: root, operatorUid: UID, fs: stalled.fs, deadline: deadline.clock });
      await untilReached(stalled);
      deadline.fire();
      const result = await settlesWithoutRelease(reading);
      expect(result.readDeadlineHit).toBe(true);
      expect(result.daemon).toEqual({ status: "custody_invalid", cause: "read_deadline" });
    } finally {
      stalled.release();
    }
  });

  it.each(schedules)("a pending %s makes liveness-status exit 70 and the status and full-status tail exit 1, before the stall is released", async stall => {
    for (const command of ["liveness-status", "status tail"] as const) {
      const root = fortress();
      writeFileSync(join(root, "liveness", "daemon.json"), "{}", { mode: 0o600 });
      const stalled = stallingFs(stall);
      const deadline = manualDeadline();
      const ctx = { platform: "darwin", getuid: () => UID, now: () => START, hostClock: host, readerFs: stalled.fs, deadline: deadline.clock };
      let out = "";
      const sink = new Writable({ write(chunk, _encoding, done) { out += String(chunk); done(); } });
      try {
        // status and full-status both end in this shared tail: the evaluated envelope mapped through the wall-only exit.
        const running = command === "liveness-status"
          ? runLivenessStatus(["--json", "--fortress", root], { ...ctx, out: sink, err: sink, env: {} })
          : evaluateFortressLiveness(root, ctx).then(wallOnlyStatusExit);
        await untilReached(stalled);
        deadline.fire();
        const exit = await settlesWithoutRelease(running);
        expect(exit, command).toBe(command === "liveness-status" ? 70 : 1);
        if (command === "liveness-status") expect(JSON.parse(out).wall.evidence.cause).toBe("read_deadline");
      } finally {
        stalled.release();
      }
    }
  });

  it("a close that rejects after the deadline is observed and never surfaces", async () => {
    const root = fortress();
    writeFileSync(join(root, "liveness", "daemon.json"), "{}", { mode: 0o600 });
    let rejectClose!: (error: Error) => void;
    let closes = 0;
    let reachedRead = false;
    let releaseRead!: () => void;
    const fs: ReaderFs = {
      open: async (path, flags) => {
        if (!path.endsWith("daemon.json")) return nodeReaderFs.open(path, flags);
        return {
          stat: async () => ({ uid: UID, mode: 0o100600, size: 2, isFile: () => true, isDirectory: () => false }),
          read: () => { reachedRead = true; return new Promise(resolve => { releaseRead = () => resolve({ bytesRead: 0 }); }); },
          close: () => { closes++; return new Promise<void>((_resolve, reject) => { rejectClose = reject; }); },
        };
      },
    };
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", onUnhandled);
    const deadline = manualDeadline();
    try {
      const reading = readLivenessRecords({ fortressPath: root, operatorUid: UID, fs, deadline: deadline.clock });
      for (let i = 0; i < 200 && !reachedRead; i++) await new Promise(resolve => setTimeout(resolve, 5));
      deadline.fire();
      expect((await settlesWithoutRelease(reading)).readDeadlineHit).toBe(true);
      releaseRead();
      for (let i = 0; i < 50 && closes === 0; i++) await new Promise(resolve => setTimeout(resolve, 5));
      rejectClose(new Error("close failed late"));
      await new Promise(resolve => setTimeout(resolve, 20));
      expect(closes).toBe(1);
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("a handle whose open completes after the deadline is closed once by the cleanup owner, and its close rejection is observed", async () => {
    const root = fortress();
    writeFileSync(join(root, "liveness", "daemon.json"), "{}", { mode: 0o600 });
    let releaseOpen!: () => void;
    let opening = false;
    let closes = 0;
    const lateHandle = {
      stat: async () => ({ uid: UID, mode: 0o100600, size: 2, isFile: () => true, isDirectory: () => false }),
      read: async () => ({ bytesRead: 0 }),
      close: () => { closes++; return Promise.reject(new Error("close failed late")); },
    };
    const fs: ReaderFs = {
      open: (path, flags) => {
        if (!path.endsWith("daemon.json")) return nodeReaderFs.open(path, flags);
        opening = true;
        return new Promise(resolve => { releaseOpen = () => resolve(lateHandle); });
      },
    };
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", onUnhandled);
    const deadline = manualDeadline();
    try {
      const reading = readLivenessRecords({ fortressPath: root, operatorUid: UID, fs, deadline: deadline.clock });
      for (let i = 0; i < 200 && !opening; i++) await new Promise(resolve => setTimeout(resolve, 5));
      deadline.fire();
      expect((await settlesWithoutRelease(reading)).readDeadlineHit).toBe(true);
      releaseOpen();
      await new Promise(resolve => setTimeout(resolve, 20));
      expect(closes).toBe(1);
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});

describe("record budgets", () => {
  const label = (seed: string) => (seed + "x".repeat(LABEL_BYTES)).slice(0, LABEL_BYTES);
  const instant = "2026-11-09T12:00:00.000Z";
  const n = COUNTER_MAX;
  const uid = 0xffffffff;
  const subject = { fortress_id: label("f"), host_id: label("h"), platform: label("p"), operator_uid: uid, agent_uid: uid };
  const failures = Array.from({ length: EVIDENCE_FAILURES_MAX }, () => ({ component: "agent", reason: "canary_destination_allowed" }));
  const envelope = (record: string) => ({
    schema_version: 1, record, subject, boot_id: label("b"), config_generation: n, sequence: n, observed_at: instant, observed_uptime_ms: n,
    collection: { started_at_ms: n, ended_at_ms: n }, evidence_failures: failures,
  });

  it("the largest daemon record every cap allows parses and fits STATUS_BYTES", () => {
    const record = {
      ...envelope("daemon"), daemon_instance: label("d"), instance_started_uptime_ms: n, daemon_period_ms: 15 * SECOND,
      raw: {
        process: { pid: uid },
        hooks: { emission_tick: false, verified_admission: false, primary_confirmation: false, pending_evidence: false, canary_slot: false, heartbeat_flush: false },
        lock_recovery: { state: "instrumented", count: n, last_at_ms: n },
        detector: { last_evaluate_at_ms: n, stalled: false },
        heartbeat: { last_durable_flush_at_ms: n },
        pending_evidence: { oldest_unresolved_age_ms: n, ingress_loss_pending: n, coalesced_pending: n, last_rejection_at_ms: n },
        decisions: { verified_admissions: n, primary_confirmations: n, last_natural_primary_at_ms: n },
        canary: {
          adapter: "unsupported",
          last_confirmation: { seq: n, captured_at_ms: n, confirmed_at_ms: n, subject_uid: uid, dest_ip: label("i"), dest_port: 65535, dest_protocol: "tcp", delivery: "durable_wal" },
          last_failure: { seq: n, admitted_at_ms: n, failed_at_ms: n }, last_late: { seq: n, admitted_at_ms: n, settled_at_ms: n },
          failure_count: n, late_count: n, last_destination_allowed: { captured_at_ms: n, principal: "agent" },
        },
        lease: { deadline_ms: n },
      },
    };
    expect(parseDaemonRecord(record).ok).toBe(true);
    const bytes = Buffer.byteLength(`${JSON.stringify(record)}\n`);
    expect(bytes).toBeLessThanOrEqual(STATUS_BYTES);
  });

  it("the largest observer record every cap allows parses and fits STATUS_BYTES", () => {
    const row = { local: "255.255.255.255.65535", foreign: "255.255.255.255.65535", tcp_state: "SYN_RECEIVED", rxbytes: n, txbytes: n, gencnt: "f".repeat(16) };
    const sample = { observed_at: instant, observed_uptime_ms: n, boot_id: label("b"), gateway: { pid: uid, start_identity: label("s"), uid, generation: label("g") }, rows: Array(CENSUS_PID_ROWS).fill(row), other_rows: n };
    const recovery = { samples: Array(RECOVERY_SAMPLES_PER_COMPONENT).fill({ sequence: n, observed_uptime_ms: n }), fault_uptime_ms: n };
    const record = {
      ...envelope("observer"), observer_instance: label("o"), observer_period_ms: 10 * SECOND,
      raw: {
        daemon_ref: { daemon_instance: label("d"), sequence: n },
        availability: { status: "unresponsive", resolved_at_ms: n },
        full_service: { loaded: false, latched: false, pid: uid, start_identity: label("s"), last_charge_at_ms: n },
        session: "reboot_no_login",
        canary_integrity: { passed: false, checked_at_ms: n },
        census: { status: "unavailable", samples: Array(CENSUS_SAMPLES_MAX).fill(sample) },
        gateway: { pid: uid, uid, start_identity: label("s"), generation: label("g"), alive: false },
        optional_reply: { required: false, last_success_at_ms: n, last_failure_at_ms: n },
        mcp: { stale_child: false },
      },
      recovery: { wall: recovery, agent: recovery },
    };
    const parsed = parseObserverRecord(record);
    expect(parsed.ok && parsed.wall.ok && parsed.agent.ok).toBe(true);
    const bytes = Buffer.byteLength(`${JSON.stringify(record)}\n`);
    expect(bytes).toBeLessThanOrEqual(STATUS_BYTES);
  });

  it("over-cap census rows are census_unavailable, and a series longer than CENSUS_SAMPLES_MAX is agent observation_invalid", () => {
    expect(parseCensus("\n".repeat(CENSUS_INPUT_ROWS + 1), { gatewayPid: 1 }).status).toBe("census_unavailable");
    const input = structuredClone(STATES.base);
    const samples = input.observer.value.raw.census.samples as unknown[];
    input.observer.value.raw.census.samples = Array.from({ length: CENSUS_SAMPLES_MAX + 1 }, (_, i) => samples[i % samples.length]);
    const envelope = evaluateLiveness(input);
    expect(envelope.agent.reasons).toContain("observation_invalid");
    expect(envelope.agent.state).toBe("agent_DOWN");
  });
});
