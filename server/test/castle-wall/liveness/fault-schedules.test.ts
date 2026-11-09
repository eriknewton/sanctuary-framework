/** Rule 8 and rule 12 fault schedules: slot waves, saturation, spam caps, paused publication, claim reads, hostile record files and record budgets. */
import { execFileSync } from "node:child_process";
import { closeSync, constants as fsConstants, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import {
  LivenessRecordPublisher,
  nodePublisherFs,
  PUBLICATION_CLAIM_BYTES,
  serializePublicationClaim,
  type LivenessPublisherOptions,
  type PublisherDeadlineClock,
  type PublisherFileHandle,
  type PublisherFs,
} from "../../../src/castle-wall/liveness/record-store.js";
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
  const BOOT = "boot-fixture";
  /** Both instances run on BOOT; the later start is the newer instance. */
  const OLD_START = 1_000;
  const NEW_START = 2_000;
  type Step = "open" | "write" | "rename";
  const liveness = (root: string) => join(root, "liveness");
  const recordAt = (root: string) => JSON.parse(readFileSync(join(liveness(root), "daemon.json"), "utf8")) as unknown;
  const claimFile = (root: string) => join(liveness(root), "daemon.json.publisher");
  const claimOf = (instance: string, start: number, boot: string | null = BOOT) =>
    serializePublicationClaim({ instance, boot_id: boot, instance_started_uptime_ms: start });
  const settled = (root: string) => readdirSync(liveness(root)).sort();
  const make = (root: string, instance: string, start: number, fs?: PublisherFs, extra: Partial<LivenessPublisherOptions> = {}) =>
    new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance, bootId: BOOT, instanceStartedUptimeMs: start, operatorUid: UID, fs, ...extra });
  /** A handle forwarding to a real one, with any method replaced. */
  const forward = (handle: PublisherFileHandle, over: Partial<PublisherFileHandle> = {}): PublisherFileHandle => ({
    stat: () => handle.stat(), read: (b, o, l, p) => handle.read(b, o, l, p), writeFile: d => handle.writeFile(d), sync: () => handle.sync(), close: () => handle.close(), ...over,
  });
  /** A one-shot pause: `hold()` signals `reached`, then waits for `release()`. */
  function pause() {
    let release!: () => void;
    const opened = new Promise<void>(resolve => { release = resolve; });
    let reach!: () => void;
    const reached = new Promise<void>(resolve => { reach = resolve; });
    return { hold: async () => { reach(); await opened; }, reached, release };
  }

  /** Pause the old publisher's second record write at one step, after its first publish has claimed the target. */
  function pausedAt(root: string, step: Step) {
    const recordTemp = join(liveness(root), `daemon.json.${OLD}.tmp`);
    const target = join(liveness(root), "daemon.json");
    const gate = pause();
    let armed = false;
    const fs: PublisherFs = {
      ...nodePublisherFs,
      open: async (path, flags, mode) => {
        if (armed && step === "open" && path === recordTemp) { armed = false; await gate.hold(); }
        const handle = await nodePublisherFs.open(path, flags, mode);
        if (path !== recordTemp) return handle;
        return forward(handle, { writeFile: async data => { if (armed && step === "write") { armed = false; await gate.hold(); } return handle.writeFile(data); } });
      },
      rename: async (from, to) => {
        if (armed && step === "rename" && to === target) { armed = false; await gate.hold(); }
        return nodePublisherFs.rename(from, to);
      },
    };
    return { fs, arm: () => { armed = true; }, atStep: gate.reached, release: gate.release };
  }

  it.each(["open", "write", "rename"] as const)("a queued old snapshot and a late %s completion never overwrite the newer instance's record", async step => {
    const root = fortress();
    const paused = pausedAt(root, step);
    const old = make(root, OLD, OLD_START, paused.fs);
    await old.publish({ sequence: 1 });
    paused.arm();
    const late = old.publish({ sequence: 2 });
    late.catch(() => undefined);
    await paused.atStep;
    // A legitimate later tick queues behind the paused write.
    const queued = old.publish({ sequence: 3 });
    queued.catch(() => undefined);
    await make(root, NEW, NEW_START).publish({ sequence: 5 });
    expect(recordAt(root)).toEqual({ sequence: 5 });
    paused.release();
    await Promise.allSettled([late, queued]);
    // A paused rename was issued after its final check; the newer instance's claim removed the temp it would have renamed.
    expect(recordAt(root)).toEqual({ sequence: 5 });
    expect(old.isRetired()).toBe(true);
    await expect(old.publish({ sequence: 4 })).rejects.toThrow("retired");
    expect(recordAt(root)).toEqual({ sequence: 5 });
    expect(settled(root)).toEqual(["daemon.json", "daemon.json.publisher"]);
    expect(readFileSync(claimFile(root), "utf8")).toBe(claimOf(NEW, NEW_START));
  });

  it("a retired publisher drops its waiting snapshot and creates nothing more", async () => {
    const root = fortress();
    const paused = pausedAt(root, "write");
    const recordTemp = join(liveness(root), `daemon.json.${OLD}.tmp`);
    let tempOpens = 0;
    const counting: PublisherFs = { ...paused.fs, open: (path, flags, mode) => { if (path === recordTemp) tempOpens++; return paused.fs.open(path, flags, mode); } };
    const p = make(root, OLD, OLD_START, counting);
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
    expect(settled(root)).toEqual(["daemon.json", "daemon.json.publisher"]);
  });

  it.each(["older", "newer"] as const)("a delayed first claim by the %s instance leaves the newer instance's claim and record", async delayed => {
    const root = fortress();
    const gate = pause();
    // The delayed instance stops in directory validation, before it has read any claim.
    const slow: PublisherFs = { ...nodePublisherFs, lstat: async path => { await gate.hold(); return nodePublisherFs.lstat(path); } };
    const old = make(root, OLD, OLD_START, delayed === "older" ? slow : undefined);
    const restarted = make(root, NEW, NEW_START, delayed === "newer" ? slow : undefined);
    const first = delayed === "older" ? old : restarted;
    const second = delayed === "older" ? restarted : old;
    const delayedPublish = first.publish({ sequence: delayed === "older" ? 1 : 5 });
    delayedPublish.catch(() => undefined);
    await gate.reached;
    await second.publish({ sequence: delayed === "older" ? 5 : 1 });
    gate.release();
    await Promise.allSettled([delayedPublish]);
    // Whichever instance claimed first, the older one never commits over the newer one and ends retired.
    await expect(old.publish({ sequence: 2 })).rejects.toThrow();
    expect(old.isRetired()).toBe(true);
    expect(recordAt(root)).toEqual({ sequence: 5 });
    expect(readFileSync(claimFile(root), "utf8")).toBe(claimOf(NEW, NEW_START));
    await restarted.publish({ sequence: 6 });
    expect(recordAt(root)).toEqual({ sequence: 6 });
    expect(settled(root)).toEqual(["daemon.json", "daemon.json.publisher"]);
  });

  it.each(["older", "newer"] as const)("concurrent first claims where the %s claim lands first leave the newer instance's claim and record", async landsFirst => {
    const root = fortress();
    const oldClaim = pause();
    const newClaim = pause();
    const oldOpen = pause();
    let oldClaimed = false;
    const oldRecordTemp = join(liveness(root), `daemon.json.${OLD}.tmp`);
    // Each instance stops at the step that lands its claim, after both have read the claim as absent.
    const claimStep = (gate: ReturnType<typeof pause>, onLanded: () => void): PublisherFs => ({
      ...nodePublisherFs,
      link: async (from, to) => { if (to === claimFile(root)) await gate.hold(); try { await nodePublisherFs.link(from, to); } finally { onLanded(); } },
      rename: async (from, to) => { if (to === claimFile(root)) await gate.hold(); await nodePublisherFs.rename(from, to); },
    });
    const oldFs: PublisherFs = {
      ...claimStep(oldClaim, () => { oldClaimed = true; }),
      // The old instance's record write waits until the newer instance has published, so the outcome is deterministic.
      open: async (path, flags, mode) => { if (path === oldRecordTemp) await oldOpen.hold(); return nodePublisherFs.open(path, flags, mode); },
    };
    const old = make(root, OLD, OLD_START, oldFs);
    const restarted = make(root, NEW, NEW_START, claimStep(newClaim, () => undefined));
    const oldFirst = old.publish({ sequence: 1 });
    oldFirst.catch(() => undefined);
    await oldClaim.reached;
    const newFirst = restarted.publish({ sequence: 5 });
    newFirst.catch(() => undefined);
    await newClaim.reached;
    if (landsFirst === "older") {
      oldClaim.release();
      await oldOpen.reached;
      expect(oldClaimed).toBe(true);
      expect(readFileSync(claimFile(root), "utf8")).toBe(claimOf(OLD, OLD_START));
      newClaim.release();
      await newFirst;
    } else {
      newClaim.release();
      await newFirst;
      oldClaim.release();
    }
    expect(recordAt(root)).toEqual({ sequence: 5 });
    oldOpen.release();
    await Promise.allSettled([oldFirst]);
    await expect(old.publish({ sequence: 2 })).rejects.toThrow();
    expect(old.isRetired()).toBe(true);
    expect(recordAt(root)).toEqual({ sequence: 5 });
    expect(readFileSync(claimFile(root), "utf8")).toBe(claimOf(NEW, NEW_START));
    expect(settled(root)).toEqual(["daemon.json", "daemon.json.publisher"]);
  });

  it("a claim left by another boot is superseded by the current boot's instance even when its start uptime is later", async () => {
    const root = fortress();
    // The previous boot's daemon started later on its own uptime clock; uptimes of different boots are not comparable.
    await make(root, OLD, NEW_START * 1_000, undefined, { bootId: "boot-previous" }).publish({ sequence: 1 });
    await make(root, NEW, NEW_START).publish({ sequence: 5 });
    expect(recordAt(root)).toEqual({ sequence: 5 });
    expect(readFileSync(claimFile(root), "utf8")).toBe(claimOf(NEW, NEW_START));
    expect(settled(root)).toEqual(["daemon.json", "daemon.json.publisher"]);
  });

  it.each(["removing the earlier instance's temps", "writing its own claim"] as const)("retirement while %s issues no later effect and leaves the earlier claim", async step => {
    const root = fortress();
    writeFileSync(claimFile(root), claimOf(OLD, OLD_START), { mode: 0o600 });
    writeFileSync(join(liveness(root), `daemon.json.${OLD}.tmp`), JSON.stringify({ sequence: 99 }), { mode: 0o600 });
    const ownClaimTemp = join(liveness(root), `daemon.json.${NEW}.publisher.tmp`);
    const gate = pause();
    let retired = false;
    const afterRetire: string[] = [];
    const note = (effect: string, path: string) => { if (retired) afterRetire.push(`${effect} ${path}`); };
    const fs: PublisherFs = {
      ...nodePublisherFs,
      mkdir: (path, options) => { note("mkdir", path); return nodePublisherFs.mkdir(path, options); },
      link: (from, to) => { note("link", to); return nodePublisherFs.link(from, to); },
      rename: (from, to) => { note("rename", to); return nodePublisherFs.rename(from, to); },
      unlink: async path => {
        // An effect is noted when it is issued; the paused unlink was issued before the retirement.
        note("unlink", path);
        if (step === "removing the earlier instance's temps" && path.includes(OLD)) await gate.hold();
        return nodePublisherFs.unlink(path);
      },
      open: async (path, flags, mode) => {
        note("open", path);
        const handle = await nodePublisherFs.open(path, flags, mode);
        if (step !== "writing its own claim" || path !== ownClaimTemp) return handle;
        return forward(handle, { sync: async () => { await gate.hold(); return handle.sync(); } });
      },
    };
    const p = make(root, NEW, NEW_START, fs);
    const publishing = p.publish({ sequence: 5 });
    publishing.catch(() => undefined);
    await gate.reached;
    p.retire();
    retired = true;
    gate.release();
    await expect(publishing).rejects.toThrow("retired");
    expect(readFileSync(claimFile(root), "utf8")).toBe(claimOf(OLD, OLD_START));
    // The only effect after retirement is removing this instance's own unfinished claim temp.
    expect(afterRetire.filter(effect => effect !== `unlink ${ownClaimTemp}`), "no effect follows the retirement").toEqual([]);
    expect(settled(root).filter(name => name.includes(NEW))).toEqual([]);
    expect(settled(root)).not.toContain("daemon.json");
  });

  it("retirement during the claim read before a commit leaves the target unchanged", async () => {
    const root = fortress();
    const gate = pause();
    let armed = false;
    const fs: PublisherFs = {
      ...nodePublisherFs,
      open: async (path, flags, mode) => { if (armed && path === claimFile(root)) { armed = false; await gate.hold(); } return nodePublisherFs.open(path, flags, mode); },
    };
    const p = make(root, OLD, OLD_START, fs);
    await p.publish({ sequence: 1 });
    armed = true;
    const publishing = p.publish({ sequence: 2 });
    publishing.catch(() => undefined);
    await gate.reached;
    p.retire();
    gate.release();
    await expect(publishing).rejects.toThrow("retired");
    expect(recordAt(root)).toEqual({ sequence: 1 });
    expect(settled(root)).toEqual(["daemon.json", "daemon.json.publisher"]);
  });

  it("retirement while a stale temp is removed before a create opens nothing", async () => {
    const root = fortress();
    const recordTemp = join(liveness(root), `daemon.json.${OLD}.tmp`);
    const gate = pause();
    let armed = false;
    const opens: string[] = [];
    const fs: PublisherFs = {
      ...nodePublisherFs,
      unlink: async path => { if (armed && path === recordTemp) { armed = false; await gate.hold(); } return nodePublisherFs.unlink(path); },
      open: (path, flags, mode) => { opens.push(path); return nodePublisherFs.open(path, flags, mode); },
    };
    const p = make(root, OLD, OLD_START, fs);
    await p.publish({ sequence: 1 });
    armed = true;
    const publishing = p.publish({ sequence: 2 });
    publishing.catch(() => undefined);
    await gate.reached;
    const opensAtRetire = opens.length;
    p.retire();
    gate.release();
    await expect(publishing).rejects.toThrow("retired");
    expect(opens.length, "no open follows the retirement").toBe(opensAtRetire);
    expect(recordAt(root)).toEqual({ sequence: 1 });
  });

  it("an old-instance record landing after the newer instance's record reads not-OK with exit 1", async () => {
    const root = fortress();
    const base = STATES.base;
    const currentRecord = base.daemon.value;
    const staleRecord = { ...currentRecord, daemon_instance: "daemon-fixture-0", sequence: currentRecord.sequence + 1 };
    const write = (record: unknown) => writeFileSync(join(liveness(root), "daemon.json"), `${JSON.stringify(record)}\n`, { mode: 0o600 });
    const evaluateOnDisk = async () => {
      const read = await readLivenessRecords({ fortressPath: root, operatorUid: UID });
      return evaluateLiveness({ ...base, daemon: read.daemon });
    };
    expect(base.observer.value.raw.daemon_ref).toEqual({ daemon_instance: currentRecord.daemon_instance, sequence: currentRecord.sequence });
    write(currentRecord);
    const current = await evaluateOnDisk();
    expect(current.exit_code, current.wall.reasons.join(",")).toBe(0);
    // A superseded instance's rename issued inside the window after its final check lands over the newer record.
    write(staleRecord);
    const stale = await evaluateOnDisk();
    expect(stale.wall.state.startsWith("wall_OK_")).toBe(false);
    expect(stale.exit_code).toBe(1);
    expect(wallOnlyStatusExit(stale)).toBe(1);
  });
});

describe("publication claim reads", () => {
  const INSTANCE = "3333333333333333";
  const OLDER = "1111111111111111";
  const liveness = (root: string) => join(root, "liveness");
  const claimFile = (root: string) => join(liveness(root), "daemon.json.publisher");
  const olderTemp = (root: string) => join(liveness(root), `daemon.json.${OLDER}.tmp`);
  const olderClaim = serializePublicationClaim({ instance: OLDER, boot_id: "boot-fixture", instance_started_uptime_ms: 1_000 });
  const make = (root: string, fs?: PublisherFs, deadline?: PublisherDeadlineClock) =>
    new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: INSTANCE, bootId: "boot-fixture", instanceStartedUptimeMs: 2_000, operatorUid: UID, fs, claimReadDeadline: deadline });
  /** A claim this instance would supersede, plus that instance's temp, so a claim read that granted ownership would delete it. */
  function seedOlder(root: string, claimBytes: string | Buffer = olderClaim) {
    writeFileSync(claimFile(root), claimBytes, { mode: 0o600 });
    writeFileSync(olderTemp(root), "{}\n", { mode: 0o600 });
  }
  const unchanged = (root: string, claimBytes: string | Buffer) => {
    expect(readFileSync(claimFile(root)).equals(Buffer.from(claimBytes)), "the claim bytes are unchanged").toBe(true);
    expect(existsSync(olderTemp(root)), "nothing is deleted").toBe(true);
    expect(existsSync(join(liveness(root), "daemon.json")), "no record is written").toBe(false);
  };

  it("an oversized claim grants nothing, deletes nothing, and reads at most PUBLICATION_CLAIM_BYTES + 1 bytes", async () => {
    const root = fortress();
    const oversized = Buffer.concat([Buffer.from(olderClaim), Buffer.alloc(2 * 1024 * 1024, 0x20)]);
    seedOlder(root, oversized);
    let requested = 0;
    const fs: PublisherFs = {
      ...nodePublisherFs,
      open: async (path, flags, mode) => {
        const handle = await nodePublisherFs.open(path, flags, mode);
        if (path !== claimFile(root)) return handle;
        return { stat: () => handle.stat(), writeFile: d => handle.writeFile(d), sync: () => handle.sync(), close: () => handle.close(),
          read: (b, o, l, p) => { requested += l; return handle.read(b, o, l, p); } };
      },
    };
    await expect(make(root, fs).publish({ sequence: 1 })).rejects.toThrow("indeterminate");
    expect(requested).toBeLessThanOrEqual(PUBLICATION_CLAIM_BYTES + 1);
    unchanged(root, oversized);
  });

  it("a FIFO in place of the claim is refused without blocking", async () => {
    const root = fortress();
    execFileSync("mkfifo", ["-m", "600", claimFile(root)]);
    writeFileSync(olderTemp(root), "{}\n", { mode: 0o600 });
    const deadline = manualDeadline();
    await expect(make(root, undefined, deadline.clock).publish({ sequence: 1 })).rejects.toThrow("indeterminate");
    expect(deadline.fired()).toBe(false);
    expect(existsSync(olderTemp(root))).toBe(true);
    expect(existsSync(join(liveness(root), "daemon.json"))).toBe(false);
  });

  it("a descriptor that is not a regular file is refused before any byte is read", async () => {
    const root = fortress();
    seedOlder(root);
    let reads = 0;
    const fs: PublisherFs = {
      ...nodePublisherFs,
      open: async (path, flags, mode) => {
        const handle = await nodePublisherFs.open(path, flags, mode);
        if (path !== claimFile(root)) return handle;
        return { writeFile: d => handle.writeFile(d), sync: () => handle.sync(), close: () => handle.close(),
          stat: async () => { const info = await handle.stat(); return { uid: info.uid, mode: info.mode, isFile: () => false }; },
          read: (b, o, l, p) => { reads++; return handle.read(b, o, l, p); } };
      },
    };
    await expect(make(root, fs).publish({ sequence: 1 })).rejects.toThrow("indeterminate");
    expect(reads).toBe(0);
    unchanged(root, olderClaim);
  });

  it("a claim with an unknown field is malformed and grants nothing", async () => {
    const root = fortress();
    const malformed = `${JSON.stringify({ instance: OLDER, boot_id: "boot-fixture", instance_started_uptime_ms: 1_000, extra: true })}\n`;
    seedOlder(root, malformed);
    await expect(make(root).publish({ sequence: 1 })).rejects.toThrow("indeterminate");
    unchanged(root, malformed);
  });

  it("a claim that becomes unreadable after this instance owns it retires the publisher before any commit", async () => {
    const root = fortress();
    const p = make(root);
    await p.publish({ sequence: 1 });
    const corrupt = "not a claim\n";
    writeFileSync(claimFile(root), corrupt, { mode: 0o600 });
    await expect(p.publish({ sequence: 2 })).rejects.toThrow("indeterminate");
    expect(p.isRetired()).toBe(true);
    expect(JSON.parse(readFileSync(join(liveness(root), "daemon.json"), "utf8"))).toEqual({ sequence: 1 });
    expect(readFileSync(claimFile(root), "utf8")).toBe(corrupt);
    expect(readdirSync(liveness(root)).sort()).toEqual(["daemon.json", "daemon.json.publisher"]);
  });

  it("a claim read that outlives its deadline grants nothing, and its late result is discarded", async () => {
    const root = fortress();
    seedOlder(root);
    const gate = { release: () => undefined as void };
    let reached!: () => void;
    const atRead = new Promise<void>(resolve => { reached = resolve; });
    const fs: PublisherFs = {
      ...nodePublisherFs,
      open: async (path, flags, mode) => {
        const handle = await nodePublisherFs.open(path, flags, mode);
        if (path !== claimFile(root)) return handle;
        return { stat: () => handle.stat(), writeFile: d => handle.writeFile(d), sync: () => handle.sync(), close: () => handle.close(),
          read: async (b, o, l, p) => { reached(); await new Promise<void>(resolve => { gate.release = resolve; }); return handle.read(b, o, l, p); } };
      },
    };
    const deadline = manualDeadline();
    const publishing = make(root, fs, deadline.clock).publish({ sequence: 1 });
    publishing.catch(() => undefined);
    await atRead;
    expect(deadline.scheduled()).toBe(true);
    deadline.fire();
    await expect(publishing).rejects.toThrow("indeterminate");
    gate.release();
    await new Promise(resolve => setTimeout(resolve, 20));
    unchanged(root, olderClaim);
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
