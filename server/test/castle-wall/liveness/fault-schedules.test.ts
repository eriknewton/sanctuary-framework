/** Rule 8 and rule 12 fault schedules: slot waves, saturation, spam caps, paused publication, hostile record files and record budgets. */
import { execFileSync } from "node:child_process";
import { closeSync, constants as fsConstants, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import { livenessFortressId, runLivenessStatus } from "../../../src/cli/castle-wall-liveness-status.js";

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

describe("publication paused before rename, then restart", () => {
  it("never trusts the old temp and a late old write cannot overwrite a newer sequence", async () => {
    const root = fortress();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let reachedRename!: () => void;
    const atRename = new Promise<void>(resolve => { reachedRename = resolve; });
    const pausedFs: PublisherFs = { ...nodePublisherFs, rename: async (from, to) => { reachedRename(); await gate; return nodePublisherFs.rename(from, to); } };
    const old = new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: "1111111111111111", operatorUid: UID, fs: pausedFs });
    const late = old.publish({ sequence: 1 });
    await atRename;
    const restarted = new LivenessRecordPublisher({ fortressPath: root, fileName: "daemon.json", instance: "2222222222222222", operatorUid: UID });
    await restarted.publish({ sequence: 5 });
    release();
    await late.catch(() => undefined);
    expect(JSON.parse(readFileSync(join(root, "liveness", "daemon.json"), "utf8"))).toEqual({ sequence: 5 });
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
