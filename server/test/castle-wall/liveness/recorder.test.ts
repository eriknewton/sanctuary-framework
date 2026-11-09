/** The daemon liveness recorder: record shape, hook wiring, heartbeat flush timing and publication independent of the audit sink. */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CANARY_IP, CANARY_PORT, CANARY_PROTOCOL, COUNTER_MAX, SECOND } from "../../../src/castle-wall/liveness/constants.js";
import { LivenessRecorder, saturatingIncrement, type CanaryOriginSubjects } from "../../../src/castle-wall/liveness/recorder.js";
import { parseDaemonRecord, REQUIRED_RECORDER_HOOKS } from "../../../src/castle-wall/liveness/schema.js";

const START = Date.parse("2026-11-09T12:00:00.000Z");
const UID = process.getuid?.() ?? 0;
const ORIGIN: CanaryOriginSubjects = { adapter: "uid", agentUid: 502, gateUid: null, agentSubject: "fortress-fixture/uid-502", gateSubject: null };
/** Real-time bound on one publication while the sink is held; a held wait would exceed it by the full test timeout. */
const TICK_BOUND_MS = 2 * SECOND;
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function recorder(options: { lockRecovery?: () => { state: "not_instrumented" } } = {}) {
  const fortressPath = mkdtempSync(join(tmpdir(), "lv-rec-"));
  roots.push(fortressPath);
  let now = START;
  let uptime = 3_600_000;
  const r = new LivenessRecorder({
    fortressPath,
    subject: { fortress_id: "fortress-fixture", host_id: "host-fixture", platform: "darwin", operator_uid: UID },
    bootId: "boot-fixture", instanceStartedUptimeMs: uptime, uptimeMs: () => uptime, now: () => now, pid: 4242, instance: "abcdef0123456789",
    origin: () => ORIGIN, ...options,
  });
  return {
    r, fortressPath,
    advance: (ms: number) => { now += ms; uptime += ms; },
    read: () => JSON.parse(readFileSync(join(fortressPath, "liveness", "daemon.json"), "utf8")) as Record<string, any>,
  };
}
function wireAll(r: LivenessRecorder) {
  r.bindEmissionNotes({ noteDecision: () => undefined, noteEmission: () => undefined, noteRejection: () => undefined });
  r.bindEmissionTick(() => ({ lastEvaluateAtMs: START, stalled: false, firstUnemittedDecisionAtMs: null }));
  r.bindPendingEvidence(() => ({ ingressLossPending: 0, coalescedPending: 0 }));
  r.bindCanarySlot();
  r.bindHeartbeatFlush();
}

describe("record shape", () => {
  it("builds a record the strict parser accepts, with every wired hook and the uninstrumented lock field", () => {
    const { r } = recorder();
    wireAll(r);
    const record = r.buildRecord();
    const parsed = parseDaemonRecord(record);
    expect(parsed.ok, JSON.stringify(parsed)).toBe(true);
    expect(Object.keys((record.raw as any).hooks).sort()).toEqual([...REQUIRED_RECORDER_HOOKS].sort());
    expect((record.raw as any).lock_recovery).toEqual({ state: "not_instrumented" });
    expect(record).toMatchObject({ boot_id: "boot-fixture", instance_started_uptime_ms: 3_600_000, observed_uptime_ms: 3_600_000, sequence: 1, subject: { agent_uid: 502 } });
  });

  it("omits a hook that was never bound, so the reader sees no wired flag", () => {
    const { r } = recorder();
    r.bindEmissionTick(() => ({ lastEvaluateAtMs: START, stalled: false, firstUnemittedDecisionAtMs: null }));
    const hooks = (r.buildRecord().raw as any).hooks as Record<string, boolean>;
    expect(hooks).toEqual({ emission_tick: true });
  });

  it("counts verified admissions and primary confirmations and never counts a canary confirmation as natural workload", () => {
    const { r } = recorder();
    const notes = r.bindEmissionNotes({ noteDecision: () => undefined, noteEmission: () => undefined, noteRejection: () => undefined });
    const slot = r.bindCanarySlot();
    slot.admit({ seq: 1, capturedAtMs: START, subjectUid: 502, destIp: CANARY_IP, destPort: CANARY_PORT, destProtocol: CANARY_PROTOCOL });
    notes.noteDecision("live");
    slot.settled(true);
    notes.noteEmission();
    let raw = r.buildRecord().raw as any;
    expect(raw.decisions).toEqual({ verified_admissions: 1, primary_confirmations: 1, last_natural_primary_at_ms: null });
    notes.noteDecision("live");
    notes.noteEmission();
    raw = r.buildRecord().raw as any;
    expect(raw.decisions.last_natural_primary_at_ms).toBe(START);
    notes.noteRejection("signature");
    expect((r.buildRecord().raw as any).pending_evidence.last_rejection_at_ms).toBe(START);
  });

  it("saturates every count at COUNTER_MAX", () => {
    expect(saturatingIncrement(COUNTER_MAX - 1)).toBe(COUNTER_MAX);
    expect(saturatingIncrement(COUNTER_MAX)).toBe(COUNTER_MAX);
  });
});

describe("heartbeat flush", () => {
  it("does not refresh the last successful flush time when the stop budget skipped the flush", async () => {
    const { r } = recorder();
    let flushed = 0;
    await r.flushHeartbeat(true, async () => { flushed++; });
    expect(flushed).toBe(0);
    expect((r.buildRecord().raw as any).heartbeat.last_durable_flush_at_ms).toBeNull();
  });

  it("records the flush time only after the durable flush resolves", async () => {
    const { r, advance } = recorder();
    let release!: () => void;
    const pending = r.flushHeartbeat(false, () => new Promise<void>(resolve => { release = resolve; }));
    expect((r.buildRecord().raw as any).heartbeat.last_durable_flush_at_ms).toBeNull();
    advance(SECOND);
    release();
    await pending;
    expect((r.buildRecord().raw as any).heartbeat.last_durable_flush_at_ms).toBe(START + SECOND);
  });

  it("a failed flush never records a success time", async () => {
    const { r } = recorder();
    await expect(r.flushHeartbeat(false, async () => { throw new Error("fixture flush failure"); })).rejects.toThrow();
    expect((r.buildRecord().raw as any).heartbeat.last_durable_flush_at_ms).toBeNull();
  });
});

describe("publication independent of the audit sink", () => {
  it("publishes on every tick while the sink is held, and reports the pending age rising", async () => {
    const { r, advance, read } = recorder();
    wireAll(r);
    let firstUnemitted: number | null = START;
    r.bindEmissionTick(() => ({ lastEvaluateAtMs: START, stalled: false, firstUnemittedDecisionAtMs: firstUnemitted }));
    // The held sink: a heartbeat flush that never resolves.
    void r.flushHeartbeat(false, () => new Promise<void>(() => undefined));
    // A tick that waited on the held sink would never settle, so it is raced against a bound well inside the test timeout.
    const tick = () => Promise.race([r.emissionTick(), new Promise<never>((_, reject) => setTimeout(() => reject(new Error("publication waited on the held audit sink")), TICK_BOUND_MS))]);
    await tick();
    const first = read();
    expect(first.sequence).toBe(1);
    expect(first.raw.pending_evidence.oldest_unresolved_age_ms).toBe(0);
    advance(15 * SECOND);
    await tick();
    const second = read();
    expect(second.sequence).toBe(2);
    expect(second.raw.pending_evidence.oldest_unresolved_age_ms).toBe(15 * SECOND);
    expect(second.raw.heartbeat.last_durable_flush_at_ms).toBeNull();
    firstUnemitted = null;
    expect(r.stats().published).toBe(2);
  });

  it("after retirement at daemon stop a tick publishes nothing and never throws", async () => {
    const { r, read } = recorder();
    wireAll(r);
    await r.emissionTick();
    expect(read().sequence).toBe(1);
    r.retire();
    await expect(r.emissionTick()).resolves.toBeUndefined();
    expect(read().sequence).toBe(1);
    expect(r.stats().published).toBe(1);
  });

  it("a publication failure is counted and never thrown into the tick", async () => {
    const { r } = recorder();
    const failing = new LivenessRecorder({
      fortressPath: "/nonexistent-fortress-path-for-fixture", subject: { fortress_id: "f", host_id: "h", platform: "darwin", operator_uid: UID },
      bootId: null, instanceStartedUptimeMs: 0, uptimeMs: () => 0, pid: 1, instance: "0123456789abcdef", origin: () => ORIGIN,
    });
    await expect(failing.emissionTick()).resolves.toBeUndefined();
    expect(failing.stats().failures).toBe(1);
    expect(r.stats().failures).toBe(0);
  });
});
