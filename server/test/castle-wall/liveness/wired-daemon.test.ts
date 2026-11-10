/** The real daemon composition wires the liveness recorder: daemon.json publishes with every hook, independent of a held audit sink. */
import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, stat, unlink } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { AuditLog, AuditLockHoldDeadlineError } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { toBase64url } from "../../../src/core/encoding.js";
import { runProvisionPin } from "../../../src/cli/castle-wall.js";
import { initializeTestCustody } from "../../helpers/custody-fixture.js";
import {
  startMacOSCastleWallDaemon as startProductionMacOSCastleWallDaemon,
  type MacOSCastleWallDaemonInput,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";
import { canaryWindow, HISTORY_WINDOW, SECOND } from "../../../src/castle-wall/liveness/constants.js";
import { evaluateLiveness } from "../../../src/castle-wall/liveness/evaluate.js";
import { readLivenessRecords } from "../../../src/castle-wall/liveness/read-status.js";
import { parseDaemonRecord, REQUIRED_RECORDER_HOOKS } from "../../../src/castle-wall/liveness/schema.js";

const silent = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
const UID = process.getuid?.() ?? 0;
const BOOT = "boot-wired-fixture";
const UPTIME = 5_000_000;
// A short real hold deadline forces recovery without waiting for the production deadline.
const LOCK_HOLD_MS = SECOND / 10;
const PUBLICATION_TICKS_PER_SECOND = 100; // One hundred publication ticks per second in this fixture.
const TICK_SECONDS = 1 / PUBLICATION_TICKS_PER_SECOND;
const STATES = JSON.parse(readFileSync(join(__dirname, "fixtures", "states.json"), "utf8")) as { base: any }; // Untyped fixture JSON, patched by path.

const hermeticGlobalPinPath = (fortressPath: string) => join(fortressPath, "test-system", "castle-pinned-pubkey.bin");
function startDaemon(input: MacOSCastleWallDaemonInput) {
  // Only temp custody: installed machine-wide trust anchors and producer state are never fixtures.
  return startProductionMacOSCastleWallDaemon({
    globalPinnedPublicKeyPath: hermeticGlobalPinPath(input.fortressPath),
    auditProducerPublicKeyPath: join(input.fortressPath, "test-system", "castle-audit-producer.pub"),
    auditProducerStatePath: null,
    ...input,
  });
}
function fakeListenerFactory(options: MacOSCastleWallListenerOptions) {
  let server: ReturnType<typeof createServer> | null = null;
  return {
    async start() {
      await new Promise<void>((resolve, reject) => {
        const s = createServer();
        s.once("error", reject);
        // port-discipline: ignore - Unix domain socket path, not a TCP port.
        s.listen(options.socketPath, () => { server = s; resolve(); });
      });
    },
    async stop() {
      if (server) { const s = server; server = null; await new Promise<void>(resolve => s.close(() => resolve())); }
      await unlink(options.socketPath).catch(() => {});
    },
    async broadcastManifestUpdate() { return 0; },
    async broadcastDecisionResponse() { return 0; },
    async broadcastArmLease() { return 0; },
    recycleConnection() { return false; },
  };
}

describe("wired daemon recorder", () => {
  const tempDirs: string[] = [];
  afterEach(async () => { for (const dir of tempDirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

  async function provisionFortress(writeLockHoldDeadlineMs?: number) {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-live-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
    await initializeTestCustody(fortressPath, { recoveryKey });
    await mkdir(join(fortressPath, "test-system"), { mode: 0o700 });
    const pin = await runProvisionPin([], { out: silent, err: silent, globalPinnedPublicKeyPath: hermeticGlobalPinPath(fortressPath),
      env: { SANCTUARY_STORAGE_PATH: fortressPath, SANCTUARY_RECOVERY_KEY: recoveryKey } });
    expect(pin).toBe(0);
    const auditLog = new AuditLog(new FilesystemStorage(join(fortressPath, "state")), masterKey, { integrityMode: "lenient", writeLockHoldDeadlineMs });
    return { fortressPath, masterKey, auditLog };
  }
  const daemonJson = (fortressPath: string) => join(fortressPath, "liveness", "daemon.json");
  async function waitForSequence(fortressPath: string, atLeast: number, atLeastRecoveries = 0): Promise<Record<string, any>> {
    for (let i = 0; i < 400; i++) {
      const text = await readFile(daemonJson(fortressPath), "utf8").catch(() => null);
      if (text !== null) {
        const record = JSON.parse(text) as Record<string, any>;
        if (record.sequence >= atLeast && record.raw.lock_recovery.count >= atLeastRecoveries) return record;
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error(`daemon.json never reached sequence ${atLeast}`);
  }

  it("publishes daemon.json from the full daemon with every recorder hook wired", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startDaemon({
      fortressPath, fortressId: "fortress-test", masterKey, localSign: true, auditLog, platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"), listenerFactory: fakeListenerFactory,
      emissionLivenessTickSeconds: 0.01, livenessHostClock: { bootId: async () => BOOT, uptimeMs: () => UPTIME },
    });
    try {
      const record = await waitForSequence(fortressPath, 2);
      const parsed = parseDaemonRecord(record);
      expect(parsed.ok, JSON.stringify(parsed)).toBe(true);
      for (const hook of REQUIRED_RECORDER_HOOKS) expect(record.raw.hooks[hook], hook).toBe(true);
      expect(record.raw.lock_recovery).toEqual({ state: "instrumented", count: 0, last_at_ms: null });
      expect(record).toMatchObject({ boot_id: BOOT, instance_started_uptime_ms: UPTIME, subject: { fortress_id: "fortress-test", platform: "darwin", operator_uid: UID } });
      // No signed agent origin is loaded, so the canary adapter is unsupported, never a uid adapter by default.
      expect(record.raw.canary.adapter).toBe("unsupported");
      expect((await stat(daemonJson(fortressPath))).mode & 0o777).toBe(0o600);

      // The published hooks satisfy gate 6 only while every one is present.
      const withHooks = structuredClone(STATES.base);
      withHooks.daemon.value.raw.hooks = record.raw.hooks;
      expect(evaluateLiveness(withHooks).wall.reasons).not.toContain("evidence_incomplete");
      for (const hook of REQUIRED_RECORDER_HOOKS) {
        const missing = structuredClone(withHooks);
        delete missing.daemon.value.raw.hooks[hook];
        expect(evaluateLiveness(missing).wall.reasons, hook).toContain("evidence_incomplete");
      }
    } finally {
      await handle.stop();
    }
  });

  async function forceRecovery(auditLog: AuditLog): Promise<void> {
    // Exercise the shipped lock deadline with a held operation; no callback or recorder is injected.
    const lock = auditLog as unknown as { withAuditWriteLock<T>(operation: () => Promise<T>): Promise<T> };
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    try {
      await expect(lock.withAuditWriteLock(() => held)).rejects.toBeInstanceOf(AuditLockHoldDeadlineError);
    } finally {
      release();
    }
  }

  it("publishes a forced recovery and the evaluator degrades through the history boundary only", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress(LOCK_HOLD_MS);
    const recoveredAt = STATES.base.nowMs - HISTORY_WINDOW;
    let now = recoveredAt - SECOND;
    const handle = await startDaemon({
      fortressPath, fortressId: "fortress-test", masterKey, localSign: true, auditLog, platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"), listenerFactory: fakeListenerFactory,
      now: () => now, emissionLivenessTickSeconds: TICK_SECONDS,
      livenessHostClock: { bootId: async () => BOOT, uptimeMs: () => UPTIME },
    });
    try {
      const before = await waitForSequence(fortressPath, 1);
      now = recoveredAt;
      await forceRecovery(auditLog);
      expect(auditLog.getWriteLockRecoveryCount()).toBe(1);
      // Let an already-started publication drain before reading the next complete tick.
      const afterRecovery = await waitForSequence(fortressPath, before.sequence + 1);
      const record = await waitForSequence(fortressPath, afterRecovery.sequence + 1, 1);
      expect(parseDaemonRecord(record).ok).toBe(true);
      expect(record.raw.lock_recovery).toEqual({ state: "instrumented", count: 1, last_at_ms: recoveredAt });
      // The remaining gates use the existing valid fixture; lock evidence is the exact published consumer value.
      const input = structuredClone(STATES.base);
      input.daemon.value.raw.lock_recovery = record.raw.lock_recovery;
      for (const age of [HISTORY_WINDOW - 1, HISTORY_WINDOW]) {
        input.nowMs = recoveredAt + age;
        const wall = evaluateLiveness(input).wall;
        expect(wall.reasons).toContain("write_lock_recovery");
        expect(wall.state).toBe("wall_DEGRADED");
      }
      input.nowMs = recoveredAt + HISTORY_WINDOW + 1;
      const aged = evaluateLiveness(input).wall;
      expect(aged.reasons).not.toContain("write_lock_recovery");
      expect(aged.state).toBe("wall_OK_AGED_HISTORY");
    } finally {
      await handle.stop();
    }
  });

  it("seeds a recovery during the boot read before the recorder subscribes", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress(LOCK_HOLD_MS);
    const recoveredAt = STATES.base.nowMs;
    let now = recoveredAt;
    const handle = await startDaemon({
      fortressPath, fortressId: "fortress-test", masterKey, localSign: true, auditLog, platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"), listenerFactory: fakeListenerFactory,
      now: () => now, emissionLivenessTickSeconds: TICK_SECONDS,
      livenessHostClock: {
        bootId: async () => { await forceRecovery(auditLog); return BOOT; },
        uptimeMs: () => UPTIME,
      },
    });
    try {
      expect(auditLog.getWriteLockRecoveryCount()).toBe(1);
      const record = await waitForSequence(fortressPath, 1);
      expect(record.raw.lock_recovery).toEqual({ state: "instrumented", count: 1, last_at_ms: recoveredAt });
      now += SECOND;
      await forceRecovery(auditLog);
      // Recovery can span many ticks; wait beyond the latest publication, not merely beyond the boot record.
      const current = JSON.parse(await readFile(daemonJson(fortressPath), "utf8"));
      const next = await waitForSequence(fortressPath, current.sequence + 1);
      const later = await waitForSequence(fortressPath, next.sequence + 1, 2);
      // The seeded event plus one subscribed event, with no double count and the new event time.
      expect(later.raw.lock_recovery).toEqual({ state: "instrumented", count: 2, last_at_ms: now });
    } finally {
      await handle.stop();
    }
  });

  it("keeps the degradation marker and retries event time when the recovery clock throws", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress(LOCK_HOLD_MS);
    let now = STATES.base.nowMs - SECOND;
    let failNextClockRead = false;
    const observedAudit = new Proxy(auditLog, {
      get(target, key) {
        if (key === "onWriteLockRecovery") return (listener: () => void) => target.onWriteLockRecovery(() => {
          failNextClockRead = true;
          listener();
        });
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === "function" ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    const handle = await startDaemon({
      fortressPath, fortressId: "fortress-test", masterKey, localSign: true, auditLog: observedAudit, platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"), listenerFactory: fakeListenerFactory,
      now: () => {
        if (failNextClockRead) { failNextClockRead = false; throw new Error("fixture clock failure"); }
        return now;
      },
      emissionLivenessTickSeconds: TICK_SECONDS,
      livenessHostClock: { bootId: async () => BOOT, uptimeMs: () => UPTIME },
    });
    try {
      await waitForSequence(fortressPath, 1);
      now += SECOND;
      await forceRecovery(auditLog);
      const current = JSON.parse(await readFile(daemonJson(fortressPath), "utf8"));
      const record = await waitForSequence(fortressPath, current.sequence + 1, 1);
      expect.soft(record.raw.lock_recovery).toEqual({ state: "instrumented", count: 1, last_at_ms: now });
    } finally {
      await handle.stop();
    }
    const { entries } = await auditLog.query({ layer: "l1" });
    const markers = entries.filter(entry => entry.operation === "castle_wall_heartbeat" || entry.operation === "filter_stopped");
    expect(markers.reduce((sum, entry) => sum + Number(entry.details?.audit_write_degraded_count ?? 0), 0)).toBe(1);
  });

  it("keeps publishing on the tick while the durable audit flush is held", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let release: () => void = () => undefined;
    let flushes = 0;
    const held = new Promise<void>(resolve => { release = resolve; });
    const heldAuditLog = new Proxy(auditLog, {
      get(target, key) {
        // Startup awaits the first beat, so the first flush passes and every later one is held.
        if (key === "flushDurable") return () => { flushes++; return flushes === 1 ? target.flushDurable() : held; };
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === "function" ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    const handle = await startDaemon({
      fortressPath, fortressId: "fortress-test", masterKey, localSign: true, auditLog: heldAuditLog, platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"), listenerFactory: fakeListenerFactory,
      emissionLivenessTickSeconds: 0.01, auditHeartbeatIntervalSeconds: 0.02,
      livenessHostClock: { bootId: async () => BOOT, uptimeMs: () => UPTIME },
    });
    try {
      const first = await waitForSequence(fortressPath, 2);
      for (let i = 0; i < 200 && flushes < 2; i++) await new Promise(resolve => setTimeout(resolve, 10));
      expect(flushes, "a heartbeat flush is held").toBeGreaterThanOrEqual(2);
      const heldAt = (await waitForSequence(fortressPath, first.sequence)).raw.heartbeat.last_durable_flush_at_ms as number | null;
      const later = await waitForSequence(fortressPath, first.sequence + 3);
      expect(later.sequence).toBeGreaterThan(first.sequence);
      // While the flush is held the last success time stays at the startup beat and never advances.
      expect(later.raw.heartbeat.last_durable_flush_at_ms, "a held flush never records a success time").toBe(heldAt);
    } finally {
      release();
      await handle.stop();
    }
  });

  it("without a recorder no daemon.json is published, which reads daemon_telemetry_stale and never OK", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startDaemon({
      fortressPath, fortressId: "fortress-test", masterKey, localSign: true, auditLog, platform: "darwin", daemonMode: "safe",
      activeConfigPath: join(fortressPath, "active.json"), listenerFactory: fakeListenerFactory, emissionLivenessTickSeconds: 0.01,
    });
    try {
      await new Promise(resolve => setTimeout(resolve, 100));
      const read = await readLivenessRecords({ fortressPath, operatorUid: UID });
      expect(read.daemon).toEqual({ status: "absent" });
      const input = structuredClone(STATES.base);
      expect(input.host.uptimeMs).toBeGreaterThan(canaryWindow(30 * SECOND));
      const envelope = evaluateLiveness({ ...input, daemon: read.daemon });
      expect(envelope.wall.reasons).toContain("daemon_telemetry_stale");
      expect(envelope.wall.state.startsWith("wall_OK_")).toBe(false);
    } finally {
      await handle.stop();
    }
  });
});
