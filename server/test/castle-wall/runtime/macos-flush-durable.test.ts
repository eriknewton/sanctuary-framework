/** The production daemon composition amortizes flow and heartbeat checkpoints and seals on stop. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { startMacOSCastleWallDaemon, type MacOSCastleWallListenerOptions } from "../../../src/castle-wall/runtime/macos-daemon.js";

const INTERVAL = 100; // Production checkpoint cadence.
const FLOW_COUNT = 300; // Three complete checkpoint intervals of agent traffic.
const HEARTBEAT_MS = 45_000; // Production audit heartbeat cadence.
const SUBJECT = Buffer.from(new Uint32Array([0, 501, 501, 501, 501, 123, 1, 1]).buffer).toString("hex"); // Darwin audit token: audit uid, credentials, pid and session fields.
let home: string;
beforeEach(async () => { home = await mkdtemp(join(tmpdir(), "daemon-durable-")); vi.stubEnv("HOME", home); });
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); await rm(home, { recursive: true, force: true }); });

it("T5 real daemon amortizes 300 flows and heartbeat ticks, then stop seals the final entry", async () => {
  const key = ed25519.utils.randomPrivateKey();
  const storage = new FilesystemStorage(join(home, "state"));
  const audit = new AuditLog(storage, key, { checkpointInterval: INTERVAL, __testMonotonicNow: () => 0 });
  let options!: MacOSCastleWallListenerOptions;
  let heartbeat!: () => void;
  // Invoke real timer callbacks deterministically without changing filesystem or deadline timers.
  vi.spyOn(globalThis, "setInterval").mockImplementation((callback, ms) => {
    if (ms === HEARTBEAT_MS) heartbeat = callback as () => void;
    return { unref() {} } as ReturnType<typeof setInterval>;
  });
  const count = async () => (await storage.list("_audit_checkpoints", "audit-checkpoint-")).length;
  const handle = await startMacOSCastleWallDaemon({
    fortressPath: home, fortressId: "durable-test", masterKey: key, auditLog: audit,
    platform: "darwin", daemonMode: "safe", auditHeartbeatIntervalSeconds: HEARTBEAT_MS / 1000,
    socketPath: join(home, "castle.sock"), activeConfigPath: join(home, "active.json"),
    globalPinnedPublicKeyPath: join(home, "pin"), auditProducerPublicKeyPath: join(home, "producer"), auditProducerStatePath: null,
    systemResolverProvider: async () => [], agentEgressProbe: async () => true,
    signerClientInvoke: async (args, data) => ({ code: 0, stderr: "", stdout: Buffer.from(args[0] === "get-pubkey" ? ed25519.getPublicKey(key) : ed25519.sign(data!, key)).toString("base64url") }),
    listenerFactory(opts) { options = opts; return { async start() {}, async stop() {}, async broadcastManifestUpdate() { return 0; }, async broadcastDecisionResponse() { return 0; }, async broadcastArmLease() { return 0; }, recycleConnection() { return false; } }; },
  });
  let stopped = false;
  try {
    expect(await count()).toBe(1); // Startup seals filter_started; its initial heartbeat remains in the tail.
    for (let index = 0; index < FLOW_COUNT; index++) {
      if (index === 0) expect(options.consumer.flushCoalescedFlowSummaries).toBeTypeOf("function");
      await options.consumer.handleFlowDecisionRecorded({
        type: "flow_decision_recorded", decision: "drop", agent: { id: SUBJECT, template: "test" },
        destination: { ip: "192.0.2.1", port: 1024 + index, protocol: "tcp", host: null, hostname_source: null, opaque: false },
        recorded_at: new Date().toISOString(),
      });
      // Catch per-flow checkpointing at the first frame, independently of chain-scan latency.
      if (index === 0) expect(await count()).toBe(1);
    }
    expect(options.consumer.getStats().decisionsRecorded).toBe(FLOW_COUNT);
    expect(await count()).toBeLessThanOrEqual(Math.ceil(FLOW_COUNT / INTERVAL) + 1);
    const flushes = vi.spyOn(audit, "flushDurable");
    const beforeTicks = await count();
    const ticks = 3; // Several independently completed heartbeat callbacks.
    for (let tick = 0; tick < ticks; tick++) {
      flushes.mockClear(); heartbeat();
      await vi.waitFor(() => expect(flushes).toHaveBeenCalled());
      await Promise.all(flushes.mock.results.map(result => result.value));
    }
    expect(await count()).toBe(beforeTicks);
    const beforeStop = await count();
    await handle.stop(); stopped = true;
    const entries = await storage.list("_audit");
    const records = await storage.list("_audit_checkpoints", "audit-checkpoint-");
    expect(records).toHaveLength(beforeStop + 1);
    const sequences = await Promise.all(records.map(async ({ key: cpKey }) => JSON.parse(Buffer.from((await storage.read("_audit_checkpoints", cpKey))!).toString()).checkpoint_sequence as number));
    expect(Math.max(...sequences)).toBe(entries.length);
    const result = await new AuditLog(storage, key).query({ limit: entries.length });
    expect(result.integrity_findings).toEqual([]);
    expect(result.entries.at(-1)?.operation).toBe("filter_stopped");
  } finally { if (!stopped) await handle.stop(); }
});

it("R2 real daemon revoke seals the stand-down marker", async () => {
  const key = ed25519.utils.randomPrivateKey();
  const storage = new FilesystemStorage(join(home, "state"));
  const audit = new AuditLog(storage, key, { checkpointInterval: INTERVAL, __testMonotonicNow: () => 0 });
  expect(typeof audit.flushDurable).toBe("function");
  let options!: MacOSCastleWallListenerOptions;
  // Invoke real timer callbacks deterministically without changing filesystem or deadline timers.
  vi.spyOn(globalThis, "setInterval").mockImplementation(() => {
    return { unref() {} } as ReturnType<typeof setInterval>;
  });
  const count = async () => (await storage.list("_audit_checkpoints", "audit-checkpoint-")).length;
  const handle = await startMacOSCastleWallDaemon({
    fortressPath: home, fortressId: "durable-test", masterKey: key, auditLog: audit,
    platform: "darwin", daemonMode: "safe", auditHeartbeatIntervalSeconds: HEARTBEAT_MS / 1000,
    socketPath: join(home, "castle.sock"), activeConfigPath: join(home, "active.json"),
    globalPinnedPublicKeyPath: join(home, "pin"), auditProducerPublicKeyPath: join(home, "producer"), auditProducerStatePath: null,
    systemResolverProvider: async () => [], agentEgressProbe: async () => true,
    signerClientInvoke: async (args, data) => ({ code: 0, stderr: "", stdout: Buffer.from(args[0] === "get-pubkey" ? ed25519.getPublicKey(key) : ed25519.sign(data!, key)).toString("base64url") }),
    listenerFactory(opts) { options = opts; return { async start() {}, async stop() {}, async broadcastManifestUpdate() { return 0; }, async broadcastDecisionResponse() { return 0; }, async broadcastArmLease() { return 0; }, recycleConnection() { return false; } }; },
  });
  try {
    await audit.flushDurable(); // Finish the startup heartbeat before measuring revoke.
    const beforeRevoke = await count();
    await options.onArmLeaseRevoke!({
      type: "arm_lease", armed: false, ttl_seconds: null,
      heartbeat_interval_seconds: HEARTBEAT_MS / 1000, updated_at: new Date().toISOString(),
    });
    expect(await count()).toBe(beforeRevoke + 1);
    const entries = await storage.list("_audit");
    const records = await storage.list("_audit_checkpoints", "audit-checkpoint-");
    const sequences = await Promise.all(records.map(async ({ key: cpKey }) =>
      JSON.parse(Buffer.from((await storage.read("_audit_checkpoints", cpKey))!).toString()).checkpoint_sequence as number));
    expect(Math.max(...sequences)).toBe(entries.length);
    const result = await new AuditLog(storage, key).query({ limit: entries.length });
    expect(result.entries.at(-1)?.operation).toBe("arm_lease_revoked");
  } finally { await handle.stop(); }
});
