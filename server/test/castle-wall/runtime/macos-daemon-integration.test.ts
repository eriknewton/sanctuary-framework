import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { frame, parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import type { ArmLeaseNotification } from "../../../src/castle-wall/ipc/messages.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { toBase64url } from "../../../src/core/encoding.js";
import { runProvisionPin } from "../../../src/cli/castle-wall.js";
import {
  CASTLE_WALL_ALREADY_RUNNING_MESSAGE,
  safeModeHandoffMessage,
  startMacOSCastleWallDaemon,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_HEARTBEAT_OPERATION,
  CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
} from "../../../src/castle-wall/constants.js";

const silent = new Writable({
  write(_chunk, _encoding, callback) {
    callback();
  },
});

describe("Castle Wall macOS daemon integration", () => {
  const tempDirs: string[] = [];
  const liveSockets: Socket[] = [];
  const liveServers: ReturnType<typeof createServer>[] = [];

  // Stand up a REAL listener on `socketPath` so the daemon's liveness probe
  // (socketHasLiveListener) sees a genuine live peer — used to exercise the
  // collision guards (a stale config with NO live listener must NOT collide).
  async function startLiveListener(socketPath: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const s = createServer();
      s.once("error", reject);
      // port-discipline: ignore - Unix domain socket path, not a TCP port.
      s.listen(socketPath, () => {
        liveServers.push(s);
        resolve();
      });
    });
  }

  afterEach(async () => {
    for (const socket of liveSockets.splice(0)) {
      socket.destroy();
    }
    for (const server of liveServers.splice(0)) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function provisionFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-daemon-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const recoveryKey = toBase64url(masterKey);
    const pinResult = await runProvisionPin([], {
      out: silent,
      err: silent,
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
    });
    expect(pinResult).toBe(0);
    const auditLog = new AuditLog(new FilesystemStorage(join(fortressPath, "state")), masterKey, {
      integrityMode: "lenient",
    });
    return { fortressPath, masterKey, auditLog };
  }

  function activeConfigPath(fortressPath: string): string {
    return join(fortressPath, "active.json");
  }

  function fakeListenerFactory(options: MacOSCastleWallListenerOptions) {
    // A REAL minimal listener: the daemon's collision guards decide liveness by
    // CONNECTING to the socket (socketHasLiveListener), not by file-existence, so a
    // started fake daemon must own a genuinely connectable socket (a plain file is
    // treated as a dead/stale socket and would no longer register as "live").
    let server: ReturnType<typeof createServer> | null = null;
    return {
      async start() {
        await new Promise<void>((resolve, reject) => {
          const s = createServer();
          s.once("error", reject);
          // port-discipline: ignore - Unix domain socket path, not a TCP port.
          s.listen(options.socketPath, () => {
            server = s;
            resolve();
          });
        });
      },
      async stop() {
        if (server) {
          const s = server;
          server = null;
          await new Promise<void>((resolve) => s.close(() => resolve()));
        }
        await unlink(options.socketPath).catch(() => {});
      },
      async broadcastManifestUpdate() {
        return 0;
      },
      async broadcastDecisionResponse() {
        return 0;
      },
      async broadcastArmLease() {
        return 0;
      },
    };
  }

  function wait(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function makeMessageReader(socket: Socket): () => Promise<Record<string, unknown>> {
    let buffer = Buffer.alloc(0);
    let pending:
      | {
          resolve: (value: Record<string, unknown>) => void;
          reject: (reason?: unknown) => void;
        }
      | null = null;

    const drain = () => {
      if (!pending) return;
      const parsed = parseFrame(buffer);
      if (parsed.kind === "need_more") return;
      const waiter = pending;
      pending = null;
      if (parsed.kind === "error") {
        waiter.reject(new Error(parsed.reason));
        return;
      }
      buffer = buffer.subarray(parsed.consumedBytes);
      const envelope = JSON.parse(parsed.body) as { params?: Record<string, unknown> };
      waiter.resolve(envelope.params ?? envelope);
    };

    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      drain();
    });

    return async () => await new Promise((resolve, reject) => {
      if (pending) {
        reject(new Error("only one pending message read is supported"));
        return;
      }
      pending = { resolve, reject };
      socket.once("error", reject);
      drain();
    });
  }

  function writeIpc(socket: Socket, message: Record<string, unknown>): void {
    socket.write(
      frame(JSON.stringify({
        jsonrpc: "2.0",
        method: `castle-wall.${String(message.type)}`,
        params: message,
      }))
    );
  }

  it("binds the fortress-scoped castle.sock and removes it on shutdown", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      listenerFactory: fakeListenerFactory,
    });

    const socketPath = join(fortressPath, "castle.sock");
    expect(handle.socketPath).toBe(socketPath);
    await expect(stat(socketPath)).resolves.toBeTruthy();

    await handle.stop();
    await expect(stat(socketPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("writes active discovery config on start and removes it on stop", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: configPath,
      listenerFactory: fakeListenerFactory,
    });

    const info = await stat(configPath);
    expect(info.mode & 0o777).toBe(0o644);
    const config = JSON.parse(await readFile(configPath, "utf8")) as {
      socket_path: string;
      fortress_id: string;
      pid: number;
      started_at: string;
      pinned_pubkey_sha256?: string;
    };
    expect(config).toMatchObject({
      socket_path: join(fortressPath, "castle.sock"),
      fortress_id: "fortress-test",
      pid: process.pid,
    });
    expect(Number.isNaN(Date.parse(config.started_at))).toBe(false);
    expect(config.pinned_pubkey_sha256).toMatch(/^[0-9a-f]{64}$/);

    await handle.stop();
    await expect(stat(configPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("stops daemon heartbeat re-arm after listener receives operator revoke", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const broadcasts: ArmLeaseNotification[] = [];
    let revokeHook: ((lease: ArmLeaseNotification) => void | Promise<void>) | undefined;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      armLeaseHeartbeatIntervalSeconds: 0.01,
      listenerFactory(options) {
        revokeHook = options.onArmLeaseRevoke;
        return {
          async start() {
            await writeFile(options.socketPath, "");
          },
          async stop() {
            await unlink(options.socketPath).catch(() => {});
          },
          async broadcastManifestUpdate() {
            return 0;
          },
          async broadcastDecisionResponse() {
            return 0;
          },
          async broadcastArmLease(lease: ArmLeaseNotification) {
            broadcasts.push(lease);
            return 0;
          },
        };
      },
    });

    await wait(35);
    expect(broadcasts.some((lease) => lease.armed === true)).toBe(true);

    broadcasts.length = 0;
    const revoke: ArmLeaseNotification = {
      type: "arm_lease",
      armed: false,
      revoked: true,
      ttl_seconds: null,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-06-10T00:00:00.000Z",
    };
    await revokeHook?.(revoke);
    broadcasts.push(revoke);
    await wait(35);

    expect(broadcasts).toEqual([revoke]);
    await handle.stop();
  });

  // Regression for the 2026-07-05 Mini1 TTL-expiry gap: `enable --ttl 90s`
  // armed the wall but at t+160s the dead-man had NOT fired. Root cause: the
  // daemon's periodic heartbeat rebuilt the lease from the static
  // `input.armLeaseTtlSeconds` (never set by any caller -> null), erasing the
  // operator's TTL in the extension every interval so `leaseExpiresAt` never
  // arrived. The fix adopts the operator's TTL (onArmLease) and re-broadcasts
  // the DECREMENTING remaining seconds toward a fixed deadline. These two tests
  // pin both invariants: the dead-man FIRES on real expiry, and NEVER fires
  // early on a still-live lease (the anti-spurious-disarm / anti-brick side).
  it("adopts the operator TTL and broadcasts ttl_seconds=0 (fail-open) once the injected clock passes the deadline", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const broadcasts: ArmLeaseNotification[] = [];
    let armHook:
      | ((lease: ArmLeaseNotification) => void | Promise<void>)
      | undefined;
    // Injected wall clock so the deadline is crossed by advancing a number, not
    // by sleeping the test.
    const clock = { ms: 1_000_000 };
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      armLeaseHeartbeatIntervalSeconds: 0.01,
      now: () => clock.ms,
      listenerFactory(options) {
        armHook = options.onArmLease;
        return {
          async start() {
            await writeFile(options.socketPath, "");
          },
          async stop() {
            await unlink(options.socketPath).catch(() => {});
          },
          async broadcastManifestUpdate() {
            return 0;
          },
          async broadcastDecisionResponse() {
            return 0;
          },
          async broadcastArmLease(lease: ArmLeaseNotification) {
            broadcasts.push(lease);
            return 0;
          },
        };
      },
    });

    // Operator arms with a 90s dead-man TTL (the drill's `--ttl 90s`). The
    // daemon adopts the deadline = now + 90s.
    await armHook?.({
      type: "arm_lease",
      armed: true,
      ttl_seconds: 90,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-05T00:00:00.000Z",
    });

    // Let several heartbeats fire WITHOUT advancing the clock: every one must
    // carry a positive remaining TTL (never null, never 0) so the operator's
    // deadline is preserved rather than erased.
    broadcasts.length = 0;
    await wait(40);
    expect(broadcasts.length).toBeGreaterThan(0);
    for (const lease of broadcasts) {
      expect(lease.armed).toBe(true);
      expect(lease.ttl_seconds).toBeGreaterThan(0);
      expect(lease.ttl_seconds).toBeLessThanOrEqual(90);
    }

    // Advance the injected clock PAST the 90s deadline. The next heartbeat must
    // broadcast ttl_seconds=0, which the Swift extension turns into an immediate
    // `ttl_expired` fail-open (the dead-man firing).
    broadcasts.length = 0;
    clock.ms += 91_000;
    await wait(40);
    expect(broadcasts.some((lease) => lease.ttl_seconds === 0)).toBe(true);

    // ...and the lease heartbeat then STOPS (it does not keep spamming a 0-TTL
    // renewal once fail-open has been signalled).
    await wait(20);
    const afterExpiry = broadcasts.length;
    await wait(40);
    expect(broadcasts.length).toBe(afterExpiry);

    await handle.stop();
  });

  it("keeps renewing a positive TTL and NEVER broadcasts 0 while the operator lease is still live (no spurious dead-man)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const broadcasts: ArmLeaseNotification[] = [];
    let armHook:
      | ((lease: ArmLeaseNotification) => void | Promise<void>)
      | undefined;
    const clock = { ms: 5_000_000 };
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      armLeaseHeartbeatIntervalSeconds: 0.01,
      now: () => clock.ms,
      listenerFactory(options) {
        armHook = options.onArmLease;
        return {
          async start() {
            await writeFile(options.socketPath, "");
          },
          async stop() {
            await unlink(options.socketPath).catch(() => {});
          },
          async broadcastManifestUpdate() {
            return 0;
          },
          async broadcastDecisionResponse() {
            return 0;
          },
          async broadcastArmLease(lease: ArmLeaseNotification) {
            broadcasts.push(lease);
            return 0;
          },
        };
      },
    });

    await armHook?.({
      type: "arm_lease",
      armed: true,
      ttl_seconds: 90,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-05T00:00:00.000Z",
    });

    // Advance the clock only PART WAY toward the deadline (30s of a 90s TTL) and
    // let many heartbeats fire. A live, unexpired lease must NEVER report 0.
    broadcasts.length = 0;
    clock.ms += 30_000;
    await wait(60);
    expect(broadcasts.length).toBeGreaterThan(0);
    for (const lease of broadcasts) {
      expect(lease.armed).toBe(true);
      expect(lease.ttl_seconds).not.toBeNull();
      expect(lease.ttl_seconds).toBeGreaterThan(0);
      // Remaining is bounded by the original 90s and reflects the ~60s left.
      expect(lease.ttl_seconds).toBeLessThanOrEqual(90);
      expect(lease.ttl_seconds).toBeGreaterThanOrEqual(59);
    }

    await handle.stop();
  });

  it("emits a provenance-marked castle_wall_heartbeat audit entry on its audit-cadence interval (Slice 2)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      // A tiny audit-heartbeat cadence so the test does not wait the 45s default.
      auditHeartbeatIntervalSeconds: 0.01,
      listenerFactory: fakeListenerFactory,
    });

    // Let the startup beat plus a couple of interval beats land.
    await wait(40);
    await handle.stop();

    const q = await auditLog.query({ layer: "l1", limit: 1000 });
    const beats = q.entries.filter(
      (e) => e.operation === CASTLE_WALL_HEARTBEAT_OPERATION,
    );
    // At least the startup beat (and almost certainly several interval beats).
    expect(beats.length).toBeGreaterThanOrEqual(1);
    // Every beat carries the SAME cw_source provenance marker enforcement
    // evidence carries, so the reader treats it as genuine Castle Wall liveness.
    for (const beat of beats) {
      const details = beat.details as Record<string, unknown>;
      expect(details[CASTLE_WALL_AUDIT_PROVENANCE_KEY]).toBe(
        CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      );
      expect(beat.result).toBe("success");
    }
  });

  it("fires a LOUD audit_emission_stall when decisions continue but emission stops (Slice M watchdog)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    // Capture the consumer the daemon builds and drive MALFORMED
    // `flow_decision_recorded` receipts: each is a reported decision that the
    // consumer rejects (never emits), producing a decided-but-not-emitted
    // divergence through the daemon wiring. HONESTY: this is a DIFFERENT
    // signature from the 07-17 stall. There the sysext stopped sending
    // receipts entirely, so the watchdog receives neither decisions nor
    // emissions and stays quiet (the Swift decided-counter feed is the owed
    // instrument for that mode). This test pins the divergence class the
    // watchdog CAN catch: decisions still reported, emission stopped.
    let captured: { consumer: MacOSCastleWallListenerOptions["consumer"] } | null = null;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      // Small grace + fast tick so the stall fires within the test window.
      emissionStallGraceMs: 20,
      emissionLivenessTickSeconds: 0.01,
      listenerFactory(options) {
        captured = { consumer: options.consumer };
        return fakeListenerFactory(options);
      },
    });

    expect(captured).not.toBeNull();
    const consumer = captured!.consumer;

    // Drive two malformed decisions: each is a DECISION (noted) that is
    // REJECTED (never emitted), so the watchdog sees decided-without-emission.
    const malformed = {
      type: "flow_decision_recorded",
      decision: "INVALID",
      destination: { host: "x", ip: "1.2.3.4", port: 443, protocol: "tcp", hostname_source: null, opaque: false },
      agent: { id: "agent-stall", template: "ops-runner" },
      matched_rule_id: null,
      recorded_at: "2026-05-11T12:01:00Z",
    } as unknown as Parameters<typeof consumer.handleFlowDecisionRecorded>[0];
    await consumer.handleFlowDecisionRecorded(malformed);
    await consumer.handleFlowDecisionRecorded(malformed);

    // Wait for the grace window to elapse and the tick to evaluate.
    await wait(120);
    await handle.stop();

    const stalls = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "audit_emission_stall");
    expect(stalls.length).toBeGreaterThanOrEqual(1);
    const details = stalls[0].details as Record<string, unknown>;
    expect(stalls[0].result).toBe("failure");
    expect(details[CASTLE_WALL_AUDIT_PROVENANCE_KEY]).toBe(
      CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    );
    expect(details.decided_since_last_emission).toBeGreaterThanOrEqual(2);
    expect(details.emitted_total).toBe(0);
  });

  it("does NOT fire audit_emission_stall on a healthy interleaved decided/emitted stream (Slice M watchdog)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let captured: { consumer: MacOSCastleWallListenerOptions["consumer"] } | null = null;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      emissionStallGraceMs: 20,
      emissionLivenessTickSeconds: 0.01,
      listenerFactory(options) {
        captured = { consumer: options.consumer };
        return fakeListenerFactory(options);
      },
    });
    const consumer = captured!.consumer;

    // Well-formed allow decisions persist as emissions on the channel path, so
    // the anchor resets each time and no stall accrues.
    const good = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: { host: "api.anthropic.com", ip: "104.18.32.10", port: 443, protocol: "tcp", hostname_source: "sni", opaque: false },
      agent: { id: "agent-live", template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00Z",
    } as unknown as Parameters<typeof consumer.handleFlowDecisionRecorded>[0];
    for (let i = 0; i < 5; i += 1) {
      await consumer.handleFlowDecisionRecorded(good);
      await wait(10);
    }
    await wait(60);
    await handle.stop();

    const stalls = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "audit_emission_stall");
    expect(stalls.length).toBe(0);
  });

  it("castle_wall_heartbeat carries the emission-liveness watchdog snapshot, including a live last_evaluate_at_ms (Slice M fix-round HIGH)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      auditHeartbeatIntervalSeconds: 0.01,
      // Fast tick so last_evaluate_at_ms is stamped within the test window.
      // Zero traffic is deliberate: the snapshot must ride EVERY heartbeat
      // (an idle wall included), and the tick pulse must be a real timestamp
      // even when no decision has ever arrived. The decided/emitted counter
      // values themselves are pinned by the watchdog unit tests and by the
      // stall/no-stall daemon tests above; this test pins the transport.
      emissionLivenessTickSeconds: 0.01,
      listenerFactory: fakeListenerFactory,
    });
    await wait(60);
    await handle.stop();

    const beats = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === CASTLE_WALL_HEARTBEAT_OPERATION);
    expect(beats.length).toBeGreaterThanOrEqual(1);
    const last = beats[beats.length - 1]!;
    const snapshot = (last.details as Record<string, unknown>)
      .emission_liveness as Record<string, unknown>;
    expect(snapshot).toBeDefined();
    expect(snapshot.decided_total).toBe(0);
    expect(snapshot.emitted_total).toBe(0);
    expect(snapshot.decided_since_last_emission).toBe(0);
    expect(snapshot.stalled).toBe(false);
    // The tick timer ran inside the window, so its pulse is a real timestamp
    // (the sibling test below pins the null/never-ticked presentation).
    expect(typeof snapshot.last_evaluate_at_ms).toBe("number");
  });

  it("castle_wall_heartbeat reports last_evaluate_at_ms null while the divergence tick has never run (staleness is observable, not silent)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      auditHeartbeatIntervalSeconds: 0.01,
      // Default (15s) tick cadence: within this short test window the tick
      // NEVER fires, which is exactly the condition a reader must be able to
      // see. A cleared or never-ticking watchdog timer shows up as a
      // null/stale last_evaluate_at_ms against advancing heartbeats.
      listenerFactory: fakeListenerFactory,
    });
    await wait(40);
    await handle.stop();

    const beats = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === CASTLE_WALL_HEARTBEAT_OPERATION);
    expect(beats.length).toBeGreaterThanOrEqual(1);
    for (const beat of beats) {
      const snapshot = (beat.details as Record<string, unknown>)
        .emission_liveness as Record<string, unknown>;
      expect(snapshot).toBeDefined();
      expect(snapshot.last_evaluate_at_ms).toBeNull();
    }
  });

  it("an arm-lease revoke stands the watchdog down (no stall post-revoke); a fresh arm re-engages it (Slice M fix-round MED)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let captured: {
      consumer: MacOSCastleWallListenerOptions["consumer"];
      onArmLease: MacOSCastleWallListenerOptions["onArmLease"];
      onArmLeaseRevoke: MacOSCastleWallListenerOptions["onArmLeaseRevoke"];
    } | null = null;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      // Grace window comfortably wider than the audit appends + revoke write
      // below, so the revoke ALWAYS lands inside the open divergence run
      // (with a tiny grace the run can mature into a stall before the revoke
      // is processed, and the test would assert the wrong thing).
      emissionStallGraceMs: 1500,
      emissionLivenessTickSeconds: 0.01,
      listenerFactory(options) {
        captured = {
          consumer: options.consumer,
          onArmLease: options.onArmLease,
          onArmLeaseRevoke: options.onArmLeaseRevoke,
        };
        return fakeListenerFactory(options);
      },
    });
    const consumer = captured!.consumer;
    const malformed = {
      type: "flow_decision_recorded",
      decision: "INVALID",
      destination: { host: "x", ip: "1.2.3.4", port: 443, protocol: "tcp", hostname_source: null, opaque: false },
      agent: { id: "agent-revoke", template: "ops-runner" },
      matched_rule_id: null,
      recorded_at: "2026-05-11T12:01:00Z",
    } as unknown as Parameters<typeof consumer.handleFlowDecisionRecorded>[0];

    // Open a divergence run, then REVOKE before the grace window matures.
    await consumer.handleFlowDecisionRecorded(malformed);
    await consumer.handleFlowDecisionRecorded(malformed);
    await captured!.onArmLeaseRevoke?.({
      type: "arm_lease",
      armed: false,
      ttl_seconds: null,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-17T00:00:00.000Z",
    });

    // Well past the grace window + many tick intervals: a deliberately
    // stood-down wall must never mature those decisions into a stall alarm.
    await wait(2500);
    let stalls = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "audit_emission_stall");
    expect(stalls.length).toBe(0);

    // A fresh operator arm re-engages the detector: the same divergence
    // signature after re-arm DOES fire (the stand-down is a gate, not a
    // permanent disable of the watchdog).
    await captured!.onArmLease?.({
      type: "arm_lease",
      armed: true,
      ttl_seconds: 90,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-17T00:00:00.000Z",
    });
    await consumer.handleFlowDecisionRecorded(malformed);
    await consumer.handleFlowDecisionRecorded(malformed);
    await wait(2500);
    await handle.stop();

    stalls = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "audit_emission_stall");
    expect(stalls.length).toBeGreaterThanOrEqual(1);
  });

  it("post-revoke egress-probe attempts are never counted as decisions: no stall can fire from the probe feed on a stood-down wall (Slice M fix-round MED)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    // uid-mode agent-origin + one provisioned rule so the probe timer runs
    // (same fixture shape as the MED-3 probe tests below).
    const egressDir = join(fortressPath, "policy", "egress");
    const rulesDir = join(egressDir, "rules");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(rulesDir, { recursive: true });
    await writeFile(
      join(egressDir, "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: 503, system_uid_allow_ceiling: 500 }),
    );
    await writeFile(
      join(rulesDir, "provisioned-hermes-aaaaaaaaaaaa.json"),
      JSON.stringify({
        id: "provisioned-hermes-aaaaaaaaaaaa",
        schema_version: 1,
        created_at: "2026-07-10T00:00:00Z",
        match: { host: ["api.venice.ai"], port: [443], protocol: "tcp" },
        scope: {},
        disposition: "allow",
        derived: true,
      }),
    );

    let captured: {
      consumer: MacOSCastleWallListenerOptions["consumer"];
      onArmLeaseRevoke: MacOSCastleWallListenerOptions["onArmLeaseRevoke"];
    } | null = null;
    const probeCalls: string[] = [];
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      emissionStallGraceMs: 20,
      emissionLivenessTickSeconds: 0.01,
      agentEgressProbeIntervalSeconds: 0.02,
      agentEgressProbe: async (_uid, host) => {
        probeCalls.push(host);
        return true;
      },
      listenerFactory(options) {
        captured = {
          consumer: options.consumer,
          onArmLeaseRevoke: options.onArmLeaseRevoke,
        };
        return fakeListenerFactory(options);
      },
    });
    // A connected sysext subscriber, so the probe feed's OTHER gate
    // (subscribers > 0) is satisfied and only the revoke gate is under test.
    captured!.consumer.registerSubscriber({
      subscriberId: "fake-sysext",
      async emitManifestUpdate() {},
    });
    // Revoke immediately: every probe attempt in the window below happens on
    // a deliberately stood-down wall.
    await captured!.onArmLeaseRevoke?.({
      type: "arm_lease",
      armed: false,
      ttl_seconds: null,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-17T00:00:00.000Z",
    });

    // Probes keep running (they still serve reachability observation), well
    // past the grace window and many ticks, but none may count as a decision.
    await wait(150);
    await handle.stop();

    expect(probeCalls.length).toBeGreaterThan(0);
    const stalls = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "audit_emission_stall");
    expect(stalls.length).toBe(0);
  });

  it("receipts landing DURING a revoked window never mature into a stall after re-arm; a FRESH post-re-arm divergence still fires (final fix-round HIGH)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let captured: {
      consumer: MacOSCastleWallListenerOptions["consumer"];
      onArmLease: MacOSCastleWallListenerOptions["onArmLease"];
      onArmLeaseRevoke: MacOSCastleWallListenerOptions["onArmLeaseRevoke"];
    } | null = null;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      // Grace SHORTER than the revoked-window wait below, so the stale run's
      // anchor is already past the grace window at re-arm time: without the
      // fresh-arm stand-down, the FIRST post-re-arm tick matures it into a
      // false audit_emission_stall (the exact pre-fix failure mode this test
      // exists to pin; it fails on pre-fix code).
      emissionStallGraceMs: 200,
      emissionLivenessTickSeconds: 0.01,
      listenerFactory(options) {
        captured = {
          consumer: options.consumer,
          onArmLease: options.onArmLease,
          onArmLeaseRevoke: options.onArmLeaseRevoke,
        };
        return fakeListenerFactory(options);
      },
    });
    const consumer = captured!.consumer;
    const malformed = {
      type: "flow_decision_recorded",
      decision: "INVALID",
      destination: { host: "x", ip: "1.2.3.4", port: 443, protocol: "tcp", hostname_source: null, opaque: false },
      agent: { id: "agent-revoked-window", template: "ops-runner" },
      matched_rule_id: null,
      recorded_at: "2026-05-11T12:01:00Z",
    } as unknown as Parameters<typeof consumer.handleFlowDecisionRecorded>[0];

    // Stand the wall down FIRST, then let receipts land DURING the revoked
    // window (an in-flight or draining sysext still delivering decisions that
    // validation rejects). The receipt feed is deliberately ungated by the
    // revoke flag, so these count into the watchdog's state.
    await captured!.onArmLeaseRevoke?.({
      type: "arm_lease",
      armed: false,
      ttl_seconds: null,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-17T00:00:00.000Z",
    });
    await consumer.handleFlowDecisionRecorded(malformed);
    await consumer.handleFlowDecisionRecorded(malformed);

    // Age the stale run well past the grace window while still revoked. The
    // tick timer is stopped, so nothing can fire during this window either
    // way; what matters is that the anchor is now grace-expired.
    await wait(400);

    // Re-arm, then run many ticks with NO fresh divergence: the stood-down
    // window's receipts must not poison the new arm window.
    await captured!.onArmLease?.({
      type: "arm_lease",
      armed: true,
      ttl_seconds: 90,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-17T00:00:00.000Z",
    });
    await wait(300);
    let stalls = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "audit_emission_stall");
    expect(stalls.length).toBe(0);

    // A FRESH post-re-arm divergence must still fire: the fresh-arm
    // stand-down resets the window, it does not blunt the detector.
    await consumer.handleFlowDecisionRecorded(malformed);
    await consumer.handleFlowDecisionRecorded(malformed);
    await wait(800);
    await handle.stop();

    stalls = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "audit_emission_stall");
    expect(stalls.length).toBeGreaterThanOrEqual(1);
  });

  it("a fresh arm restarts the audit liveness heartbeat a revoke stopped, and the post-re-arm beat carries the emission-liveness snapshot (final fix-round MED)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let captured: {
      onArmLease: MacOSCastleWallListenerOptions["onArmLease"];
      onArmLeaseRevoke: MacOSCastleWallListenerOptions["onArmLeaseRevoke"];
    } | null = null;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      auditHeartbeatIntervalSeconds: 0.01,
      // Fast tick so the re-engaged watchdog stamps a real evaluation pulse
      // for the post-re-arm beat to carry.
      emissionLivenessTickSeconds: 0.01,
      listenerFactory(options) {
        captured = {
          onArmLease: options.onArmLease,
          onArmLeaseRevoke: options.onArmLeaseRevoke,
        };
        return fakeListenerFactory(options);
      },
    });
    const countBeats = async () =>
      (
        await auditLog.query({ layer: "l1", limit: 5000 })
      ).entries.filter((e) => e.operation === CASTLE_WALL_HEARTBEAT_OPERATION);
    await wait(30);
    await captured!.onArmLeaseRevoke?.({
      type: "arm_lease",
      armed: false,
      ttl_seconds: null,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-17T00:00:00.000Z",
    });
    // Let any in-flight beat land, then confirm the revoke stand-down still
    // stops the beat (the restart must not weaken the revoke path).
    await wait(30);
    const afterRevoke = (await countBeats()).length;
    await wait(50);
    const later = (await countBeats()).length;
    expect(later).toBe(afterRevoke);

    // Re-arm: the beat must resume. Pre-fix it never did, so the re-engaged
    // watchdog's snapshot was unobservable for the rest of the process life.
    await captured!.onArmLease?.({
      type: "arm_lease",
      armed: true,
      ttl_seconds: 90,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-07-17T00:00:00.000Z",
    });
    await wait(60);
    await handle.stop();

    const beats = await countBeats();
    expect(beats.length).toBeGreaterThan(afterRevoke);
    const last = beats[beats.length - 1]!;
    const snapshot = (last.details as Record<string, unknown>)
      .emission_liveness as Record<string, unknown>;
    expect(snapshot).toBeDefined();
    expect(snapshot.stalled).toBe(false);
    expect(typeof snapshot.last_evaluate_at_ms).toBe("number");
  });

  it("rejects a zero/negative/NaN emissionLivenessTickSeconds at the daemon boundary (fix-round LOW)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    for (const bad of [0, -5, Number.NaN]) {
      await expect(
        startMacOSCastleWallDaemon({
          fortressPath,
          fortressId: "fortress-test",
          masterKey,
          localSign: true,
          auditLog,
          platform: "darwin",
          activeConfigPath: activeConfigPath(fortressPath),
          emissionLivenessTickSeconds: bad,
          listenerFactory: fakeListenerFactory,
        }),
      ).rejects.toThrow(/emissionLivenessTickSeconds must be a positive finite number/);
    }
  });

  it("stops emitting heartbeats after the daemon is stopped (same teardown as the lease heartbeat)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      auditHeartbeatIntervalSeconds: 0.01,
      listenerFactory: fakeListenerFactory,
    });
    await wait(40);
    await handle.stop();

    const afterStop = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === CASTLE_WALL_HEARTBEAT_OPERATION).length;
    // Give any leaked interval a chance to fire post-stop.
    await wait(40);
    const later = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === CASTLE_WALL_HEARTBEAT_OPERATION).length;
    expect(later).toBe(afterStop);
  });

  it("a clean stop records a provenance-marked filter_stopped stand-down (Slice 2 false-RED fix)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      auditHeartbeatIntervalSeconds: 0.01,
      listenerFactory: fakeListenerFactory,
    });
    await wait(40);
    await handle.stop();

    const stops = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter((e) => e.operation === "filter_stopped");
    // Exactly the one clean-stop event, and it carries the cw_source marker so
    // the silent-death reader recognizes it as an INTENTIONAL stand-down (off on
    // purpose) rather than reading a false dead_no_heartbeat alarm.
    expect(stops.length).toBe(1);
    const details = stops[0].details as Record<string, unknown>;
    expect(details[CASTLE_WALL_AUDIT_PROVENANCE_KEY]).toBe(
      CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    );
    expect(stops[0].result).toBe("success");
  });

  it("an arm-lease revoke records a provenance-marked arm_lease_revoked stand-down (Slice 2 false-RED fix)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let revokeHook:
      | ((lease: ArmLeaseNotification) => void | Promise<void>)
      | undefined;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      auditHeartbeatIntervalSeconds: 0.01,
      listenerFactory(options) {
        revokeHook = options.onArmLeaseRevoke;
        return fakeListenerFactory(options);
      },
    });
    await wait(40);

    const revoke: ArmLeaseNotification = {
      type: "arm_lease",
      armed: false,
      revoked: true,
      ttl_seconds: null,
      heartbeat_interval_seconds: 5,
      updated_at: "2026-06-10T00:00:00.000Z",
    };
    // The revoke path previously wrote NOTHING, so a lease-revoke stand-down was
    // indistinguishable from a silent death. It must now leave a recognizable
    // arm_lease_revoked marker on the heartbeat's trust basis.
    await revokeHook?.(revoke);

    const revokes = (
      await auditLog.query({ layer: "l1", limit: 5000 })
    ).entries.filter(
      (e) => e.operation === CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
    );
    expect(revokes.length).toBe(1);
    const details = revokes[0].details as Record<string, unknown>;
    expect(details[CASTLE_WALL_AUDIT_PROVENANCE_KEY]).toBe(
      CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    );
    expect(revokes[0].result).toBe("success");

    await handle.stop();
  });

  it("rejects a second daemon for the same fortress with the Phase 3 message", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const first = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: configPath,
      listenerFactory: fakeListenerFactory,
    });

    await expect(
      startMacOSCastleWallDaemon({
        fortressPath,
        fortressId: "fortress-test",
        masterKey,
        localSign: true,
        auditLog,
        platform: "darwin",
        activeConfigPath: configPath,
      }),
    ).rejects.toThrow(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);

    await first.stop();
  });

  it("records the daemon role in active-config (#450 item 4)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: configPath,
      listenerFactory: fakeListenerFactory,
      daemonMode: "safe",
    });
    const written = JSON.parse(await readFile(configPath, "utf8")) as { mode?: string };
    expect(written.mode).toBe("safe");
    await handle.stop();
  });

  it("a full daemon colliding with a live SAFE-MODE boot daemon gets handoff guidance, not the Phase 3 message (#450 item 4)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const sockPath = join(fortressPath, "castle.sock");
    // Simulate a GENUINELY live root safe-mode boot daemon: a real listener on the
    // recorded socket + an alive pid. (A stale config with no live listener must
    // NOT collide — covered by the regression test below.)
    await startLiveListener(sockPath);
    await writeFile(
      configPath,
      JSON.stringify({
        socket_path: sockPath,
        fortress_id: "fortress-test",
        pid: process.pid,
        started_at: new Date().toISOString(),
        mode: "safe",
      }),
    );

    // The full operator daemon must REFUSE (never orphan the root daemon) with
    // actionable stand-down guidance — and must NOT claim "Multi-wrap is Phase 3".
    let caught: Error | undefined;
    try {
      await startMacOSCastleWallDaemon({
        fortressPath,
        fortressId: "fortress-test",
        masterKey,
        localSign: true,
        auditLog,
        platform: "darwin",
        activeConfigPath: configPath,
        listenerFactory: fakeListenerFactory,
      });
    } catch (error) {
      caught = error as Error;
    }
    expect(caught).toBeDefined();
    expect(caught!.message).toBe(safeModeHandoffMessage(process.pid));
    expect(caught!.message).toContain("launchctl bootout");
    expect(caught!.message).not.toContain("Phase 3");
  });

  it("rejects startup when an active-config pid is alive AND its socket has a live listener", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const otherSock = join(fortressPath, "other.sock");
    await startLiveListener(otherSock); // a genuine live peer
    await writeFile(
      configPath,
      JSON.stringify({
        socket_path: otherSock,
        fortress_id: "other-fortress",
        pid: process.pid,
        started_at: new Date().toISOString(),
      }),
    );

    await expect(
      startMacOSCastleWallDaemon({
        fortressPath,
        fortressId: "fortress-test",
        masterKey,
        localSign: true,
        auditLog,
        platform: "darwin",
        activeConfigPath: configPath,
        listenerFactory: fakeListenerFactory,
      }),
    ).rejects.toThrow(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);
  });

  it("IGNORES a stale active-config whose recorded socket has NO live listener — reboot pid-reuse safe (#450 A1 rep-2 fix)", async () => {
    // The 2026-06-14 A1 rep-2 bug: after a reboot the recorded pid (e.g. 541) is
    // REUSED by an unrelated process, so isPidAlive() is true, but no daemon is
    // actually listening. A pid-only check falsely collided and refused the new
    // safe-mode daemon. With the liveness fix, no live listener => stale => start.
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    await writeFile(
      configPath,
      JSON.stringify({
        socket_path: join(fortressPath, "castle.sock"), // no listener bound here
        fortress_id: "fortress-test",
        pid: process.pid, // ALIVE (stands in for a reused pid)
        started_at: "2020-01-01T00:00:00.000Z",
        mode: "safe",
      }),
    );

    // Must START (not throw) — the stale config is ignored.
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: configPath,
      listenerFactory: fakeListenerFactory,
    });
    expect(handle.socketPath).toBe(join(fortressPath, "castle.sock"));
    await handle.stop();
  });

  it("unlinks a stale socket left by a crash/reboot and starts (Finding A)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const socketPath = join(fortressPath, "castle.sock");
    // A reboot or `kill -9` leaves the socket path on disk with no live owner
    // (the graceful SIGTERM unlink never ran). The old guard refused on
    // file-existence alone, wedging every restart; the daemon must now detect
    // the absence of a live listener, unlink the stale path, and start.
    await writeFile(socketPath, "");

    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      socketPath,
      activeConfigPath: configPath,
      listenerFactory: fakeListenerFactory,
    });

    expect(handle.socketPath).toBe(socketPath);
    await handle.stop();
  });

  it("refuses to start when a live process is listening on the socket (Finding A)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const socketPath = join(fortressPath, "castle.sock");
    // A genuine running daemon accepts connections on the socket; startup must
    // still refuse in that case (liveness, not file-existence, is the signal).
    const liveServer = createServer((socket) => socket.destroy());
    await new Promise<void>((resolve, reject) => {
      liveServer.once("error", reject);
      // port-discipline: ignore — socketPath is a unix-domain socket path, not a TCP port
      liveServer.listen(socketPath, () => resolve());
    });

    try {
      await expect(
        startMacOSCastleWallDaemon({
          fortressPath,
          fortressId: "fortress-test",
          masterKey,
          localSign: true,
          auditLog,
          platform: "darwin",
          socketPath,
          activeConfigPath: configPath,
          listenerFactory: fakeListenerFactory,
        }),
      ).rejects.toThrow(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);
    } finally {
      await new Promise<void>((resolve) => liveServer.close(() => resolve()));
    }
  });

  it("lets a sysext-style client read active config, subscribe, and receive manifest plus lease", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: configPath,
    });

    try {
      const config = JSON.parse(await readFile(configPath, "utf8")) as { socket_path: string };
      const socket = createConnection(config.socket_path);
      liveSockets.push(socket);
      await new Promise<void>((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      });

      const readNextMessage = makeMessageReader(socket);
      const challenge = await readNextMessage();
      const response = await readNextMessage();
      expect(challenge.type).toBe("handshake_challenge");
      expect(response).toMatchObject({
        type: "handshake_response",
        fortress_id: "fortress-test",
      });

      writeIpc(socket, { type: "manifest_subscribe", request_id: "bind-test" });
      const manifest = await readNextMessage();
      const lease = await readNextMessage();
      expect(manifest).toMatchObject({
        type: "manifest_updated",
        manifest: { fortress_id: "fortress-test" },
      });
      expect(lease).toMatchObject({
        type: "arm_lease",
        armed: true,
      });
    } finally {
      await handle.stop();
    }
  });

  it("MED-3: the periodic as-agent-uid egress probe appends egress_probe_failed for an unreachable provisioned endpoint (injected probe, uid-mode origin)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    // uid-mode agent-origin + one provisioned rule in the signing source.
    const egressDir = join(fortressPath, "policy", "egress");
    const rulesDir = join(egressDir, "rules");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(rulesDir, { recursive: true });
    await writeFile(
      join(egressDir, "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: 503, system_uid_allow_ceiling: 500 }),
    );
    await writeFile(
      join(rulesDir, "provisioned-hermes-aaaaaaaaaaaa.json"),
      JSON.stringify({
        id: "provisioned-hermes-aaaaaaaaaaaa",
        schema_version: 1,
        created_at: "2026-07-10T00:00:00Z",
        match: { host: ["api.venice.ai"], port: [443], protocol: "tcp" },
        scope: {},
        disposition: "allow",
        derived: true,
      }),
    );

    const probeCalls: Array<{ uid: number; host: string; port: number }> = [];
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-egress-probe",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      listenerFactory: fakeListenerFactory,
      agentEgressProbeIntervalSeconds: 0.05,
      agentEgressProbe: async (uid, host, port) => {
        probeCalls.push({ uid, host, port });
        return false;
      },
    });
    try {
      await wait(200);
    } finally {
      await handle.stop();
    }

    // The probe ran AS the configured agent uid against the provisioned host.
    expect(probeCalls.length).toBeGreaterThan(0);
    expect(probeCalls[0]).toEqual({ uid: 503, host: "api.venice.ai", port: 443 });

    const { entries } = await auditLog.query({ layer: "l1", limit: 200 });
    const failures = entries.filter((e) => e.operation === "egress_probe_failed");
    expect(failures.length).toBeGreaterThan(0);
    expect(failures[0]!.details).toMatchObject({
      host: "api.venice.ai",
      port: 443,
      agent_uid: 503,
      rule_id: "provisioned-hermes-aaaaaaaaaaaa",
    });
    expect(failures[0]!.result).toBe("failure");
  });

  it("MED-3: the egress probe timer stays quiet with NO uid-mode agent-origin (nothing to probe as)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const probeCalls: string[] = [];
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-egress-probe-quiet",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: activeConfigPath(fortressPath),
      listenerFactory: fakeListenerFactory,
      agentEgressProbeIntervalSeconds: 0.05,
      agentEgressProbe: async (_uid, host) => {
        probeCalls.push(host);
        return false;
      },
    });
    try {
      await wait(150);
    } finally {
      await handle.stop();
    }
    expect(probeCalls).toEqual([]);
    const { entries } = await auditLog.query({ layer: "l1", limit: 200 });
    expect(entries.filter((e) => e.operation === "egress_probe_failed")).toEqual([]);
  });
});
