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
    const pinResult = await runProvisionPin({
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
});
