import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { parseFrame } from "../../../src/castle-wall/ipc/framing.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { toBase64url } from "../../../src/core/encoding.js";
import { runProvisionPin } from "../../../src/cli/castle-wall.js";
import {
  CASTLE_WALL_ALREADY_RUNNING_MESSAGE,
  startMacOSCastleWallDaemon,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";

const silent = new Writable({
  write(_chunk, _encoding, callback) {
    callback();
  },
});

describe("Castle Wall macOS daemon integration", () => {
  const tempDirs: string[] = [];
  const liveSockets: Socket[] = [];

  afterEach(async () => {
    for (const socket of liveSockets.splice(0)) {
      socket.destroy();
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
    };
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

  it("binds the fortress-scoped castle.sock and removes it on shutdown", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
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
    };
    expect(config).toMatchObject({
      socket_path: join(fortressPath, "castle.sock"),
      fortress_id: "fortress-test",
      pid: process.pid,
    });
    expect(Number.isNaN(Date.parse(config.started_at))).toBe(false);

    await handle.stop();
    await expect(stat(configPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects a second daemon for the same fortress with the Phase 3 message", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const first = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
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
        auditLog,
        platform: "darwin",
        activeConfigPath: configPath,
      }),
    ).rejects.toThrow(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);

    await first.stop();
  });

  it("rejects startup when active discovery config points at a live PID", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    await writeFile(
      configPath,
      JSON.stringify({
        socket_path: "/tmp/other.sock",
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
        auditLog,
        platform: "darwin",
        activeConfigPath: configPath,
        listenerFactory: fakeListenerFactory,
      }),
    ).rejects.toThrow(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);
  });

  it("lets a sysext-style client read active config, connect, and receive handshake", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const configPath = activeConfigPath(fortressPath);
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
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
    } finally {
      await handle.stop();
    }
  });
});
