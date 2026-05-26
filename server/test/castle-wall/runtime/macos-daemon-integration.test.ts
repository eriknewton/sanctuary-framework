import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, stat, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

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

  afterEach(async () => {
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

  it("binds the fortress-scoped castle.sock and removes it on shutdown", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      auditLog,
      platform: "darwin",
      listenerFactory: fakeListenerFactory,
    });

    const socketPath = join(fortressPath, "castle.sock");
    expect(handle.socketPath).toBe(socketPath);
    await expect(stat(socketPath)).resolves.toBeTruthy();

    await handle.stop();
    await expect(stat(socketPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects a second daemon for the same fortress with the Phase 3 message", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const first = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-test",
      masterKey,
      auditLog,
      platform: "darwin",
      listenerFactory: fakeListenerFactory,
    });

    await expect(
      startMacOSCastleWallDaemon({
        fortressPath,
        fortressId: "fortress-test",
        masterKey,
        auditLog,
        platform: "darwin",
      }),
    ).rejects.toThrow(CASTLE_WALL_ALREADY_RUNNING_MESSAGE);

    await first.stop();
  });
});
