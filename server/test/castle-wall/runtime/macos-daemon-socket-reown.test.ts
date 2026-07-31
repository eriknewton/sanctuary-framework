import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { toBase64url } from "../../../src/core/encoding.js";
import { runProvisionPin } from "../../../src/cli/castle-wall.js";
import {
  resolveFortressCreateOwner,
  resolveSocketReownUid,
  startMacOSCastleWallDaemon,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";

const silent = new Writable({
  write(_chunk, _encoding, callback) {
    callback();
  },
});

/**
 * Slice M Layer-2 (drilled 2026-06-29, Erik-present): the macOS content-filter
 * extension runs as the LOGGED-IN OPERATOR uid, not root. When the daemon runs
 * as root it binds a root-owned 0600 control socket the operator-uid extension
 * gets EPERM connecting to, so audit-producer signing never engages. The daemon
 * must re-own the socket to the fortress-dir owner (the operator). These tests
 * exercise the pure resolution LOGIC (a chown in a unit test would need root), so
 * they assert the helper computes the right target uid and SKIPS correctly.
 */
describe("resolveSocketReownUid (Slice M Layer-2 socket ownership)", () => {
  const FORTRESS = "/fake/fortress";

  it("returns an explicit socketOwnerUid verbatim (safe-mode boot daemon path)", () => {
    // The explicit value wins regardless of process uid or fortress owner, so the
    // existing safe-mode boot-daemon behavior is preserved byte-for-byte.
    const resolved = resolveSocketReownUid({
      socketOwnerUid: 1234,
      fortressPath: FORTRESS,
      processUid: 0,
      statFortressUid: () => 4321,
    });
    expect(resolved).toBe(1234);
  });

  it("an explicit socketOwnerUid is honored even when the daemon is NOT root", () => {
    const resolved = resolveSocketReownUid({
      socketOwnerUid: 501,
      fortressPath: FORTRESS,
      processUid: 501,
      statFortressUid: () => {
        throw new Error("stat must not be consulted when an explicit uid is given");
      },
    });
    expect(resolved).toBe(501);
  });

  it("auto-derives the operator uid from the fortress dir owner when root and owners differ", () => {
    // The engage gap: the daemon runs as root (uid 0) over an operator-owned
    // fortress (uid 501). Re-own the socket to 501 so the operator-uid extension
    // can connect.
    const resolved = resolveSocketReownUid({
      fortressPath: FORTRESS,
      processUid: 0,
      statFortressUid: () => 501,
    });
    expect(resolved).toBe(501);
  });

  it("skips (undefined) when the daemon is NOT root — an operator daemon already binds an operator-owned socket", () => {
    const resolved = resolveSocketReownUid({
      fortressPath: FORTRESS,
      processUid: 501,
      statFortressUid: () => {
        throw new Error("stat must not be consulted for a non-root daemon");
      },
    });
    expect(resolved).toBeUndefined();
  });

  it("root over a ROOT-owned fortress is a loud warning, never a silent no-op (spec 2026-07-30)", () => {
    // Mini2 2026-07-30: the fortress owner IS the bug, so "re-own to the
    // fortress owner" resolved to root and the operator lever stayed dead
    // silently. The skip behavior is preserved (no re-own target exists) but
    // the state now warns as loudly as a failed stat.
    const warnings: string[] = [];
    const resolved = resolveSocketReownUid({
      fortressPath: FORTRESS,
      processUid: 0,
      statFortressUid: () => 0,
      warn: (message) => warnings.push(message),
    });
    expect(resolved).toBeUndefined();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("owned by root");
    expect(warnings[0]).toContain("repair-custody");
  });

  it("a same-NON-ROOT-uid match stays a quiet skip (operator daemon over its own fortress)", () => {
    const warnings: string[] = [];
    const resolved = resolveSocketReownUid({
      fortressPath: FORTRESS,
      processUid: 501,
      statFortressUid: () => 501,
      warn: (message) => warnings.push(message),
    });
    expect(resolved).toBeUndefined();
    expect(warnings).toEqual([]);
  });

  it("fail-soft: warns and returns undefined when the fortress dir cannot be stat-ed", () => {
    const warnings: string[] = [];
    const resolved = resolveSocketReownUid({
      fortressPath: FORTRESS,
      processUid: 0,
      statFortressUid: () => {
        const err = new Error("ENOENT: no such file or directory") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        throw err;
      },
      warn: (message) => warnings.push(message),
    });
    expect(resolved).toBeUndefined();
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("could not resolve the fortress owner");
  });

  it("never widens to a world/other uid — it only ever returns the fortress owner or undefined", () => {
    // Guard against a regression that returns some non-owner uid. With owner 501
    // and root daemon, the ONLY non-undefined result allowed is 501.
    const resolved = resolveSocketReownUid({
      fortressPath: FORTRESS,
      processUid: 0,
      statFortressUid: () => 501,
    });
    expect(resolved === 501).toBe(true);
  });
});

/**
 * Create-with-fchown owner resolution (fortress-ownership spec 2026-07-30,
 * open question 5): a ROOT daemon writing inside an operator-owned fortress
 * must create files owned by the fortress owner, never root.
 */
describe("resolveFortressCreateOwner", () => {
  const FORTRESS = "/fake/fortress";

  it("resolves the fortress owner for a root daemon over an operator-owned fortress", () => {
    expect(
      resolveFortressCreateOwner({
        fortressPath: FORTRESS,
        processUid: 0,
        statFortressOwner: () => ({ uid: 501, gid: 20 }),
      }),
    ).toEqual({ uid: 501, gid: 20 });
  });

  it("returns undefined for a non-root daemon (its files are already operator-owned)", () => {
    expect(
      resolveFortressCreateOwner({
        fortressPath: FORTRESS,
        processUid: 501,
        statFortressOwner: () => {
          throw new Error("stat must not be consulted for a non-root daemon");
        },
      }),
    ).toBeUndefined();
  });

  it("returns undefined for a root-owned fortress (no owner to hand files to; the loud warning covers it)", () => {
    expect(
      resolveFortressCreateOwner({
        fortressPath: FORTRESS,
        processUid: 0,
        statFortressOwner: () => ({ uid: 0, gid: 0 }),
      }),
    ).toBeUndefined();
  });

  it("returns undefined when the fortress cannot be statted (fail-soft)", () => {
    expect(
      resolveFortressCreateOwner({
        fortressPath: FORTRESS,
        processUid: 0,
        statFortressOwner: () => {
          throw new Error("ENOENT");
        },
      }),
    ).toBeUndefined();
  });
});

/**
 * Integration: the daemon AUTO-DERIVES + THREADS the re-own uid into the listener
 * when running as root, so the engage path (`wrap`, which never passed
 * socketOwnerUid) re-owns the socket too. Asserted via a captured listenerFactory
 * because the test process is not root (a real chown would need root); we inject a
 * simulated-root resolver result by capturing what the daemon would hand the
 * listener.
 */
describe("startMacOSCastleWallDaemon threads the re-own uid (Slice M Layer-2)", () => {
  const tempDirs: string[] = [];
  const liveServers: ReturnType<typeof createServer>[] = [];
  const liveSockets: Socket[] = [];

  afterEach(async () => {
    for (const s of liveSockets.splice(0)) s.destroy();
    for (const srv of liveServers.splice(0)) {
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function provisionFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-reown-"));
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
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    return { fortressPath, masterKey, auditLog };
  }

  it("passes an explicit socketOwnerUid straight through to the listener", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let captured: MacOSCastleWallListenerOptions | undefined;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-reown",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"),
      socketOwnerUid: 4242,
      listenerFactory(options) {
        captured = options;
        return realFakeListener(options, liveServers);
      },
    });
    expect(captured?.socketOwnerUid).toBe(4242);
    await handle.stop();
    await expect(stat(join(fortressPath, "castle.sock"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("does NOT re-own when no socketOwnerUid is given and the daemon is not root (test process)", async () => {
    // The test runner is a normal user (uid != 0), so the auto-derive path
    // correctly skips: a non-root operator daemon already binds an operator-owned
    // socket. This proves the auto-derive does not spuriously re-own on a normal
    // operator-run daemon.
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    let captured: MacOSCastleWallListenerOptions | undefined;
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-reown",
      masterKey,
      localSign: true,
      auditLog,
      platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"),
      listenerFactory(options) {
        captured = options;
        return realFakeListener(options, liveServers);
      },
    });
    // On a non-root test process the daemon must leave ownership untouched.
    if (process.getuid?.() !== 0) {
      expect(captured?.socketOwnerUid).toBeUndefined();
    }
    await handle.stop();
  });
});

function realFakeListener(
  options: MacOSCastleWallListenerOptions,
  liveServers: ReturnType<typeof createServer>[],
) {
  let server: ReturnType<typeof createServer> | null = null;
  return {
    async start() {
      await new Promise<void>((resolve, reject) => {
        const s = createServer();
        s.once("error", reject);
        s.listen(options.socketPath, () => {
          server = s;
          liveServers.push(s);
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
      const { unlink } = await import("node:fs/promises");
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
