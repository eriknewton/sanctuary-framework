/**
 * Castle Wall macOS daemon — policy-reload hang-guard tests.
 *
 * Drill-found regression (Mini1 egress acceptance drill, 2026-07-12): a
 * `protect --hermes` egress reload timed out CLIENT-side because the daemon's
 * `reloadPolicy` had no internal deadline. Its one heavy await — the helper
 * re-sign of the recomposed ruleset — could run to the helper client's own
 * (longer) shim timeout, well past the CLI's request deadline, so a healthy but
 * slow reload (or a genuinely stalled helper / wedged subscriber) surfaced as a
 * generic "IPC request timed out" and refuse-to-arm, with no specific reason.
 *
 * These tests exercise `handle.reloadPolicy()` directly (no socket) with the
 * signer/broadcast phases driven to stall, and assert that the reload now
 * returns a FAST, SPECIFIC `ok:false` bounded by the injected deadlines rather
 * than hanging — while a normal reload composes + signs + broadcasts and
 * returns `ok:true` with the live rule count, and a genuine signer failure
 * still refuses (ok:false, distinct error).
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { toBase64url } from "../../../src/core/encoding.js";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
  CASTLE_WALL_RELOAD_CLIENT_TIMEOUT_MS,
  CASTLE_WALL_RELOAD_SIGN_DEADLINE_MS,
  CASTLE_WALL_RELOAD_BROADCAST_DEADLINE_MS,
} from "../../../src/castle-wall/constants.js";
import {
  startMacOSCastleWallDaemon,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";
import type { ShimInvoker } from "../../../src/castle-wall/runtime/helper-signer.js";

type SignBehavior = "ok" | "hang" | "error";

/**
 * Controllable mock helper. `get-pubkey` always succeeds (so daemon start can
 * fetch K_helper) and signing starts healthy (so the baseline manifest signs at
 * start); a test flips `setSign(...)` to make the RELOAD sign hang or error.
 */
function makeControllableHelper() {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(seed);
  let behavior: SignBehavior = "ok";
  const invoke: ShimInvoker = async (args, stdin) => {
    const mode = args[0];
    if (mode === "get-pubkey" || mode === "re-pin") {
      return { stdout: toBase64url(pub), stderr: "", code: 0 };
    }
    // sign-manifest / sign-nonce
    if (behavior === "hang") {
      // Never resolves — models a wedged root signer helper.
      await new Promise<never>(() => {});
    }
    if (behavior === "error") {
      return { stdout: "", stderr: "root signer helper unavailable", code: 1 };
    }
    const sig = ed25519.sign(stdin ?? new Uint8Array(0), seed);
    return { stdout: toBase64url(sig), stderr: "", code: 0 };
  };
  return {
    pub,
    invoke,
    setSign(next: SignBehavior) {
      behavior = next;
    },
  };
}

describe("Castle Wall macOS daemon — policy reload hang guard", () => {
  const tempDirs: string[] = [];
  const liveSockets: Socket[] = [];

  afterEach(async () => {
    for (const socket of liveSockets.splice(0)) socket.destroy();
    for (const dir of tempDirs.splice(0)) await rm(dir, { recursive: true, force: true });
  });

  async function provisionFortress() {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-reload-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    return { fortressPath, masterKey, auditLog };
  }

  /**
   * Fake listener whose broadcast phase is controllable. `broadcastManifestUpdate`
   * normally counts calls and returns the count; when `hangBroadcast` is set it
   * never resolves (models a wedged subscriber write).
   */
  function makeControllableListener() {
    let broadcasts = 0;
    let hangBroadcast = false;
    const factory = (options: MacOSCastleWallListenerOptions) => ({
      async start() {
        await writeFile(options.socketPath, "");
      },
      async stop() {
        await unlink(options.socketPath).catch(() => {});
      },
      async broadcastManifestUpdate() {
        if (hangBroadcast) {
          await new Promise<never>(() => {});
        }
        broadcasts += 1;
        return broadcasts;
      },
      async broadcastDecisionResponse() {
        return 0;
      },
      async broadcastArmLease() {
        return 0;
      },
    });
    return {
      factory,
      get broadcasts() {
        return broadcasts;
      },
      hang() {
        hangBroadcast = true;
      },
    };
  }

  async function startDaemon(
    fortressPath: string,
    auditLog: AuditLog,
    masterKey: Uint8Array,
    helper: ReturnType<typeof makeControllableHelper>,
    listenerFactory: ReturnType<typeof makeControllableListener>["factory"],
    overrides: {
      reloadSignDeadlineMs?: number;
      reloadBroadcastDeadlineMs?: number;
      reloadAuditDeadlineMs?: number;
      reloadComposeHook?: () => Promise<void>;
    } = {},
  ) {
    return await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "fortress-reload",
      masterKey,
      auditLog,
      platform: "darwin",
      activeConfigPath: join(fortressPath, "active.json"),
      // Isolate the F-A2-1 #4 pin cross-check from any pin on the build host.
      globalPinnedPublicKeyPath: join(fortressPath, "no-such-global-pin.bin"),
      socketPath: join(fortressPath, "castle.sock"),
      listenerFactory,
      signerClientInvoke: helper.invoke,
      ...overrides,
    });
  }

  async function writeProvisionedRule(fortressPath: string): Promise<void> {
    const rulesDir = join(fortressPath, "policy", "egress", "rules");
    await mkdir(rulesDir, { recursive: true, mode: 0o700 });
    const rule = {
      id: "provisioned-hermes-test-0001",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: new Date().toISOString(),
      match: { host: "api.example.com", port: 443 },
      scope: {},
      disposition: "allow" as const,
    };
    await writeFile(join(rulesDir, `${rule.id}.json`), JSON.stringify(rule));
  }

  it("returns a fast, specific ok:false when the reload re-sign hangs (never hangs the daemon)", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeControllableHelper();
    const listener = makeControllableListener();
    const handle = await startDaemon(fortressPath, auditLog, masterKey, helper, listener.factory, {
      reloadSignDeadlineMs: 50,
    });
    try {
      // Baseline signed at start; now wedge the signer and reload.
      helper.setSign("hang");
      const started = Date.now();
      const reply = await handle.reloadPolicy({
        type: "policy_reload_request",
        request_id: "req-hang-sign",
      });
      const elapsed = Date.now() - started;
      expect(reply.ok).toBe(false);
      expect(reply.error ?? "").toMatch(/did not compose and sign within 50ms/);
      // Bounded: nowhere near the client's multi-second deadline.
      expect(elapsed).toBeLessThan(2_000);
    } finally {
      helper.setSign("ok");
      await handle.stop();
    }
  });

  it("returns a fast, specific ok:false when the manifest broadcast hangs", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeControllableHelper();
    const listener = makeControllableListener();
    const handle = await startDaemon(fortressPath, auditLog, masterKey, helper, listener.factory, {
      reloadBroadcastDeadlineMs: 50,
    });
    try {
      listener.hang();
      const started = Date.now();
      const reply = await handle.reloadPolicy({
        type: "policy_reload_request",
        request_id: "req-hang-broadcast",
      });
      const elapsed = Date.now() - started;
      expect(reply.ok).toBe(false);
      expect(reply.error ?? "").toMatch(/manifest broadcast did not complete within 50ms/);
      expect(elapsed).toBeLessThan(2_000);
    } finally {
      await handle.stop();
    }
  });

  it("returns ok:true even when the audit log is WEDGED (response is not gated on audit)", async () => {
    // Root cause of the second drill miss (2026-07-12): the reload completed the
    // compose+sign+broadcast, but the response was stuck behind auditLog.append/
    // flush. A wedged audit log must NOT turn a successful reload into a
    // client-visible timeout. Here the sign + broadcast succeed and the audit is
    // frozen; the reload must still return ok:true promptly.
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeControllableHelper();
    const listener = makeControllableListener();
    const handle = await startDaemon(fortressPath, auditLog, masterKey, helper, listener.factory, {
      reloadAuditDeadlineMs: 50,
    });
    const origAppend = auditLog.append.bind(auditLog);
    const origFlush = auditLog.flush.bind(auditLog);
    try {
      // Freeze the audit log AFTER startup (startup's own appends already ran).
      auditLog.append = (() => new Promise<void>(() => {})) as typeof auditLog.append;
      auditLog.flush = (() => new Promise<void>(() => {})) as typeof auditLog.flush;
      const started = Date.now();
      const reply = await handle.reloadPolicy({
        type: "policy_reload_request",
        request_id: "req-audit-wedged",
      });
      const elapsed = Date.now() - started;
      expect(reply.ok).toBe(true);
      expect(reply.loaded_rule_count).toBeGreaterThan(0);
      expect(listener.broadcasts).toBeGreaterThan(0);
      // Not blocked on the frozen audit write.
      expect(elapsed).toBeLessThan(2_000);
    } finally {
      // Restore before stop() so the daemon's filter_stopped audit can complete.
      auditLog.append = origAppend;
      auditLog.flush = origFlush;
      await handle.stop();
    }
  });

  it("bounds a stall at the TOP of reloadPolicy (before the signer) -> ok:false", async () => {
    // A hang BEFORE the re-sign (a wedged fortress read) must also be bounded by
    // the whole-body reload deadline, not only a signer hang.
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeControllableHelper();
    const listener = makeControllableListener();
    const handle = await startDaemon(fortressPath, auditLog, masterKey, helper, listener.factory, {
      reloadSignDeadlineMs: 50,
      reloadComposeHook: () => new Promise<void>(() => {}),
    });
    try {
      const started = Date.now();
      const reply = await handle.reloadPolicy({
        type: "policy_reload_request",
        request_id: "req-top-hang",
      });
      const elapsed = Date.now() - started;
      expect(reply.ok).toBe(false);
      expect(reply.error ?? "").toMatch(/did not compose and sign within 50ms/);
      expect(elapsed).toBeLessThan(2_000);
    } finally {
      await handle.stop();
    }
  });

  it("composes, signs, and broadcasts a normal reload -> ok:true with the live rule count", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeControllableHelper();
    const listener = makeControllableListener();
    const handle = await startDaemon(fortressPath, auditLog, masterKey, helper, listener.factory);
    try {
      const baseline = await handle.reloadPolicy({
        type: "policy_reload_request",
        request_id: "req-baseline",
      });
      expect(baseline.ok).toBe(true);
      expect(baseline.loaded_rule_count).toBeGreaterThan(0);
      const broadcastsAfterBaseline = listener.broadcasts;
      expect(broadcastsAfterBaseline).toBeGreaterThan(0);

      // Publish a provisioned allow rule; the reload must pick it up (its count
      // rises: the rule itself plus the #380 derived DNS allow) and re-broadcast.
      await writeProvisionedRule(fortressPath);
      const reloaded = await handle.reloadPolicy({
        type: "policy_reload_request",
        request_id: "req-with-rule",
      });
      expect(reloaded.ok).toBe(true);
      expect(reloaded.loaded_rule_count).toBeGreaterThan(baseline.loaded_rule_count);
      expect(reloaded.loaded_manifest_signature_b64url).toBeTruthy();
      expect(listener.broadcasts).toBeGreaterThan(broadcastsAfterBaseline);
    } finally {
      await handle.stop();
    }
  });

  it("keeps the client reload deadline strictly above the daemon's internal reload budget", () => {
    // The drill regression: the CLI's generic socket deadline (5s) was SHORTER
    // than the daemon's worst-case internal reload budget, so a healthy-but-slow
    // reload timed out client-side. The dedicated reload client deadline MUST
    // exceed the daemon's own sign + broadcast backstops (with headroom) so a
    // real stall surfaces as the daemon's specific ok:false, never a generic
    // client timeout.
    expect(CASTLE_WALL_RELOAD_CLIENT_TIMEOUT_MS).toBeGreaterThan(
      CASTLE_WALL_RELOAD_SIGN_DEADLINE_MS + CASTLE_WALL_RELOAD_BROADCAST_DEADLINE_MS,
    );
  });

  it("still refuses (ok:false) on a genuine signer failure -- distinct from a timeout", async () => {
    const { fortressPath, masterKey, auditLog } = await provisionFortress();
    const helper = makeControllableHelper();
    const listener = makeControllableListener();
    const handle = await startDaemon(fortressPath, auditLog, masterKey, helper, listener.factory, {
      reloadSignDeadlineMs: 5_000,
    });
    try {
      helper.setSign("error");
      const reply = await handle.reloadPolicy({
        type: "policy_reload_request",
        request_id: "req-sign-error",
      });
      expect(reply.ok).toBe(false);
      // A genuine helper error, NOT the deadline message: refuse-to-arm holds.
      expect(reply.error ?? "").toMatch(/root signer helper unavailable/);
      expect(reply.error ?? "").not.toMatch(/did not respond within/);
    } finally {
      helper.setSign("ok");
      await handle.stop();
    }
  });
});
