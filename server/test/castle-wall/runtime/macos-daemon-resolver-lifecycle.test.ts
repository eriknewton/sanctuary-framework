// fail-before-exempt: This change characterizes existing manual-reload serialization while hardening non-behavioral composition inputs and listener guards.
/**
 * Castle Wall macOS daemon — resolver lifecycle refresh tests.
 *
 * Fail-before: before the lifecycle monitor, a daemon that started before
 * Tailscale/MagicDNS held its boot resolver manifest until an operator reload.
 * These tests model that transition through the production daemon + listener
 * object graph and assert the signed publication changes only when its
 * normalized resolver SET changes.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { castleWallSigningKeyId } from "../../../src/castle-wall/allowlist/parse.js";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
} from "../../../src/castle-wall/constants.js";
import {
  startMacOSCastleWallDaemon,
  type DaemonSigner,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";

const DERIVED_DNS_RULE_ID = "derived_dns_for_hostname_rules";

function makeSigner(): DaemonSigner {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    mode: "local",
    signingKeyId: castleWallSigningKeyId(publicKey),
    publicKey,
    async signManifest(bytes) {
      return ed25519.sign(bytes, privateKey);
    },
    async signNonce(bytes) {
      return ed25519.sign(bytes, privateKey);
    },
  };
}

function makeControllableSigner() {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  let fail = false;
  const signer: DaemonSigner = {
    mode: "local",
    signingKeyId: castleWallSigningKeyId(publicKey),
    publicKey,
    async signManifest(bytes) {
      if (fail) throw new Error("test signer unavailable");
      return ed25519.sign(bytes, privateKey);
    },
    async signNonce(bytes) {
      return ed25519.sign(bytes, privateKey);
    },
  };
  return {
    signer,
    fail() {
      fail = true;
    },
    recover() {
      fail = false;
    },
  };
}

function makeInspectingListener() {
  const snapshots: Array<{ rules: AllowlistRule[] }> = [];
  let currentSnapshot: (() => { rules: AllowlistRule[] }) | undefined;
  let failNextManifestBroadcast = false;
  let manifestBroadcastAttempts = 0;
  const factory = (options: MacOSCastleWallListenerOptions) => {
    const consumer = options.consumer as unknown as {
      manifestProvider: { currentSnapshot(): { rules: AllowlistRule[] } };
    };
    currentSnapshot = () => consumer.manifestProvider.currentSnapshot();
    return {
      async start() {
        await writeFile(options.socketPath, "");
      },
      async stop() {
        await unlink(options.socketPath).catch(() => {});
      },
      async broadcastManifestUpdate() {
        // The production listener obtains the candidate through this consumer
        // provider. The test reads it only to assert the manifest it would send.
        manifestBroadcastAttempts += 1;
        if (failNextManifestBroadcast) {
          failNextManifestBroadcast = false;
          throw new Error("test manifest broadcast unavailable");
        }
        snapshots.push(currentSnapshot!());
        return snapshots.length;
      },
      async broadcastDecisionResponse() {
        return 0;
      },
      async broadcastArmLease() {
        return 0;
      },
      recycleConnection() {
        return false;
      },
    };
  };
  return {
    factory,
    snapshots,
    get manifestBroadcastAttempts() {
      return manifestBroadcastAttempts;
    },
    failNextManifestBroadcast() {
      failNextManifestBroadcast = true;
    },
    currentRules() {
      if (currentSnapshot === undefined) {
        throw new Error("listener has not observed a manifest publication");
      }
      return currentSnapshot().rules;
    },
  };
}

async function waitFor(condition: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() >= deadline) {
      throw new Error("timed out waiting for resolver lifecycle refresh");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe("Castle Wall macOS daemon — resolver lifecycle refresh", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  async function provision() {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-resolver-lifecycle-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    const rulesDir = join(fortressPath, "policy", "egress", "rules");
    await mkdir(rulesDir, { recursive: true, mode: 0o700 });
    const hostnameRule = {
      id: "provisioned-resolver-lifecycle-test",
      schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
      created_at: new Date().toISOString(),
      match: { host: "api.example.com", port: 443 },
      scope: {},
      disposition: "allow" as const,
    };
    await writeFile(
      join(rulesDir, `${hostnameRule.id}.json`),
      JSON.stringify(hostnameRule),
    );
    return { fortressPath, masterKey, auditLog };
  }

  async function start(
    fortressPath: string,
    masterKey: Uint8Array,
    auditLog: AuditLog,
    listenerFactory: ReturnType<typeof makeInspectingListener>["factory"],
    systemResolverProvider: () => Promise<readonly unknown[]>,
    signer: DaemonSigner = makeSigner(),
    resolverLifecycleRefreshIntervalSeconds = 0.01,
  ) {
    return await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: "resolver-lifecycle-test",
      masterKey,
      auditLog,
      signer,
      platform: "darwin",
      socketPath: join(fortressPath, "castle.sock"),
      activeConfigPath: join(fortressPath, "active.json"),
      globalPinnedPublicKeyPath: join(fortressPath, "global-pin.bin"),
      listenerFactory,
      resolverLifecycleRefreshIntervalSeconds,
      systemResolverProvider,
    });
  }

  it("re-signs and publishes when MagicDNS appears after the boot manifest", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolvers: readonly unknown[] = ["192.168.1.1"];
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => resolvers,
    );
    try {
      resolvers = ["100.100.100.100", "192.168.1.1"];
      await waitFor(() => listener.snapshots.length === 1);
      const derived = listener.snapshots[0]!.rules.find(
        (rule) => rule.id === DERIVED_DNS_RULE_ID,
      );
      expect(derived?.match.ip).toEqual(["100.100.100.100", "192.168.1.1"]);
    } finally {
      await daemon.stop();
    }
  });

  it("does not publish for order-only or duplicate-only resolver changes", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolvers: readonly unknown[] = ["192.168.1.1", "100.100.100.100"];
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => resolvers,
    );
    try {
      resolvers = ["100.100.100.100", "192.168.1.1", "100.100.100.100"];
      await new Promise((resolve) => setTimeout(resolve, 80));
      expect(listener.snapshots).toHaveLength(0);
    } finally {
      await daemon.stop();
    }
  });

  it("withdraws the derived DNS rule when a fresh read yields no resolver", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolvers: readonly unknown[] = ["192.168.1.1"];
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => resolvers,
    );
    try {
      resolvers = [];
      await waitFor(() => listener.snapshots.length === 1);
      expect(
        listener.snapshots[0]!.rules.some((rule) => rule.id === DERIVED_DNS_RULE_ID),
      ).toBe(false);
    } finally {
      await daemon.stop();
    }
  });

  it("fails closed on a throwing resolver read and stops the lifecycle timer on shutdown", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let throwResolverRead = false;
    let resolverReads = 0;
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => {
        resolverReads += 1;
        if (throwResolverRead) throw new Error("test scutil unavailable");
        return ["192.168.1.1"];
      },
    );
    let stopped = false;
    try {
      throwResolverRead = true;
      await waitFor(() => listener.snapshots.length === 1);
      expect(
        listener.snapshots[0]!.rules.some((rule) => rule.id === DERIVED_DNS_RULE_ID),
      ).toBe(false);

      await daemon.stop();
      stopped = true;
      const readsAtStop = resolverReads;
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(resolverReads).toBe(readsAtStop);
    } finally {
      if (!stopped) await daemon.stop();
    }
  });

  it("keeps the last-known-good DNS grant when lifecycle signing fails", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    const signer = makeControllableSigner();
    let resolvers: readonly unknown[] = ["192.168.1.1"];
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => resolvers,
      signer.signer,
    );
    try {
      signer.fail();
      resolvers = ["100.100.100.100"];
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(listener.snapshots).toHaveLength(0);
      // The consumer still serves the original signed manifest; the failed
      // candidate was never installed merely because composition began.
      const derived = listener.currentRules().find((rule) => rule.id === DERIVED_DNS_RULE_ID);
      expect(derived?.match.ip).toEqual(["192.168.1.1"]);
    } finally {
      signer.recover();
      await daemon.stop();
    }
  });

  it("keeps manual reload's installed manifest when its broadcast fails", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolvers: readonly unknown[] = ["192.168.1.1"];
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => resolvers,
      makeSigner(),
      // Keep the monitor out of this manual-reload compatibility assertion.
      3_600,
    );
    try {
      resolvers = ["100.100.100.100"];
      listener.failNextManifestBroadcast();
      const reply = await daemon.reloadPolicy();

      expect(reply.ok).toBe(false);
      expect(listener.snapshots).toHaveLength(0);
      // Manual reload historically installs the fully signed candidate before
      // broadcasting it. Preserve that behavior: delivery is not globally
      // atomic, so a listener error cannot safely pretend no subscriber saw it.
      const derived = listener.currentRules().find((rule) => rule.id === DERIVED_DNS_RULE_ID);
      expect(derived?.match.ip).toEqual(["100.100.100.100"]);
    } finally {
      await daemon.stop();
    }
  });

  it("returns to the host resolver after a manual broadcast failure leaves a local candidate", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolvers: readonly unknown[] = ["192.168.1.1"];
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => resolvers,
      makeSigner(),
      // Let the manual B -> host A transition settle before the first tick.
      0.25,
    );
    try {
      resolvers = ["100.100.100.100"];
      listener.failNextManifestBroadcast();
      expect((await daemon.reloadPolicy()).ok).toBe(false);
      expect(listener.currentRules().find((rule) => rule.id === DERIVED_DNS_RULE_ID)?.match.ip)
        .toEqual(["100.100.100.100"]);

      // Before this fix, the comparator still held startup A after the manual
      // B broadcast error. Seeing host A again therefore skipped publication
      // forever while the locally installed manifest remained B.
      resolvers = ["192.168.1.1"];
      await waitFor(() => listener.snapshots.length === 1);
      const derived = listener.currentRules().find((rule) => rule.id === DERIVED_DNS_RULE_ID);
      expect(derived?.match.ip).toEqual(["192.168.1.1"]);
    } finally {
      await daemon.stop();
    }
  });

  it("restores the lifecycle fingerprint after a failed broadcast so the unchanged host transition retries", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolvers: readonly unknown[] = ["192.168.1.1"];
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => resolvers,
    );
    try {
      listener.failNextManifestBroadcast();
      resolvers = ["100.100.100.100"];
      await waitFor(() => listener.manifestBroadcastAttempts >= 2);

      // The first lifecycle candidate rolled back locally; the next tick must
      // still recognize B as different from restored A and retry it.
      expect(listener.snapshots).toHaveLength(1);
      expect(
        listener.currentRules().find((rule) => rule.id === DERIVED_DNS_RULE_ID)?.match.ip,
      ).toEqual(["100.100.100.100"]);
    } finally {
      await daemon.stop();
    }
  });

  it("serializes a delayed monitor read behind a newer manual resolver reload", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolvers: readonly unknown[] = ["192.168.1.1"];
    let blockNextRead = false;
    let monitorReadStarted: (() => void) | undefined;
    const monitorStarted = new Promise<void>((resolve) => {
      monitorReadStarted = resolve;
    });
    let releaseMonitorRead: (() => void) | undefined;
    const monitorReadReleased = new Promise<void>((resolve) => {
      releaseMonitorRead = resolve;
    });
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => {
        if (blockNextRead) {
          blockNextRead = false;
          const captured = resolvers;
          monitorReadStarted?.();
          await monitorReadReleased;
          return captured;
        }
        return resolvers;
      },
    );
    try {
      // A prior design read the monitor snapshot outside the publication lock.
      // It could read A, let a manual reload publish B, then publish stale A.
      blockNextRead = true;
      resolvers = ["100.100.100.100"];
      await monitorStarted;
      resolvers = ["192.168.1.53"];
      const manualReload = daemon.reloadPolicy();
      releaseMonitorRead?.();
      const reply = await manualReload;
      expect(reply.ok).toBe(true);
      await waitFor(() => listener.snapshots.length >= 2);
      const finalDerived = listener.snapshots.at(-1)!.rules.find(
        (rule) => rule.id === DERIVED_DNS_RULE_ID,
      );
      expect(finalDerived?.match.ip).toEqual(["192.168.1.53"]);
    } finally {
      await daemon.stop();
    }
  });

  it("serializes concurrent manual reloads and publishes them in admission order", async () => {
    const { fortressPath, masterKey, auditLog } = await provision();
    const listener = makeInspectingListener();
    let resolverReadCount = 0;
    let firstReloadReadStarted: (() => void) | undefined;
    const firstReloadStarted = new Promise<void>((resolve) => {
      firstReloadReadStarted = resolve;
    });
    let releaseFirstReloadRead: (() => void) | undefined;
    const firstReloadReadReleased = new Promise<void>((resolve) => {
      releaseFirstReloadRead = resolve;
    });
    const daemon = await start(
      fortressPath,
      masterKey,
      auditLog,
      listener.factory,
      async () => {
        resolverReadCount += 1;
        if (resolverReadCount === 1) return ["192.168.1.1"];
        if (resolverReadCount === 2) {
          firstReloadReadStarted?.();
          await firstReloadReadReleased;
          return ["100.100.100.100"];
        }
        return ["192.168.1.53"];
      },
      makeSigner(),
      // Keep the lifecycle monitor out of this same-type contention test.
      3_600,
    );
    try {
      const firstReload = daemon.reloadPolicy();
      await firstReloadStarted;
      const secondReload = daemon.reloadPolicy();

      // The second reload cannot read or compose until the first publication
      // leaves the shared writer tail.
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(resolverReadCount).toBe(2);
      releaseFirstReloadRead?.();

      const [firstReply, secondReply] = await Promise.all([firstReload, secondReload]);
      expect(firstReply.ok).toBe(true);
      expect(secondReply.ok).toBe(true);
      expect(listener.snapshots).toHaveLength(2);
      expect(
        listener.snapshots[0]!.rules.find((rule) => rule.id === DERIVED_DNS_RULE_ID)?.match.ip,
      ).toEqual(["100.100.100.100"]);
      expect(
        listener.snapshots[1]!.rules.find((rule) => rule.id === DERIVED_DNS_RULE_ID)?.match.ip,
      ).toEqual(["192.168.1.53"]);
    } finally {
      releaseFirstReloadRead?.();
      await daemon.stop();
    }
  });
});
