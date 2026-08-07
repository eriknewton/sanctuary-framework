import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { mkdtemp, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { generateRandomKey } from "../../../src/core/random.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import type {
  ArmLeaseNotification,
  EnforcementAvailabilitySnapshot,
} from "../../../src/castle-wall/ipc/messages.js";
import type { MacOSFlowEventConsumer } from "../../../src/castle-wall/runtime/index.js";
import {
  CASTLE_WALL_HEARTBEAT_OPERATION,
} from "../../../src/castle-wall/constants.js";
import {
  startMacOSCastleWallDaemon,
  type DaemonSigner,
  type MacOSCastleWallDaemonHandle,
  type MacOSCastleWallListenerHandle,
  type MacOSCastleWallListenerOptions,
} from "../../../src/castle-wall/runtime/index.js";
import {
  availabilitySnapshot,
  makeAvailabilityProducerKey,
  signAvailabilityReport,
  type AvailabilityProducerKey,
} from "./availability-report-helper.js";

const FORTRESS_ID = "fortress-test";

interface WatchdogListenerHarness {
  factory(options: MacOSCastleWallListenerOptions): MacOSCastleWallListenerHandle;
  registerSubscriber(subscriberId: string): void;
  getConsumer(): MacOSFlowEventConsumer;
  revokeArmLease(): Promise<void>;
  recycles: Array<{ subscriberId: string; reason: string }>;
}

describe("Castle Wall lease-delivery watchdog", () => {
  const tempDirs: string[] = [];
  const liveHandles: MacOSCastleWallDaemonHandle[] = [];

  afterEach(async () => {
    vi.restoreAllMocks();
    for (const handle of liveHandles.splice(0)) {
      await handle.stop().catch(() => undefined);
    }
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  function makeSigner(): DaemonSigner {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return {
      mode: "local",
      signingKeyId: "test-daemon-key",
      publicKey,
      async signManifest(canonicalBytes) {
        return ed25519.sign(canonicalBytes, privateKey);
      },
      async signNonce(nonce) {
        return ed25519.sign(nonce, privateKey);
      },
    };
  }

  function makeWatchdogListenerHarness(): WatchdogListenerHarness {
    const recycles: Array<{ subscriberId: string; reason: string }> = [];
    const registered = new Set<string>();
    let consumer: MacOSFlowEventConsumer | null = null;
    let revoke:
      | ((lease: ArmLeaseNotification) => void | Promise<void>)
      | null = null;

    return {
      recycles,
      factory(options) {
        consumer = options.consumer;
        revoke = options.onArmLeaseRevoke ?? null;
        return {
          async start() {
            await writeFile(options.socketPath, "");
          },
          async stop() {
            await unlink(options.socketPath).catch(() => {});
          },
          async broadcastManifestUpdate() {
            return registered.size;
          },
          async broadcastDecisionResponse() {
            return registered.size;
          },
          async broadcastArmLease() {
            return registered.size;
          },
          recycleConnection(subscriberId: string, reason: string) {
            if (!registered.has(subscriberId)) {
              return false;
            }
            recycles.push({ subscriberId, reason });
            registered.delete(subscriberId);
            consumer?.unregisterSubscriber(subscriberId);
            return true;
          },
        };
      },
      registerSubscriber(subscriberId) {
        if (consumer === null) {
          throw new Error("listener consumer was not captured");
        }
        registered.add(subscriberId);
        consumer.registerSubscriber({
          subscriberId,
          async emitManifestUpdate() {
            // no-op
          },
        });
      },
      getConsumer() {
        if (consumer === null) {
          throw new Error("listener consumer was not captured");
        }
        return consumer;
      },
      async revokeArmLease() {
        const lease: ArmLeaseNotification = {
          type: "arm_lease",
          armed: false,
          revoked: true,
          ttl_seconds: null,
          heartbeat_interval_seconds: 5,
          updated_at: "2026-08-03T00:00:00.000Z",
        };
        await revoke?.(lease);
      },
    };
  }

  async function startHarness(input: {
    threshold?: number;
    auditHeartbeatIntervalSeconds?: number;
    configureAuditLog?: (auditLog: AuditLog) => void;
  } = {}): Promise<{
    auditLog: AuditLog;
    handle: MacOSCastleWallDaemonHandle;
    listener: WatchdogListenerHarness;
    producer: AvailabilityProducerKey;
    consumer: MacOSFlowEventConsumer;
  }> {
    const fortressPath = await mkdtemp(join(tmpdir(), "cw-lease-watchdog-"));
    tempDirs.push(fortressPath);
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(
      new FilesystemStorage(join(fortressPath, "state")),
      masterKey,
      { integrityMode: "lenient" },
    );
    input.configureAuditLog?.(auditLog);
    const producer = makeAvailabilityProducerKey();
    const producerKeyPath = join(fortressPath, "audit-producer.pub");
    await writeFile(producerKeyPath, producer.publicKey);
    const listener = makeWatchdogListenerHarness();
    const handle = await startMacOSCastleWallDaemon({
      fortressPath,
      fortressId: FORTRESS_ID,
      masterKey,
      auditLog,
      platform: "darwin",
      signer: makeSigner(),
      activeConfigPath: join(fortressPath, "active.json"),
      globalPinnedPublicKeyPath: join(fortressPath, "global-pin.pub"),
      auditProducerPublicKeyPath: producerKeyPath,
      leaseDeliveryContradictionThreshold: input.threshold ?? 3,
      ...(input.auditHeartbeatIntervalSeconds !== undefined
        ? { auditHeartbeatIntervalSeconds: input.auditHeartbeatIntervalSeconds }
        : {}),
      listenerFactory: listener.factory,
    });
    liveHandles.push(handle);
    const consumer = listener.getConsumer();
    return { auditLog, handle, listener, producer, consumer };
  }

  function feedReport(input: {
    consumer: MacOSFlowEventConsumer;
    producer: AvailabilityProducerKey;
    subscriberId: string;
    seq: number;
    snapshot: EnforcementAvailabilitySnapshot;
  }): void {
    input.consumer.handleEnforcementAvailabilityReport(
      signAvailabilityReport({
        visibleReport: input.snapshot,
        privateKey: input.producer.privateKey,
        seq: input.seq,
        fortressId: FORTRESS_ID,
      }),
      input.subscriberId,
    );
  }

  function contradictingSnapshot(): EnforcementAvailabilitySnapshot {
    return availabilitySnapshot({
      lease_state: "failed_open",
      lease_reason: "heartbeat_stopped",
    });
  }

  it("W1 recycles a connected subscriber after threshold verified heartbeat_stopped reports and logs loud first", async () => {
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const threshold = 3;
    const { listener, consumer, producer } = await startHarness({ threshold });
    const subscriberId = "aaaaaaaaaaaaaaaa";
    listener.registerSubscriber(subscriberId);

    for (let i = 0; i < threshold; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: i + 1,
        snapshot: contradictingSnapshot(),
      });
    }

    expect(listener.recycles).toEqual([
      { subscriberId, reason: "lease_delivery_wedge" },
    ]);
    const wedgeLines = stderr.mock.calls
      .map((call) => String(call[0]))
      .filter((line) => line.includes("LEASE-DELIVERY-WEDGE"));
    expect(wedgeLines).toHaveLength(1);
    expect(wedgeLines[0]).toContain("reason=lease_delivery_wedge");
    expect(wedgeLines[0]).toContain(`subscriber=${subscriberId}`);
    expect(wedgeLines[0]).toContain("lease_reason=heartbeat_stopped");
    expect(wedgeLines[0]).toContain(`consecutive=${threshold}`);
    expect(wedgeLines[0]).toContain("action=recycle_connection");
  });

  it("W2 does not recycle when verified reports confirm the lease is live", async () => {
    const threshold = 3;
    const { listener, consumer, producer } = await startHarness({ threshold });
    const subscriberId = "bbbbbbbbbbbbbbbb";
    listener.registerSubscriber(subscriberId);

    for (let i = 0; i < threshold + 2; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: i + 1,
        snapshot: availabilitySnapshot(),
      });
    }

    expect(listener.recycles).toEqual([]);
  });

  it("W3 does not count when no reports arrive or after operator revoke stops the lease beat", async () => {
    const threshold = 3;
    const { listener, consumer, producer } = await startHarness({ threshold });
    expect(listener.recycles).toEqual([]);

    const subscriberId = "cccccccccccccccc";
    listener.registerSubscriber(subscriberId);
    await listener.revokeArmLease();
    for (let i = 0; i < threshold; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: i + 1,
        snapshot: contradictingSnapshot(),
      });
    }

    expect(listener.recycles).toEqual([]);
  });

  it("W4 is level-triggered across reconnects", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const threshold = 3;
    const { listener, consumer, producer } = await startHarness({ threshold });
    const firstSubscriber = "dddddddddddddddd";
    listener.registerSubscriber(firstSubscriber);
    for (let i = 0; i < threshold; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId: firstSubscriber,
        seq: i + 1,
        snapshot: contradictingSnapshot(),
      });
    }

    const secondSubscriber = "eeeeeeeeeeeeeeee";
    listener.registerSubscriber(secondSubscriber);
    for (let i = 0; i < threshold; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId: secondSubscriber,
        seq: i + 1,
        snapshot: contradictingSnapshot(),
      });
    }

    expect(listener.recycles).toEqual([
      { subscriberId: firstSubscriber, reason: "lease_delivery_wedge" },
      { subscriberId: secondSubscriber, reason: "lease_delivery_wedge" },
    ]);
  });

  it("W5 resets below-threshold contradiction runs after an ok report", async () => {
    const threshold = 3;
    const { listener, consumer, producer } = await startHarness({ threshold });
    const subscriberId = "ffffffffffffffff";
    listener.registerSubscriber(subscriberId);
    let seq = 1;
    for (let i = 0; i < threshold - 1; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: seq++,
        snapshot: contradictingSnapshot(),
      });
    }
    feedReport({
      consumer,
      producer,
      subscriberId,
      seq: seq++,
      snapshot: availabilitySnapshot(),
    });
    for (let i = 0; i < threshold - 1; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: seq++,
        snapshot: contradictingSnapshot(),
      });
    }

    expect(listener.recycles).toEqual([]);
  });

  it("W7 clears a below-threshold contradiction count when the connection unregisters (clean disconnect)", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const threshold = 3;
    const { listener, consumer, producer } = await startHarness({ threshold });
    const subscriberId = "2222222222222222";
    listener.registerSubscriber(subscriberId);
    let seq = 1;
    for (let i = 0; i < threshold - 1; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: seq++,
        snapshot: contradictingSnapshot(),
      });
    }
    // Clean disconnect (the c26 shape): the consumer unregisters the
    // subscriber. Gate-found on PR #1086: the contradiction count survived
    // this and fired after ONE report on a same-id reconnect.
    consumer.unregisterSubscriber(subscriberId);
    listener.registerSubscriber(subscriberId);
    for (let i = 0; i < threshold - 1; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: seq++,
        snapshot: contradictingSnapshot(),
      });
    }
    // Count restarted from zero: threshold-1 post-reconnect reports must NOT
    // fire even though the pre-disconnect run left the total at 2(threshold-1).
    expect(listener.recycles).toEqual([]);
    feedReport({
      consumer,
      producer,
      subscriberId,
      seq: seq++,
      snapshot: contradictingSnapshot(),
    });
    expect(listener.recycles).toEqual([
      { subscriberId, reason: "lease_delivery_wedge" },
    ]);
  });

  it("W6 carries lease_delivery_recycles on the next castle_wall_heartbeat", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const threshold = 3;
    const { auditLog, listener, consumer, producer } = await startHarness({
      threshold,
      auditHeartbeatIntervalSeconds: 0.01,
    });
    const subscriberId = "1111111111111111";
    listener.registerSubscriber(subscriberId);
    for (let i = 0; i < threshold; i += 1) {
      feedReport({
        consumer,
        producer,
        subscriberId,
        seq: i + 1,
        snapshot: contradictingSnapshot(),
      });
    }

    await new Promise((resolve) => setTimeout(resolve, 40));
    const beats = (await auditLog.query({ layer: "l1", limit: 5000 })).entries
      .filter((entry) => entry.operation === CASTLE_WALL_HEARTBEAT_OPERATION);
    expect(
      beats.some(
        (entry) =>
          (entry.details as Record<string, unknown>).lease_delivery_recycles === 1,
      ),
    ).toBe(true);
  });

  it("W8 serializes audit heartbeats when the write path is slower than the cadence", async () => {
    const releaseBlockedHeartbeats: { current?: () => void } = {};
    let observedFirstBlockedHeartbeat: (() => void) | null = null;
    const firstBlockedHeartbeat = new Promise<void>((resolve) => {
      observedFirstBlockedHeartbeat = resolve;
    });
    const blockedHeartbeats = new Promise<void>((resolve) => {
      releaseBlockedHeartbeats.current = resolve;
    });
    let heartbeatAppends = 0;
    let blockedHeartbeatAppends = 0;
    let maxBlockedHeartbeatAppends = 0;

    await startHarness({
      auditHeartbeatIntervalSeconds: 0.001,
      configureAuditLog(auditLog) {
        const append = auditLog.append.bind(auditLog);
        vi.spyOn(auditLog, "append").mockImplementation(
          async (...args: Parameters<AuditLog["append"]>) => {
            if (args[1] === CASTLE_WALL_HEARTBEAT_OPERATION) {
              heartbeatAppends += 1;
              if (heartbeatAppends > 1) {
                blockedHeartbeatAppends += 1;
                maxBlockedHeartbeatAppends = Math.max(
                  maxBlockedHeartbeatAppends,
                  blockedHeartbeatAppends,
                );
                observedFirstBlockedHeartbeat?.();
                try {
                  await blockedHeartbeats;
                } finally {
                  blockedHeartbeatAppends -= 1;
                }
              }
            }
            return append(...args);
          },
        );
      },
    });

    await firstBlockedHeartbeat;
    await new Promise((resolve) => setTimeout(resolve, 20));
    releaseBlockedHeartbeats.current?.();
    expect(maxBlockedHeartbeatAppends).toBe(1);
  });

  it("W9 drains an in-flight heartbeat before writing filter_stopped", async () => {
    const releaseBlockedHeartbeat: { current?: () => void } = {};
    let observedBlockedHeartbeat: (() => void) | null = null;
    const blockedHeartbeatObserved = new Promise<void>((resolve) => {
      observedBlockedHeartbeat = resolve;
    });
    const blockedHeartbeatReleased = new Promise<void>((resolve) => {
      releaseBlockedHeartbeat.current = resolve;
    });
    const operations: string[] = [];
    let heartbeatAppends = 0;

    const { handle } = await startHarness({
      auditHeartbeatIntervalSeconds: 0.001,
      configureAuditLog(auditLog) {
        const append = auditLog.append.bind(auditLog);
        vi.spyOn(auditLog, "append").mockImplementation(
          async (...args: Parameters<AuditLog["append"]>) => {
            if (args[1] === CASTLE_WALL_HEARTBEAT_OPERATION) {
              heartbeatAppends += 1;
              if (heartbeatAppends > 1) {
                observedBlockedHeartbeat?.();
                await blockedHeartbeatReleased;
              }
            }
            operations.push(String(args[1]));
            return append(...args);
          },
        );
      },
    });

    await blockedHeartbeatObserved;
    const stopPromise = handle.stop();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(operations).not.toContain("filter_stopped");

    releaseBlockedHeartbeat.current?.();
    await stopPromise;
    const liveHandleIndex = liveHandles.indexOf(handle);
    if (liveHandleIndex >= 0) {
      liveHandles.splice(liveHandleIndex, 1);
    }

    const heartbeatIndex = operations.lastIndexOf(CASTLE_WALL_HEARTBEAT_OPERATION);
    const stoppedIndex = operations.lastIndexOf("filter_stopped");
    expect(heartbeatIndex).toBeGreaterThanOrEqual(0);
    expect(stoppedIndex).toBeGreaterThan(heartbeatIndex);
  });
});
