/**
 * End-to-end durability of the federation peer-sync security state at the
 * DASHBOARD seam (Federation 3/3b P0).
 *
 * These are the four merge-bar scenarios that justify the slice:
 *   (1) a captured envelope's high-water is REJECTED after a daemon restart
 *       (the anti-replay rollback guard survives the restart);
 *   (2) a node REVOCATION survives a restart (the folded projection is durable;
 *       a revoked node is NOT silently un-revoked on reboot);
 *   (3) a present-but-corrupt durable record FAILS CLOSED on boot (the sync
 *       paths deny rather than serve on empty anti-replay + empty revocation);
 *   (4) the DUR-1 outbound (reciprocal) high-water survives a restart;
 *   plus RR-1: the revoked-root predicate is wired feature-inert (empty in P0).
 *
 * A "restart" is a NEW DashboardApprovalChannel over the SAME MemoryStorage +
 * master key, re-wired with the same FederationContext and a fresh
 * FederationSyncStateStore (exactly what the production boot path does). The
 * test drives the live `V1FederationDeps` seam (the same callbacks the HTTP
 * sync handlers call) so it exercises the real persistence + rehydration code.
 *
 * Deterministic; in-memory storage; no sockets; keychain-free.
 */

import { describe, expect, it, beforeEach } from "vitest";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  FederationSyncStateStore,
  FederationSyncStateStoreError,
} from "../../src/v1/federation-sync-state-store.js";
import {
  signSyncEnvelope,
  verifySyncEnvelope,
} from "../../src/v1/federation-sync-envelope.js";
import {
  FEDERATION_SYNC_WIRE_VERSION,
  FEDERATION_NODE_EVICTION_EVENT_VERSION,
  federationOperatorAuthorityOrigin,
  signFederationNodeEvictionPayload,
} from "../../src/v1/federation-revocation.js";
import { federationEventHash } from "../../src/v1/federation.js";
import type { FederationEvent, V1FederationDeps } from "../../src/v1/federation.js";
import { buildFleetRoster } from "../../src/principal-policy/fleet-roster.js";
import { makeMultiNodeFortress, type MultiNodeFortress } from "./fed-materials.js";

type DepsAccess = DashboardApprovalChannel & {
  buildV1FederationDeps(): V1FederationDeps;
  _federationEnabled: boolean;
};

const MASTER_KEY = new Uint8Array(32).fill(11);

/**
 * Build a recipient daemon (the node that ACCEPTS syncs) over a shared storage +
 * master key, with the durable sync-state store wired and rehydrated. Returns the
 * live deps seam.
 */
async function buildRecipient(
  fortress: MultiNodeFortress,
  recipientNodeId: string,
  storage: MemoryStorage,
): Promise<{ dashboard: DepsAccess; deps: V1FederationDeps }> {
  const auditLog = new AuditLog(storage, randomBytes(32));
  const dashboard = new DashboardApprovalChannel({
    port: 0,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: "test",
    auto_open: false,
  }) as DepsAccess;
  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });
  dashboard.setFederationContext(fortress.nodes[recipientNodeId].context);
  dashboard._federationEnabled = true;
  await dashboard.setFederationSyncStateStore(
    new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }),
  );
  return { dashboard, deps: dashboard.buildV1FederationDeps() };
}

/** Sign a captured envelope from `sender` to `recipient` carrying one agent event. */
function captureEnvelope(
  fortress: MultiNodeFortress,
  senderNodeId: string,
  recipientNodeId: string,
  syncHighWater: number,
) {
  const sender = fortress.nodes[senderNodeId];
  const eventBody = {
    event_id: `${senderNodeId}:1`,
    origin_node_id: senderNodeId,
    sequence: 1,
    occurred_at: new Date().toISOString(),
    kind: "agent.identity",
    payload: { agent_id: "agent-1" },
    previous_hash: null,
  };
  const event: FederationEvent = {
    ...eventBody,
    event_hash: federationEventHash(eventBody),
  };
  return signSyncEnvelope({
    fortressId: fortress.fortressId,
    senderNodeId,
    recipientNodeId,
    syncHighWater,
    events: [event],
    senderNodeCert: sender.nodeCert,
    issuingPrincipalCert: fortress.principalCert,
    nodePrivateKey: Uint8Array.from(sender.nodePrivateKey),
  });
}

let fortress: MultiNodeFortress;

beforeEach(() => {
  fortress = makeMultiNodeFortress(["mac-1", "linux-1"]);
});

describe("Federation 3/3b P0 - durable sync-state at the dashboard seam", () => {
  it("MERGE-BAR 1: a captured envelope is REJECTED after a daemon restart", async () => {
    const storage = new MemoryStorage();

    // Boot 1: accept a sync at high-water 5 from mac-1, then persist.
    const boot1 = await buildRecipient(fortress, "linux-1", storage);
    const envelope = captureEnvelope(fortress, "mac-1", "linux-1", 5);
    const v1 = verifySyncEnvelope({
      envelope,
      pinnedMaster: fortress.pinnedMaster,
      recipientNodeId: "linux-1",
      acceptedHighWaterFor: (id) => boot1.deps.acceptedHighWaterFor(id),
      isNodeRevoked: (id) => boot1.deps.isNodeRevoked(id),
    });
    expect(v1.ok).toBe(true);
    const append1 = await boot1.deps.appendFederationEvents(envelope.events, {
      senderNodeId: "mac-1",
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
    });
    expect(append1.rejected).toEqual([]);
    const persisted = await boot1.deps.recordAcceptedHighWater("mac-1", 5);
    expect(persisted).toBe(true);

    // RESTART: a fresh dashboard over the SAME storage rehydrates the high-water.
    const boot2 = await buildRecipient(fortress, "linux-1", storage);
    expect(boot2.deps.acceptedHighWaterFor("mac-1")).toBe(5);

    // Re-presenting the SAME captured envelope (high-water 5) is now a rollback.
    const replay = verifySyncEnvelope({
      envelope,
      pinnedMaster: fortress.pinnedMaster,
      recipientNodeId: "linux-1",
      acceptedHighWaterFor: (id) => boot2.deps.acceptedHighWaterFor(id),
      isNodeRevoked: (id) => boot2.deps.isNodeRevoked(id),
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.reason).toBe("rollback_detected");
  });

  it("MERGE-BAR 2: a node revocation SURVIVES a restart (no silent un-revoke)", async () => {
    const storage = new MemoryStorage();
    const boot1 = await buildRecipient(fortress, "linux-1", storage);

    // The operator (mac-1 is the issuer node here) signs a node_eviction of
    // "linux-1"'s peer "mac-1"? No. Evict a third id the recipient knows. We
    // evict "rogue-node" via an operator-authority eviction event synced in.
    const fortressId = fortress.fortressId;
    const evictionPayload = signFederationNodeEvictionPayload({
      fortressId,
      nodeId: "rogue-node",
      reason: "compromised",
      effectiveAt: new Date().toISOString(),
      evictionSerial: 1,
      operatorPrincipalId: fortress.principalCert.principal_id,
      // The recipient's own issuing principal private key is not exposed by the
      // public materials; sign with the issuer's principal key from the context.
      operatorPrincipalPrivateKey:
        fortress.nodes["linux-1"].context.getIssuingPrincipalPrivateKey(),
    });
    const evBody = {
      event_id: `${federationOperatorAuthorityOrigin(fortressId)}:1`,
      origin_node_id: federationOperatorAuthorityOrigin(fortressId),
      sequence: 1,
      occurred_at: new Date().toISOString(),
      kind: "node_eviction",
      payload: { ...evictionPayload },
      previous_hash: null,
    };
    const evictionEvent: FederationEvent = {
      ...evBody,
      event_hash: federationEventHash(evBody),
    };
    expect(evictionEvent.payload.event_version).toBe(
      FEDERATION_NODE_EVICTION_EVENT_VERSION,
    );

    const append = await boot1.deps.appendFederationEvents([evictionEvent], {
      senderNodeId: "mac-1",
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
    });
    expect(append.accepted.map((e) => e.event_id)).toContain(evictionEvent.event_id);
    expect(boot1.deps.isNodeRevoked("rogue-node")).toBe(true);

    // RESTART over the SAME storage: the revocation must STILL hold (the event
    // log is NOT persisted, so this proves the durable PROJECTION carried it).
    const boot2 = await buildRecipient(fortress, "linux-1", storage);
    expect(boot2.deps.isNodeRevoked("rogue-node")).toBe(true);
  });

  it("MERGE-BAR 3: a present-but-corrupt durable record FAILS CLOSED on boot", async () => {
    const storage = new MemoryStorage();
    // Seed a clean record, then corrupt the on-disk ciphertext.
    await new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }).persist({
      acceptedHighWater: new Map([["mac-1", 9]]),
      outboundHighWater: 0,
      revokedNodeIds: new Set(),
      highestEvictionSerial: 0,
      revokedRootPubkeys: new Set(),
      highestRevocationSerial: 0,
    });
    const raw = await storage.read("_federation", "sync-state-v1");
    const obj = JSON.parse(new TextDecoder().decode(raw!)) as { ct: string };
    obj.ct = obj.ct.slice(0, -2) + (obj.ct.endsWith("AA") ? "BB" : "AA");
    await storage.write(
      "_federation",
      "sync-state-v1",
      new TextEncoder().encode(JSON.stringify(obj)),
    );

    // Boot with the corrupt record: the store load throws; the dashboard latches
    // sync-state-unavailable and the sync seam DENIES rather than serving empty.
    const boot = await buildRecipient(fortress, "linux-1", storage);

    // recordAcceptedHighWater fails closed (false), never silently accepting.
    await expect(
      boot.deps.recordAcceptedHighWater("mac-1", 1),
    ).resolves.toBe(false);
    // appendFederationEvents throws (handler maps to a generic deny).
    await expect(
      boot.deps.appendFederationEvents([], {
        senderNodeId: "mac-1",
        wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      }),
    ).rejects.toThrow();
    // nextOutboundHighWater throws (no reciprocal envelope on un-trusted state).
    await expect(boot.deps.nextOutboundHighWater()).rejects.toThrow();

    // Sanity: the underlying store load really does throw (not a no-op).
    await expect(
      new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }).load(),
    ).rejects.toBeInstanceOf(FederationSyncStateStoreError);
  });

  it("MERGE-BAR 4 (DUR-1): the outbound reciprocal high-water survives a restart", async () => {
    const storage = new MemoryStorage();
    const boot1 = await buildRecipient(fortress, "linux-1", storage);

    const first = await boot1.deps.nextOutboundHighWater();
    const second = await boot1.deps.nextOutboundHighWater();
    expect(first).toBe(1);
    expect(second).toBe(2);

    // RESTART: the next outbound high-water must not regress below 2.
    const boot2 = await buildRecipient(fortress, "linux-1", storage);
    const third = await boot2.deps.nextOutboundHighWater();
    expect(third).toBeGreaterThan(second);
    expect(third).toBe(3);
  });

  it("RR-1: the revoked-root predicate is wired feature-inert (empty in P0)", async () => {
    const storage = new MemoryStorage();
    const boot = await buildRecipient(fortress, "linux-1", storage);
    // No root is revoked in P0, so any master pubkey answers false. The hook
    // exists (wired) so 3c only has to populate the set.
    expect(typeof boot.deps.isRootRevoked).toBe("function");
    expect(boot.deps.isRootRevoked(fortress.pinnedMaster.public_key)).toBe(false);
    expect(boot.deps.isRootRevoked("any-other-master")).toBe(false);
  });

  it("eviction persist failure: DENIES the sync but does NOT silently un-revoke", async () => {
    // A storage that fails writes to the sync-state record only AFTER an arming
    // flag is set, so boot/hydrate succeeds but the eviction-triggered persist
    // throws. The handler must deny (throw propagates) AND the in-memory
    // revocation must stay applied (grow-only fail-safe), never roll back.
    class ArmedFailWriteStorage extends MemoryStorage {
      armed = false;
      override async write(ns: string, key: string, bytes: Uint8Array): Promise<void> {
        if (this.armed && ns === "_federation" && key === "sync-state-v1") {
          throw new Error("disk write failed");
        }
        return super.write(ns, key, bytes);
      }
    }
    const storage = new ArmedFailWriteStorage();
    const boot = await buildRecipient(fortress, "linux-1", storage);
    const fortressId = fortress.fortressId;
    const evictionPayload = signFederationNodeEvictionPayload({
      fortressId,
      nodeId: "rogue-node",
      reason: "compromised",
      effectiveAt: new Date().toISOString(),
      evictionSerial: 1,
      operatorPrincipalId: fortress.principalCert.principal_id,
      operatorPrincipalPrivateKey:
        fortress.nodes["linux-1"].context.getIssuingPrincipalPrivateKey(),
    });
    const evBody = {
      event_id: `${federationOperatorAuthorityOrigin(fortressId)}:1`,
      origin_node_id: federationOperatorAuthorityOrigin(fortressId),
      sequence: 1,
      occurred_at: new Date().toISOString(),
      kind: "node_eviction",
      payload: { ...evictionPayload },
      previous_hash: null,
    };
    const evictionEvent: FederationEvent = {
      ...evBody,
      event_hash: federationEventHash(evBody),
    };

    storage.armed = true;
    // The persist of the folded eviction throws -> the handler denies the sync.
    await expect(
      boot.deps.appendFederationEvents([evictionEvent], {
        senderNodeId: "mac-1",
        wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      }),
    ).rejects.toThrow();
    // But the revocation is STILL applied in memory (never silently un-revoked).
    expect(boot.deps.isNodeRevoked("rogue-node")).toBe(true);
  });

  it("a clean restart with NO record (fresh fortress) serves normally", async () => {
    const storage = new MemoryStorage();
    const boot = await buildRecipient(fortress, "linux-1", storage);
    // Fresh fortress: empty anti-replay, and accepts a normal advance.
    expect(boot.deps.acceptedHighWaterFor("mac-1")).toBeNull();
    await expect(boot.deps.recordAcceptedHighWater("mac-1", 1)).resolves.toBe(true);
  });

  it("PR-A: the node ROSTER + active count SURVIVE a restart (durable fleet membership)", async () => {
    // The core "count survives reboot" proof at the dashboard seam. Two peers
    // sync in (entering the durable roster), one is evicted (entering the durable
    // revoked set), the daemon restarts, and both the roster AND the active
    // (admitted, non-revoked) count rehydrate. The active count is derived by the
    // SAME buildFleetRoster summary.admitted path the console/billing consume; we
    // do not recount by hand.
    const threeNode = makeMultiNodeFortress(["linux-1", "node-a", "node-b"]);
    const storage = new MemoryStorage();

    // Boot 1: two peers sync an agent event in (each upserts into the roster and,
    // because the roster GREW, triggers a durable persist), then one is evicted.
    const boot1 = await buildRecipient(threeNode, "linux-1", storage);
    for (const sender of ["node-a", "node-b"] as const) {
      const envelope = captureEnvelope(threeNode, sender, "linux-1", 3);
      const append = await boot1.deps.appendFederationEvents(envelope.events, {
        senderNodeId: sender,
        wireVersion: FEDERATION_SYNC_WIRE_VERSION,
      });
      expect(append.rejected).toEqual([]);
    }
    // Roster now holds both peers; the active count is 2 (none revoked yet).
    expect(boot1.deps.listNodes().map((n) => n.node_id).sort()).toEqual([
      "node-a",
      "node-b",
    ]);
    expect(
      buildFleetRoster(boot1.deps, { evictionSerial: 0 }).summary.admitted,
    ).toBe(2);

    // Evict node-b via an operator-authority eviction (adds it to the durable
    // revoked set; the roster itself is NOT deleted from).
    const fortressId = threeNode.fortressId;
    const evictionPayload = signFederationNodeEvictionPayload({
      fortressId,
      nodeId: "node-b",
      reason: "compromised",
      effectiveAt: new Date().toISOString(),
      evictionSerial: 1,
      operatorPrincipalId: threeNode.principalCert.principal_id,
      operatorPrincipalPrivateKey:
        threeNode.nodes["linux-1"].context.getIssuingPrincipalPrivateKey(),
    });
    const evBody = {
      event_id: `${federationOperatorAuthorityOrigin(fortressId)}:1`,
      origin_node_id: federationOperatorAuthorityOrigin(fortressId),
      sequence: 1,
      occurred_at: new Date().toISOString(),
      kind: "node_eviction",
      payload: { ...evictionPayload },
      previous_hash: null,
    };
    const evictionEvent: FederationEvent = {
      ...evBody,
      event_hash: federationEventHash(evBody),
    };
    const evAppend = await boot1.deps.appendFederationEvents([evictionEvent], {
      senderNodeId: "node-a",
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
    });
    expect(evAppend.accepted.map((e) => e.event_id)).toContain(evictionEvent.event_id);
    expect(boot1.deps.isNodeRevoked("node-b")).toBe(true);
    // Active count is now 1 (node-a admitted, node-b revoked).
    expect(
      buildFleetRoster(boot1.deps, { evictionSerial: 1 }).summary.admitted,
    ).toBe(1);

    // RESTART over the SAME storage (the event log is NOT persisted, so the
    // roster survives ONLY via the durable snapshot this slice adds).
    const boot2 = await buildRecipient(threeNode, "linux-1", storage);

    // The roster is restored (both node ids present) ...
    expect(boot2.deps.listNodes().map((n) => n.node_id).sort()).toEqual([
      "node-a",
      "node-b",
    ]);
    // ... the eviction still holds ...
    expect(boot2.deps.isNodeRevoked("node-b")).toBe(true);
    expect(boot2.deps.isNodeRevoked("node-a")).toBe(false);
    // ... and the active (billing) count is the CORRECT 1, not 0 (pre-PR-A the
    // roster came up empty -> 0) and not 2 (revocation forgotten).
    const rosterAfter = buildFleetRoster(boot2.deps, { evictionSerial: 1 });
    expect(rosterAfter.summary.total).toBe(2);
    expect(rosterAfter.summary.admitted).toBe(1);
    expect(rosterAfter.summary.revoked).toBe(1);
  });
});
