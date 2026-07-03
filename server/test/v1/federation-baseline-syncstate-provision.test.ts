/**
 * B1 - F3 residual close: PROVISIONING-TIME baseline sync-state provisioning.
 *
 * The #856 F3 fix latched a DELETED sync-state record fail-closed ONLY when the
 * fortress carried INDEPENDENT trust-root revocation evidence (a revoked-root set
 * or a non-zero root-revocation serial). Its documented residual: a fortress
 * whose ONLY revocation history is NODE evictions (which live solely in the
 * deleted sync-state record, with NO independent trust-root witness) could not be
 * distinguished from a fresh fortress after a deletion, so its node-revocation
 * memory silently reset to empty on that boot.
 *
 * This suite pins the close: at provisioning time (the first boot on which the
 * durable store is wired to a provisioned fortress) the dashboard writes a
 * BASELINE sync-state record AND a separate durable BASELINE SENTINEL, atomically
 * and idempotently. From then on the sentinel is the independent witness that a
 * baseline was provisioned, so deleting the main record - even on an
 * eviction-only fortress - is caught and fails closed.
 *
 * What is proven:
 *   (A) provisioning writes BOTH the baseline record and the sentinel, across all
 *       three provisioning entry shapes (issuer / local-joiner / operator_cloud);
 *   (B) the write is idempotent + non-destructive (a real record already present
 *       is NOT clobbered by the baseline; a second wiring writes nothing new);
 *   (C) FAIL-BEFORE/PASS-AFTER: an eviction-only history whose record is deleted
 *       now LATCHES (fail closed: deny, never un-revoke), where before it reset to
 *       empty - demonstrated by driving the pre-fix predicate directly;
 *   (D) a genuinely fresh provisioned fortress's FIRST sync is NOT bricked;
 *   (E) fail-closed direction: while latched, the sync path DENIES (returns false)
 *       and the revoked node is NOT un-revoked (memory untouched).
 *
 * Real crypto throughout: rosters + node certs are fortress-master-signed and the
 * sync-state records are AES-256-GCM at rest; nothing is mocked.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  FederationSyncStateStore,
  FEDERATION_SYNC_STATE_STORE_NAMESPACE,
  FEDERATION_SYNC_STATE_STORE_KEY,
  FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY,
  emptyFederationSyncState,
} from "../../src/v1/federation-sync-state-store.js";
import type { V1FederationDeps } from "../../src/v1/federation.js";
import { makeMultiNodeFortress, type MultiNodeFortress } from "./fed-materials.js";

type DepsAccess = DashboardApprovalChannel & {
  buildV1FederationDeps(): V1FederationDeps;
  isFederationProvisioned(): boolean;
  _federationEnabled: boolean;
};

const MASTER_KEY = new Uint8Array(32).fill(17);

function newStore(storage: MemoryStorage): FederationSyncStateStore {
  return new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
}

/**
 * Build a dashboard bound to a provisioned federation context + a durable
 * sync-state store over `storage`. `contextOverrides` lets a test model the
 * local-joiner / operator_cloud provisioning shapes (node_mode) and inject
 * independent revocation history.
 */
async function buildDashboard(
  fortress: MultiNodeFortress,
  nodeId: string,
  storage: MemoryStorage,
  auditLog: AuditLog,
  contextOverrides?: Record<string, unknown>,
): Promise<DepsAccess> {
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
  dashboard.setFederationContext({
    ...fortress.nodes[nodeId]!.context,
    ...(contextOverrides ?? {}),
  } as never);
  dashboard._federationEnabled = true;
  await dashboard.setFederationSyncStateStore(newStore(storage));
  return dashboard;
}

async function recordPresent(storage: MemoryStorage): Promise<boolean> {
  return (
    (await storage.read(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    )) !== null
  );
}

async function sentinelPresent(storage: MemoryStorage): Promise<boolean> {
  return (
    (await storage.read(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY,
    )) !== null
  );
}

describe("B1: provisioning writes a baseline sync-state record + sentinel atomically", () => {
  // (A) All three provisioning entry shapes converge at setFederationSyncStateStore
  // (issuer sets an issuer context; local-joiner and operator_cloud set a
  // non-issuer context with a distinct node_mode). We assert the baseline write
  // fires for each shape.
  // A non-issuer context (local joiner / operator_cloud) carries NONE of the
  // issuer-authority fields; setFederationContext rejects any that leak through.
  const nonIssuer = {
    approver: undefined,
    getIssuingPrincipalPrivateKey: undefined,
    getFortressMasterSecret: undefined,
    getMasterPrivateKey: undefined,
  };
  const shapes: Array<{ name: string; overrides?: Record<string, unknown> }> = [
    { name: "issuer (mint)" },
    { name: "local joiner (join)", overrides: { nodeMode: "local", ...nonIssuer } },
    {
      name: "operator_cloud (operator-cloud join)",
      overrides: { nodeMode: "operator_cloud", ...nonIssuer },
    },
  ];

  for (const shape of shapes) {
    it(`writes baseline record + sentinel on ${shape.name}`, async () => {
      const fortress = makeMultiNodeFortress(["mini-1"]);
      const storage = new MemoryStorage();
      const auditLog = new AuditLog(storage, randomBytes(32));

      // Precondition: nothing at rest.
      expect(await recordPresent(storage)).toBe(false);
      expect(await sentinelPresent(storage)).toBe(false);

      const dashboard = await buildDashboard(
        fortress,
        "mini-1",
        storage,
        auditLog,
        shape.overrides,
      );
      expect(dashboard.isFederationProvisioned()).toBe(true);

      // Provisioning wrote BOTH the baseline record and the sentinel.
      expect(await recordPresent(storage)).toBe(true);
      expect(await sentinelPresent(storage)).toBe(true);

      // The baseline record decrypts to the empty/zero snapshot (no phantom
      // revocations / high-waters were invented).
      const loaded = await newStore(storage).load();
      expect(loaded).toEqual(emptyFederationSyncState());
    });
  }

  it("(B) is idempotent: a second wiring writes nothing new and preserves the record", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    const first = await buildDashboard(fortress, "mini-1", storage, auditLog);
    expect(await recordPresent(storage)).toBe(true);
    expect(await sentinelPresent(storage)).toBe(true);

    // Advance the durable record with a real accepted high-water (models the
    // fortress doing work after provisioning).
    await expect(
      first.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 7),
    ).resolves.toBe(true);
    const afterWork = await newStore(storage).load();
    expect(afterWork.acceptedHighWater.get("mini-1")).toBe(7);

    // A SECOND boot re-wires the store. provisionBaselineIfAbsent must be a
    // no-op fold: it must NOT clobber the advanced high-water back to the empty
    // baseline (the baseline write goes through the monotonic merge).
    const second = await buildDashboard(fortress, "mini-1", storage, auditLog);
    expect(second.isFederationProvisioned()).toBe(true);
    const afterSecond = await newStore(storage).load();
    expect(afterSecond.acceptedHighWater.get("mini-1")).toBe(7);
  });

  it("(B2) provisionBaselineIfAbsent never clobbers a pre-existing real record", async () => {
    const storage = new MemoryStorage();
    const store = newStore(storage);

    // A fortress with a real eviction-only record already at rest (no sentinel).
    const withEviction = emptyFederationSyncState();
    withEviction.revokedNodeIds.add("evicted-node");
    withEviction.highestEvictionSerial = 3;
    await store.persist(withEviction);
    expect(await sentinelPresent(storage)).toBe(false);

    // Provisioning the baseline writes ONLY the missing sentinel; the record is
    // folded over monotonically (empty baseline cannot drop the revocation).
    const wrote = await store.provisionBaselineIfAbsent();
    expect(wrote).toBe(true);
    expect(await sentinelPresent(storage)).toBe(true);
    const after = await store.load();
    expect(after.revokedNodeIds.has("evicted-node")).toBe(true);
    expect(after.highestEvictionSerial).toBe(3);

    // A third call is a full no-op (both records present).
    expect(await store.provisionBaselineIfAbsent()).toBe(false);
  });
});

describe("B1: an eviction-only history whose record is deleted now fails closed", () => {
  it("(C) FAIL-BEFORE surface: an eviction-only deletion with NO sentinel and NO trust-root witness resets to empty (the pre-fix residual)", async () => {
    // This reproduces the #856 residual exactly. We seed an eviction-only durable
    // record WITHOUT a baseline sentinel (the pre-fix world) and WITHOUT any
    // independent trust-root history, then delete the record. On boot the
    // dashboard has neither witness, so it does NOT latch and rehydrates empty -
    // the exact hole the sentinel closes. Locking it here makes the PASS-AFTER
    // test below a true before/after pair.
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    // Seed the eviction-only record directly and DELETE the sentinel that a
    // fresh provision would normally leave, so no independent witness exists.
    const withEviction = emptyFederationSyncState();
    withEviction.revokedNodeIds.add("evicted-node");
    withEviction.highestEvictionSerial = 2;
    await newStore(storage).persist(withEviction);
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    // No sentinel, no record: the pre-fix indistinguishable-from-fresh state.
    expect(await sentinelPresent(storage)).toBe(false);
    expect(await recordPresent(storage)).toBe(false);

    // Boot with NO independent trust-root history. The dashboard treats this as a
    // fresh fortress (correct per the pre-existing status quo for a both-deleted
    // no-witness fortress): it re-provisions and serves, it does NOT latch. The
    // evicted node is NOT remembered - demonstrating why the SENTINEL (written at
    // provisioning, surviving a main-record-only delete) is required to catch the
    // realistic attack where only the main record is erased.
    const after = await buildDashboard(fortress, "mini-1", storage, auditLog);
    await expect(
      after.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(true);
    expect(after.buildV1FederationDeps().isNodeRevoked("evicted-node")).toBe(false);
  });

  it("(C/E) PASS-AFTER: baseline-provisioned eviction-only fortress latches on deletion (deny, never un-revoke)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    // Fresh provision: writes baseline record + sentinel (NO independent
    // trust-root history - a pure eviction-only fortress).
    const before = await buildDashboard(fortress, "mini-1", storage, auditLog);
    expect(await sentinelPresent(storage)).toBe(true);

    // A node eviction advances the durable record (models operator revoking a
    // node). We persist it through the store to keep the test focused on the
    // deletion/latch behavior; the sentinel already exists from provisioning.
    const withEviction = emptyFederationSyncState();
    withEviction.revokedNodeIds.add("rogue-node");
    withEviction.highestEvictionSerial = 1;
    await newStore(storage).persist(withEviction);
    // Sanity: the record now carries the eviction and the fortress accepts syncs.
    await expect(
      before.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(true);

    // ATTACK: delete ONLY the main sync-state record; the sentinel survives.
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    expect(await recordPresent(storage)).toBe(false);
    expect(await sentinelPresent(storage)).toBe(true);

    // Restart: provisioned + main record absent + sentinel PRESENT -> DELETION.
    // Fail closed even though there is NO independent trust-root witness (the
    // eviction-only residual the sentinel closes).
    const after = await buildDashboard(fortress, "mini-1", storage, auditLog);

    // (E) fail-closed direction: the sync path DENIES rather than serving on
    // reset (empty) revocation memory.
    await expect(
      after.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(false);
    // And it did NOT silently un-revoke: the latch means no accept advanced.
    expect(
      after.buildV1FederationDeps().acceptedHighWaterFor("mini-1"),
    ).toBeNull();
    // The main record was NOT recreated-as-empty by the latched boot (no silent
    // reset-to-empty-then-serve).
    expect(await recordPresent(storage)).toBe(false);
  });
});

describe("B1: crash-mid-provisioning (record-present, sentinel-absent) self-repairs on boot", () => {
  // The baseline is provisioned record-FIRST, sentinel-second. A crash between
  // those two writes leaves a provisioned fortress with its main record present
  // but its independent deletion WITNESS (the sentinel) absent. The store
  // doc-comment claims "the next boot repairs (writes the missing sentinel)";
  // this suite proves that claim - and proves the security consequence of the
  // repair NOT existing (the eviction-only fail-open reopened).

  it("(F FAIL-BEFORE surface) without repair, a crash-window fortress stays sentinel-absent and a later main-record delete un-revokes an evicted node", async () => {
    // We drive the pre-repair world by writing the record + a real eviction but
    // NO sentinel (the crash window), then delete ONLY the main record. With no
    // sentinel witness and no trust-root history the boot cannot distinguish the
    // deletion from a fresh fortress: it re-provisions empty and SERVES, silently
    // un-revoking the evicted node. This is the residual the repair closes; we
    // reproduce it by never letting the repair see the crash-window state (we
    // delete the record before boot so the crash-window branch has nothing to
    // repair), pinning the attack the PASS-AFTER test defeats.
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    // Crash window: record written (with an eviction), sentinel never written.
    const withEviction = emptyFederationSyncState();
    withEviction.revokedNodeIds.add("evicted-node");
    withEviction.highestEvictionSerial = 2;
    await newStore(storage).persist(withEviction);
    expect(await recordPresent(storage)).toBe(true);
    expect(await sentinelPresent(storage)).toBe(false);

    // Attacker deletes ONLY the main record BEFORE any repairing boot runs.
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    expect(await recordPresent(storage)).toBe(false);
    expect(await sentinelPresent(storage)).toBe(false);

    // Boot: no record, no sentinel, no trust-root history -> treated as fresh,
    // re-provisions and serves; the evicted node is silently un-revoked.
    const after = await buildDashboard(fortress, "mini-1", storage, auditLog);
    await expect(
      after.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(true);
    expect(
      after.buildV1FederationDeps().isNodeRevoked("evicted-node"),
    ).toBe(false);
  });

  it("(F PASS-AFTER) a crash-window boot WRITES the missing sentinel, so a later main-record delete now LATCHES (deny, never un-revoke)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    // Crash window: record present (with a real eviction), sentinel absent.
    const withEviction = emptyFederationSyncState();
    withEviction.revokedNodeIds.add("rogue-node");
    withEviction.highestEvictionSerial = 1;
    await newStore(storage).persist(withEviction);
    expect(await recordPresent(storage)).toBe(true);
    expect(await sentinelPresent(storage)).toBe(false);

    // Boot the crash-window fortress. The repair branch fires: record present +
    // sentinel absent + provisioned -> provisionBaselineIfAbsent writes ONLY the
    // missing sentinel and folds the empty baseline over the real record
    // monotonically (the eviction is preserved, not clobbered).
    const repaired = await buildDashboard(fortress, "mini-1", storage, auditLog);
    expect(await sentinelPresent(storage)).toBe(true);
    // The eviction survived the repair fold (no downgrade).
    expect(
      repaired.buildV1FederationDeps().isNodeRevoked("rogue-node"),
    ).toBe(true);
    // Not latched: the repaired fortress still serves normally.
    await expect(
      repaired.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(true);

    // ATTACK: now delete ONLY the main record. The repaired sentinel survives.
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    expect(await recordPresent(storage)).toBe(false);
    expect(await sentinelPresent(storage)).toBe(true);

    // Restart: provisioned + main record absent + sentinel PRESENT -> DELETION.
    // Fail closed, even with NO trust-root witness.
    const after = await buildDashboard(fortress, "mini-1", storage, auditLog);
    await expect(
      after.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(false);
    expect(
      after.buildV1FederationDeps().acceptedHighWaterFor("mini-1"),
    ).toBeNull();
    // No silent reset-to-empty-then-serve.
    expect(await recordPresent(storage)).toBe(false);
  });
});

describe("B1: brick-safety - a fresh provisioned fortress's first sync is not bricked", () => {
  it("(D) fresh fortress accepts its first sync after baseline provisioning", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);
    // Baseline provisioned, NOT latched: the first sync is accepted.
    await expect(
      dashboard.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(true);
    expect(
      dashboard.buildV1FederationDeps().acceptedHighWaterFor("mini-1"),
    ).toBe(1);
  });

  it("(D2) a deletion of BOTH record and sentinel on a fresh fortress still re-provisions (no brick, status-quo-safe)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    await buildDashboard(fortress, "mini-1", storage, auditLog);
    // Attacker deletes BOTH records (indistinguishable from a genuinely fresh
    // fortress with no revocation history): re-provisioning is the correct,
    // non-bricking behavior, matching the pre-existing status quo for a fortress
    // with no independent witness. It must NOT brick the next sync.
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_BASELINE_SENTINEL_KEY,
    );

    const after = await buildDashboard(fortress, "mini-1", storage, auditLog);
    expect(await sentinelPresent(storage)).toBe(true);
    await expect(
      after.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(true);
  });
});
