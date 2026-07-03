/**
 * Remediation of two Codex-audit findings on the merged #842 M-of-N guardian
 * revocation kill-path, driven at the live DASHBOARD seam:
 *
 *   FIX 1 (F2) - ATOMIC requirement mutation. setFederationGuardianRevocationRequirement
 *   mutates three live in-memory fields + emits the intent audit BEFORE it
 *   persists. If the persist THROWS, the live fields must ROLL BACK to their
 *   prior values (so in-memory == durable == the prior value) and a SECOND
 *   critical audit must record the rollback. Verified in BOTH directions:
 *     - ENABLE-then-persist-fail rolls back to the prior guard (stays as it was);
 *     - DISABLE-then-persist-fail rolls back to ENABLED (the guard stays ON, the
 *       safe direction).
 *
 *   FIX 2 (F3) - DELETED sync-state record fails closed on a provisioned fortress
 *   that carries INDEPENDENT evidence of prior revocation history, instead of
 *   silently rehydrating empty (which would un-revoke evicted nodes + drop the
 *   guardian requirement). Three cases:
 *     (i)   fresh fortress, no independent revocation history, no record -> serves
 *           empty, NO latch (never bricks the first sync);
 *     (ii)  provisioned fortress WITH independent revocation history + record
 *           DELETED -> latch: requireGuardianRevocationSignOff returns the
 *           `{ unavailable: true }` sentinel (fail closed);
 *     (iii) present-but-corrupt record still throws + latches (existing behavior
 *           preserved).
 *
 * Real crypto: rosters are fortress-master-signed; nothing is mocked except the
 * storage write failure injected for the atomicity tests.
 */

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { issueGuardianRoster } from "../../src/mesh/guardian/guardian-roster.js";
import type { GuardianIdentity, GuardianRoster } from "../../src/mesh/guardian/types.js";
import {
  FederationSyncStateStore,
  FEDERATION_SYNC_STATE_STORE_NAMESPACE,
  FEDERATION_SYNC_STATE_STORE_KEY,
} from "../../src/v1/federation-sync-state-store.js";
import type { V1FederationDeps } from "../../src/v1/federation.js";
import type { GuardianRevocationRequirement } from "../../src/v1/federation-revocation-guardian-gate.js";
import {
  signMasterDisableAuthorization,
  type GuardianDisableAuthorization,
} from "../../src/v1/federation-guardian-disable-gate.js";
import { makeMultiNodeFortress, type MultiNodeFortress } from "./fed-materials.js";

type DepsAccess = DashboardApprovalChannel & {
  buildV1FederationDeps(): V1FederationDeps;
  setFederationGuardianRevocationRequirement(
    r: GuardianRevocationRequirement | null,
    authorization?: GuardianDisableAuthorization | null,
  ): Promise<void>;
  nextFederationGuardianDisableNonce(): number;
  _federationEnabled: boolean;
};

const MASTER_KEY = new Uint8Array(32).fill(17);

/**
 * A MemoryStorage that throws on writes to the sync-state record once armed, so
 * boot/hydrate succeeds but a later persist fails (models a disk-full / IO fault
 * at exactly the persist step).
 */
class ArmedFailWriteStorage extends MemoryStorage {
  armed = false;
  override async write(ns: string, key: string, bytes: Uint8Array): Promise<void> {
    if (
      this.armed &&
      ns === FEDERATION_SYNC_STATE_STORE_NAMESPACE &&
      key === FEDERATION_SYNC_STATE_STORE_KEY
    ) {
      throw new Error("disk write failed");
    }
    return super.write(ns, key, bytes);
  }
}

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
  await dashboard.setFederationSyncStateStore(
    new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }),
  );
  return dashboard;
}

function buildRoster(fortress: MultiNodeFortress, nodeId: string): GuardianRoster {
  const guardians: GuardianIdentity[] = [];
  for (let i = 0; i < 5; i++) {
    const kp = generateKeypair();
    guardians.push({
      guardian_id: `guardian-${i}`,
      public_key: toBase64url(kp.publicKey),
      kind: "human",
      invited_at: new Date().toISOString(),
    });
  }
  return issueGuardianRoster({
    m: 3,
    n: 5,
    guardians,
    fortress_id: fortress.fortressId,
    version: 1,
    master_private_key: fortress.nodes[nodeId]!.context.getMasterPrivateKey!(),
  });
}

function signOff(dashboard: DepsAccess) {
  return dashboard.buildV1FederationDeps().requireGuardianRevocationSignOff!();
}

describe("F2: setFederationGuardianRevocationRequirement is atomic on persist failure", () => {
  it("ENABLE that fails to persist rolls back to the PRIOR (disabled) requirement", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new ArmedFailWriteStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));
    const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);

    // Prior state: no requirement (legacy single-operator, hook returns null).
    expect(signOff(dashboard)).toBeNull();

    // Arm the write failure, then attempt to ENABLE a requirement.
    storage.armed = true;
    const roster = buildRoster(fortress, "mini-1");
    await expect(
      dashboard.setFederationGuardianRevocationRequirement({ roster }),
    ).rejects.toThrow(/disk write failed/);

    // Live state rolled back to the PRIOR value (null), NOT the attempted enable.
    expect(signOff(dashboard)).toBeNull();

    // The trail shows BOTH the intent AND the rollback.
    const { entries } = await auditLog.query({ layer: "l2", limit: 1000 });
    const ops = entries.map((e) => ({ operation: e.operation, result: e.result }));
    expect(ops).toContainEqual({
      operation: "federation_guardian_revocation_requirement_set",
      result: "success",
    });
    expect(ops).toContainEqual({
      operation: "federation_guardian_revocation_requirement_persist_failed",
      result: "failure",
    });
  });

  it("DISABLE that fails to persist rolls back to ENABLED (the guard stays ON)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new ArmedFailWriteStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));
    const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);

    // First ENABLE succeeds and durably commits (unarmed).
    const roster = buildRoster(fortress, "mini-1");
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    const enabled = signOff(dashboard) as GuardianRevocationRequirement;
    expect(enabled).not.toBeNull();
    expect(enabled.roster.master_signature).toBe(roster.master_signature);

    // Now arm the failure and attempt to DISABLE (set null), authorized via
    // the master key (F1 E1: a decrease requires an authorization).
    storage.armed = true;
    const disableNonce = dashboard.nextFederationGuardianDisableNonce();
    const masterAuthorization = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce,
      intent: "disable",
      targetM: null,
      masterPrivateKey: fortress.nodes["mini-1"]!.context.getMasterPrivateKey!(),
    });
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, { masterAuthorization }),
    ).rejects.toThrow(/disk write failed/);

    // The guard stayed ON: the hook still returns the SAME enabled requirement,
    // never null. Disabling did not silently take effect in memory.
    const after = signOff(dashboard) as GuardianRevocationRequirement;
    expect(after).not.toBeNull();
    expect(after).not.toHaveProperty("unavailable");
    expect(after.roster.master_signature).toBe(roster.master_signature);

    // The rollback is loudly recorded.
    const { entries } = await auditLog.query({ layer: "l2", limit: 1000 });
    const ops = entries.map((e) => e.operation);
    expect(ops).toContain("federation_guardian_revocation_requirement_persist_failed");
  });

  it("the rolled-back generation does not advance past the last durable set", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new ArmedFailWriteStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));
    const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);

    const roster = buildRoster(fortress, "mini-1");
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // A failed set rolls the generation back, so a subsequent SUCCESSFUL set
    // still survives a restart (its generation is not silently pre-bumped).
    storage.armed = true;
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null),
    ).rejects.toThrow();
    storage.armed = false;

    // Re-pin succeeds and survives a restart (generation climbed correctly).
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    const restarted = await buildDashboard(fortress, "mini-1", storage, auditLog);
    const state = signOff(restarted) as GuardianRevocationRequirement;
    expect(state).not.toBeNull();
    expect(state).not.toHaveProperty("unavailable");
    expect(state.roster.master_signature).toBe(roster.master_signature);
  });
});

describe("F3: a DELETED sync-state record fails closed when provisioned with revocation history", () => {
  it("(i) fresh fortress, no revocation history, no record -> serves empty, NO latch", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));
    // No record ever written, no independent revocation history.
    const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);

    // The hook returns null (legacy single-operator), NOT the unavailable
    // sentinel: a fresh fortress is not treated as a deletion.
    expect(signOff(dashboard)).toBeNull();
    // And the fresh fortress can accept its first sync (persist works, no brick).
    await expect(
      dashboard.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(true);
  });

  it("(ii) provisioned + revocation history + record DELETED -> latch (unavailable sentinel)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    // Establish a requirement + a durable record on a fortress that ALSO carries
    // independent root-revocation history (a compromise rotate happened).
    const revokedRoot = toBase64url(randomBytes(32));
    const history = {
      revokedRootPubkeys: new Set([revokedRoot]),
      highestRevocationSerial: 1,
    };
    const roster = buildRoster(fortress, "mini-1");
    const before = await buildDashboard(
      fortress,
      "mini-1",
      storage,
      auditLog,
      history,
    );
    await before.setFederationGuardianRevocationRequirement({ roster });
    // Sanity: the record exists now.
    expect(
      await new FederationSyncStateStore({
        storage,
        masterKey: MASTER_KEY,
      }).recordExists(),
    ).toBe(true);

    // ATTACK: delete the sync-state blob out of band, then restart.
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    expect(
      await new FederationSyncStateStore({
        storage,
        masterKey: MASTER_KEY,
      }).recordExists(),
    ).toBe(false);

    // Restart: provisioned + independent revocation history + record absent ->
    // FAIL CLOSED. The guardian hook returns the unavailable sentinel, NOT null
    // (which would drop to single-operator kill on reset memory).
    const after = await buildDashboard(
      fortress,
      "mini-1",
      storage,
      auditLog,
      history,
    );
    expect(signOff(after)).toEqual({ unavailable: true });
    // And the sync paths deny rather than serve on empty anti-replay memory.
    await expect(
      after.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(false);
  });

  it("(ii-b) an operator persist after a deletion latch re-establishes + clears it", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));
    const history = {
      revokedRootPubkeys: new Set([toBase64url(randomBytes(32))]),
      highestRevocationSerial: 1,
    };
    const roster = buildRoster(fortress, "mini-1");

    const before = await buildDashboard(fortress, "mini-1", storage, auditLog, history);
    await before.setFederationGuardianRevocationRequirement({ roster });
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );

    const after = await buildDashboard(fortress, "mini-1", storage, auditLog, history);
    // Latched.
    expect(signOff(after)).toEqual({ unavailable: true });

    // The operator recovers by re-pinning: a successful persist re-establishes
    // the record and clears the latch (mirrors corrupt-record recovery).
    await after.setFederationGuardianRevocationRequirement({ roster });
    const recovered = signOff(after) as GuardianRevocationRequirement;
    expect(recovered).not.toBeNull();
    expect(recovered).not.toHaveProperty("unavailable");
    expect(recovered.roster.master_signature).toBe(roster.master_signature);
  });

  it("(iii) present-but-corrupt record still throws + latches (existing behavior preserved)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, randomBytes(32));

    // Seed a clean record, then corrupt the on-disk ciphertext in place.
    await new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }).persist({
      acceptedHighWater: new Map(),
      outboundHighWater: 0,
      revokedNodeIds: new Set(),
      highestEvictionSerial: 0,
      revokedRootPubkeys: new Set(),
      highestRevocationSerial: 0,
      operatorPolicy: null,
      appliedPolicyVersions: new Map(),
      guardianRevocationRequirement: null,
      guardianRevocationRequirementGeneration: 0,
    });
    const raw = await storage.read(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    const obj = JSON.parse(new TextDecoder().decode(raw!)) as { ct: string };
    obj.ct = obj.ct.slice(0, -2) + (obj.ct.endsWith("AA") ? "BB" : "AA");
    await storage.write(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
      new TextEncoder().encode(JSON.stringify(obj)),
    );

    // A present-but-corrupt record latches unavailable independent of any
    // revocation history (the record IS present, so the F3 absence check does
    // not even apply; the load-throws path fires).
    const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);
    expect(signOff(dashboard)).toEqual({ unavailable: true });
    await expect(
      dashboard.buildV1FederationDeps().recordAcceptedHighWater("mini-1", 1),
    ).resolves.toBe(false);
  });
});
