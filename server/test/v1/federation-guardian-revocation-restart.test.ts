/**
 * End-to-end restart survival + fail-closed rehydrate of the OPTIONAL M-of-N
 * guardian revocation requirement at the DASHBOARD seam.
 *
 * The whole point of item 6 ("no single person can kill the fleet") is that the
 * requirement must NOT evaporate on a reboot. These tests drive the live
 * `V1FederationDeps.requireGuardianRevocationSignOff` seam (the exact callback
 * the revoke handler consults) across a simulated restart:
 *
 *   (a) a configured requirement SURVIVES a restart: after rebuilding the
 *       dashboard over the same storage + master key, the hook still returns the
 *       requirement (with the SAME roster) rather than null;
 *   (b) an at-rest-TAMPERED persisted roster rehydrates FAIL-CLOSED: the hook
 *       returns the `{ unavailable: true }` sentinel (NOT null), so the revoke
 *       path refuses every revocation instead of dropping to single-operator
 *       kill;
 *   (c) with NO requirement persisted, the hook returns null (legacy
 *       single-operator revoke) after a restart.
 *
 * A "restart" is a NEW DashboardApprovalChannel over the SAME MemoryStorage +
 * master key, re-wired with the same FederationContext and a fresh
 * FederationSyncStateStore, exactly what the production boot path does.
 *
 * Real crypto: rosters are signed by the fortress master; nothing is mocked.
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
import { signMasterDisableAuthorization } from "../../src/v1/federation-guardian-disable-gate.js";
import { makeMultiNodeFortress, type MultiNodeFortress } from "./fed-materials.js";

type DepsAccess = DashboardApprovalChannel & {
  buildV1FederationDeps(): V1FederationDeps;
  _federationEnabled: boolean;
};

const MASTER_KEY = new Uint8Array(32).fill(13);
// A FIXED audit-log encryption key reused across every simulated "restart" (a
// real daemon derives its audit key from the PERSISTENT master, never a fresh
// random one). A per-restart random key would mint a NEW key each boot, so the
// post-restart audit read (now consulted by the §8 anti-rollback floor) would
// try to decrypt the PRIOR process's entries under the WRONG key and fail
// integrity -> the anti-rollback floor would fail TOWARD latch. That is a
// test-rig artifact, not a product defect (mirrors the AUDIT_KEY convention in
// federation-guardian-disable-gate.test.ts).
const AUDIT_KEY = new Uint8Array(32).fill(29);

async function buildDashboard(
  fortress: MultiNodeFortress,
  nodeId: string,
  storage: MemoryStorage,
): Promise<DepsAccess> {
  const auditLog = new AuditLog(storage, AUDIT_KEY);
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
  dashboard.setFederationContext(fortress.nodes[nodeId]!.context);
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

describe("guardian revocation requirement: restart survival at the dashboard seam", () => {
  it("(a) a configured requirement SURVIVES a restart (hook still enforces)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const roster = buildRoster(fortress, "mini-1");
    const requirement: GuardianRevocationRequirement = { roster };

    const before = await buildDashboard(fortress, "mini-1", storage);
    await before.setFederationGuardianRevocationRequirement(requirement);

    // Restart: fresh dashboard, same storage + master key + context.
    const after = await buildDashboard(fortress, "mini-1", storage);
    const state = after.buildV1FederationDeps().requireGuardianRevocationSignOff!();

    expect(state).not.toBeNull();
    expect(state).not.toHaveProperty("unavailable");
    const rehydrated = state as GuardianRevocationRequirement;
    expect(rehydrated.roster.master_signature).toBe(roster.master_signature);
    expect(rehydrated.roster.m).toBe(3);
  });

  it("(b) an at-rest-tampered roster rehydrates FAIL-CLOSED (unavailable sentinel, NOT null)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const roster = buildRoster(fortress, "mini-1");

    const before = await buildDashboard(fortress, "mini-1", storage);
    await before.setFederationGuardianRevocationRequirement({ roster });

    // Tamper the persisted roster in place: decrypt, mutate m, re-encrypt under
    // the same master key (models an attacker who can re-encrypt but cannot forge
    // the fortress-master signature). The rehydrate must reject the roster.
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const snapshot = await store.load();
    expect(snapshot.guardianRevocationRequirement).not.toBeNull();
    snapshot.guardianRevocationRequirement!.roster.m = 1; // signature no longer matches
    // Overwrite the record with the tampered-but-validly-encrypted snapshot.
    await storage.delete(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
    );
    await store.persist(snapshot);

    const after = await buildDashboard(fortress, "mini-1", storage);
    const state = after.buildV1FederationDeps().requireGuardianRevocationSignOff!();

    // Fail-closed: the sentinel, NOT null (which would drop to single-operator).
    expect(state).toEqual({ unavailable: true });
  });

  it("(c) with NO requirement persisted, the hook returns null after a restart", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();

    const before = await buildDashboard(fortress, "mini-1", storage);
    // Persist some state but never set a guardian requirement.
    await before.setFederationGuardianRevocationRequirement(null);

    const after = await buildDashboard(fortress, "mini-1", storage);
    const state = after.buildV1FederationDeps().requireGuardianRevocationSignOff!();

    expect(state).toBeNull();
  });
});

describe("guardian revocation requirement: enable/disable is loudly audited", () => {
  it("emits an audit event on BOTH enabling AND disabling (disable is not silent)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
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
    dashboard.setFederationContext(fortress.nodes["mini-1"]!.context);
    dashboard._federationEnabled = true;
    await dashboard.setFederationSyncStateStore(
      new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }),
    );

    const roster = buildRoster(fortress, "mini-1");
    // Enable (increase: operator-only, unchanged), then disable (decrease: F1
    // E1 now requires a disable-gate authorization - the fortress master key
    // is the top authority and can do this instantly).
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    const disableNonce = dashboard.nextFederationGuardianDisableNonce();
    const masterAuthorization = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce,
      intent: "disable",
      targetM: null,
      masterPrivateKey: fortress.nodes["mini-1"]!.context.getMasterPrivateKey!(),
    });
    await dashboard.setFederationGuardianRevocationRequirement(null, {
      masterAuthorization,
    });

    const { entries } = await auditLog.query({ layer: "l2", limit: 1000 });
    const ops = entries.map((e) => ({ operation: e.operation, result: e.result }));

    expect(ops).toContainEqual({
      operation: "federation_guardian_revocation_requirement_set",
      result: "success",
    });
    // The disable MUST be as loud as the enable: an explicit audit event.
    expect(ops).toContainEqual({
      operation: "federation_guardian_disable_master_authorized",
      result: "success",
    });
  });

  it("F1 E1: a disable attempted WITHOUT authorization is refused (the guard stays ON)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
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
    dashboard.setFederationContext(fortress.nodes["mini-1"]!.context);
    dashboard._federationEnabled = true;
    await dashboard.setFederationSyncStateStore(
      new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }),
    );

    const roster = buildRoster(fortress, "mini-1");
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

    const deps = dashboard.buildV1FederationDeps();
    const hook = deps.requireGuardianRevocationSignOff!();
    expect(hook).not.toBeNull();
    expect((hook as { unavailable?: boolean }).unavailable).not.toBe(true);

    const { entries } = await auditLog.query({ layer: "l2", limit: 1000 });
    const ops = entries.map((e) => e.operation);
    expect(ops).toContain("federation_guardian_disable_quorum_refused");
  });
});
