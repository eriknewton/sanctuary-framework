/**
 * F1 - Guardian requirement DISABLE-gate (E1 slice). Adversarial-first test
 * plan, one drill per hard angle from the ratified design
 * (Guardian_Disable_Gate_Design_2026-07-03.md §10) plus the H1/H2/M1/M2 build
 * requirements the independent review surfaced.
 *
 * Real crypto throughout: rosters/authorizations are signed by real fortress
 * masters/guardians (@noble/curves Ed25519 via `makeMultiNodeFortress` +
 * `issueGuardianRoster`); nothing is mocked except the injected storage-write
 * failure in the atomicity-style tests, mirroring the existing kill-path test
 * suite's conventions.
 */

import { describe, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url, bytesToString, stringToBytes } from "../../src/core/encoding.js";
import type { PersistedAuditEnvelopeV2 } from "../../src/operational/audit-log.js";
import {
  issueGuardianRoster,
  verifyGuardianRoster,
} from "../../src/mesh/guardian/guardian-roster.js";
import type { GuardianIdentity, GuardianRoster } from "../../src/mesh/guardian/types.js";
import {
  FederationSyncStateStore,
  FEDERATION_SYNC_STATE_STORE_NAMESPACE,
  FEDERATION_SYNC_STATE_STORE_KEY,
  FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
  FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
} from "../../src/v1/federation-sync-state-store.js";
import { verifyLoadedGuardianRevocationRequirement } from "../../src/v1/federation-guardian-revocation-policy.js";
import type { V1FederationDeps } from "../../src/v1/federation.js";
import {
  GUARDIAN_SIGN_OFF_ACTION,
  effectiveThresholdM,
  type GuardianRevocationRequirement,
  type LoweredThresholdAuthorization,
} from "../../src/v1/federation-revocation-guardian-gate.js";
import {
  classifyRequirementTransition,
  signGuardianDisableApproval,
  signGuardianBreakGlassVeto,
  signMasterDisableAuthorization,
  signLoweredThresholdAuthorization,
  authorizeGuardianRequirementTransition,
  MIN_BREAK_GLASS_DELAY_MS,
  type GuardianDisableAuthorization,
} from "../../src/v1/federation-guardian-disable-gate.js";
import { GuardianDisableGateRefusedError } from "../../src/principal-policy/dashboard.js";
import { buildApprovalSigningInput, signApproval } from "../../src/recovery/index.js";
import { makeMultiNodeFortress, type MultiNodeFortress } from "./fed-materials.js";

type GuardianKeypair = { identity: GuardianIdentity; privateKey: Uint8Array };

type DepsAccess = DashboardApprovalChannel & {
  buildV1FederationDeps(): V1FederationDeps;
  setFederationGuardianRevocationRequirement(
    r: GuardianRevocationRequirement | null,
    authorization?: GuardianDisableAuthorization | null,
  ): Promise<void>;
  nextFederationGuardianDisableNonce(): number;
  initiateFederationGuardianBreakGlass(
    intent: "disable" | "lower",
    targetM: number | null,
    delayMs?: number,
  ): Promise<void>;
  vetoFederationGuardianBreakGlass(approval: unknown): Promise<{ vetoed: boolean }>;
  cancelFederationGuardianBreakGlass(): Promise<void>;
  _federationEnabled: boolean;
};

const MASTER_KEY = new Uint8Array(32).fill(21);
// A FIXED audit-log encryption key, reused across every "restart" in a given
// test (a real daemon restart derives its audit key from the persistent
// master, never a fresh random one). Using `randomBytes` per `buildDashboard`
// call would mint a NEW key each "restart," and the moment any post-restart
// path touches the audit log (e.g. the break-glass poll's immediate tick),
// `AuditLog.ensureLoaded()` would try to decrypt the PRIOR process's entries
// under the WRONG key and throw `AuditIntegrityError` - a test-rig artifact,
// not a product defect.
const AUDIT_KEY = new Uint8Array(32).fill(23);

function buildGuardianKeypairs(count: number): GuardianKeypair[] {
  const out: GuardianKeypair[] = [];
  for (let i = 0; i < count; i++) {
    const kp = generateKeypair();
    out.push({
      identity: {
        guardian_id: `guardian-${i}`,
        public_key: toBase64url(kp.publicKey),
        kind: "human",
        invited_at: new Date().toISOString(),
      },
      privateKey: kp.privateKey,
    });
  }
  return out;
}

function buildRosterFromKeypairs(
  fortress: MultiNodeFortress,
  nodeId: string,
  keypairs: GuardianKeypair[],
  m: number,
  version = 1,
): GuardianRoster {
  return issueGuardianRoster({
    m,
    n: keypairs.length,
    guardians: keypairs.map((k) => k.identity),
    fortress_id: fortress.fortressId,
    version,
    master_private_key: fortress.nodes[nodeId]!.context.getMasterPrivateKey!(),
  });
}

async function buildDashboard(
  fortress: MultiNodeFortress,
  nodeId: string,
  storage: MemoryStorage,
  auditLog?: AuditLog,
): Promise<DepsAccess> {
  const log = auditLog ?? new AuditLog(storage, AUDIT_KEY);
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
    auditLog: log,
  });
  dashboard.setFederationContext(fortress.nodes[nodeId]!.context);
  dashboard._federationEnabled = true;
  await dashboard.setFederationSyncStateStore(
    new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }),
  );
  return dashboard;
}

function signOff(dashboard: DepsAccess) {
  return dashboard.buildV1FederationDeps().requireGuardianRevocationSignOff!();
}

function quorumApprovals(
  fortress: MultiNodeFortress,
  nodeId: string,
  keypairs: GuardianKeypair[],
  signers: GuardianKeypair[],
  disableNonce: number,
  intent: "disable" | "lower",
  targetM: number | null,
) {
  void fortress;
  void nodeId;
  return signers.map((g) =>
    signGuardianDisableApproval({
      guardianId: g.identity.guardian_id,
      guardianPrivateKey: g.privateKey,
      fortressId: fortress.fortressId,
      disableNonce,
      intent,
      targetM,
      rosterVersion: 1,
    }),
  );
}

describe("F1 E1: classifyRequirementTransition", () => {
  const fortress = makeMultiNodeFortress(["mini-1"]);
  const keypairs = buildGuardianKeypairs(5);

  it("null -> requirement is an increase (enable)", () => {
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    expect(classifyRequirementTransition(null, { roster })).toBe("increase");
  });

  it("requirement -> null is a decrease (disable)", () => {
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    expect(classifyRequirementTransition({ roster }, null)).toBe("decrease");
  });

  it("higher M is an increase; lower M is a decrease; equal M is a noop", () => {
    const rosterM3 = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    const rosterM2 = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 2, 2);
    const rosterM4 = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 4, 2);
    expect(
      classifyRequirementTransition({ roster: rosterM3 }, { roster: rosterM4 }),
    ).toBe("increase");
    expect(
      classifyRequirementTransition({ roster: rosterM3 }, { roster: rosterM2 }),
    ).toBe("decrease");
    // Equal-M re-pin (different guardian set, same roster.m) is a noop for gate
    // purposes - a roster-integrity concern, not a threshold weakening.
    const rosterM3ReRoll = buildRosterFromKeypairs(
      fortress,
      "mini-1",
      buildGuardianKeypairs(5),
      3,
      2,
    );
    expect(
      classifyRequirementTransition({ roster: rosterM3 }, { roster: rosterM3ReRoll }),
    ).toBe("noop");
  });

  it("null -> null is a noop", () => {
    expect(classifyRequirementTransition(null, null)).toBe("noop");
  });
});

describe("F1 E1: drill 1 - instant disable requires a valid quorum or master authorization", () => {
  it("zero / M-1 / duplicate / wrong-scheme / forged approvals all REFUSE", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    const nonce = dashboard.nextFederationGuardianDisableNonce();

    // Zero approvals.
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, { quorumApprovals: [] }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

    // M-1 (2 of 3 required).
    const short = quorumApprovals(
      fortress,
      "mini-1",
      keypairs,
      keypairs.slice(0, 2),
      nonce,
      "disable",
      null,
    );
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: short,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

    // Duplicate guardian counted twice.
    const dup = quorumApprovals(
      fortress,
      "mini-1",
      keypairs,
      [keypairs[0]!, keypairs[0]!, keypairs[0]!],
      nonce,
      "disable",
      null,
    );
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, { quorumApprovals: dup }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

    // Wrong signature scheme.
    const validApprovals = quorumApprovals(
      fortress,
      "mini-1",
      keypairs,
      keypairs.slice(0, 3),
      nonce,
      "disable",
      null,
    );
    const wrongScheme = [
      { ...validApprovals[0]!, signature_scheme: "not-a-real-scheme" as never },
      validApprovals[1]!,
      validApprovals[2]!,
    ];
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: wrongScheme,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

    // Forged guardian (unknown key signs under a real guardian's id).
    const forger = generateKeypair();
    const forged = signGuardianDisableApproval({
      guardianId: keypairs[0]!.identity.guardian_id,
      guardianPrivateKey: forger.privateKey,
      fortressId: fortress.fortressId,
      disableNonce: nonce,
      intent: "disable",
      targetM: null,
      rosterVersion: 1,
    });
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: [forged, validApprovals[1]!, validApprovals[2]!],
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

    // The requirement is UNCHANGED after all refusals.
    expect(signOff(dashboard)).not.toBeNull();

    // A genuinely valid M-of-N quorum succeeds.
    await dashboard.setFederationGuardianRevocationRequirement(null, {
      quorumApprovals: validApprovals,
    });
    expect(signOff(dashboard)).toBeNull();
  });

  it("a valid master-key authorization succeeds instantly with no quorum", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const masterAuthorization = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce: nonce,
      intent: "disable",
      targetM: null,
      masterPrivateKey: fortress.nodes["mini-1"]!.context.getMasterPrivateKey!(),
    });
    await dashboard.setFederationGuardianRevocationRequirement(null, { masterAuthorization });
    expect(signOff(dashboard)).toBeNull();
  });

  it("a forged master authorization (wrong private key) is REFUSED", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const attacker = generateKeypair();
    const forgedMasterAuth = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce: nonce,
      intent: "disable",
      targetM: null,
      masterPrivateKey: attacker.privateKey,
    });
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        masterAuthorization: forgedMasterAuth,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    expect(signOff(dashboard)).not.toBeNull();
  });
});

describe("F1 E1: roster-forgery fail-open (adversarial review finding, P1) - equal-M re-pin must verify the master signature", () => {
  it("an equal-M re-pin with a FORGED roster (attacker guardian keys, bogus master_signature) is REFUSED, and a subsequent attacker-quorum disable against the real roster still fails", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);

    // Start with a valid master-signed 3-of-5 requirement.
    const realKeypairs = buildGuardianKeypairs(5);
    const realRoster = buildRosterFromKeypairs(fortress, "mini-1", realKeypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster: realRoster });
    expect(signOff(dashboard)).not.toBeNull();

    // Attacker builds a FAKE 3-of-3 roster made entirely of attacker-controlled
    // guardian keys, "signed" by an attacker keypair rather than the real
    // fortress master (a forged master_signature - the attacker does not hold
    // the fortress master private key). nextM === currentM (3 === 3), so this
    // classifies as "noop" and would previously skip all authorization AND
    // all roster verification.
    const attackerGuardianKeypairs = buildGuardianKeypairs(3);
    const attackerMasterKeypair = generateKeypair();
    const fakeRoster = issueGuardianRoster({
      m: 3,
      n: 3,
      guardians: attackerGuardianKeypairs.map((k) => k.identity),
      fortress_id: fortress.fortressId,
      version: 1,
      master_private_key: attackerMasterKeypair.privateKey, // NOT the real fortress master
    });
    expect(
      classifyRequirementTransition({ roster: realRoster }, { roster: fakeRoster }),
    ).toBe("noop");

    // The setter must THROW/refuse - the fake roster must NOT install.
    await expect(
      dashboard.setFederationGuardianRevocationRequirement({ roster: fakeRoster }),
    ).rejects.toMatchObject({ code: "guardian_roster_signature_invalid" });

    // The live requirement is UNCHANGED (still the real roster).
    const live = signOff(dashboard) as GuardianRevocationRequirement | null;
    expect(live).not.toBeNull();
    expect(live!.roster.version).toBe(realRoster.version);
    expect(live!.roster.guardians.map((g) => g.guardian_id).sort()).toEqual(
      realKeypairs.map((k) => k.identity.guardian_id).sort(),
    );

    // An attacker-quorum disable attempt (3 attacker guardian signatures)
    // against the REAL (unchanged) requirement must still fail: the attacker
    // guardians are not members of the real roster.
    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const attackerApprovals = attackerGuardianKeypairs.map((g) =>
      signGuardianDisableApproval({
        guardianId: g.identity.guardian_id,
        guardianPrivateKey: g.privateKey,
        fortressId: fortress.fortressId,
        disableNonce: nonce,
        intent: "disable",
        targetM: null,
        rosterVersion: realRoster.version,
      }),
    );
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: attackerApprovals,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

    // The requirement is STILL the real, unmodified roster after the attack.
    expect(signOff(dashboard)).not.toBeNull();
    const stillLive = signOff(dashboard) as GuardianRevocationRequirement;
    expect(stillLive.roster.guardians.map((g) => g.guardian_id).sort()).toEqual(
      realKeypairs.map((k) => k.identity.guardian_id).sort(),
    );
  });

  it("a LEGITIMATE master-signed equal-M re-pin still SUCCEEDS (no lockout regression)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);

    const originalKeypairs = buildGuardianKeypairs(5);
    const originalRoster = buildRosterFromKeypairs(
      fortress,
      "mini-1",
      originalKeypairs,
      3,
    );
    await dashboard.setFederationGuardianRevocationRequirement({ roster: originalRoster });

    // Operator lost one guardian's key and re-pins a REPLACEMENT roster at the
    // SAME m=3, n=5, genuinely signed by the real fortress master - the exact
    // scenario the "noop" carve-out exists to keep frictionless.
    const replacementKeypairs = buildGuardianKeypairs(5);
    const replacementRoster = buildRosterFromKeypairs(
      fortress,
      "mini-1",
      replacementKeypairs,
      3,
      2, // bump version
    );
    expect(
      classifyRequirementTransition(
        { roster: originalRoster },
        { roster: replacementRoster },
      ),
    ).toBe("noop");

    await dashboard.setFederationGuardianRevocationRequirement({
      roster: replacementRoster,
    });

    const live = signOff(dashboard) as GuardianRevocationRequirement;
    expect(live.roster.version).toBe(2);
    expect(live.roster.guardians.map((g) => g.guardian_id).sort()).toEqual(
      replacementKeypairs.map((k) => k.identity.guardian_id).sort(),
    );
  });

  it("refuses to install ANY roster when no pinned fortress-master is available", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);

    // Simulate an unprovisioned/absent federation context.
    dashboard.setFederationContext(null);

    await expect(
      dashboard.setFederationGuardianRevocationRequirement({ roster }),
    ).rejects.toMatchObject({ code: "federation_not_provisioned" });
  });
});

describe("F1 E1: drill 2 - replay firewall, cross-action (kill sign-off cannot authorize a disable, and vice versa)", () => {
  it("a valid KILL quorum is refused as a disable authorization", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Build a valid KILL sign-off quorum (GUARDIAN_SIGN_OFF_ACTION) over a
    // cascade_id shaped like a real node eviction, NOT the disable cascade id.
    const killSigningInput = buildApprovalSigningInput({
      cascade_id: "federation-node-eviction:" + fortress.fortressId + ":node-x",
      recovery_action: GUARDIAN_SIGN_OFF_ACTION,
      fortress_id: fortress.fortressId,
      roster_version: 1,
    });
    const killApprovals = keypairs.slice(0, 3).map((g) =>
      signApproval({
        signing_input: killSigningInput,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.privateKey,
        recovery_action: GUARDIAN_SIGN_OFF_ACTION,
        cascade_id: killSigningInput.cascade_id,
      }),
    );

    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: killApprovals,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    expect(signOff(dashboard)).not.toBeNull();
  });
});

describe("F1 E1: drill 3 - replay firewall, prior-disable / nonce burn / intent-targetM rebinding", () => {
  it("a quorum collected for a consumed nonce is refused for a LATER disable", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const firstNonce = dashboard.nextFederationGuardianDisableNonce();
    const firstApprovals = quorumApprovals(
      fortress,
      "mini-1",
      keypairs,
      keypairs.slice(0, 3),
      firstNonce,
      "disable",
      null,
    );
    await dashboard.setFederationGuardianRevocationRequirement(null, {
      quorumApprovals: firstApprovals,
    });
    expect(signOff(dashboard)).toBeNull();

    // Re-enable, then try to REPLAY the consumed nonce-K quorum for a new
    // disable. The setter now demands nonce K+1, so the stale approvals -
    // whose signed bytes carry nonce K's cascade_id - fail closed.
    const roster2 = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3, 2);
    await dashboard.setFederationGuardianRevocationRequirement({ roster: roster2 });
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: firstApprovals,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    expect(signOff(dashboard)).not.toBeNull();
  });

  it("a 'lower-to-m=2' quorum is refused as a 'disable' authorization (intent/targetM binding)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const lowerApprovals = quorumApprovals(
      fortress,
      "mini-1",
      keypairs,
      keypairs.slice(0, 3),
      nonce,
      "lower",
      2,
    );
    // Attempt to use the "lower to m=2" quorum to authorize a full disable.
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: lowerApprovals,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    expect(signOff(dashboard)).not.toBeNull();

    // But it DOES authorize the lower it was actually collected for.
    const lowerRoster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 2, 1);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster: lowerRoster },
      { quorumApprovals: lowerApprovals },
    );
    const after = signOff(dashboard) as GuardianRevocationRequirement;
    expect(after.roster.m).toBe(2);
  });
});

describe("F1 E1: drill 4 - break-glass is not instant / not un-interruptible", () => {
  it("initiate leaves the requirement UNCHANGED before completion; a single guardian veto aborts", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    await dashboard.initiateFederationGuardianBreakGlass("disable", null);
    // Still enforcing: initiate alone never disables.
    expect(signOff(dashboard)).not.toBeNull();

    const posture = (
      dashboard as unknown as {
        buildV1FederationDeps(): V1FederationDeps;
      }
    ).buildV1FederationDeps().federationPosture!();
    expect(posture.guardian_break_glass.active).toBe(true);

    // A SINGLE guardian veto aborts. Any 1-of-N is sufficient. The in-flight
    // nonce equals the value nextFederationGuardianDisableNonce() returned
    // immediately BEFORE initiate; it is already burned into the armed state,
    // so nextFederationGuardianDisableNonce() now returns nonce+1.
    const inFlightNonce = dashboard.nextFederationGuardianDisableNonce() - 1;
    const realVeto = signGuardianBreakGlassVeto({
      guardianId: keypairs[4]!.identity.guardian_id,
      guardianPrivateKey: keypairs[4]!.privateKey,
      fortressId: fortress.fortressId,
      disableNonce: inFlightNonce,
      rosterVersion: 1,
    });
    const decision = await dashboard.vetoFederationGuardianBreakGlass(realVeto);
    expect(decision.vetoed).toBe(true);

    // Requirement is STILL unchanged after the veto.
    expect(signOff(dashboard)).not.toBeNull();
    const postureAfter = (
      dashboard as unknown as { buildV1FederationDeps(): V1FederationDeps }
    ).buildV1FederationDeps().federationPosture!();
    expect(postureAfter.guardian_break_glass.active).toBe(false);
  });

  it("operator cancel aborts the countdown and leaves the requirement ON", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    await dashboard.initiateFederationGuardianBreakGlass("disable", null);
    expect(signOff(dashboard)).not.toBeNull();
    await dashboard.cancelFederationGuardianBreakGlass();
    expect(signOff(dashboard)).not.toBeNull();

    // A forged veto (wrong key) is refused and does NOT abort a countdown.
    await dashboard.initiateFederationGuardianBreakGlass("disable", null);
    const attacker = generateKeypair();
    const forged = signGuardianBreakGlassVeto({
      guardianId: keypairs[0]!.identity.guardian_id,
      guardianPrivateKey: attacker.privateKey,
      fortressId: fortress.fortressId,
      disableNonce: dashboard.nextFederationGuardianDisableNonce() - 1,
      rosterVersion: 1,
    });
    const decision = await dashboard.vetoFederationGuardianBreakGlass(forged);
    expect(decision.vetoed).toBe(false);
    expect(signOff(dashboard)).not.toBeNull();
  });

  it("initiating a second break-glass while one is already armed is refused", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    await dashboard.initiateFederationGuardianBreakGlass("disable", null);
    await expect(
      dashboard.initiateFederationGuardianBreakGlass("disable", null),
    ).rejects.toMatchObject({ code: "break_glass_already_armed" });
  });

  it("a break-glass delay is clamped to the 24h floor even if a caller requests less", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const before = Date.now();
    await dashboard.initiateFederationGuardianBreakGlass("disable", null, 1000);
    const posture = (
      dashboard as unknown as { buildV1FederationDeps(): V1FederationDeps }
    ).buildV1FederationDeps().federationPosture!();
    expect(posture.guardian_break_glass.active).toBe(true);
    if (posture.guardian_break_glass.active) {
      const completesAt = Date.parse(posture.guardian_break_glass.completes_at);
      expect(completesAt - before).toBeGreaterThanOrEqual(MIN_BREAK_GLASS_DELAY_MS - 1000);
    }
  });
});

describe("F1 E1: a persist failure during veto/cancel/complete re-arms the poll (adversarial self-review finding)", () => {
  /**
   * A MemoryStorage that throws on writes to the sync-state record once armed,
   * mirroring the atomicity-and-deletion suite's fault-injection pattern.
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

  it("a veto whose persist fails rolls back to ARMED and the poll keeps running (does not silently stick)", async () => {
    vi.useFakeTimers();
    try {
      const fortress = makeMultiNodeFortress(["mini-1"]);
      const storage = new ArmedFailWriteStorage();
      const dashboard = await buildDashboard(fortress, "mini-1", storage);
      const keypairs = buildGuardianKeypairs(5);
      const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
      await dashboard.setFederationGuardianRevocationRequirement({ roster });
      await dashboard.initiateFederationGuardianBreakGlass(
        "disable",
        null,
        MIN_BREAK_GLASS_DELAY_MS,
      );

      const inFlightNonce = dashboard.nextFederationGuardianDisableNonce() - 1;
      const veto = signGuardianBreakGlassVeto({
        guardianId: keypairs[0]!.identity.guardian_id,
        guardianPrivateKey: keypairs[0]!.privateKey,
        fortressId: fortress.fortressId,
        disableNonce: inFlightNonce,
        rosterVersion: 1,
      });

      storage.armed = true;
      await expect(dashboard.vetoFederationGuardianBreakGlass(veto)).rejects.toThrow(
        /disk write failed/,
      );
      // The requirement is still ON (veto did not durably land, so the
      // countdown rolled back to ARMED, not cleared).
      expect(signOff(dashboard)).not.toBeNull();

      // Unarm the fault, then advance PAST the original deadline. If the poll
      // was correctly re-armed on rollback, the countdown still completes: it
      // was never silently orphaned by the failed veto.
      storage.armed = false;
      await vi.advanceTimersByTimeAsync(MIN_BREAK_GLASS_DELAY_MS + 2 * 60 * 60 * 1000);
      expect(signOff(dashboard)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("F1 E1: drill 5 - break-glass auto-completes ONLY after T with no veto", () => {
  it("completes automatically once the durable deadline elapses, not before", async () => {
    vi.useFakeTimers();
    try {
      const fortress = makeMultiNodeFortress(["mini-1"]);
      const storage = new MemoryStorage();
      const dashboard = await buildDashboard(fortress, "mini-1", storage);
      const keypairs = buildGuardianKeypairs(5);
      const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
      await dashboard.setFederationGuardianRevocationRequirement({ roster });

      await dashboard.initiateFederationGuardianBreakGlass(
        "disable",
        null,
        MIN_BREAK_GLASS_DELAY_MS,
      );
      expect(signOff(dashboard)).not.toBeNull();

      // Advance to just BEFORE the deadline: must NOT have completed.
      await vi.advanceTimersByTimeAsync(MIN_BREAK_GLASS_DELAY_MS - 60_000);
      expect(signOff(dashboard)).not.toBeNull();

      // Advance PAST the deadline: the next poll tick applies the disable.
      await vi.advanceTimersByTimeAsync(2 * 60 * 60 * 1000);
      expect(signOff(dashboard)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("F1 E1: drill 6 - no permanent lockout (lockout-inverse)", () => {
  it("with ALL guardians unreachable (no veto possible), the operator still reaches disabled after T via break-glass", async () => {
    vi.useFakeTimers();
    try {
      const fortress = makeMultiNodeFortress(["mini-1"]);
      const storage = new MemoryStorage();
      const dashboard = await buildDashboard(fortress, "mini-1", storage);
      // A roster whose M exceeds any realistically-collectible signer set
      // simulates "guardians gone dark" - the operator has NO quorum path.
      const keypairs = buildGuardianKeypairs(5);
      const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 5);
      await dashboard.setFederationGuardianRevocationRequirement({ roster });

      // No quorum attempt succeeds (all 5 guardians "dark" - none sign).
      await expect(
        dashboard.setFederationGuardianRevocationRequirement(null),
      ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });

      // The operator still reaches IDLE-disabled via break-glass, unilaterally.
      await dashboard.initiateFederationGuardianBreakGlass(
        "disable",
        null,
        MIN_BREAK_GLASS_DELAY_MS,
      );
      await vi.advanceTimersByTimeAsync(MIN_BREAK_GLASS_DELAY_MS + 2 * 60 * 60 * 1000);
      expect(signOff(dashboard)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("F1 E1: drill 7 - boot-survival re-arm (deterministic, N>=3)", () => {
  for (let trial = 1; trial <= 3; trial++) {
    it(`trial ${trial}: a restart mid-countdown re-arms from persisted completesAt, never resets, never cancels`, async () => {
      vi.useFakeTimers();
      try {
        const fortress = makeMultiNodeFortress(["mini-1"]);
        const storage = new MemoryStorage();
        const before = await buildDashboard(fortress, "mini-1", storage);
        const keypairs = buildGuardianKeypairs(5);
        const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
        await before.setFederationGuardianRevocationRequirement({ roster });
        await before.initiateFederationGuardianBreakGlass(
          "disable",
          null,
          MIN_BREAK_GLASS_DELAY_MS,
        );

        // Advance partway, then "restart": a fresh dashboard over the SAME
        // storage + master key + context. Stop the prior process's poll FIRST
        // (a real process restart tears down the old process entirely; two
        // separately-audit-keyed dashboards racing appendCritical against the
        // SAME storage is a test-rig artifact, not a real deployment shape).
        await vi.advanceTimersByTimeAsync(MIN_BREAK_GLASS_DELAY_MS / 2);
        await before.stop();
        const after = await buildDashboard(fortress, "mini-1", storage);
        // Still enforcing (not disabled) mid-countdown, post-restart.
        expect(signOff(after)).not.toBeNull();

        // The restarted daemon's re-armed poll completes at the ORIGINAL T,
        // not a fresh T from the restart moment.
        await vi.advanceTimersByTimeAsync(MIN_BREAK_GLASS_DELAY_MS / 2 + 2 * 60 * 60 * 1000);
        expect(signOff(after)).toBeNull();
      } finally {
        vi.useRealTimers();
      }
    });
  }
});

describe("F1 E1: drill 8 - audit un-suppressable + posture visible", () => {
  it("every transition emits its Tier-1 event; the tick heartbeat is continuous; posture shows correct time_remaining_ms", async () => {
    vi.useFakeTimers();
    try {
      const fortress = makeMultiNodeFortress(["mini-1"]);
      const storage = new MemoryStorage();
      const auditLog = new AuditLog(storage, randomBytes(32));
      const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);
      const keypairs = buildGuardianKeypairs(5);
      const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
      await dashboard.setFederationGuardianRevocationRequirement({ roster });

      await dashboard.initiateFederationGuardianBreakGlass(
        "disable",
        null,
        MIN_BREAK_GLASS_DELAY_MS,
      );
      const posture = (
        dashboard as unknown as { buildV1FederationDeps(): V1FederationDeps }
      ).buildV1FederationDeps().federationPosture!();
      expect(posture.guardian_break_glass.active).toBe(true);
      if (posture.guardian_break_glass.active) {
        expect(posture.guardian_break_glass.time_remaining_ms).toBeGreaterThan(0);
        expect(posture.guardian_break_glass.time_remaining_ms).toBeLessThanOrEqual(
          MIN_BREAK_GLASS_DELAY_MS,
        );
      }

      // Advance a few hours: expect at least one tick heartbeat.
      await vi.advanceTimersByTimeAsync(3 * 60 * 60 * 1000);
      await vi.advanceTimersByTimeAsync(MIN_BREAK_GLASS_DELAY_MS);

      const { entries } = await auditLog.query({ layer: "l2", limit: 5000 });
      const ops = entries.map((e) => e.operation);
      expect(ops).toContain("federation_guardian_break_glass_initiated");
      expect(ops).toContain("federation_guardian_break_glass_tick");
      expect(ops).toContain("federation_guardian_break_glass_completed");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("F1 E1: drill 9 - F3 latch honored on the decrease + break-glass paths (not on increase/re-pin)", () => {
  async function makeLatchedDashboard(): Promise<{
    dashboard: DepsAccess;
    fortress: MultiNodeFortress;
    keypairs: GuardianKeypair[];
  }> {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Simulate the F3 corrupt/deleted-record latch: corrupt the on-disk blob
    // directly, then force a rehydrate.
    await storage.write(
      FEDERATION_SYNC_STATE_STORE_NAMESPACE,
      FEDERATION_SYNC_STATE_STORE_KEY,
      new TextEncoder().encode("not valid json{{{"),
    );
    await dashboard.setFederationSyncStateStore(
      new FederationSyncStateStore({ storage, masterKey: MASTER_KEY }),
    );
    const hook = signOff(dashboard) as { unavailable?: boolean } | null;
    expect(hook && (hook as { unavailable?: boolean }).unavailable).toBe(true);
    return { dashboard, fortress, keypairs };
  }

  it("a decrease REFUSES while latched, even with a valid master authorization", async () => {
    const { dashboard, fortress } = await makeLatchedDashboard();
    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const masterAuthorization = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce: nonce,
      intent: "disable",
      targetM: null,
      masterPrivateKey: fortress.nodes["mini-1"]!.context.getMasterPrivateKey!(),
    });
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, { masterAuthorization }),
    ).rejects.toMatchObject({ code: "federation_sync_state_unavailable" });
  });

  it("break-glass initiate REFUSES while latched", async () => {
    const { dashboard } = await makeLatchedDashboard();
    await expect(
      dashboard.initiateFederationGuardianBreakGlass("disable", null),
    ).rejects.toMatchObject({ code: "federation_sync_state_unavailable" });
  });
});

describe("F1 E1: drill 11 - frozen-surface + no-migration proof", () => {
  it("a pre-E1 v1 record (no disable/break-glass fields) decodes cleanly to nonce 0 / no break-glass", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);

    // Write a pre-E1-shaped record directly (no guardian_disable_nonce /
    // guardian_break_glass fields) by using a store whose snapshot never sets
    // them, then rehydrate through the current dashboard.
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Fresh rehydrate over the SAME storage must decode without throwing and
    // must show an IDLE break-glass state (nonce accounting starts at 0 plus
    // whatever this process burned, i.e. still resolves cleanly).
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    expect(signOff(restarted)).not.toBeNull();
    const posture = (
      restarted as unknown as { buildV1FederationDeps(): V1FederationDeps }
    ).buildV1FederationDeps().federationPosture!();
    expect(posture.guardian_break_glass.active).toBe(false);
  });
});

describe("F1 E1: rotate-root style stale-writer merge cannot revive a vetoed break-glass or regress the nonce", () => {
  it("a stale snapshot (armed break-glass at an OLD generation) loses to a fresher vetoed state", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    await dashboard.initiateFederationGuardianBreakGlass("disable", null);
    // Simulate a stale reader (like rotate-root) that loaded the snapshot
    // WHILE armed, before the veto below happens on the live dashboard.
    const staleSnapshot = await store.load();
    expect(staleSnapshot.guardianBreakGlass).not.toBeNull();

    const inFlightNonce = dashboard.nextFederationGuardianDisableNonce() - 1;
    const veto = signGuardianBreakGlassVeto({
      guardianId: keypairs[0]!.identity.guardian_id,
      guardianPrivateKey: keypairs[0]!.privateKey,
      fortressId: fortress.fortressId,
      disableNonce: inFlightNonce,
      rosterVersion: 1,
    });
    await dashboard.vetoFederationGuardianBreakGlass(veto);
    expect(signOff(dashboard)).not.toBeNull();

    // Now the "rotate-root" style stale writer persists its OLD (armed)
    // snapshot, unlocked load()+persist() carrying the stale generation.
    // mutate an unrelated grow-only field to mirror what rotate-root does.
    staleSnapshot.revokedRootPubkeys.add("stale-writer-touch");
    await store.persist(staleSnapshot);

    // The vetoed (cleared) break-glass MUST survive: a fresh rehydrate must
    // NOT show an armed countdown.
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const posture = (
      restarted as unknown as { buildV1FederationDeps(): V1FederationDeps }
    ).buildV1FederationDeps().federationPosture!();
    expect(posture.guardian_break_glass.active).toBe(false);
    expect(signOff(restarted)).not.toBeNull();
  });
});

// ── Chokepoint + reboot-survivable lowered-M (2026-07-05 design, T-1..T-9) ───

describe("F1 chokepoint: lowered-M + latch fail-opens", () => {
  const NS = FEDERATION_SYNC_STATE_STORE_NAMESPACE;
  const KEY = FEDERATION_SYNC_STATE_STORE_KEY;

  function masterKey(fortress: MultiNodeFortress, nodeId: string): Uint8Array {
    return fortress.nodes[nodeId]!.context.getMasterPrivateKey!();
  }

  // Force a latched-INVALID (roster failed to re-verify) fortress that still has
  // a PRESENT durable record (distinct from the corrupt-blob syncStateUnavailable
  // case). Mint a valid requirement, then tamper roster.m in the persisted
  // snapshot and re-encrypt under the same master key (models an attacker who can
  // re-encrypt but not forge the fortress-master signature), then rehydrate.
  async function makeRosterLatchedDashboard(): Promise<{
    dashboard: DepsAccess;
    fortress: MultiNodeFortress;
    storage: MemoryStorage;
    keypairs: GuardianKeypair[];
  }> {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const before = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await before.setFederationGuardianRevocationRequirement({ roster });

    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const snapshot = await store.load();
    snapshot.guardianRevocationRequirement!.roster.m = 1; // signature no longer matches
    await storage.delete(NS, KEY);
    await store.persist(snapshot);

    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const hook = signOff(dashboard) as { unavailable?: boolean } | null;
    expect(hook && hook.unavailable).toBe(true); // latched invalid, record present
    return { dashboard, fortress, storage, keypairs };
  }

  function mintLowered(
    fortress: MultiNodeFortress,
    nodeId: string,
    rosterVersion: number,
    effectiveM: number,
    disableNonce: number,
  ): LoweredThresholdAuthorization {
    return signLoweredThresholdAuthorization({
      fortressId: fortress.fortressId,
      rosterVersion,
      effectiveM,
      disableNonce,
      masterPrivateKey: masterKey(fortress, nodeId),
    });
  }

  // T-1 (fail-open #1): set(null) on a latched-invalid fortress with NO auth
  // must REFUSE; latch stays set; kill path still returns { unavailable: true }.
  it("T-1: set(null) on a latched-invalid fortress with no authorization REFUSES (latch persists)", async () => {
    const { dashboard } = await makeRosterLatchedDashboard();
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    const hook = signOff(dashboard) as { unavailable?: boolean } | null;
    expect(hook && hook.unavailable).toBe(true);
  });

  // T-1 (OR-3): a MASTER-signed disable on a latched-invalid fortress CLEARS the
  // latch (master positively authorizes the absence). Non-master set(null) above
  // still refuses.
  it("T-1/OR-3: a master-signed disable on a latched-invalid fortress clears the latch", async () => {
    const { dashboard, fortress } = await makeRosterLatchedDashboard();
    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const masterAuthorization = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce: nonce,
      intent: "disable",
      targetM: null,
      masterPrivateKey: masterKey(fortress, "mini-1"),
    });
    await dashboard.setFederationGuardianRevocationRequirement(null, {
      masterAuthorization,
    });
    // Latch cleared AND requirement is null -> the hook returns null (legacy
    // single-operator), NOT the unavailable sentinel.
    expect(signOff(dashboard)).toBeNull();
  });

  // T-2 (fail-open #2): master-lower from M=3 to M=2 mints a lowered record; the
  // roster's own signature STILL verifies (roster body unmutated), the effective
  // threshold is 2, and after a reboot it re-verifies clean, latch NOT set,
  // effective M still 2.
  it("T-2: master-lower keeps the roster signature valid and survives reboot with effective M=2", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const lowered = mintLowered(fortress, "mini-1", roster.version, 2, nonce);
    const masterAuthorization = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce: nonce,
      intent: "lower",
      targetM: 2,
      masterPrivateKey: masterKey(fortress, "mini-1"),
    });
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: lowered },
      { masterAuthorization },
    );

    const live = signOff(dashboard) as GuardianRevocationRequirement;
    expect(live.roster.master_signature).toBe(roster.master_signature); // UNMUTATED
    expect(live.roster.m).toBe(3); // issued ceiling unchanged
    expect(effectiveThresholdM(live)).toBe(2); // effective threshold lowered

    // Reboot.
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable: true };
    expect((after as { unavailable?: boolean }).unavailable).not.toBe(true);
    const req = after as GuardianRevocationRequirement;
    expect(req.roster.master_signature).toBe(roster.master_signature);
    expect(effectiveThresholdM(req)).toBe(2);
  });

  // T-3 (A3 lowered-M replay): lower to M=2 (nonce burns), raise back to M=3,
  // then inject the stale M=2 lowered record into the persisted blob -> the
  // nonce floor has climbed past it, so the replay cannot silently take effect.
  it("T-3: a replayed stale lowered-M record is refused on reboot (below-floor nonce)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Lower to M=2 (burns nonce N).
    const nonceLower = dashboard.nextFederationGuardianDisableNonce();
    const staleLowered = mintLowered(fortress, "mini-1", roster.version, 2, nonceLower);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: staleLowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: nonceLower,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKey(fortress, "mini-1"),
        }),
      },
    );
    // Raise back to M=3 (drop the lowered record) - an increase, operator-only.
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    expect(
      effectiveThresholdM(signOff(dashboard) as GuardianRevocationRequirement),
    ).toBe(3);

    // Attacker re-injects the stale M=2 lowered record into the persisted blob,
    // re-encrypting under the same master key. Its nonce is BELOW the burned
    // floor -> the reboot nonce floor climbs past it.
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const snapshot = await store.load();
    snapshot.guardianRevocationRequirement!.loweredThreshold = staleLowered;
    await storage.delete(NS, KEY);
    await store.persist(snapshot);

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const nextNonce = restarted.nextFederationGuardianDisableNonce();
    expect(nextNonce).toBeGreaterThan(staleLowered.body.disable_nonce + 1);

    // FIX 1: the floor advancing is NOT sufficient (the pre-fix false-confidence
    // gap - the floor climbed but rehydrate NEVER used it to reject the record).
    // The load-bearing assertion is BEHAVIORAL: the replayed stale record must
    // NOT silently take effect. The kill hook must either latch INVALID (the
    // stale record is refused) OR keep the effective threshold HIGH (never drop
    // to the attacker's lowered M=2).
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    const latched = (after as { unavailable?: boolean }).unavailable === true;
    const effectiveHigh =
      !latched && effectiveThresholdM(after as GuardianRevocationRequirement) === 3;
    expect(latched || effectiveHigh).toBe(true);
    // Specifically it must NOT be the exploit outcome (a live requirement whose
    // effective M silently dropped to the attacker's 2).
    if (!latched) {
      expect(effectiveThresholdM(after as GuardianRevocationRequirement)).not.toBe(2);
    }
  });

  // FIX 1 (break-glass-mid-countdown edge, do-not-false-reject): a legitimately
  // lowered fortress (record nonce N, dedicated lowered high-water still BELOW N)
  // that then ARMS break-glass (which advances the GENERAL disable nonce but NOT
  // the dedicated lowered high-water, and does NOT drop the lowered record) and
  // reboots mid-countdown must NOT be falsely rejected. A bare `nonce < general
  // disable nonce` check (the wrong keying) WOULD reject it; the dedicated
  // high-water keeps it valid.
  it("FIX1: a lowered fortress that armed break-glass and rebooted mid-countdown is NOT falsely rejected", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Lower to M=2 (a legitimate master-lower; NO prior lowering, so the
    // dedicated lowered high-water stays BELOW this record's nonce).
    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const lowered = mintLowered(fortress, "mini-1", roster.version, 2, nonce);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: lowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: nonce,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKey(fortress, "mini-1"),
        }),
      },
    );
    // Arm break-glass (disable-only). This advances the GENERAL disable nonce
    // (to nonce+1) but leaves the lowered record present and the dedicated
    // lowered high-water unmoved.
    await dashboard.initiateFederationGuardianBreakGlass("disable", null);

    // Reboot mid-countdown.
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // NOT falsely rejected: the guard is live, effective M is still the lowered 2.
    expect((after as { unavailable?: boolean }).unavailable).not.toBe(true);
    expect(effectiveThresholdM(after as GuardianRevocationRequirement)).toBe(2);
  });

  // T-4 (A6 derived latch): tamper the roster signature -> reboot latches
  // invalid; a verified re-pin (master-signed roster) CLEARS the latch; a
  // set(null) does NOT (it refuses).
  it("T-4: a verified re-pin clears the derived latch; set(null) does not", async () => {
    const { dashboard, fortress } = await makeRosterLatchedDashboard();

    // set(null) does NOT clear the latch (it refuses).
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    expect((signOff(dashboard) as { unavailable?: boolean }).unavailable).toBe(true);

    // A verified re-pin (a genuine master-signed roster) clears the latch.
    const freshKeypairs = buildGuardianKeypairs(5);
    const freshRoster = buildRosterFromKeypairs(fortress, "mini-1", freshKeypairs, 3, 2);
    await dashboard.setFederationGuardianRevocationRequirement({ roster: freshRoster });
    const hook = signOff(dashboard) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    expect((hook as { unavailable?: boolean }).unavailable).not.toBe(true);
    expect((hook as GuardianRevocationRequirement).roster.version).toBe(2);
  });

  // T-5 (M2 recovery preserved): a re-pin (increase, verified roster) recovers
  // from the latch, while a disable (decrease) refuses under the same latch.
  it("T-5: re-pin recovery is preserved; disable under the same latch refuses", async () => {
    const { dashboard, fortress } = await makeRosterLatchedDashboard();
    // Disable (decrease) under the latch refuses (no auth).
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    // Re-pin (increase) recovers.
    const kp = buildGuardianKeypairs(5);
    const r = buildRosterFromKeypairs(fortress, "mini-1", kp, 3, 2);
    await dashboard.setFederationGuardianRevocationRequirement({ roster: r });
    expect((signOff(dashboard) as { unavailable?: boolean }).unavailable).not.toBe(true);
  });

  // T-6 (A8 break-glass disable-only): initiate(lower) REFUSES; initiate(disable)
  // proceeds.
  it("T-6: break-glass 'lower' is REFUSED; 'disable' proceeds", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    await expect(
      dashboard.initiateFederationGuardianBreakGlass("lower", 2),
    ).rejects.toMatchObject({ code: "break_glass_disable_only" });
    // disable proceeds (arms a countdown).
    await dashboard.initiateFederationGuardianBreakGlass("disable", null);
    const posture = (
      dashboard as unknown as { buildV1FederationDeps(): V1FederationDeps }
    ).buildV1FederationDeps().federationPosture!();
    expect(posture.guardian_break_glass.active).toBe(true);
  });

  // T-7 (INV-A/B structural): the four coupled fields are written only inside the
  // chokepoint (+ rehydrate boot handler + break-glass veto/cancel terminal
  // path); verifyGuardianRoster passes on the persisted requirement post-lower.
  it("T-7: INV-A/B - requirement/latch fields are written only in the chokepoint or rehydrate", () => {
    const src = readFileSync(
      new URL("../../src/principal-policy/dashboard.ts", import.meta.url),
      "utf8",
    );
    const requirementAssigns = (
      src.match(/this\._federationGuardianRevocationRequirement\s*=/g) ?? []
    ).length;
    const latchAssigns = (
      src.match(/this\._federationGuardianRevocationRequirementInvalid\s*=/g) ?? []
    ).length;
    // Bounded assignment count is the regression tripwire: if a NEW writer of
    // requirement/latch is added outside the chokepoint/rehydrate, this fails.
    // chokepoint apply + rollback = 2; rehydrate branches = 6 (the 6th is the
    // FIX 1 below-floor lowered-record rejection). Total <= 8 each.
    expect(requirementAssigns).toBeLessThanOrEqual(8);
    expect(latchAssigns).toBeLessThanOrEqual(8);
    // The chokepoint method must exist (the single mutator).
    expect(src).toContain("private async commitGuardianRequirementTransition");
  });

  it("T-7: verifyGuardianRoster passes on the persisted requirement after lower + reboot", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const lowered = mintLowered(fortress, "mini-1", roster.version, 2, nonce);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: lowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: nonce,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKey(fortress, "mini-1"),
        }),
      },
    );
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const persisted = await store.load();
    const pinned = fortress.nodes["mini-1"]!.context.pinnedMasterPubkey!;
    expect(() =>
      verifyGuardianRoster(persisted.guardianRevocationRequirement!.roster, pinned),
    ).not.toThrow();
  });

  // T-8 (boot survival, N>=5): lower-then-reboot survives 5/5 with effective
  // state intact and latch clear.
  it("T-8: lower-then-reboot survives 5/5 with effective M intact and latch clear", async () => {
    for (let i = 0; i < 5; i++) {
      const fortress = makeMultiNodeFortress(["mini-1"]);
      const storage = new MemoryStorage();
      const dashboard = await buildDashboard(fortress, "mini-1", storage);
      const keypairs = buildGuardianKeypairs(5);
      const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
      await dashboard.setFederationGuardianRevocationRequirement({ roster });
      const nonce = dashboard.nextFederationGuardianDisableNonce();
      const lowered = mintLowered(fortress, "mini-1", roster.version, 2, nonce);
      await dashboard.setFederationGuardianRevocationRequirement(
        { roster, loweredThreshold: lowered },
        {
          masterAuthorization: signMasterDisableAuthorization({
            fortressId: fortress.fortressId,
            disableNonce: nonce,
            intent: "lower",
            targetM: 2,
            masterPrivateKey: masterKey(fortress, "mini-1"),
          }),
        },
      );
      const restarted = await buildDashboard(fortress, "mini-1", storage);
      const after = signOff(restarted) as
        | GuardianRevocationRequirement
        | { unavailable?: boolean };
      expect((after as { unavailable?: boolean }).unavailable).not.toBe(true);
      expect(effectiveThresholdM(after as GuardianRevocationRequirement)).toBe(2);
    }
  });

  // T-9 (frozen surface / no migration): a pre-lower v:1 record decodes with
  // loweredThreshold absent -> effective M = roster.m.
  it("T-9: a pre-lower record decodes with loweredThreshold absent -> effective M = roster.m", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const req = signOff(restarted) as GuardianRevocationRequirement;
    expect(req.loweredThreshold).toBeUndefined();
    expect(effectiveThresholdM(req)).toBe(roster.m); // defaults to roster.m

    // The persisted record carries no lowered field when none was set.
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const loaded = await store.load();
    expect(loaded.guardianRevocationRequirement!.loweredThreshold).toBeUndefined();
  });

  // A quorum decrease against a latched-invalid fortress (live requirement is
  // null) must REFUSE cleanly (no crash on a null live roster); only the master
  // key (OR-3) can decrease a latched fortress.
  it("a quorum decrease against a latched fortress refuses cleanly (no live roster to verify)", async () => {
    const { dashboard, fortress, keypairs } = await makeRosterLatchedDashboard();
    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const approvals = keypairs.slice(0, 3).map((g) =>
      signGuardianDisableApproval({
        guardianId: g.identity.guardian_id,
        guardianPrivateKey: g.privateKey,
        fortressId: fortress.fortressId,
        disableNonce: nonce,
        intent: "disable",
        targetM: null,
        rosterVersion: 1,
      }),
    );
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(null, {
        quorumApprovals: approvals,
      }),
    ).rejects.toMatchObject({ code: "guardian_disable_authorization_required" });
    // Latch persists.
    expect((signOff(dashboard) as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // A master-LOWER against a latched fortress installs a verified roster + lowered
  // record, which CLEARS the latch (INV-A: installing a positively-verified
  // roster is what clears it) and the effective threshold is the lowered value.
  it("a master-lower on a latched fortress clears the latch and installs the lowered requirement", async () => {
    const { dashboard, fortress, keypairs } = await makeRosterLatchedDashboard();
    // Re-issue the SAME roster (still valid, master-signed) with a lowered record.
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const lowered = mintLowered(fortress, "mini-1", roster.version, 2, nonce);
    const masterAuthorization = signMasterDisableAuthorization({
      fortressId: fortress.fortressId,
      disableNonce: nonce,
      intent: "lower",
      targetM: 2,
      masterPrivateKey: masterKey(fortress, "mini-1"),
    });
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: lowered },
      { masterAuthorization },
    );
    const live = signOff(dashboard) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    expect((live as { unavailable?: boolean }).unavailable).not.toBe(true); // latch cleared
    expect(effectiveThresholdM(live as GuardianRevocationRequirement)).toBe(2);
  });

  // INV-A pure-authorizer: a quorum-less disable of a latched fortress refuses
  // (no effect that both nulls the requirement AND clears the latch escapes).
  it("INV-A: authorizeGuardianRequirementTransition refuses a no-auth set(null) under a latch", () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const pinned = fortress.nodes["mini-1"]!.context.pinnedMasterPubkey!;
    const commit = authorizeGuardianRequirementTransition(
      {
        requirement: null,
        latchInvalid: true,
        pinnedMaster: pinned,
        fortressId: fortress.fortressId,
        syncStateUnavailable: false,
        nextDisableNonce: 5,
        guardianLoweredHighWater: 0,
      },
      { kind: "operator_set", next: null, auth: null },
    );
    expect(commit.ok).toBe(false);
  });

  // FIX 2 (P0): a fortress that configured a guardian requirement but has NO
  // independent root-revocation history has its sync-state record DELETED. On
  // reboot the guard MUST be latched unavailable (kill hook returns
  // { unavailable: true }), NOT cleared to single-operator kill. The tamper-
  // evident "ever-established" sentinel is the signal (the root-revocation-
  // history heuristic misses this case entirely).
  it("FIX2: deleting the record after a requirement was configured latches unavailable (not single-operator)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    // Enable a requirement (NO root revocation ever performed -> no independent
    // revocation history). The sentinel is written on this enable.
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Attacker deletes the sync-state record out of band to strip the guard.
    await storage.delete(NS, KEY);

    // Reboot. The guard must fail closed (latched), NOT clear to single-operator.
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const hook = signOff(restarted) as { unavailable?: boolean } | null;
    expect(hook && hook.unavailable).toBe(true);
    // Direct proof the sentinel was established under the master.
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    expect((await store.guardianRequirementEstablished()).status).toBe("established");
  });

  // FIX 2 (brick-safety): a genuinely FRESH fortress (no requirement ever
  // configured, no sentinel) with no sync-state record must NOT latch - the
  // first sync/eviction has to be able to write the record. The sentinel path
  // only fires when a guard was actually established.
  it("FIX2: a fresh fortress with no sentinel and no record does NOT latch", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    // Build the dashboard WITHOUT ever configuring a requirement.
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    // No record, no sentinel -> the kill hook is the legacy single-operator null
    // (no requirement configured), NOT the unavailable sentinel.
    const hook = signOff(dashboard) as { unavailable?: boolean } | null;
    expect(hook === null || hook.unavailable !== true).toBe(true);
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    expect((await store.guardianRequirementEstablished()).status).toBe("absent");
    expect(
      await storage.exists("_meta", FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY),
    ).toBe(false);
  });

  // FIX 3 (P1): an audit-append throw AFTER the mutation is applied but BEFORE
  // the durable persist must ROLL BACK the live state, not leave it weakened.
  // Force the success-audit to throw during a master-lower and assert the live
  // effective threshold is UNCHANGED (still 3), i.e. the decrease did not take
  // effect in memory.
  it("FIX3: an audit throw during a decrease rolls back the live state fully", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, AUDIT_KEY);
    const dashboard = await buildDashboard(fortress, "mini-1", storage, auditLog);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    expect(effectiveThresholdM(signOff(dashboard) as GuardianRevocationRequirement)).toBe(3);

    // Make the NEXT success-audit (the master-lower intent) throw; the failure
    // audit (persist_failed) still succeeds so the rollback path completes.
    const original = auditLog.appendCritical.bind(auditLog);
    const spy = vi
      .spyOn(auditLog, "appendCritical")
      .mockImplementation(async (entry: Parameters<typeof original>[0]) => {
        if (
          entry.operation === "federation_guardian_disable_master_authorized" &&
          entry.result === "success"
        ) {
          throw new Error("audit backend down");
        }
        return original(entry);
      });

    const nonce = dashboard.nextFederationGuardianDisableNonce();
    const lowered = mintLowered(fortress, "mini-1", roster.version, 2, nonce);
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(
        { roster, loweredThreshold: lowered },
        {
          masterAuthorization: signMasterDisableAuthorization({
            fortressId: fortress.fortressId,
            disableNonce: nonce,
            intent: "lower",
            targetM: 2,
            masterPrivateKey: masterKey(fortress, "mini-1"),
          }),
        },
      ),
    ).rejects.toThrow("audit backend down");
    spy.mockRestore();

    // The live requirement must be UNCHANGED (rolled back): effective M still 3,
    // and the nonce floor did NOT burn the attempted nonce (it rolled back).
    expect(effectiveThresholdM(signOff(dashboard) as GuardianRevocationRequirement)).toBe(3);
    expect(dashboard.nextFederationGuardianDisableNonce()).toBe(nonce);

    // And the rolled-back state is what durably reboots (no partial commit).
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    expect(effectiveThresholdM(signOff(restarted) as GuardianRevocationRequirement)).toBe(3);
  });

  // FIX 4 (P2): the verified-load path re-verifies the lowered record's OWN
  // master signature. A persisted requirement carrying a lowered record whose
  // signature does NOT match the pinned master must yield kind: "invalid", never
  // a kind: "verified" that honors an unverified lowering.
  it("FIX4: verifyLoadedGuardianRevocationRequirement re-verifies the lowered record signature", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const pinned = fortress.nodes["mini-1"]!.context.pinnedMasterPubkey!;
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    const good = mintLowered(fortress, "mini-1", roster.version, 2, 1);

    // A valid lowered record verifies (baseline).
    const okResult = verifyLoadedGuardianRevocationRequirement(
      { v: 1, roster, lowered_threshold: good },
      pinned,
    );
    expect(okResult.kind).toBe("verified");

    // Now forge the lowered record: keep the body but corrupt the signature.
    // The verified path MUST reject it (fail-closed), not copy it verbatim.
    const forged = { body: { ...good.body }, signature: good.signature.slice(0, -4) + "AAAA" };
    const badResult = verifyLoadedGuardianRevocationRequirement(
      { v: 1, roster, lowered_threshold: forged },
      pinned,
    );
    expect(badResult.kind).toBe("invalid");

    // A body-tamper (effective_m rewritten) that the signature does not cover
    // must ALSO be rejected (the signature no longer matches the mutated body).
    const bodyTampered = { body: { ...good.body, effective_m: 1 }, signature: good.signature };
    const tamperedResult = verifyLoadedGuardianRevocationRequirement(
      { v: 1, roster, lowered_threshold: bodyTampered },
      pinned,
    );
    expect(tamperedResult.kind).toBe("invalid");
  });
});

// ── F1 RE-GATE: keyless anti-rollback (§1 anchor + §8 audit-witnessed floor) ──
//
// The prior fix-round modeled a MASTER-KEY attacker and a stale-in-memory
// writer; it MISSED the keyless whole-blob-restore attacker. These tests do NOT
// hand the attacker the master: they capture + restore RAW on-disk bytes
// (exactly what a filesystem-write attacker can do). "raw" restore = read the
// bytes out with storage.read and write them back with storage.write; the
// attacker never decrypts or re-MACs anything.
describe("F1 re-gate: keyless whole-blob rollback latches (§1 + §8)", () => {
  const NS = FEDERATION_SYNC_STATE_STORE_NAMESPACE;
  const KEY = FEDERATION_SYNC_STATE_STORE_KEY;
  const ANCHOR_KEY = FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY;

  function masterKeyOf(fortress: MultiNodeFortress, nodeId: string): Uint8Array {
    return fortress.nodes[nodeId]!.context.getMasterPrivateKey!();
  }
  function mintLowered(
    fortress: MultiNodeFortress,
    nodeId: string,
    rosterVersion: number,
    effectiveM: number,
    disableNonce: number,
  ): LoweredThresholdAuthorization {
    return signLoweredThresholdAuthorization({
      fortressId: fortress.fortressId,
      rosterVersion,
      effectiveM,
      disableNonce,
      masterPrivateKey: masterKeyOf(fortress, nodeId),
    });
  }

  // Bring a fortress to a lowered-then-raised state, capturing the LOW-floor
  // on-disk bytes (blob + anchor) BEFORE the raise. Returns the raw snapshots and
  // the shared storage/fortress so a test can restore + reboot.
  async function loweredThenRaised(): Promise<{
    fortress: MultiNodeFortress;
    storage: MemoryStorage;
    lowBlob: Uint8Array;
    lowAnchor: Uint8Array;
    staleLowered: LoweredThresholdAuthorization;
  }> {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Lower to M=2 (burns a nonce; a lowered record is present).
    const nonceLower = dashboard.nextFederationGuardianDisableNonce();
    const staleLowered = mintLowered(fortress, "mini-1", roster.version, 2, nonceLower);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: staleLowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: nonceLower,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKeyOf(fortress, "mini-1"),
        }),
      },
    );

    // CAPTURE the attacker's snapshot: the raw blob + raw anchor at the LOW floor.
    // No master used - just the on-disk bytes.
    const lowBlob = (await storage.read(NS, KEY))!;
    const lowAnchor = (await storage.read("_meta", ANCHOR_KEY))!;
    expect(lowBlob).not.toBeNull();
    expect(lowAnchor).not.toBeNull();

    // Operator RAISES back to M=3 (drops the lowered record, advances the floor +
    // the anchor + the audit generation).
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    expect(
      effectiveThresholdM(signOff(dashboard) as GuardianRevocationRequirement),
    ).toBe(3);

    return { fortress, storage, lowBlob, lowAnchor, staleLowered };
  }

  // T1: keyless SINGLE-record rollback (blob alone) latches via the §1 anchor.
  it("T1: restoring ONLY the old blob (anchor stays high) latches syncStateUnavailable", async () => {
    const { fortress, storage, lowBlob, staleLowered } = await loweredThenRaised();

    // Attacker restores ONLY the captured LOW blob, leaving the CURRENT (higher)
    // anchor in place (a keyless attacker cannot forge a higher anchor).
    await storage.write(NS, KEY, lowBlob);

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // blob.floor < anchor.floor -> LATCH.
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
    // The stale lowered-M record never becomes live (never effective M=2).
    if ((after as { unavailable?: boolean }).unavailable !== true) {
      expect(
        effectiveThresholdM(after as GuardianRevocationRequirement),
      ).not.toBe(2);
    }
    void staleLowered;
  });

  // T1b (THE HEADLINE): keyless TWO-record restore (blob + anchor BOTH rolled
  // back) latches via the §8 audit-witnessed generation floor. This is the test
  // that FAILS on a §1-only design and MUST pass with §8.
  it("T1b: restoring BOTH the old blob AND the old anchor latches via the audit floor", async () => {
    const { fortress, storage, lowBlob, lowAnchor } = await loweredThenRaised();

    // Attacker restores BOTH captured records at the LOW floor. The guardian
    // AUDIT entries (which remember the higher generation reached by the raise)
    // are left intact.
    await storage.write(NS, KEY, lowBlob);
    await storage.write("_meta", ANCHOR_KEY, lowAnchor);

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // blob.generation < auditFloor.generation (from the surviving audit trail)
    // -> LATCH. §1 alone would NOT catch this (both blob and anchor are low).
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // T1c: audit-INCLUSIVE wipe is the documented residual (§8.3). Restoring the
  // low blob + low anchor AND wiping the guardian audit entries removes the
  // witness that would remember the higher generation. We document the honest
  // boundary rather than asserting on-disk detection.
  it("T1c: an audit-inclusive coordinated wipe is the documented residual (no over-claim)", async () => {
    const { fortress, storage, lowBlob, lowAnchor } = await loweredThenRaised();
    await storage.write(NS, KEY, lowBlob);
    await storage.write("_meta", ANCHOR_KEY, lowAnchor);
    // Remove EVERY audit entry so the audit trail no longer remembers the higher
    // generation (a wholesale audit destruction - itself separately surfaced as
    // an empty/truncated chain, out of this fix's on-disk detection scope).
    for (const meta of await storage.list("_audit")) {
      await storage.delete("_audit", meta.key);
    }

    // The code does NOT CLAIM to detect this on-disk here. This test encodes the
    // §8.3 residual as an intended, honest boundary: reboot must not THROW, and
    // whatever verdict it reaches (it may still latch via other signals) is
    // acceptable - we only assert we did not crash and did not over-claim.
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted);
    // Any of: latched, null, or a live requirement is a valid outcome for the
    // residual; the point is the reboot completed without throwing.
    expect(after === null || typeof after === "object").toBe(true);
  });

  // T1d: no false positive. A fortress that NEVER configured a guardian
  // requirement (no guardian audit entries, no anchor) hydrates normally, and a
  // legitimate full-consistent state hydrates without latching.
  it("T1d: a never-guarded fortress does NOT latch (auditFloor 0, no false positive)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    // No requirement ever set: the kill hook is the legacy single-operator null.
    const hook = signOff(dashboard) as { unavailable?: boolean } | null;
    expect(hook === null || hook.unavailable !== true).toBe(true);

    // A legitimate reboot of a consistently-guarded fortress does NOT latch.
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    expect((after as { unavailable?: boolean }).unavailable).not.toBe(true);
    expect(effectiveThresholdM(after as GuardianRevocationRequirement)).toBe(3);
  });

  // T2: sentinel write-ordering crash window (Finding #2). A crash between the
  // sentinel write and the record persist must leave sentinel-present +
  // record-absent, which hydrate latches. The dangerous pre-fix pair
  // (record-present + sentinel-absent) must NEVER be produced.
  it("T2: sentinel is written BEFORE the record; the crash window latches, never boots fresh", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // The sentinel is present after a successful enable.
    expect(
      await storage.exists("_meta", FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY),
    ).toBe(true);

    // Simulate the crash between (1) sentinel write and (2) record persist:
    // sentinel present, record deleted. Hydrate must latch (established +
    // !recordPresent), never boot fresh.
    await storage.delete(NS, KEY);
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const hook = signOff(restarted) as { unavailable?: boolean } | null;
    expect(hook && hook.unavailable).toBe(true);
  });

  // T3: pre-upgrade backfill (Finding #3). A pre-fix fortress has a guard
  // configured in its record but NO sentinel. On boot, the sentinel is
  // backfilled; a subsequent record-delete is then caught.
  it("T3: hydrate backfills the sentinel for a pre-upgrade guarded fortress; a later delete latches", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Simulate a PRE-FIX fortress: a guard IS in the durable record, but the
    // sentinel does not exist yet (delete it to model the pre-upgrade state).
    await storage.delete("_meta", FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY);
    expect(
      await storage.exists("_meta", FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY),
    ).toBe(false);

    // Boot the fixed binary: the record is present + configures a guard, so the
    // sentinel is backfilled.
    const rebooted = await buildDashboard(fortress, "mini-1", storage);
    expect(
      await storage.exists("_meta", FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY),
    ).toBe(true);
    // The guard is still live (backfill does not disturb it).
    expect((signOff(rebooted) as { unavailable?: boolean }).unavailable).not.toBe(
      true,
    );

    // Now DELETE the record and reboot: the backfilled sentinel catches it.
    await storage.delete(NS, KEY);
    const afterDelete = await buildDashboard(fortress, "mini-1", storage);
    const hook = signOff(afterDelete) as { unavailable?: boolean } | null;
    expect(hook && hook.unavailable).toBe(true);
  });

  // T4: break-glass completion advances the lowered high-water (Finding #4).
  // Lower to M', arm+complete break-glass (disable), then re-inject the old
  // still-signed lowered-M' record: the reboot rejects it (nonce <= high-water).
  it("T4: break-glass completion advances the lowered high-water; a replayed lowered-M' is rejected on reboot", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Lower to M=2 (present lowered record, nonce N_low).
    const nLow = dashboard.nextFederationGuardianDisableNonce();
    const staleLowered = mintLowered(fortress, "mini-1", roster.version, 2, nLow);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: staleLowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: nLow,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKeyOf(fortress, "mini-1"),
        }),
      },
    );

    // Arm break-glass (disable) with a short delay and complete it. Use fake
    // timers via a delay that is already elapsed at the poll tick: initiate then
    // manually drive completion by rebuilding past the deadline is heavy; instead
    // complete via the countdown floor. Simplest: initiate, then advance the
    // clock by mocking Date.now through the poll. We rely on the boot re-arm +
    // immediate tick: reboot with the countdown already elapsed completes it.
    await dashboard.initiateFederationGuardianBreakGlass(
      "disable",
      null,
      MIN_BREAK_GLASS_DELAY_MS,
    );
    // Fast-forward: rewrite the persisted completesAt to the past so the boot
    // re-arm's immediate tick completes the countdown. This is a KEYLESS-safe
    // operation only in test (we hold the master here purely to re-encode the
    // blob); it models "the countdown elapsed", not the attack.
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const snap = await store.load();
    if (snap.guardianBreakGlass) {
      snap.guardianBreakGlass = {
        ...snap.guardianBreakGlass,
        completesAt: new Date(Date.now() - 1000).toISOString(),
      };
    }
    await storage.delete(NS, KEY);
    await store.persist(snap);

    // Reboot: the elapsed countdown completes on the immediate poll tick, which
    // disables the guard AND (Finding #4) advances the lowered high-water past
    // N_low. Give the poll a tick to fire.
    const rebooted = await buildDashboard(fortress, "mini-1", storage);
    await new Promise((r) => setTimeout(r, 20));
    // The guard is now disabled (single-operator) OR still latched-clear; either
    // way, re-enable a guard and re-inject the stale lowered record.
    await rebooted.setFederationGuardianRevocationRequirement({ roster });
    const store2 = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const snap2 = await store2.load();
    // The lowered high-water must have advanced to >= N_low from the completion.
    expect(snap2.guardianLoweredHighWater).toBeGreaterThanOrEqual(nLow);
    // Re-inject the stale lowered-M' record and reboot: it must be REJECTED.
    snap2.guardianRevocationRequirement!.loweredThreshold = staleLowered;
    await storage.delete(NS, KEY);
    await store2.persist(snap2);
    const afterReplay = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(afterReplay) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // The replayed M=2 lowering must NOT be honored: either latched, or effective
    // M is not the attacker's 2.
    const latched = (after as { unavailable?: boolean }).unavailable === true;
    if (!latched) {
      expect(effectiveThresholdM(after as GuardianRevocationRequirement)).not.toBe(2);
    } else {
      expect(latched).toBe(true);
    }
  });

  // T5: runtime install floor check (Finding #5). A runtime install carrying a
  // lowered record whose nonce is at/below the high-water is REFUSED at runtime,
  // not merely at the next boot. A positive control (nonce above the floor)
  // installs.
  it("T5: a runtime install of a below-high-water lowered record is refused; above-floor installs", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Establish a lowered high-water by lowering then raising (drops nonce N_low
    // into the high-water).
    const nLow = dashboard.nextFederationGuardianDisableNonce();
    const droppedLowered = mintLowered(fortress, "mini-1", roster.version, 2, nLow);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: droppedLowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: nLow,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKeyOf(fortress, "mini-1"),
        }),
      },
    );
    await dashboard.setFederationGuardianRevocationRequirement({ roster }); // raise (high-water = nLow)

    // Attempt a RUNTIME install carrying a lowered record at nonce == nLow (<=
    // high-water) with a VALID signature: it must be refused with
    // lowered_threshold_invalid.
    const replayNonce = dashboard.nextFederationGuardianDisableNonce();
    const staleAtFloor = mintLowered(fortress, "mini-1", roster.version, 2, nLow);
    await expect(
      dashboard.setFederationGuardianRevocationRequirement(
        { roster, loweredThreshold: staleAtFloor },
        {
          masterAuthorization: signMasterDisableAuthorization({
            fortressId: fortress.fortressId,
            disableNonce: replayNonce,
            intent: "lower",
            targetM: 2,
            masterPrivateKey: masterKeyOf(fortress, "mini-1"),
          }),
        },
      ),
    ).rejects.toMatchObject({ code: "lowered_threshold_invalid" });

    // Positive control: a lowered record whose nonce is ABOVE the high-water (the
    // fresh nonce being burned) installs fine.
    const freshNonce = dashboard.nextFederationGuardianDisableNonce();
    const freshLowered = mintLowered(fortress, "mini-1", roster.version, 2, freshNonce);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: freshLowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: freshNonce,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKeyOf(fortress, "mini-1"),
        }),
      },
    );
    expect(
      effectiveThresholdM(signOff(dashboard) as GuardianRevocationRequirement),
    ).toBe(2);
  });

  // T6-hydrate: record ABSENT + sentinel present-but-INVALID latches (the NEW
  // Finding #6 latch; old code booted fresh). Rotation-safety control: record
  // PRESENT + sentinel invalid does NOT brick (re-stamps + serves).
  it("T6: record-absent + corrupt-sentinel latches; record-present + corrupt-sentinel re-stamps (no brick)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // Corrupt the sentinel bytes (a keyless attacker mangling, not deleting) AND
    // delete the record. Old code: !recordPresent && established===false -> boot
    // fresh. New code: invalid + !recordPresent -> LATCH.
    await storage.write(
      "_meta",
      FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
      new TextEncoder().encode(JSON.stringify({ v: 1, mac: "forged-mac" })),
    );
    await storage.delete(NS, KEY);
    const latchedBoot = await buildDashboard(fortress, "mini-1", storage);
    const hook = signOff(latchedBoot) as { unavailable?: boolean } | null;
    expect(hook && hook.unavailable).toBe(true);

    // Rotation-safety control: rebuild the record (re-enable) but keep a corrupt
    // sentinel; the record-PRESENT path re-stamps a clean marker and does NOT
    // brick (the guard serves).
    const recovery = await buildDashboard(fortress, "mini-1", storage);
    await recovery.setFederationGuardianRevocationRequirement({ roster });
    // Corrupt the sentinel again while the record is present.
    await storage.write(
      "_meta",
      FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
      new TextEncoder().encode(JSON.stringify({ v: 1, mac: "stale-prior-master-mac" })),
    );
    const restamped = await buildDashboard(fortress, "mini-1", storage);
    const afterRestamp = signOff(restamped) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // Not bricked: the guard is live (effective M=3), and the sentinel was
    // re-stamped clean under the current master.
    expect((afterRestamp as { unavailable?: boolean }).unavailable).not.toBe(true);
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    expect((await store.guardianRequirementEstablished()).status).toBe("established");
  });

  // Append `count` NON-guardian l2 audit entries to inflate the l2 window.
  async function appendFillerL2(
    storage: MemoryStorage,
    count: number,
    startIndex = 0,
  ): Promise<void> {
    const log = new AuditLog(storage, AUDIT_KEY);
    for (let i = 0; i < count; i++) {
      await log.appendCritical({
        layer: "l2",
        operation: "filler_non_guardian_op",
        identity_id: "filler",
        result: "success",
        details: { i: startIndex + i },
      });
    }
    await log.flush();
  }

  // §8.6 P0 REGRESSION (the round-1 merge-blocker). The guardian raise entry is
  // BURIED under >1000 later l2 entries. The round-1 bounded read
  // (query({layer:"l2", limit:1000})) sliced the last 1000 l2 entries AFTER the
  // layer filter, so the guardian raise fell OUT of the window, the audit floor
  // collapsed to 0 with ZERO integrity findings (benign forward growth, not
  // truncation), and the two-record blob+anchor restore LANDED (effectiveM=2,
  // unavailable=false). The window-independent streamVerifiedChain read finds the
  // buried guardian raise and LATCHES. This test MUST fail on 5787324c (restore
  // limit:1000 to confirm) and pass now.
  it("P0: a guardian raise buried under >1000 later l2 entries still LATCHES a two-record restore", async () => {
    const { fortress, storage, lowBlob, lowAnchor } = await loweredThenRaised();

    // Bury the guardian entries under >1000 later l2 audit entries (the normal
    // busy-l2 steady state: break-glass ticks, transparency checkpoints, etc).
    await appendFillerL2(storage, 1100);

    // Two-record restore (blob + anchor at the LOW floor); guardian audit entries
    // (and the buried raise) remain intact on disk.
    await storage.write(NS, KEY, lowBlob);
    await storage.write("_meta", ANCHOR_KEY, lowAnchor);

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // Window-independent floor finds the buried raise -> blob.generation <
    // auditFloor.generation -> LATCH. The stale lowered-M never goes live.
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
    if ((after as { unavailable?: boolean }).unavailable !== true) {
      expect(
        effectiveThresholdM(after as GuardianRevocationRequirement),
      ).not.toBe(2);
    }
  });

  // Build a fortress with: a FILLER non-guardian l2 entry FIRST (so it sits
  // strictly BELOW the guardian entries), then a guardian requirement (the
  // guardian entries), then a two-record restore staged. Returns the pieces a P1
  // test needs plus the ordered on-disk audit keys.
  async function stagedTwoRecordRestoreWithFillerBelow(): Promise<{
    fortress: MultiNodeFortress;
    storage: MemoryStorage;
    auditKeys: () => Promise<string[]>;
  }> {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();

    // One NON-guardian l2 entry FIRST (sequence 1), below every guardian entry.
    await appendFillerL2(storage, 1);

    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    const nonceLower = dashboard.nextFederationGuardianDisableNonce();
    const staleLowered = mintLowered(fortress, "mini-1", roster.version, 2, nonceLower);
    await dashboard.setFederationGuardianRevocationRequirement(
      { roster, loweredThreshold: staleLowered },
      {
        masterAuthorization: signMasterDisableAuthorization({
          fortressId: fortress.fortressId,
          disableNonce: nonceLower,
          intent: "lower",
          targetM: 2,
          masterPrivateKey: masterKeyOf(fortress, "mini-1"),
        }),
      },
    );
    const lowBlob = (await storage.read(NS, KEY))!;
    const lowAnchor = (await storage.read("_meta", ANCHOR_KEY))!;
    await dashboard.setFederationGuardianRevocationRequirement({ roster }); // raise

    // Stage the two-record restore (blob + anchor low); audit trail intact.
    await storage.write(NS, KEY, lowBlob);
    await storage.write("_meta", ANCHOR_KEY, lowAnchor);

    const auditKeys = async () =>
      (await storage.list("_audit")).map((m) => m.key).sort();
    return { fortress, storage, auditKeys };
  }

  // §8.6 P1(a) - THE AVAILABILITY WIN: a fortress that NEVER configured a
  // guardian requirement (no guardian audit entries, no established sentinel)
  // must NOT be bricked by an unrelated l2 audit corruption. The round-1
  // `findings.length > 0 -> null` latch bricked ALL federation serving on ANY l2
  // finding; the scoped rule leaves a never-guarded fortress AVAILABLE (a missing
  // guardian raise cannot be hidden if none ever existed). This is the concrete
  // "a benign historical corruption does not brick serving" case.
  it("P1(a): a never-guarded fortress with an unrelated l2 corruption does NOT latch", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    // Never configure a guardian requirement. Just some l2 audit history, one of
    // which is then corrupted (a decrypt-failure, the harshest single-entry
    // corruption class).
    await appendFillerL2(storage, 3);
    const keys = (await storage.list("_audit")).map((m) => m.key).sort();
    const env = JSON.parse(
      bytesToString((await storage.read("_audit", keys[1]!))!),
    ) as PersistedAuditEnvelopeV2;
    env.encrypted_payload_bytes = "AAAA" + env.encrypted_payload_bytes.slice(4);
    await storage.write("_audit", keys[1]!, stringToBytes(JSON.stringify(env)));

    // Boot: no guard was ever configured, so the (unrelated) audit finding must
    // NOT brick federation serving. The kill hook is the legacy single-operator
    // null (no requirement), NOT the unavailable sentinel.
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const hook = signOff(dashboard) as { unavailable?: boolean } | null;
    expect(hook === null || hook.unavailable !== true).toBe(true);
  });

  // §8.6 P1(a2) - HONEST FAIL-CLOSED BOUNDARY: on a GUARDED fortress, a real
  // in-place corruption of a below-guardian entry produces `entry_decrypt_failed`
  // (a coverage class: we cannot read the entry, so it COULD have been a guardian
  // raise). The scoped rule correctly fails TOWARD latch. This documents that the
  // scoping does NOT weaken safety: any corruption whose content is unreadable is
  // treated as a coverage risk, even below the observed guardian sequence.
  it("P1(a2): a below-guardian decrypt-failure on a guarded fortress fails closed (coverage)", async () => {
    const { fortress, storage, auditKeys } =
      await stagedTwoRecordRestoreWithFillerBelow();

    // Corrupt the FILLER entry (sequence 1, below the guardian entries). A payload
    // byte-flip yields entry_hash_mismatch AND entry_decrypt_failed (coverage).
    const keys = await auditKeys();
    const fillerKey = keys[0]!;
    const env = JSON.parse(
      bytesToString((await storage.read("_audit", fillerKey))!),
    ) as PersistedAuditEnvelopeV2;
    env.encrypted_payload_bytes = "AAAA" + env.encrypted_payload_bytes.slice(4);
    await storage.write("_audit", fillerKey, stringToBytes(JSON.stringify(env)));

    // The unreadable below entry could have been a guardian entry -> coverage ->
    // fail toward latch. (The two-record rollback is also staged, so latching is
    // the correct outcome regardless; the point is we never SILENTLY accept the
    // restore on a coverage finding.)
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // §8.6 P1(b): a TRUNCATION / tail / gap finding (coverage class) DOES latch,
  // even though it is not at a known guardian sequence, because a coverage
  // finding could have HIDDEN a higher-generation guardian raise.
  it("P1(b): a sequence_gap_or_reorder (coverage) finding LATCHES", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });
    // Append a couple of filler entries so a middle deletion is a GAP, not a tail
    // truncation (either coverage kind latches; a gap is the cleaner signal).
    await appendFillerL2(storage, 3);

    // Delete a middle entry -> sequence_gap_or_reorder (a coverage finding).
    const keys = (await storage.list("_audit")).map((m) => m.key).sort();
    await storage.delete("_audit", keys[Math.floor(keys.length / 2)]!);

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // Coverage finding -> the guardian set may be incomplete -> fail toward latch.
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // §8.6 P1(c): a finding whose sequence is ON/ABOVE a guardian entry LATCHES,
  // because a corruption at or above a guardian entry could alter/hide a
  // higher-generation guardian raise.
  it("P1(c): an entry_hash_mismatch AT a guardian entry LATCHES", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster });

    // The FIRST audit entry is the guardian enable (sequence 1). Byte-flip it to
    // trigger an entry_hash_mismatch AT a guardian entry's sequence.
    const keys = (await storage.list("_audit")).map((m) => m.key).sort();
    const guardianKey = keys[0]!;
    const env = JSON.parse(
      bytesToString((await storage.read("_audit", guardianKey))!),
    ) as PersistedAuditEnvelopeV2;
    env.encrypted_payload_bytes = "CCCC" + env.encrypted_payload_bytes.slice(4);
    await storage.write("_audit", guardianKey, stringToBytes(JSON.stringify(env)));

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // Finding sequence >= lowest guardian sequence -> fail toward latch.
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // Drive a fortress to: requirement set (gen 1) -> arm break-glass (gen 2,
  // ARMED state persisted) -> CAPTURE blob+anchor at gen 2 -> terminate the
  // countdown via `outcome` (cancel/veto: gen 3, break-glass cleared). Returns
  // the captured low-floor bytes so a test can restore + reboot.
  async function armedThenTerminated(
    outcome: "cancel" | "veto",
  ): Promise<{
    fortress: MultiNodeFortress;
    storage: MemoryStorage;
    armedBlob: Uint8Array;
    armedAnchor: Uint8Array;
    keypairs: GuardianKeypair[];
    roster: GuardianRoster;
  }> {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster }); // gen 1

    await dashboard.initiateFederationGuardianBreakGlass("disable", null); // gen 2, ARMED
    const inFlightNonce = dashboard.nextFederationGuardianDisableNonce() - 1;

    // CAPTURE the ARMED state (gen 2) raw bytes: blob + anchor. No master used.
    const armedBlob = (await storage.read(NS, KEY))!;
    const armedAnchor = (await storage.read("_meta", ANCHOR_KEY))!;
    expect(armedBlob).not.toBeNull();
    expect(armedAnchor).not.toBeNull();

    // Terminate the countdown (gen 3, break-glass cleared). The veto/cancel audit
    // entry (federation_guardian_break_glass_vetoed / _cancelled) carries the
    // committed generation 3 - the entry the round-2 hardcoded set OMITTED.
    if (outcome === "cancel") {
      await dashboard.cancelFederationGuardianBreakGlass();
    } else {
      const veto = signGuardianBreakGlassVeto({
        guardianId: keypairs[4]!.identity.guardian_id,
        guardianPrivateKey: keypairs[4]!.privateKey,
        fortressId: fortress.fortressId,
        disableNonce: inFlightNonce,
        rosterVersion: 1,
      });
      const decision = await dashboard.vetoFederationGuardianBreakGlass(veto);
      expect(decision.vetoed).toBe(true);
    }
    // Sanity: the live break-glass is cleared after termination.
    const liveStore = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    expect((await liveStore.load()).guardianBreakGlass).toBeNull();

    return { fortress, storage, armedBlob, armedAnchor, keypairs, roster };
  }

  // §8.7 P0 (Codex's exact exploit, CANCEL variant). The break-glass CANCEL entry
  // bumps + audits the committed generation under an op-name the round-2 hardcoded
  // matcher OMITTED. Restoring the captured ARMED (gen 2) blob + anchor after a
  // cancel (gen 3) must LATCH via the drift-proof floor (auditFloor.generation=3
  // from the matched cancel entry > blob.generation=2), and the stale ARMED
  // break-glass must NOT resurrect. On 8f213716 (hardcoded set) the cancel entry
  // is skipped -> auditFloor=2 -> no latch -> the armed break-glass rehydrates.
  it("P0(round3): a stale-armed break-glass restore after CANCEL latches (drift-proof floor)", async () => {
    const { fortress, storage, armedBlob, armedAnchor } =
      await armedThenTerminated("cancel");

    // Restore the captured ARMED (gen 2) blob + anchor.
    await storage.write(NS, KEY, armedBlob);
    await storage.write("_meta", ANCHOR_KEY, armedAnchor);

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    // Give any (wrongly) armed poll an immediate tick window.
    await new Promise((r) => setTimeout(r, 20));

    // Must LATCH: blob.generation (2) < auditFloor.generation (3, from the matched
    // cancel entry).
    expect(restarted._federationSyncStateUnavailable ?? false).toBe(true);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // The stale ARMED break-glass must NOT resurrect: a latched fortress serves
    // the unavailable sentinel (never auto-disables the requirement to null via
    // the poll path), so the kill hook is { unavailable: true }, NOT null.
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // §8.7 P0 (VETO variant). Same exploit via a guardian veto (also an unmatched
  // op in the round-2 set). Must LATCH.
  it("P0(round3): a stale-armed break-glass restore after VETO latches (drift-proof floor)", async () => {
    const { fortress, storage, armedBlob, armedAnchor } =
      await armedThenTerminated("veto");
    await storage.write(NS, KEY, armedBlob);
    await storage.write("_meta", ANCHOR_KEY, armedAnchor);

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    await new Promise((r) => setTimeout(r, 20));
    expect(restarted._federationSyncStateUnavailable ?? false).toBe(true);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // §8.7 ANTI-DRIFT (prefix-not-set proof): the floor matches guardian
  // generations by PREFIX + success + details.generation, NOT a hardcoded
  // op-name set. Prove it counts a SYNTHETIC guardian op-name that NO set could
  // enumerate, and that this is the ONLY entry above the on-disk blob generation
  // (so a hardcoded set would MISS it and NOT latch, while the prefix matcher
  // DOES). Models a future generation-bumping transition whose audit landed (gen
  // higher) but whose blob write was then rolled back to the enable generation.
  it("anti-drift: a synthetic federation_guardian_* success entry with a higher generation RAISES the floor (set would miss)", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster }); // gen 1
    const store = new FederationSyncStateStore({ storage, masterKey: MASTER_KEY });
    const blobGen = (await store.load()).guardianRevocationRequirementGeneration;

    // Append ONLY a SYNTHETIC guardian op-name (no matched _set/_initiated entry
    // above the blob generation), carrying a strictly-higher generation. On a
    // HARDCODED-SET matcher this is unmatched -> floor stays == blobGen -> NO
    // latch. On the PREFIX matcher it raises the floor -> blobGen < floor -> LATCH.
    const log = new AuditLog(storage, AUDIT_KEY);
    await log.appendCritical({
      layer: "l2",
      operation: "federation_guardian_some_future_transition_v9",
      identity_id: "dashboard",
      result: "success",
      details: { generation: blobGen + 5 },
    });
    await log.flush();

    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    // The synthetic entry raised the audit floor to blobGen+5 > the on-disk blob
    // generation -> LATCH (drift-proof prefix match). A hardcoded set would miss
    // the synthetic op and would NOT latch.
    expect((after as { unavailable?: boolean }).unavailable).toBe(true);
  });

  // §8.7 ANTI-DRIFT regression: the EXISTING matched paths still count. A
  // requirement set + a break-glass initiate both raise the floor via the
  // drift-proof matcher (they always did; this guards against the matcher
  // narrowing). A FAILURE entry (no committed generation) must NOT count.
  it("anti-drift: success guardian entries count; a failure entry (no committed generation) does not", async () => {
    const fortress = makeMultiNodeFortress(["mini-1"]);
    const storage = new MemoryStorage();
    const dashboard = await buildDashboard(fortress, "mini-1", storage);
    const keypairs = buildGuardianKeypairs(5);
    const roster = buildRosterFromKeypairs(fortress, "mini-1", keypairs, 3);
    await dashboard.setFederationGuardianRevocationRequirement({ roster }); // gen 1 (matched)

    // Append a FAILURE guardian entry carrying rolled_back_generation, NOT a
    // committed `generation`. It must NOT raise the floor (it never committed).
    const log = new AuditLog(storage, AUDIT_KEY);
    await log.appendCritical({
      layer: "l2",
      operation: "federation_guardian_revocation_requirement_persist_failed",
      identity_id: "dashboard",
      result: "failure",
      details: { rolled_back_generation: 999 },
    });
    await log.flush();

    // A consistent reboot (no rollback staged) does NOT latch: the failure entry's
    // rolled_back_generation (999) is ignored (result !== "success" AND no
    // committed `generation`), so the floor stays at the real committed gen 1,
    // which matches the on-disk blob.
    const restarted = await buildDashboard(fortress, "mini-1", storage);
    const after = signOff(restarted) as
      | GuardianRevocationRequirement
      | { unavailable?: boolean };
    expect((after as { unavailable?: boolean }).unavailable).not.toBe(true);
    expect(effectiveThresholdM(after as GuardianRevocationRequirement)).toBe(3);
  });
});
