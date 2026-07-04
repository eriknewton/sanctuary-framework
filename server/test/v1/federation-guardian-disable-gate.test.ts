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
import { toBase64url } from "../../src/core/encoding.js";
import {
  issueGuardianRoster,
  verifyGuardianRoster,
} from "../../src/mesh/guardian/guardian-roster.js";
import type { GuardianIdentity, GuardianRoster } from "../../src/mesh/guardian/types.js";
import {
  FederationSyncStateStore,
  FEDERATION_SYNC_STATE_STORE_NAMESPACE,
  FEDERATION_SYNC_STATE_STORE_KEY,
} from "../../src/v1/federation-sync-state-store.js";
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
    // chokepoint apply + rollback = 2; rehydrate branches = 5. Total <= 7 each.
    expect(requirementAssigns).toBeLessThanOrEqual(7);
    expect(latchAssigns).toBeLessThanOrEqual(7);
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
      },
      { kind: "operator_set", next: null, auth: null },
    );
    expect(commit.ok).toBe(false);
  });
});
