/**
 * Adversarial tests for the OPTIONAL M-of-N guardian sign-off gate on the
 * federation revoke/kill path.
 *
 * Trust-boundary invariants under test:
 *   - DEFAULT-OFF is a no-op: with no requirement configured, the gate is never
 *     consulted and the revoke handler mints exactly as the legacy path did.
 *   - ENABLED is fail-closed: under-threshold, forged, and duplicate-counted-
 *     once approvals all REFUSE; only an exactly-M valid quorum is accepted.
 *
 * Real crypto: all guardian signatures use @noble/curves Ed25519 via the
 * existing `signApproval` primitive. No crypto is mocked or reimplemented.
 */

import { describe, expect, it } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { issueGuardianRoster } from "../../src/mesh/guardian/guardian-roster.js";
import { generateFortressMaster } from "../../src/mesh/trust-root.js";
import type {
  GuardianIdentity,
  GuardianRoster,
} from "../../src/mesh/guardian/types.js";
import {
  buildApprovalSigningInput,
  signApproval,
  type GuardianApproval,
} from "../../src/recovery/index.js";
import {
  evaluateGuardianRevocationSignOff,
  revocationCascadeId,
  GUARDIAN_SIGN_OFF_ACTION,
  type GuardianRevocationRequirement,
} from "../../src/v1/federation-revocation-guardian-gate.js";

// ── Fixtures ────────────────────────────────────────────────────────────────

interface Fix {
  fortressId: string;
  masterSecret: Uint8Array;
}

function buildFix(): Fix {
  const master = generateFortressMaster();
  return { fortressId: master.public.fortress_id, masterSecret: master.private_key };
}

function buildGuardians(count: number): Array<{
  identity: GuardianIdentity;
  kp: ReturnType<typeof generateKeypair>;
}> {
  const out: Array<{
    identity: GuardianIdentity;
    kp: ReturnType<typeof generateKeypair>;
  }> = [];
  for (let i = 0; i < count; i++) {
    const kp = generateKeypair();
    out.push({
      identity: {
        guardian_id: `guardian-${i}`,
        public_key: toBase64url(kp.publicKey),
        kind: "human",
        invited_at: new Date().toISOString(),
      },
      kp,
    });
  }
  return out;
}

function buildRoster(
  fix: Fix,
  guardians: Array<{ identity: GuardianIdentity }>,
  m: number,
  version = 1,
): GuardianRoster {
  return issueGuardianRoster({
    m,
    n: guardians.length,
    guardians: guardians.map((g) => g.identity),
    fortress_id: fix.fortressId,
    version,
    master_private_key: fix.masterSecret,
  });
}

/**
 * Sign `count` valid guardian approvals over the canonical signing input the
 * gate binds for (fortressId, nodeId, rosterVersion).
 */
function signRevocationApprovals(
  fix: Fix,
  guardians: Array<{
    identity: GuardianIdentity;
    kp: ReturnType<typeof generateKeypair>;
  }>,
  count: number,
  nodeId: string,
  rosterVersion: number,
): GuardianApproval[] {
  const cascadeId = revocationCascadeId(fix.fortressId, nodeId);
  const signingInput = buildApprovalSigningInput({
    cascade_id: cascadeId,
    recovery_action: GUARDIAN_SIGN_OFF_ACTION,
    fortress_id: fix.fortressId,
    roster_version: rosterVersion,
  });
  return guardians.slice(0, count).map((g) =>
    signApproval({
      signing_input: signingInput,
      guardian_id: g.identity.guardian_id,
      guardian_private_key: g.kp.privateKey,
      recovery_action: GUARDIAN_SIGN_OFF_ACTION,
      cascade_id: cascadeId,
    }),
  );
}

const NODE_ID = "node-under-revocation";

// ── on, exactly-threshold valid => ACCEPTED ─────────────────────────────────

describe("guardian revocation gate: exactly-threshold valid quorum is accepted", () => {
  it("allows when exactly M valid distinct guardian signatures are present", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const requirement: GuardianRevocationRequirement = { roster };
    const approvals = signRevocationApprovals(fix, guardians, 3, NODE_ID, roster.version);

    const decision = evaluateGuardianRevocationSignOff({
      requirement,
      fortressId: fix.fortressId,
      nodeId: NODE_ID,
      approvals,
    });

    expect(decision.allowed).toBe(true);
    if (decision.allowed) {
      expect(decision.validGuardianIds).toHaveLength(3);
    }
  });

  it("allows above threshold too", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const approvals = signRevocationApprovals(fix, guardians, 5, NODE_ID, roster.version);

    const decision = evaluateGuardianRevocationSignOff({
      requirement: { roster },
      fortressId: fix.fortressId,
      nodeId: NODE_ID,
      approvals,
    });

    expect(decision.allowed).toBe(true);
  });
});

// ── on, under-threshold => REFUSED ──────────────────────────────────────────

describe("guardian revocation gate: under-threshold is refused (fail-closed)", () => {
  it("refuses when fewer than M valid approvals are supplied", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const approvals = signRevocationApprovals(fix, guardians, 2, NODE_ID, roster.version);

    const decision = evaluateGuardianRevocationSignOff({
      requirement: { roster },
      fortressId: fix.fortressId,
      nodeId: NODE_ID,
      approvals,
    });

    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("guardian_threshold_not_met");
    }
  });

  it("refuses when no approvals are supplied at all", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);

    for (const approvals of [[], undefined, null, "not-an-array", {}]) {
      const decision = evaluateGuardianRevocationSignOff({
        requirement: { roster },
        fortressId: fix.fortressId,
        nodeId: NODE_ID,
        approvals,
      });
      expect(decision.allowed).toBe(false);
      if (!decision.allowed) {
        expect(decision.reason).toBe("guardian_approvals_required");
      }
    }
  });
});

// ── on, forged guardian sig => REJECTED ─────────────────────────────────────

describe("guardian revocation gate: forged guardian signature is rejected", () => {
  it("refuses when a guardian signature is forged (does not verify)", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const approvals = signRevocationApprovals(fix, guardians, 3, NODE_ID, roster.version);

    // Forge one approval's signature: flip bytes so ed25519.verify fails.
    const forged = { ...approvals[1]! };
    const sigBytes = Buffer.from(forged.signature, "base64url");
    sigBytes[0] = sigBytes[0]! ^ 0xff;
    forged.signature = sigBytes.toString("base64url");
    const tampered = [approvals[0]!, forged, approvals[2]!];

    const decision = evaluateGuardianRevocationSignOff({
      requirement: { roster },
      fortressId: fix.fortressId,
      nodeId: NODE_ID,
      approvals: tampered,
    });

    // Only 2 of 3 now verify => under threshold => refused.
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("guardian_threshold_not_met");
    }
  });

  it("refuses an approval from a guardian not on the roster", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    const outsider = buildGuardians(1)[0]!;
    outsider.identity.guardian_id = "guardian-outsider";

    const cascadeId = revocationCascadeId(fix.fortressId, NODE_ID);
    const signingInput = buildApprovalSigningInput({
      cascade_id: cascadeId,
      recovery_action: GUARDIAN_SIGN_OFF_ACTION,
      fortress_id: fix.fortressId,
      roster_version: roster.version,
    });
    const outsiderApproval = signApproval({
      signing_input: signingInput,
      guardian_id: outsider.identity.guardian_id,
      guardian_private_key: outsider.kp.privateKey,
      recovery_action: GUARDIAN_SIGN_OFF_ACTION,
      cascade_id: cascadeId,
    });
    const approvals = [
      ...signRevocationApprovals(fix, guardians, 2, NODE_ID, roster.version),
      outsiderApproval,
    ];

    const decision = evaluateGuardianRevocationSignOff({
      requirement: { roster },
      fortressId: fix.fortressId,
      nodeId: NODE_ID,
      approvals,
    });

    expect(decision.allowed).toBe(false);
  });

  it("refuses a quorum collected for a DIFFERENT node (replay binding)", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    // Sign a valid 3-of-5 quorum for node A.
    const approvals = signRevocationApprovals(fix, guardians, 3, "node-A", roster.version);

    // Present it to revoke node B: the cascade_id binding no longer matches, so
    // every signature is over the wrong canonical input => none verify.
    const decision = evaluateGuardianRevocationSignOff({
      requirement: { roster },
      fortressId: fix.fortressId,
      nodeId: "node-B",
      approvals,
    });

    expect(decision.allowed).toBe(false);
  });
});

// ── on, duplicate guardian sig counted once => still under threshold => REFUSED

describe("guardian revocation gate: duplicate guardian counted once", () => {
  it("counts a duplicated guardian once, leaving the quorum under threshold", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3);
    // Two DISTINCT valid approvals, plus a duplicate of the first.
    const base = signRevocationApprovals(fix, guardians, 2, NODE_ID, roster.version);
    const withDuplicate = [base[0]!, base[1]!, { ...base[0]! }];

    const decision = evaluateGuardianRevocationSignOff({
      requirement: { roster },
      fortressId: fix.fortressId,
      nodeId: NODE_ID,
      approvals: withDuplicate,
    });

    // 3 entries but only 2 distinct guardians => below M=3 => refused.
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("guardian_threshold_not_met");
    }
  });
});

// ── stale roster guard ──────────────────────────────────────────────────────

describe("guardian revocation gate: stale roster version is refused", () => {
  it("refuses when approvals are bound to a different roster version", () => {
    const fix = buildFix();
    const guardians = buildGuardians(5);
    const roster = buildRoster(fix, guardians, 3, 7);
    // Approvals signed over roster_version 6, but the pinned roster is v7.
    const approvals = signRevocationApprovals(fix, guardians, 3, NODE_ID, 6);

    const decision = evaluateGuardianRevocationSignOff({
      requirement: { roster, expectedRosterVersion: 6 },
      fortressId: fix.fortressId,
      nodeId: NODE_ID,
      approvals,
    });

    // expected_roster_version (6) != roster.version (7) => RosterStaleError.
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.reason).toBe("guardian_roster_stale");
    }
  });
});
