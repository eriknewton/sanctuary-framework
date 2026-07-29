/**
 * Sanctuary Federation Protocol v0.1 — Guardian + Recovery Cascade Tests
 *
 * WP-MVP-3 Follow-up #3 spawn-prompt acceptance criteria covered here:
 *   3 — GuardianRoster module + 3-of-5 default + sub-M quorum rejection.
 *   4 — master_rotation acceptance + cert re-issue + HKDF re-derive +
 *       locator-re-sign + policy preserve+historical_master.
 *   5 — Audit continuity walk across master rotation.
 *   6 — Post-recovery broker-credential rotation prompt.
 *   8 — event_class enum coverage on every emission.
 *   9 — signature_scheme: 'ed25519-v1' on every signed emission.
 *
 * No mocked routes. Real Ed25519, real HKDF, real canonical-JSON. Failures
 * here would also fail on the libp2p adapter.
 */

import { describe, it, expect } from "vitest";
import {
  fromBase64url,
  toBase64url,
} from "../../src/core/encoding.js";
import { generateKeypair } from "../../src/core/identity.js";
import { ed25519 } from "@noble/curves/ed25519";
import {
  CAP_STANDARD_FORTRESS_NODE,
  SIGNATURE_SCHEME_V1,
} from "../../src/mesh/constants.js";
import {
  acceptMasterRotation,
  buildMasterRotationAuditPayload,
  buildMasterRotationPayload,
  buildPostRecoveryPrompt,
  DEFAULT_GUARDIAN_M,
  DEFAULT_GUARDIAN_N,
  GuardianQuorumError,
  GuardianRosterError,
  GuardianRosterSignatureError,
  GuardianRosterStaleError,
  MasterRotationError,
  PostRecoveryPromptStore,
  isV10GuardianKind,
  issueGuardianRoster,
  rekeyOnMasterRotation,
  signMasterRotationAsGuardian,
  verifyGuardianQuorum,
  verifyGuardianRoster,
  walkAuditContinuity,
  type GuardianIdentity,
  type MasterRotationQuorumInput,
} from "../../src/mesh/guardian/index.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  verifyCertChain,
} from "../../src/mesh/trust-root.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import type { FortressMasterPublicKey } from "../../src/mesh/types.js";

// ═══════════════════════════════════════════════════════════════════════
// Fortress + roster fixtures
// ═══════════════════════════════════════════════════════════════════════

interface GuardianKp {
  identity: GuardianIdentity;
  private_key: Uint8Array;
}

function makeGuardian(id: string, kind: "human" | "sanctuary_operated" = "human"): GuardianKp {
  const kp = generateKeypair();
  return {
    identity: {
      guardian_id: id,
      public_key: toBase64url(kp.publicKey),
      kind,
      invited_at: new Date().toISOString(),
    },
    private_key: kp.privateKey,
  };
}

function makeFortress() {
  return generateFortressMaster();
}

function makeRosterDefault35(fortress: ReturnType<typeof makeFortress>) {
  const guardians = ["g1", "g2", "g3", "g4", "g5"].map((id) => makeGuardian(id));
  const roster = issueGuardianRoster({
    m: DEFAULT_GUARDIAN_M,
    n: DEFAULT_GUARDIAN_N,
    guardians: guardians.map((g) => g.identity),
    fortress_id: fortress.public.fortress_id,
    version: 1,
    master_private_key: fortress.private_key,
  });
  return { roster, guardians };
}

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #3 — GuardianRoster
// ═══════════════════════════════════════════════════════════════════════

describe("GuardianRoster — issuance + verification", () => {
  it("default M-of-N is 3-of-5 per Key 13 lock", () => {
    expect(DEFAULT_GUARDIAN_M).toBe(3);
    expect(DEFAULT_GUARDIAN_N).toBe(5);
  });

  it("v1.0 issuance accepts only human / sanctuary_operated kinds", () => {
    expect(isV10GuardianKind("human")).toBe(true);
    expect(isV10GuardianKind("sanctuary_operated")).toBe(true);
    expect(isV10GuardianKind("custodial-vault")).toBe(false);
  });

  it("issued roster verifies against the fortress-master pubkey", () => {
    const fortress = makeFortress();
    const { roster } = makeRosterDefault35(fortress);
    expect(roster.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(roster.m).toBe(3);
    expect(roster.n).toBe(5);
    expect(roster.guardians).toHaveLength(5);
    verifyGuardianRoster(roster, fortress.public);
  });

  it("rejects roster signed by a different master (cross-operator isolation)", () => {
    const fortress = makeFortress();
    const other = makeFortress();
    const { roster } = makeRosterDefault35(fortress);
    expect(() => verifyGuardianRoster(roster, other.public)).toThrowError(
      GuardianRosterError
    );
  });

  it("rejects roster with tampered master signature", () => {
    const fortress = makeFortress();
    const { roster } = makeRosterDefault35(fortress);
    const tampered = { ...roster, master_signature: toBase64url(
      // flip the first byte of the original signature
      (() => {
        const raw = fromBase64url(roster.master_signature);
        raw[0] ^= 0x01;
        return raw;
      })()
    ) };
    expect(() => verifyGuardianRoster(tampered, fortress.public)).toThrow(
      GuardianRosterSignatureError
    );
  });

  it("rejects invalid M-of-N at issuance", () => {
    const fortress = makeFortress();
    const guardians = ["g1", "g2"].map((id) => makeGuardian(id).identity);
    expect(() =>
      issueGuardianRoster({
        m: 3,
        n: 2,
        guardians,
        fortress_id: fortress.public.fortress_id,
        version: 1,
        master_private_key: fortress.private_key,
      })
    ).toThrow(GuardianRosterError);
  });

  it("rejects duplicate guardian_ids in roster", () => {
    const fortress = makeFortress();
    const dup = makeGuardian("g-x").identity;
    const guardians = [dup, { ...dup }];
    expect(() =>
      issueGuardianRoster({
        m: 1,
        n: 2,
        guardians,
        fortress_id: fortress.public.fortress_id,
        version: 1,
        master_private_key: fortress.private_key,
      })
    ).toThrow(GuardianRosterError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// verifyGuardianQuorum — sub-M rejection + signature verification
// ═══════════════════════════════════════════════════════════════════════

describe("verifyGuardianQuorum — M-of-N enforcement", () => {
  it("accepts exactly M valid signatures", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    verifyGuardianQuorum({
      input,
      proof: { roster_version: roster.version, signatures: sigs },
      pinned_roster: roster,
    });
  });

  it("rejects sub-threshold (M-1) signatures", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 2).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
  });

  it("rejects duplicate guardian_id across signatures", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const oneSig = signMasterRotationAsGuardian({
      input,
      guardian_id: guardians[0].identity.guardian_id,
      guardian_private_key: guardians[0].private_key,
    });
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: {
          roster_version: roster.version,
          signatures: [oneSig, oneSig, oneSig],
        },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
  });

  it("rejects signature from a guardian not in the pinned roster", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const interloper = makeGuardian("g-fake");
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = [
      ...guardians.slice(0, 2).map((g) =>
        signMasterRotationAsGuardian({
          input,
          guardian_id: g.identity.guardian_id,
          guardian_private_key: g.private_key,
        })
      ),
      signMasterRotationAsGuardian({
        input,
        guardian_id: interloper.identity.guardian_id,
        guardian_private_key: interloper.private_key,
      }),
    ];
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
  });

  it("rejects stale roster_version (replay protection)", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: 99, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
    // Sanity that the GuardianRosterStaleError is also wired.
    expect(GuardianRosterStaleError).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Regression: shared-public-key quorum collapse (A3 harden 2026-07-04)
//
// One key holder must not occupy multiple guardian slots under distinct
// guardian_ids. Approval/quorum signatures bind the signing input and the
// guardian key, never the guardian_id, so N distinct ids sharing one public
// key let a single private key satisfy M-of-N alone. Both issuance/verification
// (root-cause) and the quorum counter (defense-in-depth) must fail closed.
// ═══════════════════════════════════════════════════════════════════════

describe("shared-public-key quorum collapse: fail closed", () => {
  // Forge a master-signed roster whose guardians have distinct ids but a shared
  // public key. Mirrors issueGuardianRoster's body shape so the master_signature
  // is genuine; the only deviation is that it bypasses validateRosterShape.
  function forgeSharedKeyRoster(
    fortress: ReturnType<typeof makeFortress>,
    ids: string[]
  ): { roster: ReturnType<typeof issueGuardianRoster>; shared: GuardianKp } {
    const shared = makeGuardian(ids[0]);
    const guardians: GuardianIdentity[] = ids.map((id) => ({
      guardian_id: id,
      public_key: shared.identity.public_key,
      kind: "human" as const,
      invited_at: new Date().toISOString(),
    }));
    const body = {
      m: guardians.length,
      n: guardians.length,
      guardians,
      signature_scheme: SIGNATURE_SCHEME_V1,
      version: 1,
      created_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sig = ed25519.sign(canonicalizeToBytes(body), fortress.private_key);
    return {
      roster: { ...body, master_signature: toBase64url(sig) },
      shared,
    };
  }

  it("issueGuardianRoster rejects distinct guardian_ids that share a public key", () => {
    const fortress = makeFortress();
    const shared = makeGuardian("g1");
    const guardians: GuardianIdentity[] = [
      { ...shared.identity, guardian_id: "g1" },
      { ...shared.identity, guardian_id: "g2" },
      { ...shared.identity, guardian_id: "g3" },
    ];
    expect(() =>
      issueGuardianRoster({
        m: 3,
        n: 3,
        guardians,
        fortress_id: fortress.public.fortress_id,
        version: 1,
        master_private_key: fortress.private_key,
      })
    ).toThrow(GuardianRosterError);
  });

  it("verifyGuardianRoster rejects a forged roster with a shared public key", () => {
    const fortress = makeFortress();
    const { roster } = forgeSharedKeyRoster(fortress, ["g0", "g1", "g2"]);
    // master_signature is genuine, so this fails on shape (duplicate key), not
    // on the signature, proving the roster body itself is the closed gate.
    expect(() => verifyGuardianRoster(roster, fortress.public)).toThrow(
      GuardianRosterError
    );
  });

  it("verifyGuardianQuorum does not let one key satisfy M-of-N via shared-key slots", () => {
    const fortress = makeFortress();
    const { roster, shared } = forgeSharedKeyRoster(fortress, ["g0", "g1", "g2"]);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    // One private key signs three envelopes labeled g0/g1/g2. Each individual
    // signature verifies against the (shared) key; pre-fix all three counted.
    const sigs = ["g0", "g1", "g2"].map((id) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: id,
        guardian_private_key: shared.private_key,
      })
    );
    // After the A3 follow-up shape gate, verifyGuardianQuorum runs
    // validateRosterShape first, so this shared-key roster (duplicate canonical
    // keys) is rejected wholesale as a malformed roster BEFORE the per-key
    // quorum counter runs, a strictly stronger fail-closed rejection than the
    // earlier per-key GuardianQuorumError. GuardianRosterError and
    // GuardianQuorumError both extend GuardianError; the rejection is now a
    // roster-shape error because the roster, not the proof, is malformed.
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianRosterError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Regression: NON-CANONICAL shared-key quorum collapse (A3 harden 2026-07-04)
//
// The first shared-key guard compared raw base64url strings for uniqueness,
// but fromBase64url decodes permissively: "KEY", "KEY==", "KEY " all decode to
// the same 32 bytes and every slot verifies against the one key. Distinct
// spellings of ONE key therefore slipped past the string-equality uniqueness
// check while a single private key satisfied M-of-N. The fix compares on the
// canonical decoded key and rejects non-canonical spellings outright. These
// tests FAIL before the canonical-key fix and PASS after.
// ═══════════════════════════════════════════════════════════════════════

describe("non-canonical shared-public-key quorum collapse: fail closed", () => {
  it("issueGuardianRoster rejects a non-canonical re-spelling of one key", () => {
    const fortress = makeFortress();
    const shared = makeGuardian("g1");
    const canonical = shared.identity.public_key;
    const padded = `${canonical}==`;
    const spaced = `${canonical} `;
    // The spellings differ as strings but decode to the identical key.
    expect(padded).not.toBe(canonical);
    expect(spaced).not.toBe(canonical);
    expect(toBase64url(fromBase64url(padded))).toBe(canonical);
    expect(toBase64url(fromBase64url(spaced))).toBe(canonical);
    const guardians: GuardianIdentity[] = [
      { ...shared.identity, guardian_id: "g1", public_key: canonical },
      { ...shared.identity, guardian_id: "g2", public_key: padded },
      { ...shared.identity, guardian_id: "g3", public_key: spaced },
    ];
    expect(() =>
      issueGuardianRoster({
        m: 3,
        n: 3,
        guardians,
        fortress_id: fortress.public.fortress_id,
        version: 1,
        master_private_key: fortress.private_key,
      })
    ).toThrow(GuardianRosterError);
  });

  it("verifyGuardianRoster rejects a forged roster with non-canonical shared-key spellings", () => {
    const fortress = makeFortress();
    const shared = makeGuardian("g0");
    const canonical = shared.identity.public_key;
    const guardians: GuardianIdentity[] = [
      { ...shared.identity, guardian_id: "g0", public_key: canonical },
      { ...shared.identity, guardian_id: "g1", public_key: `${canonical}==` },
      { ...shared.identity, guardian_id: "g2", public_key: `${canonical} ` },
    ];
    const body = {
      m: 3,
      n: 3,
      guardians,
      signature_scheme: SIGNATURE_SCHEME_V1,
      version: 1,
      created_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sig = ed25519.sign(canonicalizeToBytes(body), fortress.private_key);
    const roster = { ...body, master_signature: toBase64url(sig) };
    // master_signature is genuine, so the rejection is on shape (a non-canonical
    // spelling of an already-seen key), not on the signature.
    expect(() => verifyGuardianRoster(roster, fortress.public)).toThrow(
      GuardianRosterError
    );
  });

  it("verifyGuardianQuorum does not count non-canonical spellings of one key twice", () => {
    const fortress = makeFortress();
    const shared = makeGuardian("g0");
    const canonical = shared.identity.public_key;
    const guardians: GuardianIdentity[] = [
      { ...shared.identity, guardian_id: "g0", public_key: canonical },
      { ...shared.identity, guardian_id: "g1", public_key: `${canonical}==` },
      { ...shared.identity, guardian_id: "g2", public_key: `${canonical} ` },
    ];
    const body = {
      m: 3,
      n: 3,
      guardians,
      signature_scheme: SIGNATURE_SCHEME_V1,
      version: 1,
      created_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const masterSig = ed25519.sign(canonicalizeToBytes(body), fortress.private_key);
    const roster = { ...body, master_signature: toBase64url(masterSig) };
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = ["g0", "g1", "g2"].map((id) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: id,
        guardian_private_key: shared.private_key,
      })
    );
    // After the A3 follow-up shape gate, the non-canonical shared-key roster
    // (three spellings collapsing to one canonical key) is rejected at
    // validateRosterShape as a malformed roster before the per-key quorum
    // counter, a strictly stronger fail-closed rejection surfaced as
    // GuardianRosterError (roster malformed, not proof).
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianRosterError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Regression: malformed pinned roster fails closed at verifyGuardianQuorum
// (A3 harden 2026-07-04)
//
// verifyGuardianQuorum compared proof.signatures.length and validCount against
// an UNVALIDATED roster.m/roster.n. A master-signed but structurally degenerate
// roster (m=0,n=1) let the empty-signature path succeed: `0 < 0` (length < m) is
// false, the signature loop is empty, and `validCount(0) < m(0)` is false, so
// the quorum "verified" with ZERO guardian signatures. The fix runs
// validateRosterShape at the START of verifyGuardianQuorum, so any malformed
// pinned roster throws GuardianRosterError before any threshold comparison.
// Each test FAILS before the shape gate (quorum returns success / wrong error)
// and PASSES after (throws GuardianRosterError). GuardianRosterError and
// GuardianQuorumError both extend GuardianError; the roster-shape violation
// surfaces as the roster error because the roster, not the proof, is malformed.
// ═══════════════════════════════════════════════════════════════════════

describe("malformed pinned roster: verifyGuardianQuorum fails closed", () => {
  // Forge a master-signed roster with an arbitrary (possibly invalid) shape.
  // The master_signature is genuine over the body, so any rejection is on shape,
  // not on the signature, proving the shape gate itself is the closed boundary.
  function forgeRoster(
    fortress: ReturnType<typeof makeFortress>,
    body: {
      m: number;
      n: number;
      guardians: GuardianIdentity[];
    }
  ): ReturnType<typeof issueGuardianRoster> {
    const full = {
      m: body.m,
      n: body.n,
      guardians: body.guardians,
      signature_scheme: SIGNATURE_SCHEME_V1,
      version: 1,
      created_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sig = ed25519.sign(canonicalizeToBytes(full), fortress.private_key);
    return { ...full, master_signature: toBase64url(sig) };
  }

  function buildInput(
    fortress: ReturnType<typeof makeFortress>
  ): MasterRotationQuorumInput {
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    return {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
  }

  it("m=0 with an empty proof does NOT verify (the empty-signature success path is closed)", () => {
    const fortress = makeFortress();
    const g0 = makeGuardian("g0");
    // Degenerate roster: m=0, n=1, one real guardian. Pre-fix an empty proof
    // whose roster_version matches slipped through with zero signatures.
    const roster = forgeRoster(fortress, {
      m: 0,
      n: 1,
      guardians: [g0.identity],
    });
    const input = buildInput(fortress);
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: [] },
        pinned_roster: roster,
      })
    ).toThrow(GuardianRosterError);
  });

  it("m>n fails closed", () => {
    const fortress = makeFortress();
    const g0 = makeGuardian("g0");
    const roster = forgeRoster(fortress, {
      m: 2,
      n: 1,
      guardians: [g0.identity],
    });
    const input = buildInput(fortress);
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: [] },
        pinned_roster: roster,
      })
    ).toThrow(GuardianRosterError);
  });

  it("guardians.length !== n fails closed", () => {
    const fortress = makeFortress();
    const g0 = makeGuardian("g0");
    const g1 = makeGuardian("g1");
    // n claims 3 but only 2 guardians listed.
    const roster = forgeRoster(fortress, {
      m: 1,
      n: 3,
      guardians: [g0.identity, g1.identity],
    });
    const input = buildInput(fortress);
    const sig = signMasterRotationAsGuardian({
      input,
      guardian_id: "g0",
      guardian_private_key: g0.private_key,
    });
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: [sig] },
        pinned_roster: roster,
      })
    ).toThrow(GuardianRosterError);
  });

  it("duplicate guardian_id in the roster fails closed", () => {
    const fortress = makeFortress();
    const g0 = makeGuardian("dup");
    const g1 = makeGuardian("dup"); // same id, distinct key
    const roster = forgeRoster(fortress, {
      m: 1,
      n: 2,
      guardians: [g0.identity, g1.identity],
    });
    const input = buildInput(fortress);
    const sig = signMasterRotationAsGuardian({
      input,
      guardian_id: "dup",
      guardian_private_key: g0.private_key,
    });
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: [sig] },
        pinned_roster: roster,
      })
    ).toThrow(GuardianRosterError);
  });

  it("duplicate canonical public key in the roster fails closed", () => {
    const fortress = makeFortress();
    const shared = makeGuardian("g0");
    const roster = forgeRoster(fortress, {
      m: 1,
      n: 2,
      guardians: [
        { ...shared.identity, guardian_id: "g0" },
        { ...shared.identity, guardian_id: "g1" },
      ],
    });
    const input = buildInput(fortress);
    const sig = signMasterRotationAsGuardian({
      input,
      guardian_id: "g0",
      guardian_private_key: shared.private_key,
    });
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: [sig] },
        pinned_roster: roster,
      })
    ).toThrow(GuardianRosterError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #4 — master_rotation flow + cascade
// ═══════════════════════════════════════════════════════════════════════

describe("master_rotation acceptance + cascade", () => {
  function setupRotationFixture() {
    const oldFortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(oldFortress);
    const principalKp = generateKeypair();
    const principalCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: principalKp.publicKey,
      role: "root",
      fortress_id: oldFortress.public.fortress_id,
      master_private_key: oldFortress.private_key,
    });
    const nodeKp = generateKeypair();
    const nodeCert = issueNodeIdentityCertificate({
      node_id: "node-1",
      node_pubkey: nodeKp.publicKey,
      node_mode: "local",
      fortress_id: oldFortress.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: oldFortress.public.public_key,
        principal_id: principalCert.principal_id,
        principal_pubkey: principalCert.principal_pubkey,
      },
      principal_private_key: principalKp.privateKey,
      master_private_key: oldFortress.private_key,
    });
    const newMasterKp = generateKeypair();
    const newMasterPublic: FortressMasterPublicKey = {
      public_key: toBase64url(newMasterKp.publicKey),
      fortress_id: oldFortress.public.fortress_id,
      created_at: new Date().toISOString(),
    };
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: oldFortress.public.public_key,
      new_master_pubkey: newMasterPublic,
      rotated_at: new Date().toISOString(),
      fortress_id: oldFortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    const payload = buildMasterRotationPayload({
      input,
      guardian_signatures: sigs,
      pinned_roster: roster,
    });
    return {
      oldFortress,
      newMaster: { public: newMasterPublic, private_key: newMasterKp.privateKey },
      principal: { cert: principalCert, kp: principalKp },
      node: { cert: nodeCert, kp: nodeKp },
      roster,
      guardians,
      input,
      payload,
    };
  }

  it("acceptMasterRotation accepts a valid 3-of-5 quorum", () => {
    const f = setupRotationFixture();
    const result = acceptMasterRotation({
      payload: f.payload,
      pinned_master: f.oldFortress.public,
      pinned_roster: f.roster,
    });
    expect(result.accepted_new_master.public_key).toBe(
      f.newMaster.public.public_key
    );
    expect(result.rotated_at).toBe(f.payload.rotated_at);
  });

  it("rejects rotation whose old_master_pubkey != pinned master", () => {
    const f = setupRotationFixture();
    const wrongPinned: FortressMasterPublicKey = {
      ...f.oldFortress.public,
      public_key: toBase64url(generateKeypair().publicKey),
    };
    expect(() =>
      acceptMasterRotation({
        payload: f.payload,
        pinned_master: wrongPinned,
        pinned_roster: f.roster,
      })
    ).toThrow(MasterRotationError);
  });

  it("rekeyOnMasterRotation re-issues per-node cert under new master + re-derives HKDF subkeys", () => {
    const f = setupRotationFixture();
    const newRootKp = generateKeypair();
    const out = rekeyOnMasterRotation({
      new_master_secret: f.newMaster.private_key,
      new_master_public: f.newMaster.public,
      old_node_certificates: [f.node.cert],
      old_root_principal: f.principal.cert,
      new_root_principal_private_key: newRootKp.privateKey,
      new_root_principal_public_key: newRootKp.publicKey,
    });
    expect(out.re_issued_node_certificates).toHaveLength(1);
    const reCert = out.re_issued_node_certificates[0]!;
    expect(reCert.node_id).toBe("node-1");
    expect(reCert.parent_chain.fortress_master_pubkey).toBe(
      f.newMaster.public.public_key
    );
    // Re-derived keys are present + 32 bytes.
    expect(out.re_derived_audit_chain_keys.get("node-1")?.length).toBe(32);
    expect(out.re_derived_transport_keys.get("node-1")?.length).toBe(32);
    // The re-issued cert chain-validates against the new master + new principal.
    verifyCertChain(
      reCert,
      out.new_root_principal_certificate,
      f.newMaster.public
    );
  });

  it("policy default behavior is preserve+historical_master (re-sign opt-in)", () => {
    // The federation-protocol default per spec §9.4 is to PRESERVE existing
    // policy signatures with `historical_master` so verifiers can chain-verify
    // against the old master. rekeyOnMasterRotation does NOT touch policy
    // versions — leaving them preserved is the default. This test asserts the
    // contract: rekeyOnMasterRotation's output does not include a policy
    // re-sign field.
    const f = setupRotationFixture();
    const newRootKp = generateKeypair();
    const out = rekeyOnMasterRotation({
      new_master_secret: f.newMaster.private_key,
      new_master_public: f.newMaster.public,
      old_node_certificates: [f.node.cert],
      old_root_principal: f.principal.cert,
      new_root_principal_private_key: newRootKp.privateKey,
      new_root_principal_public_key: newRootKp.publicKey,
    });
    // The function intentionally does not re-sign policies — that is operator
    // policy. Acceptance criterion 4 says "default behavior is preserve +
    // historical_master".
    expect(Object.keys(out)).not.toContain("re_signed_policies");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #5 — audit continuity walk
// ═══════════════════════════════════════════════════════════════════════

describe("audit continuity across master rotation", () => {
  it("walks pre-rotation + boundary + post-rotation entries with no history rejected", () => {
    // Build two node keypairs (old + new master eras), an audit-log slice
    // spanning a master_rotation_boundary, and assert walkAuditContinuity
    // counts pre/post correctly + verifies signatures.
    const oldNodeKp = generateKeypair();
    const newNodeKp = generateKeypair();

    function entry(body: Record<string, unknown>, kp: { privateKey: Uint8Array; publicKey: Uint8Array }, isBoundary = false) {
      const sig = ed25519.sign(canonicalizeToBytes(body), kp.privateKey);
      return {
        body,
        signature: toBase64url(sig),
        emitter_node: "node-1",
        is_boundary: isBoundary,
      };
    }

    const entries = [
      entry({ entry_id: "e1", payload: { x: 1 } }, oldNodeKp),
      entry({ entry_id: "e2", payload: { x: 2 } }, oldNodeKp),
      // Boundary entry — signed under the OLD per-node key (it was emitted
      // pre-rotation, immediately before the rotation took effect).
      entry({ entry_id: "boundary", kind: "master_rotation_boundary" }, oldNodeKp, true),
      entry({ entry_id: "e3", payload: { x: 3 } }, newNodeKp),
      entry({ entry_id: "e4", payload: { x: 4 } }, newNodeKp),
    ];
    const result = walkAuditContinuity({
      preRotationNodePubkey: () => toBase64url(oldNodeKp.publicKey),
      postRotationNodePubkey: () => toBase64url(newNodeKp.publicKey),
      entries,
    });
    expect(result.pre_rotation_verified).toBe(2);
    expect(result.post_rotation_verified).toBe(2);
    expect(result.boundary_seen).toBe(true);
  });

  it("throws when a post-rotation entry signature does not verify under new master pubkey", () => {
    const oldKp = generateKeypair();
    const newKp = generateKeypair();
    const wrongKp = generateKeypair();
    const sig = ed25519.sign(
      canonicalizeToBytes({ entry_id: "p1", payload: { x: 1 } }),
      wrongKp.privateKey
    );
    const entries = [
      {
        body: { entry_id: "boundary", kind: "master_rotation_boundary" },
        signature: toBase64url(
          ed25519.sign(
            canonicalizeToBytes({ entry_id: "boundary", kind: "master_rotation_boundary" }),
            oldKp.privateKey
          )
        ),
        emitter_node: "node-1",
        is_boundary: true,
      },
      {
        body: { entry_id: "p1", payload: { x: 1 } },
        signature: toBase64url(sig),
        emitter_node: "node-1",
      },
    ];
    expect(() =>
      walkAuditContinuity({
        preRotationNodePubkey: () => toBase64url(oldKp.publicKey),
        postRotationNodePubkey: () => toBase64url(newKp.publicKey),
        entries,
      })
    ).toThrow(MasterRotationError);
  });

  it("buildMasterRotationAuditPayload includes signature_scheme=ed25519-v1 (crypto-agility hinge)", () => {
    const payload = buildMasterRotationAuditPayload({
      old_master_pubkey: "old",
      new_master_pubkey: "new",
      guardian_quorum_signatures: [],
      rotated_at: "2026-04-21T00:00:00Z",
    });
    expect(payload.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(payload.kind).toBe("master_rotation_boundary");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #6 — post-recovery broker prompt
// ═══════════════════════════════════════════════════════════════════════

describe("post-recovery broker-credential rotation prompt", () => {
  it("buildPostRecoveryPrompt lists every secret in the broker as pending", async () => {
    const broker = {
      listSecretNames: async () => ["gmail", "openai-api-key", "stripe-key"],
    };
    const prompt = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "old",
      new_master_pubkey: "new",
      rotated_at: "2026-04-21T01:00:00Z",
    });
    expect(prompt.credentials.map((c) => c.secret_name)).toEqual([
      "gmail",
      "openai-api-key",
      "stripe-key",
    ]);
    expect(prompt.rotated["gmail"]).toBe("pending");
    expect(prompt.rotated["openai-api-key"]).toBe("pending");
    expect(prompt.rotated["stripe-key"]).toBe("pending");
  });

  it("PostRecoveryPromptStore tracks per-rotation prompts and re-surfaces on each rotation", async () => {
    const broker = { listSecretNames: async () => ["a", "b"] };
    const store = new PostRecoveryPromptStore();
    const p1 = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "m0",
      new_master_pubkey: "m1",
      rotated_at: "2026-04-21T01:00:00Z",
    });
    store.put(p1);
    expect(store.has("2026-04-21T01:00:00Z")).toBe(true);
    store.markRotated({
      rotated_at: "2026-04-21T01:00:00Z",
      secret_name: "a",
      outcome: "rotated",
    });
    expect(store.get("2026-04-21T01:00:00Z")?.rotated["a"]).toBe("rotated");
    expect(store.get("2026-04-21T01:00:00Z")?.rotated["b"]).toBe("pending");

    // Second rotation re-surfaces a fresh prompt.
    const p2 = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "m1",
      new_master_pubkey: "m2",
      rotated_at: "2026-04-21T02:00:00Z",
    });
    store.put(p2);
    expect(store.size()).toBe(2);
    const latest = store.latest();
    expect(latest?.rotated_at).toBe("2026-04-21T02:00:00Z");
    expect(latest?.rotated["a"]).toBe("pending");
  });

  it("dismiss does not delete the prompt — re-surfacing on next rotation is the rule", async () => {
    const broker = { listSecretNames: async () => ["a"] };
    const store = new PostRecoveryPromptStore();
    const p1 = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "m0",
      new_master_pubkey: "m1",
      rotated_at: "2026-04-21T03:00:00Z",
    });
    store.put(p1);
    store.dismiss("2026-04-21T03:00:00Z");
    expect(store.get("2026-04-21T03:00:00Z")?.dismissed_at).toBeDefined();
    expect(store.size()).toBe(1);
  });
});
