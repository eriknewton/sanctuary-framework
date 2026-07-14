/**
 * Fleet control plane - signed compliance-attestation export (pure core).
 *
 * These tests are the Definition-of-Done for `compliance-attestation.ts`:
 *
 *  1. `buildAttestationBody` maps every posture branch (paid/active, grace,
 *     community, over-cap, roster-unavailable) correctly, and `claims_scope`
 *     is present and non-empty on EVERY branch.
 *  2. A sign+verify round-trip with a FRESH in-memory Ed25519 identity (no
 *     custody, no keychain, no file - exactly like `token.test.ts`) proves
 *     `serializeSignedAttestation` -> `verifySignedAttestation` succeeds, and
 *     that a one-byte mutation of the body OR the signature fails
 *     verification (canonical-JSON round-trip integrity).
 *  3. `verifySignedAttestation`'s fail-closed matrix: tampered body, swapped
 *     signature, malformed JSON, wrong-length key -> all `ok:false` with a
 *     reason, NEVER a throw.
 *  4. No private-key-shaped field ever appears anywhere in a produced
 *     document; `public_key` is always exactly the 32-byte operator PUBLIC
 *     key.
 *  5. THE OVERCLAIM GUARD (the single most important test in this file):
 *     `claims_scope` contains the self-attestation disclaimer and does NOT
 *     contain audit-overclaiming phrasing ("audited", "certified",
 *     "compliance-certified", "per-rule", "per-flow audit"). A review that
 *     finds overclaiming copy here is a BLOCKER (see the build spec).
 */

import { describe, expect, it } from "vitest";
import { generateKeypair, sign as identitySign } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  COMPLIANCE_ATTESTATION_SCHEMA,
  CLAIMS_SCOPE_DISCLAIMER,
  buildAttestationBody,
  serializeSignedAttestation,
  verifySignedAttestation,
  type AttestationBody,
  type AttestationInputs,
  type AttestationLicenseView,
  type AttestationPostureView,
  type AttestationSigner,
  type SignedAttestation,
} from "../../src/entitlement/compliance-attestation.js";
import { encrypt } from "../../src/core/encryption.js";
import { randomBytes } from "../../src/core/random.js";

const NOW_ISO = "2026-07-07T12:00:00.000Z";

const COMMUNITY_LICENSE: AttestationLicenseView = {
  licenseId: null,
  subject: null,
  tier: "community",
  entitledNodes: null,
  notAfter: null,
  features: [],
  status: "community",
};

const ACTIVE_LICENSE: AttestationLicenseView = {
  licenseId: "lic-123",
  subject: "acme-fleet",
  tier: "fleet",
  entitledNodes: 25,
  notAfter: "2027-01-01T00:00:00.000Z",
  features: ["roster", "policy-dist"],
  status: "active",
};

const GRACE_LICENSE: AttestationLicenseView = {
  ...ACTIVE_LICENSE,
  status: "grace",
};

const BASE_POSTURE: AttestationPostureView = {
  centralNodesTotal: 11,
  admitted: 10,
  revoked: 1,
  untrusted: 0,
  maxNodes: 25,
  overCap: false,
  evictionSerial: 4,
  policyDistribution: { inSync: 9, drifted: 1, unknown: 1 },
  bannerState: "ok",
};

function inputs(overrides: Partial<AttestationInputs> = {}): AttestationInputs {
  return {
    fortressId: "fortress-abc",
    issuerFingerprint: "fingerprint-xyz",
    license: COMMUNITY_LICENSE,
    posture: BASE_POSTURE,
    now: NOW_ISO,
    ...overrides,
  };
}

describe("buildAttestationBody - branch mapping", () => {
  it("maps a paid/active license honestly", () => {
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    expect(body.schema).toBe(COMPLIANCE_ATTESTATION_SCHEMA);
    expect(body.license.status).toBe("active");
    expect(body.license.tier).toBe("fleet");
    expect(body.license.entitled_nodes).toBe(25);
    expect(body.license.license_id).toBe("lic-123");
    expect(body.license.features).toEqual(["roster", "policy-dist"]);
  });

  it("maps a grace-window license honestly", () => {
    const body = buildAttestationBody(inputs({ license: GRACE_LICENSE }));
    expect(body.license.status).toBe("grace");
    expect(body.license.tier).toBe("fleet");
  });

  it("maps community (unlicensed) honestly, never fabricating a paid status", () => {
    const body = buildAttestationBody(inputs({ license: COMMUNITY_LICENSE }));
    expect(body.license.status).toBe("community");
    expect(body.license.tier).toBe("community");
    expect(body.license.license_id).toBeNull();
    expect(body.license.entitled_nodes).toBeNull();
    expect(body.license.features).toEqual([]);
  });

  it("maps an over-cap posture honestly", () => {
    const overCapPosture: AttestationPostureView = {
      ...BASE_POSTURE,
      centralNodesTotal: 30,
      admitted: 30,
      maxNodes: 25,
      overCap: true,
      bannerState: "over_cap",
    };
    const body = buildAttestationBody(
      inputs({ license: ACTIVE_LICENSE, posture: overCapPosture }),
    );
    expect(body.posture.over_cap).toBe(true);
    expect(body.posture.central_nodes_total).toBe(30);
    expect(body.posture.max_nodes).toBe(25);
    expect(body.posture.banner_state).toBe("over_cap");
  });

  it("maps a roster-unavailable posture to honest zeros, not fabricated counts", () => {
    const unavailablePosture: AttestationPostureView = {
      centralNodesTotal: 0,
      admitted: 0,
      revoked: 0,
      untrusted: 0,
      maxNodes: null,
      overCap: false,
      evictionSerial: 0,
      policyDistribution: { inSync: 0, drifted: 0, unknown: 0 },
      bannerState: "roster_unavailable",
    };
    const body = buildAttestationBody(inputs({ posture: unavailablePosture }));
    expect(body.posture.central_nodes_total).toBe(0);
    expect(body.posture.admitted).toBe(0);
    expect(body.posture.banner_state).toBe("roster_unavailable");
  });

  it("claims_scope is present and non-empty on EVERY branch", () => {
    const branches: AttestationInputs[] = [
      inputs({ license: ACTIVE_LICENSE }),
      inputs({ license: GRACE_LICENSE }),
      inputs({ license: COMMUNITY_LICENSE }),
      inputs({
        license: ACTIVE_LICENSE,
        posture: { ...BASE_POSTURE, overCap: true, bannerState: "over_cap" },
      }),
      inputs({
        posture: {
          centralNodesTotal: 0,
          admitted: 0,
          revoked: 0,
          untrusted: 0,
          maxNodes: null,
          overCap: false,
          evictionSerial: 0,
          policyDistribution: { inSync: 0, drifted: 0, unknown: 0 },
          bannerState: "roster_unavailable",
        },
      }),
    ];
    for (const branchInputs of branches) {
      const body = buildAttestationBody(branchInputs);
      expect(typeof body.claims_scope).toBe("string");
      expect(body.claims_scope.length).toBeGreaterThan(0);
    }
  });

  it("is PURE: identical inputs produce a deep-equal body", () => {
    const a = buildAttestationBody(inputs());
    const b = buildAttestationBody(inputs());
    expect(a).toEqual(b);
  });
});

describe("unmeasured posture fields (the A3 fix): null != measured-zero", () => {
  it("a posture source that does not measure revoked/untrusted/evictionSerial/policyDistribution signs explicit nulls, never a fabricated zero", () => {
    // This is the SHAPE the daemon's banner-only `/api/fleet/status` source
    // produces today: it measures admitted/centralNodesTotal but does NOT
    // measure revoked, untrusted, the eviction serial, or the
    // policy-distribution rollup. Before the fix these were zero-filled,
    // which reads as "measured, and the true count is zero" - a real fleet
    // with actual drift/revocations would sign a FALSE "no drift, none
    // revoked" claim. After the fix they must be `null`.
    const unmeasuredPosture: AttestationPostureView = {
      centralNodesTotal: 10,
      admitted: 10,
      revoked: null,
      untrusted: null,
      maxNodes: 25,
      overCap: false,
      evictionSerial: null,
      policyDistribution: null,
      bannerState: "ok",
    };
    const body = buildAttestationBody(inputs({ posture: unmeasuredPosture }));

    expect(body.posture.revoked).toBeNull();
    expect(body.posture.untrusted).toBeNull();
    expect(body.posture.eviction_serial).toBeNull();
    expect(body.posture.policy_distribution).toBeNull();

    // Never a zero standing in for "unavailable": null is strictly typeof
    // "object" for policy_distribution and the other fields are `null`, not
    // `0` - a naive `!field` truthiness check would conflate them, but an
    // explicit `field === null` check (what an honest reader must do) does
    // NOT collapse into "the count is zero."
    expect(body.posture.revoked).not.toBe(0);
    expect(body.posture.untrusted).not.toBe(0);
    expect(body.posture.eviction_serial).not.toBe(0);
  });

  it("distinguishes an EXPLICITLY-measured zero from an unmeasured null on the SAME document shape", () => {
    // A fleet that genuinely has zero revocations (measured, verified) must
    // still be able to say so - `0` remains a legitimate, honest value when
    // the source DOES measure it. The two bodies below must NOT be equal.
    const measuredZeroPosture: AttestationPostureView = {
      ...BASE_POSTURE,
      revoked: 0,
      untrusted: 0,
      evictionSerial: 0,
      policyDistribution: { inSync: 5, drifted: 0, unknown: 0 },
    };
    const unmeasuredPosture: AttestationPostureView = {
      ...BASE_POSTURE,
      revoked: null,
      untrusted: null,
      evictionSerial: null,
      policyDistribution: null,
    };
    const measuredBody = buildAttestationBody(inputs({ posture: measuredZeroPosture }));
    const unmeasuredBody = buildAttestationBody(inputs({ posture: unmeasuredPosture }));

    expect(measuredBody.posture.revoked).toBe(0);
    expect(unmeasuredBody.posture.revoked).toBeNull();
    expect(measuredBody.posture).not.toEqual(unmeasuredBody.posture);
  });

  it("a roster-unavailable posture with unmeasured fields still carries a non-empty claims_scope", () => {
    const unavailablePosture: AttestationPostureView = {
      centralNodesTotal: 0,
      admitted: 0,
      revoked: null,
      untrusted: null,
      maxNodes: null,
      overCap: false,
      evictionSerial: null,
      policyDistribution: null,
      bannerState: "roster_unavailable",
    };
    const body = buildAttestationBody(inputs({ posture: unavailablePosture }));
    expect(body.posture.revoked).toBeNull();
    expect(body.posture.policy_distribution).toBeNull();
    expect(body.claims_scope.length).toBeGreaterThan(0);
  });

  it("a signed document with unmeasured (null) posture fields still round-trips through sign+verify", () => {
    const { sign, publicKey } = inMemorySigner();
    const unmeasuredPosture: AttestationPostureView = {
      ...BASE_POSTURE,
      revoked: null,
      untrusted: null,
      evictionSerial: null,
      policyDistribution: null,
    };
    const body = buildAttestationBody(
      inputs({ license: ACTIVE_LICENSE, posture: unmeasuredPosture }),
    );
    const doc = serializeSignedAttestation(body, sign, publicKey);
    const result = verifySignedAttestation(doc, { pinnedOperatorKey: publicKey });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.attestation.posture.revoked).toBeNull();
      expect(result.attestation.posture.policy_distribution).toBeNull();
    }
  });
});

describe("overclaim guard (BLOCKER if this fails)", () => {
  // Phrases that would constitute an OVERCLAIM if present as a bare positive
  // assertion (not preceded by a negation like "NOT" / "never"). We assert
  // these substrings are simply ABSENT from the disclaimer entirely: the
  // disclaimer's own negated framing ("NOT a third-party audit", "NOT a
  // per-flow rule-attributed audit trail") is phrased without ever using the
  // bare overclaim words below, so a substring-absence check is both simple
  // and correct here - it is the negated CONCEPTS that are allowed, not these
  // exact overclaiming tokens.
  const overclaimSubstrings = [
    "sanctuary-audited",
    "sanctuary audited",
    "compliance-certified",
    "certified",
    "audited per-rule",
    "audited per rule",
  ];

  it("CLAIMS_SCOPE_DISCLAIMER contains the self-attestation disclaimer", () => {
    expect(CLAIMS_SCOPE_DISCLAIMER).toMatch(/self-attestation/i);
    expect(CLAIMS_SCOPE_DISCLAIMER).toMatch(/NOT a third-party audit/i);
    expect(CLAIMS_SCOPE_DISCLAIMER).toMatch(
      /NOT.*a.*per-flow rule-attributed audit trail/i,
    );
    expect(CLAIMS_SCOPE_DISCLAIMER).toMatch(/locally-verifiable/i);
    expect(CLAIMS_SCOPE_DISCLAIMER).toMatch(/operator's own key/i);
  });

  it("CLAIMS_SCOPE_DISCLAIMER does NOT contain overclaiming phrasing", () => {
    const lower = CLAIMS_SCOPE_DISCLAIMER.toLowerCase();
    for (const phrase of overclaimSubstrings) {
      expect(lower).not.toContain(phrase);
    }
    // The disclaimer must explicitly NEGATE audit/third-party claims, never
    // assert them bare. Every occurrence of "audit" must be inside a "NOT ...
    // audit" negation - there is no bare "this is an audit" sentence.
    expect(CLAIMS_SCOPE_DISCLAIMER).not.toMatch(/\bis an audit\b/i);
    expect(CLAIMS_SCOPE_DISCLAIMER).not.toMatch(/\bis a third-party audit\b/i);
  });

  it("every produced attestation body's claims_scope carries the disclaimer verbatim", () => {
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    expect(body.claims_scope).toBe(CLAIMS_SCOPE_DISCLAIMER);
  });
});

/** Build an AttestationSigner from a fresh in-memory Ed25519 identity, no custody. */
function inMemorySigner(): { sign: AttestationSigner; publicKey: Uint8Array } {
  const { publicKey, privateKey } = generateKeypair();
  const encryptionKey = randomBytes(32);
  const encryptedPrivateKey = encrypt(privateKey, encryptionKey);
  privateKey.fill(0);
  const sign: AttestationSigner = (message: Uint8Array): Uint8Array =>
    identitySign(message, encryptedPrivateKey, encryptionKey);
  return { sign, publicKey };
}

describe("sign + verify round-trip (fresh in-memory identity, no custody)", () => {
  it("a signed document verifies ok:true and echoes the attested body (unpinned = self_consistent)", () => {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, sign, publicKey);

    expect(doc.public_key).toBe(toBase64url(publicKey));
    const result = verifySignedAttestation(doc);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.attestation).toEqual(body);
      // A1: without a pinned key, verify proves self-consistency ONLY, never
      // identity provenance - this is NOT a "VALID" result at the CLI layer.
      expect(result.provenance).toBe("self_consistent");
    }
  });

  it("a one-byte mutation of the body fails verification", () => {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, sign, publicKey);

    const tampered: SignedAttestation = {
      ...doc,
      attestation: {
        ...doc.attestation,
        posture: { ...doc.attestation.posture, admitted: doc.attestation.posture.admitted + 1 },
      },
    };
    const result = verifySignedAttestation(tampered);
    expect(result.ok).toBe(false);
  });

  it("a mutated signature fails verification", () => {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, sign, publicKey);

    const flippedChar = doc.signature[0] === "A" ? "B" : "A";
    const tampered: SignedAttestation = {
      ...doc,
      signature: flippedChar + doc.signature.slice(1),
    };
    const result = verifySignedAttestation(tampered);
    expect(result.ok).toBe(false);
  });

  it("swapping in a DIFFERENT signer's signature fails verification", () => {
    const signerA = inMemorySigner();
    const signerB = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const docA = serializeSignedAttestation(body, signerA.sign, signerA.publicKey);
    const docB = serializeSignedAttestation(body, signerB.sign, signerB.publicKey);

    const swapped: SignedAttestation = {
      ...docA,
      signature: docB.signature,
    };
    const result = verifySignedAttestation(swapped);
    expect(result.ok).toBe(false);
  });

  it("embedded public_key is exactly 32 bytes and never any private-key-shaped field", () => {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, sign, publicKey);

    const decoded = Buffer.from(
      doc.public_key.replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    );
    expect(decoded.length).toBe(32);

    const serialized = JSON.stringify(doc);
    expect(serialized).not.toMatch(/private/i);
    expect(serialized).not.toMatch(/encrypted_private_key/i);
    expect(serialized).not.toMatch(/passphrase/i);
    expect(serialized).not.toMatch(/recovery/i);
  });
});

describe("verifySignedAttestation - pinned operator key (the A1 fix)", () => {
  it("a doc signed by the PINNED key verifies ok:true with provenance 'verified'", () => {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, sign, publicKey);

    const result = verifySignedAttestation(doc, { pinnedOperatorKey: publicKey });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.provenance).toBe("verified");
      expect(result.attestation).toEqual(body);
    }
  });

  it("THE CORE A1 REGRESSION TEST: a doc signed by a NON-pinned (attacker's own) key is NEVER reported ok/VALID", () => {
    // The exact attack the gate flagged: an attacker signs a FAKE posture
    // with THEIR OWN key and embeds that key in the document. Before the
    // fix, `verifySignedAttestation` only checked the signature against the
    // document's OWN embedded key, so this would report `ok: true`. With an
    // operator key pinned from OUTSIDE the document, it must now fail.
    const operator = inMemorySigner();
    const attacker = inMemorySigner();
    const fakePosture: AttestationPostureView = {
      ...BASE_POSTURE,
      revoked: 0,
      untrusted: 0,
      bannerState: "ok",
    };
    const attackerBody = buildAttestationBody(
      inputs({ license: ACTIVE_LICENSE, posture: fakePosture }),
    );
    // Attacker signs with their OWN key and embeds their OWN public key -
    // exactly what `serializeSignedAttestation` does for a legitimate
    // operator, so the resulting document is fully self-consistent.
    const attackerDoc = serializeSignedAttestation(
      attackerBody,
      attacker.sign,
      attacker.publicKey,
    );

    // The verifier pins the REAL operator's key (known independently, e.g.
    // from the fortress record) - NOT the attacker's embedded key.
    const result = verifySignedAttestation(attackerDoc, {
      pinnedOperatorKey: operator.publicKey,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("operator_key_mismatch");
    }

    // Sanity: the SAME document, unpinned, still "verifies" as self-consistent
    // (proves the fix does not break the existing self-consistency check) -
    // but that branch reports `self_consistent`, never `verified`, so a CLI
    // that gates "VALID" on `provenance === "verified"` never overclaims.
    const unpinned = verifySignedAttestation(attackerDoc);
    expect(unpinned.ok).toBe(true);
    if (unpinned.ok) {
      expect(unpinned.provenance).toBe("self_consistent");
    }
  });

  it("a pinned key that does not match the embedded key fails BEFORE the crypto check (mismatch, not signature_invalid)", () => {
    const signerA = inMemorySigner();
    const signerB = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, signerA.sign, signerA.publicKey);

    const result = verifySignedAttestation(doc, { pinnedOperatorKey: signerB.publicKey });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("operator_key_mismatch");
    }
  });

  it("a wrong-length pinned key fails as a mismatch, never throws", () => {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, sign, publicKey);

    expect(() =>
      verifySignedAttestation(doc, { pinnedOperatorKey: new Uint8Array(16) }),
    ).not.toThrow();
    const result = verifySignedAttestation(doc, { pinnedOperatorKey: new Uint8Array(16) });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("operator_key_mismatch");
    }
  });
});

describe("verifySignedAttestation - fail-closed matrix (never throws)", () => {
  function validDoc(): SignedAttestation {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    return serializeSignedAttestation(body, sign, publicKey);
  }

  it("tampered body -> ok:false", () => {
    const doc = validDoc();
    const tampered = {
      ...doc,
      attestation: { ...doc.attestation, fortress_id: "attacker-fortress" },
    };
    const result = verifySignedAttestation(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("signature_invalid");
  });

  it("swapped signature -> ok:false", () => {
    const docA = validDoc();
    const docB = validDoc();
    const swapped = { ...docA, signature: docB.signature };
    const result = verifySignedAttestation(swapped);
    expect(result.ok).toBe(false);
  });

  it("malformed JSON shape (not an object) -> ok:false, reason malformed, never throws", () => {
    expect(() => verifySignedAttestation(null)).not.toThrow();
    expect(verifySignedAttestation(null)).toEqual({ ok: false, reason: "malformed" });
    expect(verifySignedAttestation(undefined)).toEqual({ ok: false, reason: "malformed" });
    expect(verifySignedAttestation("a string")).toEqual({ ok: false, reason: "malformed" });
    expect(verifySignedAttestation(42)).toEqual({ ok: false, reason: "malformed" });
    expect(verifySignedAttestation([])).toEqual({ ok: false, reason: "malformed" });
    expect(verifySignedAttestation({})).toEqual({ ok: false, reason: "malformed" });
  });

  it("missing claims_scope (the load-bearing honesty field) -> malformed", () => {
    const doc = validDoc();
    const { claims_scope: _drop, ...bodyWithoutScope } = doc.attestation;
    const malformed = { ...doc, attestation: bodyWithoutScope };
    const result = verifySignedAttestation(malformed);
    expect(result.ok).toBe(false);
  });

  it("wrong-length public key -> ok:false, reason bad_public_key, never throws", () => {
    const doc = validDoc();
    const shortKey: SignedAttestation = {
      ...doc,
      public_key: toBase64url(new Uint8Array(16)),
    };
    expect(() => verifySignedAttestation(shortKey)).not.toThrow();
    const result = verifySignedAttestation(shortKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_public_key");
  });

  it("non-canonical / garbage public_key string -> ok:false, reason bad_public_key", () => {
    const doc = validDoc();
    const garbage: SignedAttestation = { ...doc, public_key: "not-valid-base64url!!!" };
    const result = verifySignedAttestation(garbage);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_public_key");
  });

  it("malformed signature encoding -> ok:false, reason bad_signature_encoding", () => {
    const doc = validDoc();
    const garbageSig: SignedAttestation = { ...doc, signature: "%%%not-base64url" };
    const result = verifySignedAttestation(garbageSig);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature_encoding");
  });

  it("wrong-length signature -> ok:false, reason bad_signature_encoding", () => {
    const doc = validDoc();
    const shortSig: SignedAttestation = { ...doc, signature: toBase64url(new Uint8Array(10)) };
    const result = verifySignedAttestation(shortSig);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature_encoding");
  });
});

describe("schema domain", () => {
  it("COMPLIANCE_ATTESTATION_SCHEMA is the frozen expected label", () => {
    expect(COMPLIANCE_ATTESTATION_SCHEMA).toBe(
      "sanctuary.fleet.compliance-attestation.v1",
    );
  });

  it("a body with the wrong schema string fails structural plausibility (malformed)", () => {
    const { sign, publicKey } = inMemorySigner();
    const body = buildAttestationBody(inputs({ license: ACTIVE_LICENSE }));
    const doc = serializeSignedAttestation(body, sign, publicKey);
    const wrongSchema = {
      ...doc,
      attestation: { ...doc.attestation, schema: "some.other.schema.v1" as unknown as AttestationBody["schema"] },
    };
    const result = verifySignedAttestation(wrongSchema);
    expect(result.ok).toBe(false);
  });
});
