/**
 * Fleet entitlement (S1 scaffold) - offline verify/resolve fail-closed core.
 *
 * These tests are the Definition-of-Done for the S1 verify/resolve core:
 *
 *  1. A table-driven battery proves that absent, malformed, unknown-tier,
 *     bad-signature, tampered, not-yet-valid, and expired tokens ALL resolve
 *     to the community tier and NEVER report `granted: true`. The only path
 *     that grants a paid tier is a well-formed, correctly-signed, in-window
 *     token.
 *  2. A no-key-leak test proves that no private key ever appears in a
 *     resolution result or its serialization (Hard Rule 6).
 *
 * Fixtures sign with a real Ed25519 issuer key so a regression that drops or
 * weakens signature verification fails here rather than passing silently.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  COMMUNITY_TIER,
  ENTITLEMENT_TIERS,
  ENTITLEMENT_TOKEN_VERSION,
  buildEntitlementMessage,
  resolveEntitlement,
  tierAtLeast,
  tierRank,
  type EntitlementClaims,
  type EntitlementDenyReason,
  type EntitlementToken,
} from "../../src/entitlement/index.js";

const issuer = generateKeypair();
const NOW = 1_800_000_000; // arbitrary fixed "current" Unix second

/** Sign claims with a raw Ed25519 private key and package a token. */
function signToken(
  claims: EntitlementClaims,
  privateKey: Uint8Array = issuer.privateKey,
): EntitlementToken {
  const message = buildEntitlementMessage(claims);
  const signature = ed25519.sign(message, privateKey);
  return { claims, signature: toBase64url(signature) };
}

function paidClaims(
  overrides: Partial<EntitlementClaims> = {},
): EntitlementClaims {
  return {
    version: ENTITLEMENT_TOKEN_VERSION,
    subject: "fleet-op-1",
    tier: "fleet",
    notBefore: NOW - 100,
    notAfter: NOW + 100,
    ...overrides,
  };
}

describe("resolveEntitlement - success path", () => {
  it("grants the claimed paid tier for a well-formed, signed, in-window token", () => {
    const result = resolveEntitlement({
      token: signToken(paidClaims()),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(true);
    expect(result.tier).toBe("fleet");
    expect(result.reason).toBeUndefined();
  });

  it("grants each paid tier when correctly signed and in window", () => {
    for (const tier of ENTITLEMENT_TIERS) {
      const result = resolveEntitlement({
        token: signToken(paidClaims({ tier })),
        issuerPublicKey: issuer.publicKey,
        now: NOW,
      });
      expect(result.granted).toBe(true);
      expect(result.tier).toBe(tier);
    }
  });
});

describe("resolveEntitlement - fail-closed to community (table-driven)", () => {
  interface FailCase {
    name: string;
    token: EntitlementToken | null | undefined;
    now?: number;
    expectedReason: EntitlementDenyReason;
  }

  const wrongIssuer = generateKeypair();

  // A token whose signature is valid but was made by a DIFFERENT issuer.
  const foreignSigned = signToken(paidClaims(), wrongIssuer.privateKey);

  // A token that was validly signed, then had a claim tampered AFTER signing.
  const tampered = signToken(paidClaims({ tier: "community" }));
  const tamperedToPaid: EntitlementToken = {
    claims: { ...tampered.claims, tier: "enterprise" },
    signature: tampered.signature,
  };

  const cases: FailCase[] = [
    { name: "absent (null)", token: null, expectedReason: "absent" },
    {
      name: "absent (undefined)",
      token: undefined,
      expectedReason: "absent",
    },
    {
      name: "malformed - wrong version",
      token: signToken(paidClaims({ version: 999 })),
      expectedReason: "malformed",
    },
    {
      name: "malformed - empty subject",
      token: signToken(paidClaims({ subject: "" })),
      expectedReason: "malformed",
    },
    {
      name: "malformed - inverted window",
      token: signToken(paidClaims({ notBefore: NOW + 10, notAfter: NOW - 10 })),
      expectedReason: "malformed",
    },
    {
      name: "unknown tier",
      token: signToken(
        paidClaims({ tier: "root" as unknown as EntitlementClaims["tier"] }),
      ),
      expectedReason: "unknown_tier",
    },
    {
      name: "bad signature - signed by a different issuer",
      token: foreignSigned,
      expectedReason: "bad_signature",
    },
    {
      // A non-base64url signature decodes (leniently) to a wrong-length byte
      // string, so it is rejected as a bad signature. Either way it is a
      // denial that resolves to community; the reason is a signature failure.
      name: "bad signature - not valid base64url",
      token: { claims: paidClaims(), signature: "!!!not-base64url!!!" },
      expectedReason: "bad_signature",
    },
    {
      name: "bad signature - wrong length",
      token: { claims: paidClaims(), signature: toBase64url(new Uint8Array(10)) },
      expectedReason: "bad_signature",
    },
    {
      name: "tampered - tier raised after signing",
      token: tamperedToPaid,
      expectedReason: "bad_signature",
    },
    {
      name: "not yet valid",
      token: signToken(paidClaims({ notBefore: NOW + 1000, notAfter: NOW + 2000 })),
      expectedReason: "not_yet_valid",
    },
    {
      name: "expired",
      token: signToken(paidClaims({ notBefore: NOW - 2000, notAfter: NOW - 1000 })),
      expectedReason: "expired",
    },
  ];

  for (const c of cases) {
    it(`resolves to community and never grants: ${c.name}`, () => {
      const result = resolveEntitlement({
        token: c.token,
        issuerPublicKey: issuer.publicKey,
        now: c.now ?? NOW,
      });
      expect(result.tier).toBe(COMMUNITY_TIER);
      expect(result.granted).toBe(false);
      expect(result.reason).toBe(c.expectedReason);
      // Safe-degrade invariant: never above the community floor on failure.
      expect(tierRank(result.tier)).toBe(tierRank(COMMUNITY_TIER));
      expect(tierAtLeast(result.tier, "team")).toBe(false);
    });
  }

  it("a boundary flip of one second past notAfter expires the grant", () => {
    const claims = paidClaims({ notBefore: NOW - 100, notAfter: NOW });
    const valid = resolveEntitlement({
      token: signToken(claims),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(valid.granted).toBe(true);

    const expired = resolveEntitlement({
      token: signToken(claims),
      issuerPublicKey: issuer.publicKey,
      now: NOW + 1,
    });
    expect(expired.granted).toBe(false);
    expect(expired.tier).toBe(COMMUNITY_TIER);
  });
});

describe("resolveEntitlement - no key material ever leaks (Hard Rule 6)", () => {
  it("never returns or serializes the issuer private key", () => {
    const result = resolveEntitlement({
      token: signToken(paidClaims()),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });

    const serialized = JSON.stringify(result);
    const privHex = Buffer.from(issuer.privateKey).toString("hex");
    const privB64 = toBase64url(issuer.privateKey);

    expect(serialized).not.toContain(privHex);
    expect(serialized).not.toContain(privB64);

    // The result surface is exactly {tier, granted, reason?} - no key fields.
    expect(Object.keys(result).sort()).toEqual(["granted", "tier"]);
  });

  it("failure resolutions expose no key material either", () => {
    const result = resolveEntitlement({
      token: null,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    const serialized = JSON.stringify(result);
    const privHex = Buffer.from(issuer.privateKey).toString("hex");
    expect(serialized).not.toContain(privHex);
    expect(Object.keys(result).sort()).toEqual(["granted", "reason", "tier"]);
  });
});
