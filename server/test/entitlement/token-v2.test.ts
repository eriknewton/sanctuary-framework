/**
 * Fleet entitlement v2 (license schema) — offline verify/resolve, fail-closed.
 *
 * These tests are the Definition-of-Done for the v2 license path (PR-1). They
 * prove:
 *
 *  1. A v2 round-trip surfaces every enforcement field on a granted resolution.
 *  2. Tampering ANY signed field (tier, entitledCount, featureFlags, subject,
 *     period, notAfter, graceUntil, licenseId, issuer, pricingUnit) flips
 *     verification to `bad_signature` → community, never a fabricated paid
 *     capability.
 *  3. featureFlags are order/dupe independent under the signature, but a
 *     genuinely different set does NOT verify.
 *  4. The validity window + 14-day-style grace semantics (before/in/grace/after)
 *     resolve correctly, with a non-finite clock denying as in v1.
 *  5. v1 tokens still resolve EXACTLY as before (byte-stable regression), and a
 *     v1 grant's resolution key set is unchanged (no leaked v2 fields).
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
  ENTITLEMENT_TOKEN_VERSION,
  ENTITLEMENT_TOKEN_VERSION_V2,
  buildEntitlementMessage,
  buildEntitlementMessageV2,
  resolveEntitlement,
  tierAtLeast,
  type EntitlementClaims,
  type EntitlementClaimsV2,
  type EntitlementToken,
} from "../../src/entitlement/index.js";

const issuer = generateKeypair();
const wrongIssuer = generateKeypair();
const NOW = 1_800_000_000;
const ISSUER_ID = "issuer-fingerprint-abc123";

function signV2(
  claims: EntitlementClaimsV2,
  privateKey: Uint8Array = issuer.privateKey,
): EntitlementToken {
  const message = buildEntitlementMessageV2(claims);
  return { claims, signature: toBase64url(ed25519.sign(message, privateKey)) };
}

function v2Claims(
  overrides: Partial<EntitlementClaimsV2> = {},
): EntitlementClaimsV2 {
  return {
    version: ENTITLEMENT_TOKEN_VERSION_V2,
    licenseId: "lic-0001",
    subject: "fleet-op-1",
    tier: "fleet",
    pricingUnit: "node",
    entitledCount: 25,
    period: "monthly",
    notBefore: NOW - 100,
    notAfter: NOW + 100,
    graceUntil: NOW + 100 + 14 * 86_400,
    featureFlags: ["roster", "policy-dist"],
    issuer: ISSUER_ID,
    ...overrides,
  };
}

describe("resolveEntitlement v2 — success path surfaces enforcement fields", () => {
  it("grants and surfaces every signed enforcement field", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims()),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(true);
    expect(result.tier).toBe("fleet");
    expect(result.entitledCount).toBe(25);
    expect(result.pricingUnit).toBe("node");
    expect(result.period).toBe("monthly");
    expect(result.licenseId).toBe("lic-0001");
    expect(result.issuer).toBe(ISSUER_ID);
    expect(result.featureFlags).toEqual(["policy-dist", "roster"]); // canonical order
    expect(result.graceUntil).toBe(NOW + 100 + 14 * 86_400);
    expect(result.graceActive).toBeUndefined(); // in-window, not in grace
    expect(result.reason).toBeUndefined();
  });

  it("surfaces unlimited (null) entitledCount and null grace", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ entitledCount: null, graceUntil: null })),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(true);
    expect(result.entitledCount).toBeNull();
    expect(result.graceUntil).toBeNull();
  });

  it("returns a fresh featureFlags array (consumer cannot mutate module state)", () => {
    const token = signV2(v2Claims());
    const a = resolveEntitlement({ token, issuerPublicKey: issuer.publicKey, now: NOW });
    a.featureFlags?.push("kill-safety");
    const b = resolveEntitlement({ token, issuerPublicKey: issuer.publicKey, now: NOW });
    expect(b.featureFlags).toEqual(["policy-dist", "roster"]);
  });
});

describe("resolveEntitlement v2 — tamper each signed field → bad_signature → community", () => {
  // Each case: sign a valid token, then mutate ONE signed field AFTER signing.
  const tamperCases: Array<{ name: string; mutate: (c: EntitlementClaimsV2) => EntitlementClaimsV2 }> = [
    { name: "tier raised", mutate: (c) => ({ ...c, tier: "enterprise" }) },
    { name: "entitledCount raised", mutate: (c) => ({ ...c, entitledCount: 9999 }) },
    { name: "entitledCount null->unlimited", mutate: (c) => ({ ...c, entitledCount: null }) },
    { name: "featureFlags added", mutate: (c) => ({ ...c, featureFlags: [...c.featureFlags, "console"] }) },
    { name: "subject swapped", mutate: (c) => ({ ...c, subject: "attacker-fleet" }) },
    { name: "period swapped", mutate: (c) => ({ ...c, period: "annual" }) },
    { name: "notAfter extended", mutate: (c) => ({ ...c, notAfter: c.notAfter + 999_999 }) },
    { name: "graceUntil extended", mutate: (c) => ({ ...c, graceUntil: (c.graceUntil ?? 0) + 999_999 }) },
    { name: "licenseId swapped", mutate: (c) => ({ ...c, licenseId: "lic-forged" }) },
    { name: "issuer swapped", mutate: (c) => ({ ...c, issuer: "issuer-forged" }) },
    { name: "pricingUnit swapped", mutate: (c) => ({ ...c, pricingUnit: "seat" }) },
  ];

  for (const tc of tamperCases) {
    it(`rejects tamper: ${tc.name}`, () => {
      const signed = signV2(v2Claims());
      const tampered: EntitlementToken = {
        claims: tc.mutate(signed.claims as EntitlementClaimsV2),
        signature: signed.signature,
      };
      const result = resolveEntitlement({
        token: tampered,
        issuerPublicKey: issuer.publicKey,
        now: NOW,
      });
      expect(result.granted).toBe(false);
      expect(result.tier).toBe(COMMUNITY_TIER);
      expect(result.reason).toBe("bad_signature");
      // Fail-closed: no enforcement field leaks on a denial.
      expect(result.entitledCount).toBeUndefined();
      expect(result.featureFlags).toBeUndefined();
      expect(tierAtLeast(result.tier, "team")).toBe(false);
    });
  }

  it("rejects a token signed by a different issuer", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims(), wrongIssuer.privateKey),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(false);
    expect(result.reason).toBe("bad_signature");
  });
});

describe("resolveEntitlement v2 — featureFlags order/dupe independence", () => {
  it("two logically-equal sets (different order + dupes) verify identically", () => {
    const a = signV2(v2Claims({ featureFlags: ["roster", "policy-dist"] }));
    // Sign a claims object with a DIFFERENT literal order + a duplicate; the
    // canonicalization must make the signed message identical, so `a`'s
    // signature verifies against this reordered claims object too.
    const reordered = v2Claims({ featureFlags: ["policy-dist", "roster", "roster"] });
    const crossToken: EntitlementToken = { claims: reordered, signature: a.signature };
    const result = resolveEntitlement({
      token: crossToken,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(true);
    expect(result.featureFlags).toEqual(["policy-dist", "roster"]);
  });

  it("a genuinely different set does NOT verify under another set's signature", () => {
    const a = signV2(v2Claims({ featureFlags: ["roster"] }));
    const different = v2Claims({ featureFlags: ["roster", "kill-safety"] });
    const result = resolveEntitlement({
      token: { claims: different, signature: a.signature },
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(false);
    expect(result.reason).toBe("bad_signature");
  });

  it("empty featureFlags round-trips", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ featureFlags: [] })),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(true);
    expect(result.featureFlags).toEqual([]);
  });
});

describe("resolveEntitlement v2 — window + grace semantics", () => {
  const nb = NOW - 100;
  const na = NOW; // expires exactly at NOW
  const grace = na + 14 * 86_400;

  it("before notBefore → not_yet_valid", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ notBefore: NOW + 1000, notAfter: NOW + 2000, graceUntil: NOW + 3000 })),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(false);
    expect(result.reason).toBe("not_yet_valid");
  });

  it("in-window → granted, no graceActive", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ notBefore: nb, notAfter: na, graceUntil: grace })),
      issuerPublicKey: issuer.publicKey,
      now: na, // inclusive
    });
    expect(result.granted).toBe(true);
    expect(result.graceActive).toBeUndefined();
  });

  it("inside grace window → granted + graceActive:true", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ notBefore: nb, notAfter: na, graceUntil: grace })),
      issuerPublicKey: issuer.publicKey,
      now: na + 5 * 86_400, // 5 days into grace
    });
    expect(result.granted).toBe(true);
    expect(result.graceActive).toBe(true);
    // Paid features stay live during grace.
    expect(result.tier).toBe("fleet");
    expect(result.featureFlags).toEqual(["policy-dist", "roster"]);
  });

  it("at graceUntil boundary (inclusive) → still granted + graceActive", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ notBefore: nb, notAfter: na, graceUntil: grace })),
      issuerPublicKey: issuer.publicKey,
      now: grace,
    });
    expect(result.granted).toBe(true);
    expect(result.graceActive).toBe(true);
  });

  it("one second past graceUntil → expired → community", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ notBefore: nb, notAfter: na, graceUntil: grace })),
      issuerPublicKey: issuer.publicKey,
      now: grace + 1,
    });
    expect(result.granted).toBe(false);
    expect(result.reason).toBe("expired");
    expect(result.tier).toBe(COMMUNITY_TIER);
  });

  it("graceUntil null, past notAfter → expired immediately (no grace)", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ notBefore: nb, notAfter: na, graceUntil: null })),
      issuerPublicKey: issuer.publicKey,
      now: na + 1,
    });
    expect(result.granted).toBe(false);
    expect(result.reason).toBe("expired");
  });

  it("non-finite clock (NaN) → expired even inside the window", () => {
    const result = resolveEntitlement({
      token: signV2(v2Claims({ notBefore: nb, notAfter: na, graceUntil: grace })),
      issuerPublicKey: issuer.publicKey,
      now: Number.NaN,
    });
    expect(result.granted).toBe(false);
    expect(result.reason).toBe("expired");
    expect(result.tier).toBe(COMMUNITY_TIER);
  });
});

describe("resolveEntitlement v2 — malformed shapes fail closed", () => {
  interface Bad {
    name: string;
    claims: Partial<Record<keyof EntitlementClaimsV2, unknown>>;
    reason: "malformed" | "unknown_tier";
  }
  const bads: Bad[] = [
    { name: "empty licenseId", claims: { licenseId: "" }, reason: "malformed" },
    { name: "empty subject", claims: { subject: "" }, reason: "malformed" },
    { name: "empty issuer", claims: { issuer: "" }, reason: "malformed" },
    { name: "bad pricingUnit", claims: { pricingUnit: "core" as never }, reason: "malformed" },
    { name: "bad period", claims: { period: "weekly" as never }, reason: "malformed" },
    { name: "negative entitledCount", claims: { entitledCount: -1 }, reason: "malformed" },
    { name: "non-integer entitledCount", claims: { entitledCount: 3.5 }, reason: "malformed" },
    { name: "inverted window", claims: { notBefore: NOW + 10, notAfter: NOW - 10 }, reason: "malformed" },
    { name: "graceUntil before notAfter", claims: { graceUntil: NOW - 5000 }, reason: "malformed" },
    { name: "featureFlags not array", claims: { featureFlags: "roster" as never }, reason: "malformed" },
    { name: "featureFlags has empty string", claims: { featureFlags: ["roster", ""] as never }, reason: "malformed" },
    { name: "unknown tier", claims: { tier: "root" as never }, reason: "unknown_tier" },
  ];

  for (const b of bads) {
    it(`fails closed: ${b.name}`, () => {
      // Build claims, sign the (possibly invalid) shape with the real issuer so
      // the failure is attributable to normalize, not to a signature mismatch.
      // For shapes that buildEntitlementMessageV2 refuses (bad featureFlags),
      // the resolve still denies without throwing.
      let token: EntitlementToken;
      const claims = v2Claims(b.claims as Partial<EntitlementClaimsV2>);
      try {
        token = signV2(claims);
      } catch {
        // buildEntitlementMessageV2 threw on the malformed set; attach a dummy
        // signature — resolve must still fail closed (normalize rejects first).
        token = { claims, signature: toBase64url(new Uint8Array(64)) };
      }
      const result = resolveEntitlement({
        token,
        issuerPublicKey: issuer.publicKey,
        now: NOW,
      });
      expect(result.granted).toBe(false);
      expect(result.tier).toBe(COMMUNITY_TIER);
      expect([b.reason, "bad_signature"]).toContain(result.reason);
    });
  }

  it("absent version → malformed", () => {
    const claims = { ...v2Claims() } as Record<string, unknown>;
    delete claims.version;
    const result = resolveEntitlement({
      token: { claims: claims as unknown as EntitlementClaimsV2, signature: toBase64url(new Uint8Array(64)) },
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(false);
    expect(result.reason).toBe("malformed");
  });
});

describe("resolveEntitlement — v1 tokens still resolve exactly as before (regression)", () => {
  function signV1(claims: EntitlementClaims): EntitlementToken {
    const message = buildEntitlementMessage(claims);
    return { claims, signature: toBase64url(ed25519.sign(message, issuer.privateKey)) };
  }
  const v1Claims: EntitlementClaims = {
    version: ENTITLEMENT_TOKEN_VERSION,
    subject: "fleet-op-1",
    tier: "team",
    notBefore: NOW - 100,
    notAfter: NOW + 100,
  };

  it("a valid v1 token grants with NO leaked v2 fields (key set unchanged)", () => {
    const result = resolveEntitlement({
      token: signV1(v1Claims),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(true);
    expect(result.tier).toBe("team");
    // The v1 grant surface must be exactly {tier, granted} — no v2 fields.
    expect(Object.keys(result).sort()).toEqual(["granted", "tier"]);
  });

  it("an expired v1 token still degrades to community", () => {
    const result = resolveEntitlement({
      token: signV1({ ...v1Claims, notBefore: NOW - 2000, notAfter: NOW - 1000 }),
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(false);
    expect(result.tier).toBe(COMMUNITY_TIER);
    expect(result.reason).toBe("expired");
  });

  it("a v1 token cannot be fed through the v2 path (version dispatch)", () => {
    // A v1-signed token whose version we bump to 2 must fail (the v2 normalize
    // rejects the missing v2 fields, and the signature covers v1 anyway).
    const v1 = signV1(v1Claims);
    const spoofed: EntitlementToken = {
      claims: { ...(v1.claims as EntitlementClaims), version: 2 } as unknown as EntitlementClaimsV2,
      signature: v1.signature,
    };
    const result = resolveEntitlement({
      token: spoofed,
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.granted).toBe(false);
    expect(result.tier).toBe(COMMUNITY_TIER);
  });
});
