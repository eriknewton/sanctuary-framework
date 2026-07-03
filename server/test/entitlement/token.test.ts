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

  // A correctly-signed, in-window token whose base64url signature has been
  // made NON-CANONICAL (suffixed "!", padding "==", or embedded whitespace).
  // A lenient decoder collapses all of these back to the same 64 valid bytes,
  // so without a strict decode gate they verify and GRANT the paid tier
  // fail-open. Each must resolve to community with reason "bad_signature".
  const canonicalSigned = signToken(paidClaims());
  const canonicalSig = canonicalSigned.signature;
  const nonCanonicalSig = (suffix: string, prefixInsert?: string): string =>
    prefixInsert === undefined
      ? canonicalSig + suffix
      : canonicalSig.slice(0, 4) + prefixInsert + canonicalSig.slice(4);

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
      // A non-base64url signature is rejected by the strict decode gate
      // before verify, resolving to community as a signature failure.
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
      // Fail-open regression: valid signature bytes with a "!" suffix. A
      // lenient decoder drops the "!" and verifies; the strict gate rejects.
      name: "bad signature - valid bytes, non-canonical '!' suffix",
      token: { claims: paidClaims(), signature: nonCanonicalSig("!") },
      expectedReason: "bad_signature",
    },
    {
      // Fail-open regression: valid signature bytes with "==" padding. The
      // canonical no-padding form omits it; a lenient decoder tolerates it.
      name: "bad signature - valid bytes, non-canonical '==' padding",
      token: { claims: paidClaims(), signature: nonCanonicalSig("==") },
      expectedReason: "bad_signature",
    },
    {
      // Fail-open regression: valid signature bytes with a single "=" pad.
      name: "bad signature - valid bytes, non-canonical '=' padding",
      token: { claims: paidClaims(), signature: nonCanonicalSig("=") },
      expectedReason: "bad_signature",
    },
    {
      // Fail-open regression: valid signature bytes with an embedded newline.
      // A lenient decoder strips ASCII whitespace before decoding.
      name: "bad signature - valid bytes, embedded newline",
      token: { claims: paidClaims(), signature: nonCanonicalSig("", "\n") },
      expectedReason: "bad_signature",
    },
    {
      // Fail-open regression: valid signature bytes with an embedded space.
      name: "bad signature - valid bytes, embedded space",
      token: { claims: paidClaims(), signature: nonCanonicalSig("", " ") },
      expectedReason: "bad_signature",
    },
    {
      // Sanity anchor: the same signature UNMODIFIED grants, proving the
      // cases above fail solely on the non-canonical encoding, not bad bytes.
      // (Asserted directly below the table as well.)
      name: "bad signature - trailing whitespace suffix",
      token: { claims: paidClaims(), signature: nonCanonicalSig("\t") },
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
      // Safe-degrade invariant: exactly the community floor, never above it.
      expect(result.tier).toBe(COMMUNITY_TIER);
      expect(tierAtLeast(result.tier, "team")).toBe(false);
    });
  }

  it("the same signature bytes UNMODIFIED grant (non-canonical cases fail only on encoding)", () => {
    const control = resolveEntitlement({
      token: { claims: paidClaims(), signature: canonicalSig },
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(control.granted).toBe(true);
    expect(control.tier).toBe("fleet");
  });

  it("denies an otherwise-valid token on a non-finite clock (NaN)", () => {
    // Regression: a NaN clock makes both `now < notBefore` and
    // `now > notAfter` false, so without an explicit finite-clock guard an
    // out-of-window (or any) token would be granted. The window guarantee
    // must hold for every clock input.
    const result = resolveEntitlement({
      token: signToken(paidClaims()),
      issuerPublicKey: issuer.publicKey,
      now: Number.NaN,
    });
    expect(result.granted).toBe(false);
    expect(result.tier).toBe(COMMUNITY_TIER);
    expect(result.reason).toBe("expired");
  });

  it("denies an otherwise-valid token when the clock is undefined", () => {
    // `undefined` coerces to NaN in the numeric comparisons, so it must be
    // denied for the same reason as NaN.
    const result = resolveEntitlement({
      token: signToken(paidClaims()),
      issuerPublicKey: issuer.publicKey,
      now: undefined as unknown as number,
    });
    expect(result.granted).toBe(false);
    expect(result.tier).toBe(COMMUNITY_TIER);
    expect(result.reason).toBe("expired");
  });

  it("denies an otherwise-valid token on a positive-infinity clock", () => {
    const result = resolveEntitlement({
      token: signToken(paidClaims()),
      issuerPublicKey: issuer.publicKey,
      now: Number.POSITIVE_INFINITY,
    });
    expect(result.granted).toBe(false);
    expect(result.tier).toBe(COMMUNITY_TIER);
  });

  it("a mutating tier getter cannot raise the tier after signing (snapshot chokepoint)", () => {
    // HIGH regression: the claims object is untrusted. Here `tier` is an
    // ACCESSOR that returns "community" on the reads used to validate and
    // build the signing message (so a valid signature is produced over the
    // community claims), then flips to "enterprise" on the read that once
    // populated the returned resolution. Before the snapshot fix, the final
    // read at the return site saw "enterprise" and resolved
    // {tier:"enterprise", granted:true} despite the signature covering only
    // "community". After the fix, every downstream read uses the single frozen
    // snapshot, so this either resolves to "community" (granted) or fails
    // closed - it must NEVER return a paid tier.
    let reads = 0;
    const base = {
      version: ENTITLEMENT_TOKEN_VERSION,
      subject: "fleet-op-1",
      notBefore: NOW - 100,
      notAfter: NOW + 100,
    };
    const malicious = Object.defineProperty(
      { ...base } as Record<string, unknown>,
      "tier",
      {
        enumerable: true,
        get() {
          reads += 1;
          // First read (validation) and second read (canonical message) see
          // community; any later read sees enterprise.
          return reads <= 2 ? "community" : "enterprise";
        },
      },
    );

    // Sign the message that the SERVER will build for the community view. The
    // canonicalJson call inside buildEntitlementMessage reads `tier` once; we
    // reset the counter so signing sees community.
    reads = 0;
    const signMessage = buildEntitlementMessage({
      ...base,
      tier: "community",
    } as EntitlementClaims);
    const signature = ed25519.sign(signMessage, issuer.privateKey);

    reads = 0;
    const result = resolveEntitlement({
      token: {
        claims: malicious as unknown as EntitlementClaims,
        signature: toBase64url(signature),
      },
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });

    // The paid tier must never leak through the accessor.
    expect(result.tier).not.toBe("enterprise");
    expect(tierAtLeast(result.tier, "team")).toBe(false);
    if (result.granted) {
      // If it grants at all, it grants only what was actually signed.
      expect(result.tier).toBe("community");
    }
  });

  it("a prototype-backed tier cannot grant a tier the signature never covered", () => {
    // A partial claims object whose `tier` lives on the PROTOTYPE, not as an
    // own property. `canonicalJson` (the SIGNING view) walks own-enumerable
    // props only, so the prototype `tier` is invisible to the message an
    // issuer would sign - yet a plain `claims.tier` property read still sees
    // it. Before the snapshot fix, validation and the returned tier read the
    // prototype value while the signed message omitted it, a split view. The
    // snapshot resolves `tier` once into an OWN primitive, so the message that
    // is verified always includes exactly the tier that would be granted: an
    // "enterprise" prototype tier can only grant if the signature covers an
    // enterprise snapshot, which a community-issued signature does not. Here
    // we sign a benign community token, then swap in a prototype "enterprise"
    // tier: it must fail closed, never granting enterprise.
    const communityToken = signToken(
      paidClaims({ tier: "community" }),
    );
    const proto = { tier: "enterprise" };
    const ownOnly = {
      version: ENTITLEMENT_TOKEN_VERSION,
      subject: "fleet-op-1",
      notBefore: NOW - 100,
      notAfter: NOW + 100,
    };
    const claimsLike = Object.assign(Object.create(proto), ownOnly);
    const result = resolveEntitlement({
      token: {
        claims: claimsLike as unknown as EntitlementClaims,
        signature: communityToken.signature,
      },
      issuerPublicKey: issuer.publicKey,
      now: NOW,
    });
    expect(result.tier).not.toBe("enterprise");
    expect(tierAtLeast(result.tier, "team")).toBe(false);
  });

  it("resolveEntitlement(undefined) fails closed to community and never throws", () => {
    // MED regression: options used to be destructured BEFORE the fail-closed
    // try/catch, so an absent/malformed options bag raised a TypeError instead
    // of degrading to community. The whole options read now lives inside the
    // guard: any non-object options resolves to the community floor, granted
    // false, and NEVER throws.
    expect(() =>
      resolveEntitlement(undefined as unknown as Parameters<
        typeof resolveEntitlement
      >[0]),
    ).not.toThrow();

    for (const bad of [undefined, null, 42, "x", true] as const) {
      const result = resolveEntitlement(
        bad as unknown as Parameters<typeof resolveEntitlement>[0],
      );
      expect(result.granted).toBe(false);
      expect(result.tier).toBe(COMMUNITY_TIER);
      expect(tierAtLeast(result.tier, "team")).toBe(false);
    }
  });

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

describe("tierAtLeast - fails closed on malformed operands", () => {
  // Regression for the fail-open where a malformed REQUIRED tier (a typo or
  // bad config in `b`) would grant a paid gate to the floor. tierRank returns
  // -1 for an unknown string, so tierRank("community") (0) >= tierRank(bad)
  // (-1) used to be true. tierAtLeast must validate both operands and deny.
  it("denies when the required tier is a typo (fail-open regression)", () => {
    expect(tierAtLeast("community", "fleeet" as never)).toBe(false);
    expect(tierAtLeast("enterprise", "fleeet" as never)).toBe(false);
  });

  it("denies when the held tier is malformed", () => {
    expect(tierAtLeast("bogus" as never, "team")).toBe(false);
    expect(tierAtLeast("" as never, "community")).toBe(false);
  });

  it("still answers correctly for two valid tiers", () => {
    expect(tierAtLeast("fleet", "team")).toBe(true);
    expect(tierAtLeast("community", "fleet")).toBe(false);
    expect(tierAtLeast("team", "team")).toBe(true);
  });

  it("a public sort/mutation of ENTITLEMENT_TIERS cannot change tierAtLeast (frozen lattice)", () => {
    // HIGH regression: the capability lattice used to be READ from the live
    // exported array via indexOf, so a consumer could reorder it and make a
    // lower tier satisfy a higher-tier gate. The array is now frozen AND the
    // ranks come from a private frozen index map captured at load, so neither a
    // sort nor a splice can move the lattice.
    const before = tierAtLeast("fleet", "enterprise");
    expect(before).toBe(false);

    // Attempting to mutate the frozen array must throw (or no-op) and, either
    // way, must not perturb the ranking used by tierAtLeast.
    expect(() => {
      (ENTITLEMENT_TIERS as unknown as string[]).sort();
    }).toThrow();
    expect(() => {
      (ENTITLEMENT_TIERS as unknown as string[]).reverse();
    }).toThrow();
    expect(() => {
      (ENTITLEMENT_TIERS as unknown as string[]).push("attacker" as never);
    }).toThrow();

    // The lattice is unchanged: fleet still does NOT satisfy an enterprise gate,
    // enterprise still outranks fleet, and the canonical order is intact.
    expect(tierAtLeast("fleet", "enterprise")).toBe(false);
    expect(tierAtLeast("enterprise", "fleet")).toBe(true);
    expect(tierAtLeast("community", "team")).toBe(false);
    expect(Array.from(ENTITLEMENT_TIERS)).toEqual([
      "community",
      "team",
      "fleet",
      "enterprise",
    ]);
  });

  it("does NOT export the raw fail-open tierRank primitive (chokepoint)", async () => {
    // MED regression: `tierRank` used to be exported and, applied directly as
    // `tierRank(held) >= tierRank(required)`, fails OPEN when `required` is a
    // typo (indexOf -> -1). Removing it from the module surface forces every
    // sibling caller through `tierAtLeast`, which validates both operands.
    const surface = await import("../../src/entitlement/index.js");
    expect("tierRank" in surface).toBe(false);
    expect(
      (surface as Record<string, unknown>).tierRank,
    ).toBeUndefined();
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
