/**
 * Sovereignty-Gated Reputation Tiers — Tests
 *
 * Tests for tier resolution, weighted scoring, and tier distribution.
 */

import { describe, it, expect } from "vitest";
import {
  resolveTier,
  resolveTierByDid,
  computeWeightedScore,
  tierDistribution,
  TIER_WEIGHTS,
  type SovereigntyTier,
  type TieredAttestation,
} from "../../src/l4-reputation/tiers.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";
import { publicKeyToDid } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";

// Minimal mock SHR for handshake results
const mockSHR: SignedSHR = {
  body: {
    shr_version: "1.0",
    implementation: {
      sanctuary_version: "0.4.0",
      node_version: "20.0.0",
      generated_by: "sanctuary-mcp-server",
    },
    instance_id: "counterparty-123",
    generated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    layers: {
      l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
      l2: { status: "degraded", isolation_type: "local-process", attestation_available: true },
      l3: { status: "active", proof_system: "schnorr-pedersen", selective_disclosure: true },
      l4: { status: "active", reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
    },
    capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
    degradations: [],
  },
  signed_by: "mock-key",
  signature_scheme: "ed25519-v1",
  signature: "mock-sig",
};

function makeHandshakeResult(
  overrides: Partial<HandshakeResult> = {}
): HandshakeResult {
  return {
    counterparty_id: "counterparty-123",
    counterparty_shr: mockSHR,
    verified: true,
    sovereignty_level: "degraded",
    trust_tier: "verified-degraded",
    completed_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    errors: [],
    liveness_proven: true,
    ...overrides,
  };
}

describe("Sovereignty-Gated Reputation Tiers", () => {
  describe("resolveTier", () => {
    it("returns verified-sovereign for a verified handshake with full sovereignty", () => {
      const results = new Map<string, HandshakeResult>();
      results.set("cp-1", makeHandshakeResult({
        counterparty_id: "cp-1",
        trust_tier: "verified-sovereign",
      }));

      const tier = resolveTier("cp-1", results, true);
      expect(tier.sovereignty_tier).toBe("verified-sovereign");
      expect(tier.handshake_completed_at).toBeTruthy();
    });

    it("returns verified-degraded for a degraded handshake", () => {
      const results = new Map<string, HandshakeResult>();
      results.set("cp-1", makeHandshakeResult({
        counterparty_id: "cp-1",
        trust_tier: "verified-degraded",
      }));

      const tier = resolveTier("cp-1", results, true);
      expect(tier.sovereignty_tier).toBe("verified-degraded");
    });

    it("returns self-attested when no handshake but has identity", () => {
      const results = new Map<string, HandshakeResult>();
      const tier = resolveTier("cp-1", results, true);
      expect(tier.sovereignty_tier).toBe("self-attested");
    });

    it("returns unverified when no handshake and no identity", () => {
      const results = new Map<string, HandshakeResult>();
      const tier = resolveTier("cp-1", results, false);
      expect(tier.sovereignty_tier).toBe("unverified");
    });

    it("falls back to self-attested when handshake is expired", () => {
      const results = new Map<string, HandshakeResult>();
      results.set("cp-1", makeHandshakeResult({
        counterparty_id: "cp-1",
        expires_at: new Date(Date.now() - 1000).toISOString(), // already expired
      }));

      const tier = resolveTier("cp-1", results, true);
      expect(tier.sovereignty_tier).toBe("self-attested");
    });

    it("falls back to unverified for unverified handshake", () => {
      const results = new Map<string, HandshakeResult>();
      results.set("cp-1", makeHandshakeResult({
        counterparty_id: "cp-1",
        verified: false,
        trust_tier: "unverified",
      }));

      const tier = resolveTier("cp-1", results, false);
      expect(tier.sovereignty_tier).toBe("unverified");
    });
  });

  describe("resolveTierByDid (DID-keyed lookup, F2)", () => {
    const pubkey = new Uint8Array(32).fill(7);
    const did = publicKeyToDid(pubkey);
    const signedByB64 = toBase64url(pubkey);

    function verifiedByDidMap(): Map<string, HandshakeResult> {
      const results = new Map<string, HandshakeResult>();
      results.set(
        "instance-xyz",
        makeHandshakeResult({
          counterparty_id: "instance-xyz",
          trust_tier: "verified-sovereign",
          counterparty_shr: { ...mockSHR, signed_by: signedByB64 },
        })
      );
      return results;
    }

    it("credits a verified peer looked up by DID (resolveTier would miss it)", () => {
      const results = verifiedByDidMap();
      // The old path keyed the DID into an instance_id-keyed map → always missed.
      expect(resolveTier(did, results, false).sovereignty_tier).toBe("unverified");
      // The DID-aware path matches via counterparty_shr.signed_by and credits it.
      expect(resolveTierByDid(did, results, false).sovereignty_tier).toBe("verified-sovereign");
    });

    it("falls through to the default when no handshake matches the DID (fail-safe)", () => {
      const results = verifiedByDidMap();
      const otherDid = publicKeyToDid(new Uint8Array(32).fill(9));
      expect(resolveTierByDid(otherDid, results, false).sovereignty_tier).toBe("unverified");
      expect(resolveTierByDid(otherDid, results, true).sovereignty_tier).toBe("self-attested");
    });

    it("never over-credits: a different DID cannot borrow a verified peer's tier", () => {
      const results = verifiedByDidMap();
      const otherDid = publicKeyToDid(new Uint8Array(32).fill(3));
      expect(resolveTierByDid(otherDid, results, false).sovereignty_tier).not.toBe(
        "verified-sovereign"
      );
    });

    it("skips a handshake whose signing key cannot be decoded (no throw)", () => {
      const results = new Map<string, HandshakeResult>();
      results.set(
        "bad",
        makeHandshakeResult({
          counterparty_id: "bad",
          counterparty_shr: { ...mockSHR, signed_by: "!!!not-base64!!!" },
        })
      );
      expect(() => resolveTierByDid(did, results, false)).not.toThrow();
      expect(resolveTierByDid(did, results, false).sovereignty_tier).toBe("unverified");
    });
  });

  describe("computeWeightedScore", () => {
    it("returns null for empty attestations", () => {
      expect(computeWeightedScore([])).toBeNull();
    });

    it("weights verified-sovereign attestations at 1.0", () => {
      const attestations: TieredAttestation[] = [
        { value: 100, tier: "verified-sovereign" },
      ];
      expect(computeWeightedScore(attestations)).toBe(100);
    });

    it("weights unverified attestations lower", () => {
      const attestations: TieredAttestation[] = [
        { value: 100, tier: "unverified" },
      ];
      // 100 * 0.2 / 0.2 = 100 (single attestation always = its own value)
      expect(computeWeightedScore(attestations)).toBe(100);
    });

    it("correctly weights mixed tiers", () => {
      const attestations: TieredAttestation[] = [
        { value: 100, tier: "verified-sovereign" },  // 100 * 1.0 = 100
        { value: 50, tier: "unverified" },            // 50 * 0.2 = 10
      ];
      // (100 + 10) / (1.0 + 0.2) = 110 / 1.2 ≈ 91.67
      const score = computeWeightedScore(attestations)!;
      expect(score).toBeCloseTo(91.67, 1);
    });

    it("verified attestations dominate over many unverified", () => {
      const attestations: TieredAttestation[] = [
        { value: 90, tier: "verified-sovereign" },     // 90 * 1.0 = 90
        { value: 50, tier: "unverified" },              // 50 * 0.2 = 10
        { value: 50, tier: "unverified" },              // 50 * 0.2 = 10
        { value: 50, tier: "unverified" },              // 50 * 0.2 = 10
        { value: 50, tier: "unverified" },              // 50 * 0.2 = 10
      ];
      // (90 + 10*4) / (1.0 + 0.2*4) = 130 / 1.8 ≈ 72.2
      const score = computeWeightedScore(attestations)!;
      expect(score).toBeGreaterThan(70);
      // Without weighting, average would be 58
    });

    it("fails closed on an unknown/imported-invalid tier (no NaN poisoning)", () => {
      const attestations: TieredAttestation[] = [
        { value: 100, tier: "verified-sovereign" },
        // Simulates an imported attestation whose tier is not in TIER_WEIGHTS.
        { value: 9999, tier: "totally-bogus-tier" as unknown as TieredAttestation["tier"] },
      ];
      // The bogus-tier attestation contributes 0 weight and is skipped; the
      // score must be the valid attestation's value, never NaN.
      const score = computeWeightedScore(attestations);
      expect(score).toBe(100);
      expect(Number.isNaN(score as number)).toBe(false);
    });

    it("fails closed on a non-finite metric value (no NaN/Infinity poisoning)", () => {
      const attestations: TieredAttestation[] = [
        { value: 100, tier: "verified-sovereign" },
        { value: Infinity, tier: "verified-sovereign" },
        { value: NaN, tier: "unverified" },
      ];
      const score = computeWeightedScore(attestations)!;
      expect(score).toBe(100);
      expect(Number.isFinite(score)).toBe(true);
    });

    it("returns null when every attestation is invalid", () => {
      const attestations: TieredAttestation[] = [
        { value: Infinity, tier: "verified-sovereign" },
        { value: 5, tier: "nope" as unknown as TieredAttestation["tier"] },
      ];
      expect(computeWeightedScore(attestations)).toBeNull();
    });
  });

  describe("tierDistribution", () => {
    it("counts tiers correctly", () => {
      const tiers: SovereigntyTier[] = [
        "verified-sovereign",
        "verified-degraded",
        "verified-degraded",
        "self-attested",
        "unverified",
        "unverified",
        "unverified",
      ];

      const dist = tierDistribution(tiers);
      expect(dist["verified-sovereign"]).toBe(1);
      expect(dist["verified-degraded"]).toBe(2);
      expect(dist["self-attested"]).toBe(1);
      expect(dist["unverified"]).toBe(3);
    });

    it("returns all zeros for empty array", () => {
      const dist = tierDistribution([]);
      expect(Object.values(dist).every((v) => v === 0)).toBe(true);
    });
  });

  describe("TIER_WEIGHTS", () => {
    it("has monotonically decreasing weights", () => {
      expect(TIER_WEIGHTS["verified-sovereign"]).toBeGreaterThan(TIER_WEIGHTS["verified-degraded"]);
      expect(TIER_WEIGHTS["verified-degraded"]).toBeGreaterThan(TIER_WEIGHTS["self-attested"]);
      expect(TIER_WEIGHTS["self-attested"]).toBeGreaterThan(TIER_WEIGHTS["unverified"]);
    });

    it("has all weights between 0 and 1 inclusive", () => {
      for (const w of Object.values(TIER_WEIGHTS)) {
        expect(w).toBeGreaterThan(0);
        expect(w).toBeLessThanOrEqual(1);
      }
    });
  });
});
