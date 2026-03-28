/**
 * Sovereignty-Gated Reputation Tiers — Tests
 *
 * Tests for tier resolution, weighted scoring, and tier distribution.
 */

import { describe, it, expect } from "vitest";
import {
  resolveTier,
  computeWeightedScore,
  tierDistribution,
  TIER_WEIGHTS,
  type SovereigntyTier,
  type TieredAttestation,
} from "../../src/l4-reputation/tiers.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";

// Minimal mock SHR for handshake results
const mockSHR: SignedSHR = {
  body: {
    shr_version: "1.0",
    instance_id: "counterparty-123",
    generated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    layers: {
      l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
      l2: { status: "degraded", isolation_type: "local-process", attestation_available: true },
      l3: { status: "degraded", proof_system: "commitment-only", selective_disclosure: false },
      l4: { status: "active", reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
    },
    capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
    degradations: [],
  },
  signed_by: "mock-key",
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
