/**
 * L4 Degradation Emitter (v0.9.1)
 *
 * Unit tests for `deriveL4Degradations` — the pure function that maps
 * observed L4 evidence to SHR degradation entries. Each code has its
 * own test so a regression on any single degradation is visible.
 */

import { describe, it, expect } from "vitest";
import {
  deriveL4Degradations,
  DEFAULT_FRESHNESS_WINDOW_DAYS,
  DEFAULT_LOW_TIER_DOMINANCE_THRESHOLD,
  type L4Evidence,
} from "../../src/shr/generator.js";
import type { SovereigntyTier } from "../../src/l4-reputation/tiers.js";

function zeroTiers(): Record<SovereigntyTier, number> {
  return {
    "verified-sovereign": 0,
    "verified-degraded": 0,
    "self-attested": 0,
    "unverified": 0,
  };
}

function evidence(overrides: Partial<L4Evidence> = {}): L4Evidence {
  return {
    attestation_count: 0,
    tier_distribution: zeroTiers(),
    most_recent_attestation_at: null,
    dispute_count: 0,
    context_breakdown: {},
    verascore_linked: false,
    ...overrides,
  };
}

describe("deriveL4Degradations — v0.9.1 L4 emitter", () => {
  describe("NO_REPUTATION_HISTORY", () => {
    it("fires when attestation_count is zero", () => {
      const out = deriveL4Degradations(evidence({ verascore_linked: true }));
      const codes = out.map((d) => d.code);
      expect(codes).toContain("NO_REPUTATION_HISTORY");
      const entry = out.find((d) => d.code === "NO_REPUTATION_HISTORY");
      expect(entry?.severity).toBe("warning");
      expect(entry?.layer).toBe("l4");
      expect(entry?.mitigation).toBeTruthy();
    });

    it("does NOT fire when at least one attestation exists", () => {
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 1,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 1 },
          most_recent_attestation_at: new Date().toISOString(),
          verascore_linked: true,
        })
      );
      expect(out.find((d) => d.code === "NO_REPUTATION_HISTORY")).toBeUndefined();
    });

    it("suppresses other per-attestation signals when count is zero", () => {
      const out = deriveL4Degradations(evidence({ verascore_linked: true }));
      const codes = out.map((d) => d.code);
      expect(codes).not.toContain("LOW_TIER_DOMINANCE");
      expect(codes).not.toContain("STALE_REPUTATION");
      expect(codes).not.toContain("DISPUTE_ON_RECORD");
    });
  });

  describe("LOW_TIER_DOMINANCE", () => {
    it("fires when self-attested + unverified share exceeds the 60% threshold", () => {
      // 7 of 10 attestations are low-tier → 70% → triggers (default 0.6)
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 10,
          tier_distribution: {
            "verified-sovereign": 2,
            "verified-degraded": 1,
            "self-attested": 4,
            "unverified": 3,
          },
          most_recent_attestation_at: new Date().toISOString(),
          verascore_linked: true,
        })
      );
      const entry = out.find((d) => d.code === "LOW_TIER_DOMINANCE");
      expect(entry).toBeDefined();
      expect(entry?.severity).toBe("info");
      expect(entry?.description).toMatch(/70%/);
    });

    it("does NOT fire at exactly the threshold (strict >, not ≥)", () => {
      // 6 of 10 → 0.6 — not strictly greater
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 10,
          tier_distribution: {
            "verified-sovereign": 3,
            "verified-degraded": 1,
            "self-attested": 3,
            "unverified": 3,
          },
          most_recent_attestation_at: new Date().toISOString(),
          verascore_linked: true,
        })
      );
      expect(out.find((d) => d.code === "LOW_TIER_DOMINANCE")).toBeUndefined();
    });

    it("respects a custom dominance threshold override", () => {
      // 5 of 10 → 50% — fires only if threshold is lowered under 0.5
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 10,
          tier_distribution: {
            "verified-sovereign": 5,
            "verified-degraded": 0,
            "self-attested": 3,
            "unverified": 2,
          },
          most_recent_attestation_at: new Date().toISOString(),
          verascore_linked: true,
          thresholds: { low_tier_dominance_threshold: 0.4 },
        })
      );
      expect(out.find((d) => d.code === "LOW_TIER_DOMINANCE")).toBeDefined();
    });

    it("DEFAULT_LOW_TIER_DOMINANCE_THRESHOLD is 0.6", () => {
      expect(DEFAULT_LOW_TIER_DOMINANCE_THRESHOLD).toBe(0.6);
    });
  });

  describe("STALE_REPUTATION", () => {
    it("fires when most recent attestation exceeds the freshness window", () => {
      const now = new Date("2026-05-01T00:00:00Z");
      const oldTs = new Date(now.getTime() - 45 * 24 * 60 * 60 * 1000).toISOString();
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 3,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 3 },
          most_recent_attestation_at: oldTs,
          verascore_linked: true,
        }),
        now
      );
      const entry = out.find((d) => d.code === "STALE_REPUTATION");
      expect(entry).toBeDefined();
      expect(entry?.severity).toBe("info");
      expect(entry?.description).toMatch(/45 days old/);
    });

    it("does NOT fire when the attestation is fresh", () => {
      const now = new Date("2026-05-01T00:00:00Z");
      const freshTs = new Date(now.getTime() - 5 * 24 * 60 * 60 * 1000).toISOString();
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 3,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 3 },
          most_recent_attestation_at: freshTs,
          verascore_linked: true,
        }),
        now
      );
      expect(out.find((d) => d.code === "STALE_REPUTATION")).toBeUndefined();
    });

    it("respects a custom freshness window override", () => {
      const now = new Date("2026-05-01T00:00:00Z");
      const tenDaysAgo = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000).toISOString();
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 1,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 1 },
          most_recent_attestation_at: tenDaysAgo,
          verascore_linked: true,
          thresholds: { freshness_window_days: 5 },
        }),
        now
      );
      expect(out.find((d) => d.code === "STALE_REPUTATION")).toBeDefined();
    });

    it("DEFAULT_FRESHNESS_WINDOW_DAYS is 30", () => {
      expect(DEFAULT_FRESHNESS_WINDOW_DAYS).toBe(30);
    });
  });

  describe("DISPUTE_ON_RECORD", () => {
    it("fires when any attestation is disputed", () => {
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 5,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 5 },
          most_recent_attestation_at: new Date().toISOString(),
          dispute_count: 1,
          verascore_linked: true,
        })
      );
      const entry = out.find((d) => d.code === "DISPUTE_ON_RECORD");
      expect(entry).toBeDefined();
      expect(entry?.severity).toBe("warning");
      expect(entry?.description).toMatch(/1 attestation marked/);
    });

    it("pluralizes the description correctly", () => {
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 5,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 5 },
          most_recent_attestation_at: new Date().toISOString(),
          dispute_count: 3,
          verascore_linked: true,
        })
      );
      const entry = out.find((d) => d.code === "DISPUTE_ON_RECORD");
      expect(entry?.description).toMatch(/3 attestations marked/);
    });

    it("does NOT fire when there are zero disputes", () => {
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 5,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 5 },
          most_recent_attestation_at: new Date().toISOString(),
          verascore_linked: true,
        })
      );
      expect(out.find((d) => d.code === "DISPUTE_ON_RECORD")).toBeUndefined();
    });
  });

  describe("NO_VERASCORE_LINK", () => {
    it("fires when verascore_linked is false", () => {
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 5,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 5 },
          most_recent_attestation_at: new Date().toISOString(),
          verascore_linked: false,
        })
      );
      const entry = out.find((d) => d.code === "NO_VERASCORE_LINK");
      expect(entry).toBeDefined();
      expect(entry?.severity).toBe("info");
    });

    it("does NOT fire when verascore_linked is true", () => {
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 5,
          tier_distribution: { ...zeroTiers(), "verified-sovereign": 5 },
          most_recent_attestation_at: new Date().toISOString(),
          verascore_linked: true,
        })
      );
      expect(out.find((d) => d.code === "NO_VERASCORE_LINK")).toBeUndefined();
    });

    it("fires independently of attestation history (can coexist with NO_REPUTATION_HISTORY)", () => {
      const out = deriveL4Degradations(evidence({ verascore_linked: false }));
      const codes = out.map((d) => d.code);
      expect(codes).toContain("NO_REPUTATION_HISTORY");
      expect(codes).toContain("NO_VERASCORE_LINK");
    });
  });

  describe("combined signals", () => {
    it("emits multiple degradations when several conditions are true", () => {
      const now = new Date("2026-05-01T00:00:00Z");
      const stale = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000).toISOString();
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 4,
          tier_distribution: {
            "verified-sovereign": 0,
            "verified-degraded": 0,
            "self-attested": 3,
            "unverified": 1,
          },
          most_recent_attestation_at: stale,
          dispute_count: 1,
          verascore_linked: false,
        }),
        now
      );
      const codes = out.map((d) => d.code).sort();
      expect(codes).toEqual(
        [
          "LOW_TIER_DOMINANCE",
          "STALE_REPUTATION",
          "DISPUTE_ON_RECORD",
          "NO_VERASCORE_LINK",
        ].sort()
      );
    });

    it("returns empty array when everything is healthy", () => {
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 10,
          tier_distribution: {
            "verified-sovereign": 8,
            "verified-degraded": 2,
            "self-attested": 0,
            "unverified": 0,
          },
          most_recent_attestation_at: new Date().toISOString(),
          dispute_count: 0,
          verascore_linked: true,
        })
      );
      expect(out).toEqual([]);
    });

    it("tags every emitted degradation with layer 'l4'", () => {
      const now = new Date("2026-05-01T00:00:00Z");
      const stale = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString();
      const out = deriveL4Degradations(
        evidence({
          attestation_count: 3,
          tier_distribution: {
            "verified-sovereign": 0,
            "verified-degraded": 0,
            "self-attested": 2,
            "unverified": 1,
          },
          most_recent_attestation_at: stale,
          dispute_count: 1,
          verascore_linked: false,
        }),
        now
      );
      for (const d of out) expect(d.layer).toBe("l4");
    });
  });
});
