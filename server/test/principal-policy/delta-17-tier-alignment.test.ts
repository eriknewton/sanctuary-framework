/**
 * DELTA-17: Assert the Principal Policy loader registers the sanctuary_*
 * meta-tools in the tiers documented in the tool-file comments:
 *
 *   sanctuary_bootstrap              → Tier 1 (always approve)
 *   sanctuary_export_identity_bundle → Tier 1 (always approve)
 *   sanctuary_link_to_human          → Tier 2 (anomaly-gated; NOT tier 3)
 *   sanctuary_sign_challenge         → Tier 2 (anomaly-gated; NOT tier 3)
 *   sanctuary_policy_status          → Tier 3 (auto-allow with audit)
 *
 * Tier 2 = "not in tier1, not in tier3". This test is the canonical
 * guard: if a future change flips link_to_human or sign_challenge into
 * Tier 3, this test fails.
 */

import { describe, it, expect } from "vitest";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";

describe("DELTA-17: principal policy tier alignment", () => {
  it("sanctuary_bootstrap is Tier 1", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("sanctuary_bootstrap");
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain("sanctuary_bootstrap");
  });

  it("sanctuary_export_identity_bundle is Tier 1", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).toContain(
      "sanctuary_export_identity_bundle"
    );
  });

  it("sanctuary_link_to_human is Tier 2 (NOT tier 3)", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).not.toContain(
      "sanctuary_link_to_human"
    );
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain(
      "sanctuary_link_to_human"
    );
  });

  it("sanctuary_sign_challenge is Tier 2 (NOT tier 3)", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).not.toContain(
      "sanctuary_sign_challenge"
    );
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain(
      "sanctuary_sign_challenge"
    );
  });

  it("sanctuary_policy_status is Tier 3", () => {
    expect(DEFAULT_POLICY.tier3_always_allow).toContain(
      "sanctuary_policy_status"
    );
  });
});
