/**
 * Principal Policy Loader Tests
 *
 * Verifies:
 * - YAML policy parsing (scalars, lists, nested objects)
 * - JSON policy parsing
 * - Default policy generation when no file exists
 * - Policy validation with missing fields falls back to defaults
 * - extractOperationName strips "" prefix
 */

import { describe, it, expect } from "vitest";
import {
  parsePolicy,
  extractOperationName,
  DEFAULT_POLICY,
} from "../../src/principal-policy/loader.js";

describe("Principal Policy Loader", () => {
  describe("parsePolicy — YAML", () => {
    it("parses a complete YAML policy", () => {
      const yaml = `
version: 1
tier1_always_approve:
  - state_export
  - identity_rotate
tier2_anomaly:
  new_namespace_access: approve
  new_counterparty: log
  frequency_spike_multiplier: 3
  max_signs_per_minute: 5
  bulk_read_threshold: 10
  first_session_policy: approve
tier3_always_allow:
  - state_read
  - state_write
  - identity_sign
approval_channel:
  type: stderr
  timeout_seconds: 120
  auto_deny: false
`;
      const policy = parsePolicy(yaml);

      expect(policy.version).toBe(1);
      expect(policy.tier1_always_approve).toEqual([
        "state_export",
        "identity_rotate",
        "identity_sign",
      ]);
      expect(policy.tier2_anomaly.new_namespace_access).toBe("approve");
      expect(policy.tier2_anomaly.new_counterparty).toBe("log");
      expect(policy.tier2_anomaly.frequency_spike_multiplier).toBe(3);
      expect(policy.tier2_anomaly.max_signs_per_minute).toBe(5);
      expect(policy.tier2_anomaly.bulk_read_threshold).toBe(10);
      // User's tier3 entries are preserved, and defaults are merged in
      expect(policy.tier3_always_allow).toContain("state_read");
      expect(policy.tier3_always_allow).toContain("state_write");
      expect(policy.tier3_always_allow).not.toContain("identity_sign");
      // Defaults merged from DEFAULT_POLICY (upgrade-safe)
      expect(policy.tier3_always_allow).toContain("sovereignty_audit");
      expect(policy.tier3_always_allow).toContain("shr_generate");
      expect(policy.tier3_always_allow).toContain("monitor_health");
      expect(policy.approval_channel.type).toBe("stderr");
      expect(policy.approval_channel.timeout_seconds).toBe(120);
      // SEC-002: auto_deny is stripped by the parser — always undefined
      expect(policy.approval_channel.auto_deny).toBeUndefined();
    });

    it("handles comments in YAML", () => {
      const yaml = `
version: 1 # policy version
tier1_always_approve:
  - state_export   # dangerous!
  - identity_rotate
approval_channel:
  type: stderr
`;
      const policy = parsePolicy(yaml);
      expect(policy.version).toBe(1);
      expect(policy.tier1_always_approve).toEqual([
        "state_export",
        "identity_rotate",
        "identity_sign",
      ]);
    });

    it("fills optional fields with defaults when required keys present", () => {
      const yaml = `
version: 2
tier1_always_approve:
  - state_export
approval_channel:
  type: stderr
`;
      const policy = parsePolicy(yaml);

      expect(policy.version).toBe(2);
      expect(policy.tier1_always_approve).toEqual([
        "state_export",
        "identity_sign",
      ]);
      // Tier 2 should have defaults
      expect(policy.tier2_anomaly.frequency_spike_multiplier).toBe(5);
      expect(policy.tier2_anomaly.max_signs_per_minute).toBe(10);
      // Tier 3 should have defaults
      expect(policy.tier3_always_allow).toEqual(DEFAULT_POLICY.tier3_always_allow);
      // SEC-002: auto_deny is stripped -- always undefined
      expect(policy.approval_channel.auto_deny).toBeUndefined();
    });
  });

  describe("parsePolicy — JSON", () => {
    it("parses a JSON policy", () => {
      const json = JSON.stringify({
        version: 1,
        tier1_always_approve: ["state_export"],
        tier2_anomaly: {
          new_namespace_access: "log",
          frequency_spike_multiplier: 8,
        },
        tier3_always_allow: ["state_read"],
        approval_channel: { type: "stderr", auto_deny: false },
      });

      const policy = parsePolicy(json);

      expect(policy.version).toBe(1);
      expect(policy.tier1_always_approve).toEqual([
        "state_export",
        "identity_sign",
      ]);
      expect(policy.tier2_anomaly.new_namespace_access).toBe("log");
      expect(policy.tier2_anomaly.frequency_spike_multiplier).toBe(8);
      // Defaults filled in
      expect(policy.tier2_anomaly.max_signs_per_minute).toBe(10);
      // SEC-002: auto_deny is stripped by the parser — always undefined
      expect(policy.approval_channel.auto_deny).toBeUndefined();
    });
  });

  describe("DEFAULT_POLICY", () => {
    it("has sensible tier 1 operations", () => {
      expect(DEFAULT_POLICY.tier1_always_approve).toContain("state_export");
      expect(DEFAULT_POLICY.tier1_always_approve).toContain("state_import");
      expect(DEFAULT_POLICY.tier1_always_approve).toContain("identity_rotate");
      expect(DEFAULT_POLICY.tier1_always_approve).toContain("reputation_import");
    });

    it("has standard tier 3 operations", () => {
      expect(DEFAULT_POLICY.tier3_always_allow).toContain("state_read");
      expect(DEFAULT_POLICY.tier3_always_allow).toContain("state_write");
      expect(DEFAULT_POLICY.tier3_always_allow).toContain("monitor_health");
      expect(DEFAULT_POLICY.tier3_always_allow).toContain("identity_verify");
      expect(DEFAULT_POLICY.tier3_always_allow).not.toContain("identity_sign");
    });

    it("classifies raw identity_sign as Tier 1", () => {
      expect(DEFAULT_POLICY.tier1_always_approve).toContain("identity_sign");
    });

    it("does not include auto_deny (SEC-002: hardcoded deny)", () => {
      // SEC-002: auto_deny is no longer in the default policy
      expect(DEFAULT_POLICY.approval_channel.auto_deny).toBeUndefined();
    });
  });

  describe("extractOperationName", () => {
    it("strips sanctuary/ prefix", () => {
      expect(extractOperationName("state_export")).toBe("state_export");
    });

    it("returns bare name unchanged", () => {
      expect(extractOperationName("state_export")).toBe("state_export");
    });

    it("handles nested slashes by stripping only sanctuary/", () => {
      expect(extractOperationName("identity_sign")).toBe("identity_sign");
    });
  });
});
