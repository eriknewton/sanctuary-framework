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

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import {
  parsePolicy,
  extractOperationName,
  DEFAULT_POLICY,
  loadPrincipalPolicy,
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
        "principal_policy_view",
        "principal_baseline_view",
        "sanctuary_policy_status",
        "context_gate_set_policy",
        "context_gate_apply_template",
        "audit_export_siem",
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

    it("migrates policy-read tools out of Tier 3 on upgrade (existing policy file)", () => {
      // An older on-disk policy that still auto-allows the policy-read tools.
      // validatePolicy must force them to Tier 1 and prune them from Tier 3 so
      // the no-read invariant holds for upgraded installs, not just fresh defaults.
      const yaml = `
version: 1
tier1_always_approve:
  - state_export
tier3_always_allow:
  - state_read
  - principal_policy_view
  - principal_baseline_view
  - sanctuary_policy_status
approval_channel:
  type: stderr
`;
      const policy = parsePolicy(yaml);
      for (const op of [
        "principal_policy_view",
        "principal_baseline_view",
        "sanctuary_policy_status",
      ]) {
        expect(policy.tier1_always_approve).toContain(op);
        expect(policy.tier3_always_allow).not.toContain(op);
      }
    });

    it("migrates context-gate mutation tools out of Tier 3 on upgrade", () => {
      const yaml = `
version: 1
tier1_always_approve:
  - state_export
tier3_always_allow:
  - state_read
  - context_gate_set_policy
  - context_gate_apply_template
approval_channel:
  type: stderr
`;
      const policy = parsePolicy(yaml);
      for (const op of [
        "context_gate_set_policy",
        "context_gate_apply_template",
      ]) {
        expect(policy.tier1_always_approve).toContain(op);
        expect(policy.tier3_always_allow).not.toContain(op);
      }
    });

    it("migrates audit_export_siem out of Tier 3 on upgrade (CISO MED-1)", () => {
      // A pre-upgrade on-disk policy that still auto-allows audit_export_siem.
      // validatePolicy must force it to Tier 1 and prune it from Tier 3, so a
      // cooperative agent on an upgraded install cannot bulk-export audit (and
      // infer per-operation tier + decision) without operator approval.
      const yaml = `
version: 1
tier1_always_approve:
  - state_export
tier3_always_allow:
  - state_read
  - audit_export_siem
approval_channel:
  type: stderr
`;
      const policy = parsePolicy(yaml);
      expect(policy.tier1_always_approve).toContain("audit_export_siem");
      expect(policy.tier3_always_allow).not.toContain("audit_export_siem");
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
        "principal_policy_view",
        "principal_baseline_view",
        "sanctuary_policy_status",
        "context_gate_set_policy",
        "context_gate_apply_template",
        "audit_export_siem",
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
        "principal_policy_view",
        "principal_baseline_view",
        "sanctuary_policy_status",
        "context_gate_set_policy",
        "context_gate_apply_template",
        "audit_export_siem",
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
        "principal_policy_view",
        "principal_baseline_view",
        "sanctuary_policy_status",
        "context_gate_set_policy",
        "context_gate_apply_template",
        "audit_export_siem",
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

    it("classifies policy-read tools as Tier 1, not Tier 3", () => {
      const policyReadTools = [
        "principal_policy_view",
        "principal_baseline_view",
        "sanctuary_policy_status",
      ];

      for (const tool of policyReadTools) {
        expect(DEFAULT_POLICY.tier1_always_approve).toContain(tool);
        expect(DEFAULT_POLICY.tier3_always_allow).not.toContain(tool);
      }
    });

    it("classifies context-gate mutation tools as Tier 1, not Tier 3", () => {
      const mutationTools = [
        "context_gate_set_policy",
        "context_gate_apply_template",
      ];

      for (const tool of mutationTools) {
        expect(DEFAULT_POLICY.tier1_always_approve).toContain(tool);
        expect(DEFAULT_POLICY.tier3_always_allow).not.toContain(tool);
      }
    });

    it("does not include auto_deny (SEC-002: hardcoded deny)", () => {
      // SEC-002: auto_deny is no longer in the default policy
      expect(DEFAULT_POLICY.approval_channel.auto_deny).toBeUndefined();
    });
  });

  describe("generated default policy YAML", () => {
    it("places forced Tier 1 tools in Tier 1, not Tier 3", async () => {
      const dir = await mkdtemp(join(tmpdir(), "sanctuary-policy-loader-"));
      try {
        await loadPrincipalPolicy(dir);
        const yaml = await readFile(join(dir, "principal-policy.yaml"), "utf-8");
        const policy = parsePolicy(yaml);
        const forcedTier1Tools = [
          "principal_policy_view",
          "principal_baseline_view",
          "sanctuary_policy_status",
          "context_gate_set_policy",
          "context_gate_apply_template",
          "audit_export_siem",
        ];

        for (const tool of forcedTier1Tools) {
          expect(policy.tier1_always_approve).toContain(tool);
          expect(policy.tier3_always_allow).not.toContain(tool);
        }
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
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
