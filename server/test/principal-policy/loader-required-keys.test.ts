/**
 * Regression test for full-sweep #68: required-key enforcement in policy loader.
 *
 * tier1_always_approve and approval_channel must be explicitly present in
 * the policy file. Silent default substitution hides operator intent.
 *
 * tier2_anomaly and tier3_always_allow may be omitted (merge from defaults).
 * Raw identity_sign is always forced into Tier 1 even when the operator
 * starts from a smaller explicit list.
 */

import { describe, it, expect } from "vitest";
import { parsePolicy } from "../../src/principal-policy/loader.js";

describe("policy loader required-key enforcement (#68)", () => {
  it("throws when tier1_always_approve is missing from YAML", () => {
    const yaml = `
version: 1
approval_channel:
  type: stderr
tier3_always_allow:
  - state_read
`;
    expect(() => parsePolicy(yaml)).toThrow("tier1_always_approve");
  });

  it("throws when tier1_always_approve is missing from JSON", () => {
    const json = JSON.stringify({
      version: 1,
      approval_channel: { type: "stderr" },
    });
    expect(() => parsePolicy(json)).toThrow("tier1_always_approve");
  });

  it("throws when approval_channel is missing from YAML", () => {
    const yaml = `
version: 1
tier1_always_approve:
  - state_export
`;
    expect(() => parsePolicy(yaml)).toThrow("approval_channel");
  });

  it("throws when approval_channel is missing from JSON", () => {
    const json = JSON.stringify({
      version: 1,
      tier1_always_approve: ["state_export"],
    });
    expect(() => parsePolicy(json)).toThrow("approval_channel");
  });

  it("allows omitting tier2_anomaly (fills from defaults)", () => {
    const yaml = `
version: 1
tier1_always_approve:
  - state_export
approval_channel:
  type: stderr
`;
    const policy = parsePolicy(yaml);
    expect(policy.tier2_anomaly.frequency_spike_multiplier).toBe(5);
  });

  it("allows omitting tier3_always_allow (fills from defaults)", () => {
    const yaml = `
version: 1
tier1_always_approve:
  - state_export
approval_channel:
  type: stderr
`;
    const policy = parsePolicy(yaml);
    expect(policy.tier3_always_allow.length).toBeGreaterThan(0);
  });

  it("accepts a complete valid policy without error", () => {
    const yaml = `
version: 1
tier1_always_approve:
  - state_export
  - state_import
tier2_anomaly:
  new_namespace_access: approve
tier3_always_allow:
  - state_read
approval_channel:
  type: stderr
  timeout_seconds: 120
`;
    const policy = parsePolicy(yaml);
    expect(policy.tier1_always_approve).toEqual([
      "state_export",
      "state_import",
      "identity_sign",
      "principal_policy_view",
      "principal_baseline_view",
      "sanctuary_policy_status",
      "context_gate_set_policy",
      "context_gate_apply_template",
      "audit_export_siem",
      "compliance_generate_eu_ai_act_bundle",
      "memory_delete",
      "operator_cloud_provision",
      "federation_node_join",
      "file_grant",
      "castle_wall_observe_promote",
      "enforcement_export_enabled",
      "memory_checkpoint_restore",
    ]);
    expect(policy.approval_channel.type).toBe("stderr");
  });

  it("accepts empty tier1_always_approve list while preserving forced raw signing gate", () => {
    const json = JSON.stringify({
      version: 1,
      tier1_always_approve: [],
      approval_channel: { type: "stderr" },
    });
    const policy = parsePolicy(json);
    expect(policy.tier1_always_approve).toEqual([
      "identity_sign",
      "principal_policy_view",
      "principal_baseline_view",
      "sanctuary_policy_status",
      "context_gate_set_policy",
      "context_gate_apply_template",
      "audit_export_siem",
      "compliance_generate_eu_ai_act_bundle",
      "memory_delete",
      "operator_cloud_provision",
      "federation_node_join",
      "file_grant",
      "castle_wall_observe_promote",
      "enforcement_export_enabled",
      "memory_checkpoint_restore",
    ]);
  });

  it("accepts empty approval_channel object", () => {
    const json = JSON.stringify({
      version: 1,
      tier1_always_approve: ["state_export"],
      approval_channel: {},
    });
    const policy = parsePolicy(json);
    expect(policy.approval_channel.type).toBe("stderr");
  });
});
