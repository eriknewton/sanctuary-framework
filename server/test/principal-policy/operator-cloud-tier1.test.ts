/**
 * Operator Cloud Slice 2, non-relaxable Tier-1 cloud-join gate (HIGH / MED-1).
 *
 * `operator_cloud_provision` and `federation_node_join` are exports of custody
 * material / trust-boundary changes. A hand-authored policy must NEVER be able to
 * relax them into Tier 3 or auto-approve. This is enforced at BOTH points:
 *   - policy LOAD (parsePolicy merges the forced set into Tier 1 and prunes it
 *     from Tier 3),
 *   - runtime CLASSIFICATION (ApprovalGate.classifyRiskTier checks the forced
 *     list first).
 * A drift guard pins that both forced lists carry the shared set.
 */

import { describe, expect, it } from "vitest";

import {
  parsePolicy,
  NON_RELAXABLE_CLOUD_TIER1_OPERATIONS,
} from "../../src/principal-policy/loader.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { AutoApproveChannel } from "../../src/principal-policy/approval-channel.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";

function makeGate(policy: PrincipalPolicy): ApprovalGate {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  return new ApprovalGate(
    policy,
    new BaselineTracker(storage, masterKey),
    new AutoApproveChannel(),
    new AuditLog(storage, masterKey),
  );
}

describe("operator-cloud non-relaxable Tier 1, policy load", () => {
  for (const op of NON_RELAXABLE_CLOUD_TIER1_OPERATIONS) {
    it(`${op}: a hand-authored policy placing it in Tier 3 still ends up Tier 1`, () => {
      const hostile = [
        "tier1_always_approve:",
        "  - state_export",
        "tier3_always_allow:",
        `  - ${op}`,
        "approval_channel:",
        "  type: stderr",
      ].join("\n");
      const policy = parsePolicy(hostile);
      expect(policy.tier1_always_approve).toContain(op);
      expect(policy.tier3_always_allow).not.toContain(op);
    });

    it(`${op}: a policy omitting it entirely still classifies it Tier 1`, () => {
      const minimal = [
        "tier1_always_approve:",
        "  - state_export",
        "approval_channel:",
        "  type: stderr",
      ].join("\n");
      const policy = parsePolicy(minimal);
      expect(policy.tier1_always_approve).toContain(op);
    });
  }
});

describe("operator-cloud non-relaxable Tier 1, runtime classification", () => {
  for (const op of NON_RELAXABLE_CLOUD_TIER1_OPERATIONS) {
    it(`${op}: classifyRiskTier returns 1 even for a permissive (Tier 3) policy`, () => {
      // Construct a deliberately permissive policy object that bypasses the
      // loader merge (simulating drift / an attacker-crafted in-memory policy).
      const permissive: PrincipalPolicy = {
        version: 1,
        tier1_always_approve: [],
        tier2_anomaly: {
          new_namespace_access: "allow",
          new_counterparty: "allow",
          frequency_spike_multiplier: 1000,
          max_signs_per_minute: 1000,
          bulk_read_threshold: 1000,
          first_session_policy: "allow",
        },
        tier3_always_allow: [op], // hostile: list the op as auto-allow
        approval_channel: { type: "stderr", timeout_seconds: 300 },
      };
      const gate = makeGate(permissive);
      // The runtime forced list wins: Tier 1, never Tier 3.
      expect(gate.classifyRiskTier(op, {})).toBe(1);
    });
  }
});

describe("operator-cloud non-relaxable Tier 1, drift guard (MED-1)", () => {
  it("the loader forced list and the gate forced list both carry every shared op", () => {
    // Both enforcement points spread NON_RELAXABLE_CLOUD_TIER1_OPERATIONS. If a
    // refactor drops the spread on either side, one of these classifications
    // would fall back to a relaxable tier. Assert via behavior at both points.
    for (const op of NON_RELAXABLE_CLOUD_TIER1_OPERATIONS) {
      // Loader side: default policy carries it under Tier 1.
      const policy = parsePolicy(
        ["tier1_always_approve:", "  - state_export", "approval_channel:", "  type: stderr"].join("\n"),
      );
      expect(policy.tier1_always_approve).toContain(op);
      // Gate side: forced even when the policy says otherwise.
      const gate = makeGate({
        version: 1,
        tier1_always_approve: [],
        tier2_anomaly: {
          new_namespace_access: "allow",
          new_counterparty: "allow",
          frequency_spike_multiplier: 1000,
          max_signs_per_minute: 1000,
          bulk_read_threshold: 1000,
          first_session_policy: "allow",
        },
        tier3_always_allow: [op],
        approval_channel: { type: "stderr", timeout_seconds: 300 },
      });
      expect(gate.classifyRiskTier(op, {})).toBe(1);
    }
  });

  it("the shared set names exactly the two operator-cloud custody operations", () => {
    expect([...NON_RELAXABLE_CLOUD_TIER1_OPERATIONS].sort()).toEqual([
      "federation_node_join",
      "operator_cloud_provision",
    ]);
  });
});
