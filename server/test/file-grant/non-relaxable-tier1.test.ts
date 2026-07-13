/**
 * Governed File-Grant v1 -- non-relaxable Tier-1 drift guard (DoD gate 1,
 * the load-bearing test).
 *
 * Modeled verbatim in shape on
 * test/principal-policy/operator-cloud-tier1.test.ts: `file_grant` must
 * classify Tier 1 at BOTH policy load (loader.ts) and runtime classification
 * (gate.ts), no matter what a hand-authored or maximally-permissive policy
 * says, because both force-lists spread the SAME
 * `NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS` single source of truth.
 */

import { describe, expect, it } from "vitest";

import {
  parsePolicy,
  NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS,
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

describe("file-grant non-relaxable Tier 1, policy load", () => {
  for (const op of NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS) {
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

describe("file-grant non-relaxable Tier 1, runtime classification", () => {
  for (const op of NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS) {
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

describe("file-grant non-relaxable Tier 1, drift guard", () => {
  it("the loader forced list and the gate forced list both carry every shared op", () => {
    for (const op of NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS) {
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

  it("the shared set names exactly the file-grant mint operation", () => {
    expect([...NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS]).toEqual(["file_grant"]);
  });
});
