/**
 * Memory integrity restore -- non-relaxable Tier-1 drift guard.
 *
 * Restoring a memory checkpoint overwrites current exportable state. It must
 * classify Tier 1 at BOTH policy load and runtime classification, regardless
 * of hand-authored policy attempts to relax it into Tier 3.
 */

import { describe, expect, it } from "vitest";

import {
  NON_RELAXABLE_MEMORY_INTEGRITY_TIER1_OPERATIONS,
  enforceForcedTiers,
  parsePolicy,
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

const permissive = (op: string): PrincipalPolicy => ({
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

describe("memory integrity restore non-relaxable Tier 1", () => {
  it("names exactly the memory-integrity Tier-1 operations", () => {
    expect([...NON_RELAXABLE_MEMORY_INTEGRITY_TIER1_OPERATIONS]).toEqual([
      "memory_checkpoint_restore",
      "sdw_memory_provenance_migrate",
      "sdw_memory_provenance_abort_migration",
      "sdw_memory_provenance_repair_completion_marker",
    ]);
  });

  for (const op of NON_RELAXABLE_MEMORY_INTEGRITY_TIER1_OPERATIONS) {
    it(`${op}: policy load force-adds Tier 1 and prunes Tier 3`, () => {
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

    it(`${op}: enforceForcedTiers prunes direct policy mutation attempts`, () => {
      const policy = enforceForcedTiers(permissive(op));
      expect(policy.tier1_always_approve).toContain(op);
      expect(policy.tier3_always_allow).not.toContain(op);
    });

    it(`${op}: runtime classification stays Tier 1 under a permissive policy`, () => {
      const gate = makeGate(permissive(op));
      expect(gate.classifyRiskTier(op, {})).toBe(1);
    });
  }
});
