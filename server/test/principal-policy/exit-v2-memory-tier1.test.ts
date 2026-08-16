/** Exit V2 SDW memory carriage must remain non-relaxable Tier 1. */

import { describe, expect, it } from "vitest";

import { AutoApproveChannel } from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import {
  NON_RELAXABLE_EXIT_V2_MEMORY_TIER1_OPERATIONS,
  enforceForcedTiers,
  parsePolicy,
} from "../../src/principal-policy/loader.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const permissive = (operation: string): PrincipalPolicy => ({
  version: 1,
  tier1_always_approve: [],
  tier2_anomaly: {
    new_namespace_access: "allow",
    new_counterparty: "allow",
    frequency_spike_multiplier: 1_000,
    max_signs_per_minute: 1_000,
    bulk_read_threshold: 1_000,
    first_session_policy: "allow",
  },
  tier3_always_allow: [operation],
  approval_channel: { type: "stderr", timeout_seconds: 300 },
});

function gate(policy: PrincipalPolicy): ApprovalGate {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  return new ApprovalGate(
    policy,
    new BaselineTracker(storage, masterKey),
    new AutoApproveChannel(),
    new AuditLog(storage, masterKey),
  );
}

describe("Exit V2 SDW memory CLI non-relaxable Tier 1", () => {
  it("single-sources exactly the two operator carriage operations", () => {
    expect([...NON_RELAXABLE_EXIT_V2_MEMORY_TIER1_OPERATIONS]).toEqual([
      "memory_archive_export",
      "memory_archive_import",
    ]);
  });

  for (const operation of ["memory_archive_export", "memory_archive_import"]) {
    it(`${operation}: policy load and direct mutation cannot relax it`, () => {
      const hostile = parsePolicy([
        "tier1_always_approve:",
        "  - state_export",
        "tier3_always_allow:",
        `  - ${operation}`,
        "approval_channel:",
        "  type: stderr",
      ].join("\n"));
      expect(hostile.tier1_always_approve).toContain(operation);
      expect(hostile.tier3_always_allow).not.toContain(operation);

      const normalized = enforceForcedTiers(permissive(operation));
      expect(normalized.tier1_always_approve).toContain(operation);
      expect(normalized.tier3_always_allow).not.toContain(operation);
    });

    it(`${operation}: runtime classification stays Tier 1`, () => {
      expect(gate(permissive(operation)).classifyRiskTier(operation, {})).toBe(1);
    });
  }
});
