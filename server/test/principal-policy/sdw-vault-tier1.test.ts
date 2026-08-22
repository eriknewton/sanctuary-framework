/** SDW vault export / import / post-export delete must remain non-relaxable Tier 1 (HIGH-C1). */

import { describe, expect, it } from "vitest";

import { AutoApproveChannel } from "../../src/principal-policy/approval-channel.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import {
  NON_RELAXABLE_SDW_VAULT_TIER1_OPERATIONS,
  parsePolicy,
} from "../../src/principal-policy/loader.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createSdwTools } from "../../src/sdw/tools.js";
import type { AuditLog as AuditLogType } from "../../src/operational/audit-log.js";

function gateFor(policy: ReturnType<typeof parsePolicy>): ApprovalGate {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  return new ApprovalGate(
    policy,
    new BaselineTracker(storage, masterKey),
    new AutoApproveChannel(),
    new AuditLog(storage, masterKey),
  );
}

describe("SDW vault non-relaxable Tier 1", () => {
  it("single-sources the two vault tool names createSdwTools registers", () => {
    const registered = createSdwTools({
      storage: new MemoryStorage(),
      inventory: { listNamespaceSync: () => [] },
      auditLog: {} as AuditLogType,
      fortressId: "fortress:pin",
      exportDir: "/nonexistent",
      signingKey: () => null,
      resolvePublicKey: () => null,
      resolveSourceMasterKey: () => null,
      targetMasterKey: new Uint8Array(32),
    }).map((t) => t.name).sort();
    expect([...NON_RELAXABLE_SDW_VAULT_TIER1_OPERATIONS].sort()).toEqual(registered);
  });

  for (const operation of NON_RELAXABLE_SDW_VAULT_TIER1_OPERATIONS) {
    it(`${operation}: a hand-authored policy relaxing it to Tier 3 is rejected at load AND at the gate`, async () => {
      const hostile = parsePolicy(
        [
          "version: 1",
          "tier1_always_approve: []",
          "tier3_always_allow:",
          `  - ${operation}`,
          "approval_channel:",
          "  type: stderr",
          "  timeout_seconds: 300",
        ].join("\n"),
      );
      // Loader: force-added back to Tier 1 and pruned from Tier 3.
      expect(hostile.tier1_always_approve).toContain(operation);
      expect(hostile.tier3_always_allow).not.toContain(operation);
      // Gate: even a policy object mutated after load classifies Tier 1.
      const mutated = { ...hostile, tier1_always_approve: [], tier3_always_allow: [operation] };
      const result = await gateFor(mutated).evaluate(operation, {});
      expect(result.tier).toBe(1);
    });
  }
});
