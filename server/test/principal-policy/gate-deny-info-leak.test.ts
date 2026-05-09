/**
 * Regression test for full-sweep #48 (P1): gate denial info-leak.
 *
 * Asserts that every deny / approval-required path on the principal-policy
 * approval gate returns a generic agent-visible reason from the vocabulary,
 * never revealing tier numbers, operation names, or policy structure.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { AGENT_VISIBLE_DENY_REASONS } from "../../src/principal-policy/deny-vocabulary.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { ApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";

const VOCABULARY_VALUES = Object.values(AGENT_VISIBLE_DENY_REASONS);

function makeDenyChannel(): ApprovalChannel {
  return {
    requestApproval: async (_req: ApprovalRequest) => ({
      decision: "deny" as const,
      decided_at: new Date().toISOString(),
      decided_by: "timeout" as const,
    }),
    stop: async () => {},
  };
}

describe("principal-policy gate deny info-leak (#48)", () => {
  let gate: ApprovalGate;

  beforeEach(() => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const baseline = new BaselineTracker(storage, masterKey);
    gate = new ApprovalGate(DEFAULT_POLICY, baseline, makeDenyChannel(), auditLog);
  });

  it("Tier 1 operation deny returns generic vocabulary, not operation name", async () => {
    const result = await gate.evaluate("state_export", {});
    expect(result.allowed).toBe(false);
    expect(VOCABULARY_VALUES).toContain(result.reason);
    expect(result.reason).not.toContain("state_export");
    expect(result.reason).not.toContain("Tier");
  });

  it("Tier 2 anomaly deny returns generic vocabulary", async () => {
    // First call establishes baseline, second may trigger anomaly
    await gate.evaluate("state_read", { namespace: "ns1" });
    const result = await gate.evaluate("state_read", { namespace: "brand_new_ns" });
    if (!result.allowed) {
      expect(VOCABULARY_VALUES).toContain(result.reason);
      expect(result.reason).not.toContain("namespace");
      expect(result.reason).not.toContain("Tier");
    }
  });

  it("unlisted operation deny returns generic vocabulary, not SEC-011 reference", async () => {
    const result = await gate.evaluate("totally_unknown_operation", {});
    expect(result.allowed).toBe(false);
    expect(VOCABULARY_VALUES).toContain(result.reason);
    expect(result.reason).not.toContain("SEC-011");
    expect(result.reason).not.toContain("Tier");
    expect(result.reason).not.toContain("totally_unknown_operation");
  });

  it("deny vocabulary is one of the canonical strings", () => {
    expect(VOCABULARY_VALUES).toContain(AGENT_VISIBLE_DENY_REASONS.REQUIRES_APPROVAL);
    expect(VOCABULARY_VALUES).toContain(AGENT_VISIBLE_DENY_REASONS.NOT_PERMITTED);
    expect(VOCABULARY_VALUES).toContain(AGENT_VISIBLE_DENY_REASONS.REQUIRES_OPERATOR);
    expect(VOCABULARY_VALUES).toHaveLength(3);
  });
});
