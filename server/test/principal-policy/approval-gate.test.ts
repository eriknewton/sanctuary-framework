/**
 * Approval Gate Tests
 *
 * Verifies the three-tier evaluation logic:
 * - Tier 1: Always-approve operations are gated
 * - Tier 2: Behavioral anomalies trigger approval
 * - Tier 3: Normal operations pass through
 * - Denial responses don't reveal policy details
 * - Approval channel integration
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import {
  AutoApproveChannel,
  CallbackApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import type { PrincipalPolicy, ApprovalRequest } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function createTestPolicy(overrides?: Partial<PrincipalPolicy>): PrincipalPolicy {
  return {
    version: 1,
    tier1_always_approve: ["state_export", "state_delete", "identity_rotate"],
    tier2_anomaly: {
      new_namespace_access: "approve",
      new_counterparty: "approve",
      frequency_spike_multiplier: 5,
      max_signs_per_minute: 3,
      bulk_read_threshold: 5,
      first_session_policy: "approve",
    },
    tier3_always_allow: [
      "state_read", "state_write", "state_list",
      "identity_create", "identity_list", "identity_sign", "identity_verify",
      "monitor_health", "principal_policy_view", "principal_baseline_view",
    ],
    approval_channel: {
      type: "stderr",
      timeout_seconds: 300,
      auto_deny: true,
    },
    ...overrides,
  };
}

describe("Approval Gate", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  let auditLog: AuditLog;
  let baseline: BaselineTracker;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    auditLog = new AuditLog(storage, masterKey);
    baseline = new BaselineTracker(storage, masterKey);
  });

  describe("Tier 1 — always requires approval", () => {
    it("gates Tier 1 operations and returns approval result", async () => {
      const policy = createTestPolicy();
      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline, channel, auditLog);

      const result = await gate.evaluate("sanctuary/state_export", {});

      expect(result.tier).toBe(1);
      expect(result.allowed).toBe(true); // AutoApprove always approves
      expect(result.approval_required).toBe(true);
    });

    it("denies Tier 1 operations when channel denies", async () => {
      const policy = createTestPolicy();
      const channel = new CallbackApprovalChannel(async () => ({
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      }));
      const gate = new ApprovalGate(policy, baseline, channel, auditLog);

      const result = await gate.evaluate("sanctuary/state_export", {});

      expect(result.tier).toBe(1);
      expect(result.allowed).toBe(false);
      expect(result.approval_required).toBe(true);
    });
  });

  describe("Tier 2 — behavioral anomaly detection", () => {
    it("flags first session with non-tier-3 operations", async () => {
      const policy = createTestPolicy();
      const channel = new CallbackApprovalChannel(async () => ({
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      }));
      const gate = new ApprovalGate(policy, baseline, channel, auditLog);

      // "reputation_record" is not in tier3_always_allow for this test policy
      const result = await gate.evaluate("sanctuary/reputation_record", {});

      expect(result.tier).toBe(2);
      expect(result.approval_required).toBe(true);
    });

    it("flags new namespace access", async () => {
      const policy = createTestPolicy();
      // Load a saved baseline so it's not first session
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      const result = await gate.evaluate("sanctuary/state_read", {
        namespace: "brand-new-namespace",
      });

      expect(result.tier).toBe(2);
      expect(result.approval_required).toBe(true);
    });

    it("flags new counterparty", async () => {
      const policy = createTestPolicy();
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      const result = await gate.evaluate("sanctuary/reputation_record", {
        counterparty_did: "did:sanctuary:unknown-agent",
      });

      // Should be tier 2 for new counterparty
      expect(result.tier).toBe(2);
      expect(result.approval_required).toBe(true);
    });

    it("flags excessive signing", async () => {
      const policy = createTestPolicy();
      // Not first session
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      // Sign 4 times — exceeds max_signs_per_minute of 3
      await gate.evaluate("sanctuary/identity_sign", { payload: "a" });
      await gate.evaluate("sanctuary/identity_sign", { payload: "b" });
      await gate.evaluate("sanctuary/identity_sign", { payload: "c" });
      const result = await gate.evaluate("sanctuary/identity_sign", { payload: "d" });

      expect(result.tier).toBe(2);
      expect(result.approval_required).toBe(true);
    });

    it("flags bulk reads", async () => {
      const policy = createTestPolicy();
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();
      // Seed the namespace so it's known
      baseline2.recordNamespaceAccess("target-ns");

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      // Read 6 times from same namespace — exceeds bulk_read_threshold of 5
      for (let i = 0; i < 5; i++) {
        await gate.evaluate("sanctuary/state_read", { namespace: "target-ns" });
      }
      const result = await gate.evaluate("sanctuary/state_read", { namespace: "target-ns" });

      expect(result.tier).toBe(2);
      expect(result.approval_required).toBe(true);
    });
  });

  describe("Tier 3 — always allowed", () => {
    it("allows standard operations without approval", async () => {
      const policy = createTestPolicy();
      // Not first session
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      // state_read with no namespace arg → no anomaly
      const result = await gate.evaluate("sanctuary/state_read", {});

      expect(result.tier).toBe(3);
      expect(result.allowed).toBe(true);
      expect(result.approval_required).toBe(false);
    });

    it("allows monitor_health without approval", async () => {
      const policy = createTestPolicy();
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      const result = await gate.evaluate("sanctuary/monitor_health", {});

      expect(result.tier).toBe(3);
      expect(result.allowed).toBe(true);
      expect(result.approval_required).toBe(false);
    });
  });

  describe("SEC-011 — unlisted operations default to Tier 1", () => {
    it("requires approval for operations not in any tier list", async () => {
      const policy = createTestPolicy();
      const channel = new AutoApproveChannel();
      // Not first session
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      // "totally_new_tool" is not in tier1, tier3, or any list
      const result = await gate.evaluate("sanctuary/totally_new_tool", {});

      expect(result.tier).toBe(1);
      expect(result.approval_required).toBe(true);
      expect(result.allowed).toBe(true); // AutoApprove approves
    });

    it("denies unlisted operations when channel denies", async () => {
      const policy = createTestPolicy();
      const channel = new CallbackApprovalChannel(async () => ({
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      }));
      // Not first session
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      const result = await gate.evaluate("sanctuary/totally_new_tool", {});

      expect(result.tier).toBe(1);
      expect(result.approval_required).toBe(true);
      expect(result.allowed).toBe(false);
    });

    it("logs unclassified operation to audit log", async () => {
      const policy = createTestPolicy();
      const channel = new AutoApproveChannel();
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      await gate.evaluate("sanctuary/unregistered_dangerous_op", {});

      // Audit log should have entries: one for unclassified warning, one for gate decision
      expect(auditLog.size).toBeGreaterThanOrEqual(2);
    });

    it("still allows explicitly listed Tier 3 operations", async () => {
      const policy = createTestPolicy();
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      // state_read is in tier3_always_allow
      const result = await gate.evaluate("sanctuary/state_read", {});

      expect(result.tier).toBe(3);
      expect(result.allowed).toBe(true);
      expect(result.approval_required).toBe(false);
    });
  });

  describe("security properties", () => {
    it("denial responses do not reveal tier1 operation list", async () => {
      const policy = createTestPolicy();
      const denials: ApprovalRequest[] = [];
      const channel = new CallbackApprovalChannel(async (req) => {
        denials.push(req);
        return {
          decision: "deny",
          decided_at: new Date().toISOString(),
          decided_by: "human",
        };
      });
      const gate = new ApprovalGate(policy, baseline, channel, auditLog);

      const result = await gate.evaluate("sanctuary/state_export", {});

      // The gate result reason should not list other tier1 operations
      expect(result.reason).not.toContain("identity_rotate");
      expect(result.reason).not.toContain("tier1_always_approve");
    });

    it("all gate decisions are audit-logged", async () => {
      const policy = createTestPolicy();
      await baseline.save();
      const baseline2 = new BaselineTracker(storage, masterKey);
      await baseline2.load();

      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

      // Tier 1 → approve
      await gate.evaluate("sanctuary/state_export", {});
      // Tier 3 → allow
      await gate.evaluate("sanctuary/state_read", {});

      expect(auditLog.size).toBeGreaterThanOrEqual(2);
    });

    it("strips sanctuary/ prefix before evaluation", async () => {
      const policy = createTestPolicy();
      const channel = new AutoApproveChannel();
      const gate = new ApprovalGate(policy, baseline, channel, auditLog);

      // "sanctuary/state_export" should match "state_export" in tier1
      const result = await gate.evaluate("sanctuary/state_export", {});
      expect(result.tier).toBe(1);
    });
  });
});
