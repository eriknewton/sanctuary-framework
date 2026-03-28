/**
 * Sanctuary MCP Server — SEC-001 Regression Test
 *
 * SEC-001: state_delete with 3-pass secure overwrite was classified as
 * Tier 3 (auto-allow), meaning an agent could irreversibly destroy all
 * user state without human approval.
 *
 * This test verifies that state_delete is now Tier 1 (always requires
 * explicit human approval before execution).
 *
 * These tests would have FAILED before the SEC-001 fix was applied.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import {
  AutoApproveChannel,
  CallbackApprovalChannel,
  StderrApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY, parsePolicy } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

describe("SEC-001: state_delete requires explicit human approval", () => {
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

  // ── Policy structure tests ─────────────────────────────────────────

  it("DEFAULT_POLICY includes state_delete in tier1_always_approve", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("state_delete");
  });

  it("DEFAULT_POLICY does NOT include state_delete in tier3_always_allow", () => {
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain("state_delete");
  });

  // ── Gate evaluation tests ──────────────────────────────────────────

  it("gate classifies state_delete as Tier 1 and denies when channel denies", async () => {
    const denials: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (req) => {
      denials.push(req);
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      };
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const result = await gate.evaluate("sanctuary/state_delete", {
      namespace: "user-data",
      key: "important-state",
    });

    expect(result.tier).toBe(1);
    expect(result.approval_required).toBe(true);
    expect(result.allowed).toBe(false);
    // Verify the approval request was sent to the channel
    expect(denials).toHaveLength(1);
    expect(denials[0]!.operation).toBe("state_delete");
    expect(denials[0]!.tier).toBe(1);
  });

  it("gate allows state_delete when human explicitly approves", async () => {
    const channel = new AutoApproveChannel();
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const result = await gate.evaluate("sanctuary/state_delete", {
      namespace: "user-data",
      key: "some-key",
    });

    expect(result.tier).toBe(1);
    expect(result.approval_required).toBe(true);
    expect(result.allowed).toBe(true);
  });

  it("gate denies state_delete on stderr channel timeout (SEC-002 integration)", async () => {
    // The stderr channel auto-denies after 100ms (SEC-002 hardened).
    // state_delete as Tier 1 must be denied on timeout.
    const channel = new StderrApprovalChannel({
      type: "stderr",
      timeout_seconds: 0.1, // 100ms
    });
    const gate = new ApprovalGate(DEFAULT_POLICY, baseline, channel, auditLog);

    const result = await gate.evaluate("sanctuary/state_delete", {
      namespace: "user-data",
      key: "critical-key",
    });

    expect(result.allowed).toBe(false);
    expect(result.approval_required).toBe(true);
    expect(result.tier).toBe(1);
  });

  // ── Generated YAML policy tests ────────────────────────────────────

  it("generated default YAML places state_delete in tier1_always_approve", () => {
    // The default YAML is what gets written to ~/.sanctuary/principal-policy.yaml
    // on first run. Parse it and verify state_delete is in Tier 1.
    // We test this by re-parsing the DEFAULT_POLICY through parsePolicy
    // with a JSON representation, simulating what loadPrincipalPolicy does.
    const policyJson = JSON.stringify({
      version: 1,
      tier1_always_approve: DEFAULT_POLICY.tier1_always_approve,
      tier3_always_allow: DEFAULT_POLICY.tier3_always_allow,
    });
    const parsed = parsePolicy(policyJson);

    expect(parsed.tier1_always_approve).toContain("state_delete");
    expect(parsed.tier3_always_allow).not.toContain("state_delete");
  });

  it("user policy YAML that still lists state_delete in tier3 does not override DEFAULT_POLICY tier1", () => {
    // If a user has an old policy YAML that lists state_delete in tier3,
    // and they also have it in tier1, the gate checks tier1 FIRST.
    // This test verifies the gate evaluation order is correct.
    const customPolicy = {
      ...DEFAULT_POLICY,
      tier1_always_approve: [...DEFAULT_POLICY.tier1_always_approve],
      // Simulate old policy that still has state_delete in tier3
      tier3_always_allow: [...DEFAULT_POLICY.tier3_always_allow, "state_delete"],
    };

    const channel = new CallbackApprovalChannel(async () => ({
      decision: "deny",
      decided_at: new Date().toISOString(),
      decided_by: "human",
    }));
    const gate = new ApprovalGate(customPolicy, baseline, channel, auditLog);

    return gate.evaluate("sanctuary/state_delete", {
      namespace: "test",
      key: "test",
    }).then((result) => {
      // Tier 1 check happens before Tier 3 in gate.ts — state_delete
      // is caught at Tier 1 even if it also appears in Tier 3.
      expect(result.tier).toBe(1);
      expect(result.approval_required).toBe(true);
    });
  });
});
