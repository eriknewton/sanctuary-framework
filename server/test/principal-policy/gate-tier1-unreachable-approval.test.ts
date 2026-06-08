/**
 * Approval-gate fail-closed guard for unreachable approval channels
 *
 * Regression guard for full-sweep finding #49. The gate's contract is that a
 * Tier 1 operation NEVER auto-allows. Channel-internal timeouts already
 * resolve with decision: "deny" per SEC-002 (StderrApprovalChannel,
 * WebhookApprovalChannel). The remaining path is a channel that throws
 * (network down, callback unreachable, dashboard SSE peer dropped, webhook
 * DNS failure). The gate catches and converts the exception to a denial,
 * audit-logging the cause.
 *
 * If a future refactor removes the catch in `requestApproval` and lets a
 * channel exception propagate, this test fails loudly: an unhandled
 * rejection on a Tier 1 operation is an indeterminate state and a Sanctuary
 * Invariant violation.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function createTestPolicy(): PrincipalPolicy {
  return {
    version: 1,
    tier1_always_approve: [
      "state_export",
      "state_delete",
      "identity_rotate",
      "principal_policy_view",
      "principal_baseline_view",
      "sanctuary_policy_status",
    ],
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
      "monitor_health",
    ],
    approval_channel: {
      type: "stderr",
      timeout_seconds: 300,
      auto_deny: true,
    },
  };
}

describe("Approval gate fail-closed on unreachable channel (full-sweep #49)", () => {
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

  it("denies a Tier 1 operation when the approval channel throws (network-down simulation)", async () => {
    const policy = createTestPolicy();
    const channelError = new Error("network unreachable: ECONNREFUSED 127.0.0.1:7777");
    const channel = new CallbackApprovalChannel(async () => {
      throw channelError;
    });
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);

    const result = await gate.evaluate("state_export", {});

    // Gate must NOT allow.
    expect(result.allowed).toBe(false);
    // Gate must NOT raise. The await returned cleanly.
    expect(result.tier).toBe(1);
    expect(result.approval_required).toBe(true);
    // The synthetic deny response is attached so callers can inspect why.
    expect(result.approval_response?.decision).toBe("deny");
    expect(result.approval_response?.decided_by).toBe("channel_failure");
  });

  it("audit-logs the deny with channel_failure cause and the underlying error message", async () => {
    const policy = createTestPolicy();
    const channelError = new Error("timed out waiting for SSE peer");
    const channel = new CallbackApprovalChannel(async () => {
      throw channelError;
    });
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);

    await gate.evaluate("identity_rotate", {});

    const { entries } = await auditLog.query({ layer: "l2", limit: 50 });
    const denyEntry = entries.find(
      (e) => e.operation === "gate_deny:identity_rotate"
    );
    expect(denyEntry).toBeDefined();
    expect(denyEntry?.details?.decided_by).toBe("channel_failure");
    expect(denyEntry?.details?.channel_error).toContain("timed out waiting for SSE peer");
    expect(denyEntry?.details?.tier).toBe(1);
  });

  it("denies an unclassified operation (SEC-011 default-Tier-1) when the channel throws", async () => {
    const policy = createTestPolicy();
    const channel = new CallbackApprovalChannel(async () => {
      throw new Error("dashboard websocket disconnected");
    });

    // Skip first-session anomaly evaluation (which would short-circuit at
    // Tier 2 before SEC-011's Tier-1 default kicks in) by saving and
    // reloading the baseline.
    await baseline.save();
    const baseline2 = new BaselineTracker(storage, masterKey);
    await baseline2.load();
    const gate = new ApprovalGate(policy, baseline2, channel, auditLog);

    const result = await gate.evaluate("totally_unknown_operation", {});

    expect(result.allowed).toBe(false);
    expect(result.tier).toBe(1);
    expect(result.approval_response?.decided_by).toBe("channel_failure");
  });
});
