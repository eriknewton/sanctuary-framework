import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import {
  CallbackApprovalChannel,
  type ApprovalRequest,
} from "../../src/principal-policy/approval-channel.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

function createTestPolicy(): PrincipalPolicy {
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
    tier3_always_allow: ["state_read", "state_write", "state_list"],
    approval_channel: { type: "stderr", timeout_seconds: 300, auto_deny: true },
  };
}

// SIEM-1: the approval context can be delivered to an EXTERNAL webhook /
// dashboard before approval, so it must never carry secret content. This guards
// summarizeArgs against leaking secret-named fields or nested object secrets.
describe("Approval gate redacts secrets from the approval context (SIEM-1)", () => {
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

  it("redacts secret-named fields, summarizes objects, and leaks no content to the channel", async () => {
    const policy = createTestPolicy();
    let captured: ApprovalRequest | undefined;
    const channel = new CallbackApprovalChannel(async (req: ApprovalRequest) => {
      captured = req;
      return {
        request_id: req.request_id,
        decision: "deny" as const,
        decided_by: "test",
        reason: "captured",
      };
    });
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);

    await gate.evaluate("state_export", {
      passphrase: "topsecret-passphrase-value",
      identity: { encrypted_private_key: "SUPERSECRETKEYMATERIAL", did: "did:key:z" },
      namespace: "my-namespace",
    });

    expect(captured).toBeDefined();
    const summary = captured!.context.args_summary as Record<string, unknown>;
    // secret-named field redacted regardless of value
    expect(summary.passphrase).toBe("[redacted]");
    // object value summarized to shape, not content (nested secret cannot leak)
    expect(summary.identity).toBe("[object(2 keys)]");
    // non-sensitive scalar still passes through for operator context
    expect(summary.namespace).toBe("my-namespace");
    // the raw secret strings must appear NOWHERE in the outbound request
    const serialized = JSON.stringify(captured);
    expect(serialized).not.toContain("SUPERSECRETKEYMATERIAL");
    expect(serialized).not.toContain("topsecret-passphrase-value");
  });
});
