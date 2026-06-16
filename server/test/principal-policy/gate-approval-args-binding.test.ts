/**
 * Approval-amplification fix — gate-level args-binding emission.
 *
 * Finding (security sweep, main @ b3b6aca1): in `replace`-mode
 * approval-redirect the inbox matched an operator resolution to a pending
 * Tier-1 request SOLELY by `<timestamp>:<operation>`, with no args binding.
 * Two same-op same-ms requests with DIFFERENT args (e.g. state_export of
 * PUBLIC vs SECRET) collapsed to ONE inbox card with TWO channel waiters, so
 * one benign approval settled both — approving a never-displayed SECRET
 * export off a PUBLIC approval (Invariant #3 violation).
 *
 * The fix computes `args_binding = normalizedArgsHash(args)` at the gate
 * (the SAME normalization the direct approval-proof envelope binds via
 * `normalized_args_hash`) and threads it onto every `requested`/`resolved`
 * approval event and onto the `ApprovalRequest`. This test asserts the gate
 * emission contract: the binding is present, equals the canonical hash, and
 * DIFFERS for different args while being STABLE for identical args.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import type { ApprovalGateEvent } from "../../src/principal-policy/approval-aggregator.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  normalizedArgsHash,
  deriveTargetResource,
} from "../../src/agent-native/safety-base.js";

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

describe("gate args-binding emission (approval-amplification fix)", () => {
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

  /** Capture the `requested` event the gate emits for one evaluate() call. */
  async function captureRequestedEvent(
    operation: string,
    args: Record<string, unknown>,
  ): Promise<ApprovalGateEvent> {
    const events: ApprovalGateEvent[] = [];
    // Channel denies (callback throws) so evaluate() returns promptly; the
    // `requested` event has already been emitted before the channel call.
    const channel = new CallbackApprovalChannel(async () => {
      throw new Error("channel down");
    });
    const gate = new ApprovalGate(
      createTestPolicy(),
      baseline,
      channel,
      auditLog,
      undefined, // injectionDetector
      undefined, // onInjectionAlert
      (e) => events.push(e as ApprovalGateEvent),
    );
    await gate.evaluate(operation, args);
    const requested = events.find((e) => e.phase === "requested");
    expect(requested).toBeDefined();
    return requested!;
  }

  it("emits args_binding equal to the canonical normalizedArgsHash", async () => {
    const args = { namespace: "SECRET" };
    const ev = await captureRequestedEvent("state_export", args);
    expect(ev.args_binding).toBe(normalizedArgsHash(args));
    // target_resource surfaces the operator-facing label.
    expect(ev.target_resource).toBe(deriveTargetResource("state_export", args));
    expect(ev.target_resource).toContain("SECRET");
  });

  it("emits DIFFERENT args_binding for the same op with different args", async () => {
    const pub = await captureRequestedEvent("state_export", {
      namespace: "PUBLIC",
    });
    const secret = await captureRequestedEvent("state_export", {
      namespace: "SECRET",
    });
    expect(pub.args_binding).toBeDefined();
    expect(secret.args_binding).toBeDefined();
    expect(pub.args_binding).not.toBe(secret.args_binding);
  });

  it("emits STABLE args_binding for the same op with identical args", async () => {
    const a = await captureRequestedEvent("state_export", {
      namespace: "PUBLIC",
    });
    const b = await captureRequestedEvent("state_export", {
      namespace: "PUBLIC",
    });
    expect(a.args_binding).toBe(b.args_binding);
  });
});
