/**
 * Coordination policy-gate enforcement.
 *
 * Two surfaces are exercised:
 *
 *   1. `proposeHandoff` runs the recipient policy gate. A deny short-circuits
 *      handoff creation: no record is persisted, a single signed denial
 *      audit payload is emitted with `actor_role: "policy_gate"`.
 *
 *   2. `transferContextSlot` (called when context content actually moves
 *      from sender to recipient post-acceptance) runs the same gate plus an
 *      optional privacy filter.
 */

import { describe, expect, it } from "vitest";
import {
  type CoordinationGateDecision,
  type CoordinationPolicyGate,
  HandoffPolicyDenialError,
  transferContextSlot,
  verifyAuditPayload,
} from "../../src/coordination/index.js";
import { buildCoordinationFixture } from "./fixture.js";

function gate(decision: CoordinationGateDecision): CoordinationPolicyGate {
  return {
    evaluateContextTransfer: () => decision,
  };
}

describe("coordination/policy-gate — proposeHandoff", () => {
  it("policy deny on context transfer fails closed and emits a signed operator denial", async () => {
    const f = buildCoordinationFixture({
      policyGate: gate({ decision: "deny", reason_code: "no_matching_grant" }),
    });
    const result = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: {
        category: "delegate_subtask",
        requested_capabilities: ["plans"],
        priority: "normal",
      },
      context_reference: {
        policy_context_id: "pc-test-1",
        audit_entry_id: "ae-test-1",
        placeholder_refs: [],
      },
      operator: f.operator.signer,
    });
    expect(result.status).toBe("denied");
    expect(result.record).toBeUndefined();
    expect(result.audit_payload.actor_role).toBe("policy_gate");
    expect(result.audit_payload.reason_class).toBe("policy_deny");
    expect(verifyAuditPayload(result.audit_payload, f.keyResolver)).toBe(true);

    const persisted = await f.coordinator.listHandoffs();
    expect(persisted).toHaveLength(0);
  });

  it("policy deny without an operator signer surfaces HandoffPolicyDenialError", async () => {
    const f = buildCoordinationFixture({
      policyGate: gate({ decision: "deny", reason_code: "no_matching_grant" }),
    });
    await expect(
      f.coordinator.proposeHandoff({
        sender: f.sender.signer,
        recipient_agent_id: f.recipient.agent_id,
        identity_id: f.operator.identity_id,
        task_scope: {
          category: "delegate_subtask",
          requested_capabilities: ["plans"],
          priority: "normal",
        },
        context_reference: {
          policy_context_id: "pc-test-1",
          audit_entry_id: "ae-test-1",
          placeholder_refs: [],
        },
      }),
    ).rejects.toBeInstanceOf(HandoffPolicyDenialError);
  });

  it("policy allow proceeds to a normal handoff create", async () => {
    const f = buildCoordinationFixture({
      policyGate: gate({ decision: "allow", reason_code: "rule_allow" }),
    });
    const result = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: {
        category: "delegate_subtask",
        requested_capabilities: ["plans"],
        priority: "normal",
      },
      context_reference: {
        policy_context_id: "pc-test-1",
        audit_entry_id: "ae-test-1",
        placeholder_refs: [],
      },
    });
    expect(result.status).toBe("created");
    expect(result.record).toBeDefined();
  });
});

describe("coordination/policy-gate — transferContextSlot", () => {
  it("denies when handoff is not in accepted state", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: {
        category: "delegate_subtask",
        requested_capabilities: ["plans"],
        priority: "normal",
      },
      context_reference: {
        policy_context_id: "pc-test-1",
        audit_entry_id: "ae-test-1",
        placeholder_refs: [],
      },
    });
    const result = await transferContextSlot({
      handoff: proposed.record!,
      request: { slot: "plans", content: { task: "summarize" } },
      policyGate: gate({ decision: "allow", reason_code: "rule_allow" }),
    });
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      expect(result.reason_code).toBe("handoff_not_accepted");
    }
  });

  it("denies when policy gate denies, even after acceptance", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: {
        category: "delegate_subtask",
        requested_capabilities: ["credentials"],
        priority: "normal",
      },
      context_reference: {
        policy_context_id: "pc-test-1",
        audit_entry_id: "ae-test-1",
        placeholder_refs: [],
      },
    });
    await f.coordinator.acceptHandoff({
      handoff_id: proposed.record!.handoff_id,
      recipient: f.recipient.signer,
    });
    const updated = (await f.coordinator.getHandoff(
      proposed.record!.handoff_id,
    ))!;
    const result = await transferContextSlot({
      handoff: updated,
      request: { slot: "credentials", content: { token: "redacted" } },
      policyGate: gate({
        decision: "deny",
        reason_code: "no_matching_grant",
      }),
    });
    expect(result.status).toBe("denied");
    if (result.status === "denied") {
      expect(result.reason_code).toBe("no_matching_grant");
    }
  });

  it("filtered status surfaces when privacy adapter mutates content", async () => {
    const f = buildCoordinationFixture();
    const proposed = await f.coordinator.proposeHandoff({
      sender: f.sender.signer,
      recipient_agent_id: f.recipient.agent_id,
      identity_id: f.operator.identity_id,
      task_scope: {
        category: "delegate_subtask",
        requested_capabilities: ["outputs"],
        priority: "normal",
      },
      context_reference: {
        policy_context_id: "pc-test-1",
        audit_entry_id: "ae-test-1",
        placeholder_refs: [],
      },
    });
    await f.coordinator.acceptHandoff({
      handoff_id: proposed.record!.handoff_id,
      recipient: f.recipient.signer,
    });
    const updated = (await f.coordinator.getHandoff(
      proposed.record!.handoff_id,
    ))!;
    const result = await transferContextSlot({
      handoff: updated,
      request: { slot: "outputs", content: { person: "Alice" } },
      policyGate: gate({ decision: "allow", reason_code: "rule_allow" }),
      privacyFilter: {
        async filterForPeerAgent({ payload }) {
          void payload;
          return { status: "filtered", payload: { person: "PERSON_1" } };
        },
      },
    });
    expect(result.status).toBe("filtered");
    if (result.status === "filtered") {
      expect(result.content).toEqual({ person: "PERSON_1" });
    }
  });
});
