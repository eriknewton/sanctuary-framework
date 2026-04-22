/**
 * Four slot-gate entry points — allow/deny coverage + signed-receipt shape.
 *
 * Each of the four gates (memory, credentials, plans, outputs) is exercised
 * with: hermetic null policy, deny-mode rule, no-matching-grant, matching
 * grant. Receipts are verified with the evaluating node's public key.
 */

import { describe, expect, it } from "vitest";
import { GATE_REASON_CODES, POLICY_SLOTS } from "../../src/policy-engine/constants.js";
import {
  evaluateCredentialsGate,
  evaluateGate,
  evaluateMemoryGate,
  evaluateOutputsGate,
  evaluatePlansGate,
} from "../../src/policy-engine/gates/index.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import { verifyGateReceipt } from "../../src/policy-engine/gate-receipts.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import type { GateRequest } from "../../src/policy-engine/types.js";
import { buildFortress } from "./fixture.js";

function ctxFor(f: ReturnType<typeof buildFortress>, policy: SlotGateExtendedContext["policy"]): SlotGateExtendedContext {
  return {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: f.master.public.fortress_id,
  };
}

describe("policy-engine/gates — hermetic default (null policy)", () => {
  it("null policy denies every slot with null_policy_hermetic_deny", () => {
    const f = buildFortress();
    const ctx = ctxFor(f, null);
    const req: GateRequest = {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
    };
    for (const slot of POLICY_SLOTS) {
      const result = evaluateGate(slot, ctx, req);
      expect(result.decision).toBe("deny");
      expect(result.reason_code).toBe(GATE_REASON_CODES.NULL_POLICY_HERMETIC_DENY);
      expect(result.receipt.slot).toBe(slot);
      expect(result.receipt.policy_version).toBeNull();
      expect(
        verifyGateReceipt(result.receipt, f.nodeKeypair.publicKey)
      ).toBe(true);
    }
  });
});

describe("policy-engine/gates — deny-mode slot rule", () => {
  it("denies with slot_mode_deny even when counterparty matches another slot's grant", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    // memory slot is deny-mode; outputs is grant-mode.
    const ctx = ctxFor(f, policy);
    const result = evaluateMemoryGate(ctx, {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(GATE_REASON_CODES.SLOT_MODE_DENY);
  });
});

describe("policy-engine/gates — grant lookup", () => {
  it("denies on no_matching_grant for the wrong action", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    const ctx = ctxFor(f, policy);
    const result = evaluateOutputsGate(ctx, {
      agent_id: "a1",
      counterparty: "a2",
      action: "write", // grant is read-only
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(GATE_REASON_CODES.NO_MATCHING_GRANT);
  });

  it("allows on a matching grant with a signed receipt", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 7,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    const ctx = ctxFor(f, policy);
    const result = evaluateOutputsGate(ctx, {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
    });
    expect(result.decision).toBe("allow");
    expect(result.reason_code).toBe(GATE_REASON_CODES.RULE_ALLOW);
    expect(result.receipt.policy_version).toBe(7);
    expect(result.receipt.evaluating_node_id).toBe(f.nodeCert.node_id);
    expect(verifyGateReceipt(result.receipt, f.nodeKeypair.publicKey)).toBe(true);
  });
});

describe("policy-engine/gates — four entry points behave identically on identical input", () => {
  it("all four slot gates return the same decision shape under null policy", () => {
    const f = buildFortress();
    const ctx = ctxFor(f, null);
    const req: GateRequest = {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
    };
    const results = [
      evaluateMemoryGate(ctx, req),
      evaluateCredentialsGate(ctx, req),
      evaluatePlansGate(ctx, req),
      evaluateOutputsGate(ctx, req),
    ];
    for (const r of results) {
      expect(r.decision).toBe("deny");
      expect(r.reason_code).toBe(GATE_REASON_CODES.NULL_POLICY_HERMETIC_DENY);
    }
    // Exactly one slot is covered per receipt.
    const slots = results.map((r) => r.receipt.slot);
    expect(new Set(slots)).toEqual(new Set(POLICY_SLOTS));
  });
});

describe("policy-engine/gates — receipt tamper detection", () => {
  it("flips a bit in the signature and verification fails", () => {
    const f = buildFortress();
    const ctx = ctxFor(f, null);
    const r = evaluateMemoryGate(ctx, {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
    });
    // Tamper the FIRST character — base64url last-char touches only padding
    // bits on some lengths so a trailing-char flip can leave the decoded
    // bytes unchanged. First char always affects meaningful payload bytes.
    const firstChar = r.receipt.signature[0];
    const swappedFirst = firstChar === "A" ? "B" : "A";
    const tampered = {
      ...r.receipt,
      signature: swappedFirst + r.receipt.signature.slice(1),
    };
    expect(verifyGateReceipt(tampered, f.nodeKeypair.publicKey)).toBe(false);
  });
});
