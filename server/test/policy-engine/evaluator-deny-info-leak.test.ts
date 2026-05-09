/**
 * Regression test for full-sweep #48 (P1): evaluator denial info-leak.
 *
 * Asserts that every deny path on the policy-engine slot-gate evaluator
 * returns a generic explanation, not revealing slot names, agent IDs,
 * counterparties, or actions.
 */

import { describe, it, expect } from "vitest";
import {
  evaluateMemoryGate,
  evaluateOutputsGate,
} from "../../src/policy-engine/gates/index.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import { GATE_REASON_CODES } from "../../src/policy-engine/constants.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import type { GateRequest } from "../../src/policy-engine/types.js";
import { buildFortress } from "./fixture.js";

function ctxFor(
  f: ReturnType<typeof buildFortress>,
  policy: SlotGateExtendedContext["policy"]
): SlotGateExtendedContext {
  return {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: f.master.public.fortress_id,
  };
}

const GENERIC = "operation not permitted";

describe("policy-engine evaluator deny info-leak (#48)", () => {
  it("NULL_POLICY_HERMETIC_DENY uses generic explanation", () => {
    const f = buildFortress();
    const ctx = ctxFor(f, null);
    const req: GateRequest = {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
    };
    const result = evaluateMemoryGate(ctx, req);
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(GATE_REASON_CODES.NULL_POLICY_HERMETIC_DENY);
    expect(result.explanation).toBe(GENERIC);
    expect(result.explanation).not.toContain("a1");
    expect(result.explanation).not.toContain("hermetic");
  });

  it("SLOT_MODE_DENY uses generic explanation", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    const ctx = ctxFor(f, policy);
    const result = evaluateMemoryGate(ctx, {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(GATE_REASON_CODES.SLOT_MODE_DENY);
    expect(result.explanation).toBe(GENERIC);
    expect(result.explanation).not.toContain("memory");
    expect(result.explanation).not.toContain("a1");
  });

  it("NO_MATCHING_GRANT uses generic explanation", () => {
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
      action: "write",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(GATE_REASON_CODES.NO_MATCHING_GRANT);
    expect(result.explanation).toBe(GENERIC);
    expect(result.explanation).not.toContain("grant");
    expect(result.explanation).not.toContain("a1");
  });

  it("ALLOW path retains rich explanation (not genericized)", () => {
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
      action: "read",
    });
    expect(result.decision).toBe("allow");
    expect(result.reason_code).toBe(GATE_REASON_CODES.RULE_ALLOW);
    expect(result.explanation).toContain("grant matched");
  });
});
