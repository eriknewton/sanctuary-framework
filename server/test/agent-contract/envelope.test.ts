/**
 * Agent Contract v0.1 — Harness envelope tests (§2.3).
 */

import { describe, it, expect } from "vitest";
import {
  stampReceiverCheck,
  verifyEnvelopeBodyHash,
  wrapHarnessEnvelope,
} from "../../src/agent-contract/envelope.js";
import { AgentContractError } from "../../src/agent-contract/errors.js";

describe("Harness envelope (§2.3)", () => {
  it("wraps a body, computes body_hash, passes schema validation", () => {
    const env = wrapHarnessEnvelope({
      direction: "harness_in",
      agent_id: "a",
      fortress_id: "f",
      capability_kind: "tool-call",
      capability_target: "filesystem/read",
      body: { a: 1, b: "two" },
      policy_version: 1,
      claimant: "a",
    });
    expect(env.direction).toBe("harness_in");
    expect(env.body_hash.length).toBeGreaterThan(0);
  });

  it("receiver_check stamp yields a valid envelope", () => {
    const env = wrapHarnessEnvelope({
      direction: "harness_out",
      agent_id: "a",
      fortress_id: "f",
      capability_kind: "tool-call",
      capability_target: "x",
      body: { k: "v" },
      policy_version: 1,
      claimant: "a",
    });
    const stamped = stampReceiverCheck(env, {
      decision: "allow",
      reason_code: "ok",
    });
    expect(stamped.receiver_check?.decision).toBe("allow");
  });

  it("body_hash is deterministic across key-order permutations", () => {
    const a = wrapHarnessEnvelope({
      direction: "harness_out",
      agent_id: "a",
      fortress_id: "f",
      capability_kind: "tool-call",
      capability_target: "x",
      body: { a: 1, b: 2 },
      policy_version: 1,
      claimant: "a",
    });
    const b = wrapHarnessEnvelope({
      direction: "harness_out",
      agent_id: "a",
      fortress_id: "f",
      capability_kind: "tool-call",
      capability_target: "x",
      body: { b: 2, a: 1 },
      policy_version: 1,
      claimant: "a",
    });
    expect(a.body_hash).toBe(b.body_hash);
  });

  it("verifyEnvelopeBodyHash catches tampered body", () => {
    const env = wrapHarnessEnvelope({
      direction: "harness_out",
      agent_id: "a",
      fortress_id: "f",
      capability_kind: "tool-call",
      capability_target: "x",
      body: { k: "v" },
      policy_version: 1,
      claimant: "a",
    });
    const tampered = {
      ...env,
      body: { k: "forged" },
    } as typeof env;
    expect(() => verifyEnvelopeBodyHash(tampered)).toThrow(AgentContractError);
  });
});
