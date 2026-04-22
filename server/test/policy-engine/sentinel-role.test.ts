/**
 * Sentinel-role flag enforcement (Walkthrough Key 11 LOCKED).
 * Sentinels are inward-facing only — narrower attack surface than ordinary agents.
 */

import { describe, expect, it } from "vitest";
import { GATE_REASON_CODES } from "../../src/policy-engine/constants.js";
import {
  evaluateMemoryGate,
  evaluateOutputsGate,
} from "../../src/policy-engine/gates/index.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import {
  checkSentinelRestriction,
  sentinelPolicyIsValid,
} from "../../src/policy-engine/sentinel-role.js";
import { buildFortress } from "./fixture.js";

function ctxFor(f: ReturnType<typeof buildFortress>, policy: SlotGateExtendedContext["policy"]): SlotGateExtendedContext {
  return {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: f.master.public.fortress_id,
  };
}

describe("policy-engine/sentinel-role — inward-facing restriction", () => {
  it("denies sentinel access to another agent even when a grant exists", () => {
    const f = buildFortress();
    // Pathological authoring: operator incorrectly granted a sentinel an
    // outbound read. The sentinel restriction must still deny.
    const policy = compileFixturePolicy({
      agent_id: "watcher",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent watcher is a sentinel.",
        "Agent watcher may read outputs from agent researcher.",
      ].join("\n"),
    });
    const ctx = ctxFor(f, policy);
    const result = evaluateOutputsGate(ctx, {
      agent_id: "watcher",
      counterparty: "researcher",
      action: "read",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(GATE_REASON_CODES.SENTINEL_INWARD_RESTRICTION);
  });

  it("permits sentinel access to self (audit log reads, etc.)", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "watcher",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent watcher is a sentinel.",
        "Agent watcher may read memory from agent watcher.",
      ].join("\n"),
    });
    const ctx = ctxFor(f, policy);
    const result = evaluateMemoryGate(ctx, {
      agent_id: "watcher",
      counterparty: "watcher",
      action: "read",
    });
    expect(result.decision).toBe("allow");
  });

  it("non-sentinel agents pass the sentinel check cleanly", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english: "Agent a1 may read outputs from agent a2.",
    });
    expect(checkSentinelRestriction(policy, "a2").allowed).toBe(true);
  });
});

describe("policy-engine/sentinel-role — structural policy validation", () => {
  it("rejects a sentinel policy that declares commitment classes", () => {
    const policy = compileFixturePolicy({
      agent_id: "watcher",
      fortress_id: "f1",
      policy_version: 1,
      source_english: [
        "Agent watcher is a sentinel.",
        "Agent watcher may emit commitments of class research-findings.",
      ].join("\n"),
    });
    const v = sentinelPolicyIsValid(policy);
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/sentinel.*commitment/i);
  });

  it("accepts a non-sentinel policy that declares commitment classes", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english: "Agent a1 may emit commitments of class research-findings.",
    });
    expect(sentinelPolicyIsValid(policy).valid).toBe(true);
  });
});
