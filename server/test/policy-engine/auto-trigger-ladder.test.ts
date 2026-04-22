/**
 * Auto-trigger ladder (Walkthrough Key 11 LOCKED).
 * - Tier 1 (honeypot): live auto-freeze.
 * - Tier 2 (threshold_rule): stub → always operator_approval_required.
 * - Tier 3 (ml_anomaly): stub → always operator_approval_required.
 */

import { describe, expect, it } from "vitest";
import { GATE_REASON_CODES } from "../../src/policy-engine/constants.js";
import {
  evaluateHoneypotTier,
  evaluateLadder,
  evaluateMLAnomalyTier,
  evaluateThresholdRuleTier,
} from "../../src/policy-engine/auto-trigger-ladder.js";
import { evaluateOutputsGate } from "../../src/policy-engine/gates/index.js";
import type { SlotGateExtendedContext } from "../../src/policy-engine/gates/evaluator.js";
import { compileFixturePolicy } from "../../src/policy-engine/compiler-fixture.js";
import { buildFortress } from "./fixture.js";

function ctxFor(
  f: ReturnType<typeof buildFortress>,
  policy: SlotGateExtendedContext["policy"],
  extras: Partial<SlotGateExtendedContext> = {}
): SlotGateExtendedContext {
  return {
    policy,
    nodeSigningKey: f.nodeKeypair.privateKey,
    nodeId: f.nodeCert.node_id,
    fortressId: f.master.public.fortress_id,
    ...extras,
  };
}

describe("policy-engine/auto-trigger-ladder — honeypot tier (live at v0.1)", () => {
  it("auto-freezes when a registered honeypot skill is invoked", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 may read outputs from agent a2.",
        "Register honeypot exfiltrate_audit_logs on agent a1.",
      ].join("\n"),
    });
    const ctx = ctxFor(f, policy);
    const result = evaluateOutputsGate(ctx, {
      agent_id: "a1",
      counterparty: "a2",
      action: "read",
      invoked_skill_id: "exfiltrate_audit_logs",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(GATE_REASON_CODES.HONEYPOT_AUTO_FREEZE);
    expect(result.receipt.ladder_tier_fired).toBe("honeypot");
  });

  it("ignores invoked_skill_id that is not a registered honeypot", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english:
        "Register honeypot dump_all_creds on agent a1.",
    });
    const res = evaluateHoneypotTier(policy, "read_user_profile");
    expect(res.fired).toBeUndefined();
  });

  it("does not fire when auto_freeze is false in the compiled policy", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english: "Register honeypot trap on agent a1.",
    });
    policy.auto_trigger_ladder.honeypot_auto_freeze = false;
    const res = evaluateHoneypotTier(policy, "trap");
    expect(res.fired).toBeUndefined();
  });
});

describe("policy-engine/auto-trigger-ladder — threshold_rule (stub)", () => {
  it("returns operator_approval_required when a threshold signal is present", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english: "",
    });
    const res = evaluateThresholdRuleTier(policy, "egress_volume_3x_baseline");
    expect(res.fired).toBe("threshold_rule");
    expect(res.decision).toBe("operator_approval_required");
    expect(res.reason_code).toBe(
      GATE_REASON_CODES.THRESHOLD_RULE_OPERATOR_APPROVAL_REQUIRED
    );
  });

  it("passes through when no signal is provided", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english: "",
    });
    expect(evaluateThresholdRuleTier(policy, undefined).fired).toBeUndefined();
  });
});

describe("policy-engine/auto-trigger-ladder — ml_anomaly (stub)", () => {
  it("always routes to operator at v1.0 per Key 11 LOCKED", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english: "",
    });
    policy.auto_trigger_ladder.ml_anomaly_action = "auto"; // v1.x intent
    const res = evaluateMLAnomalyTier(policy, "pattern_drift_score_0.82");
    // Even when the flag says "auto", v1.0 enforces operator_approval_required.
    expect(res.decision).toBe("operator_approval_required");
    expect(res.reason_code).toBe(
      GATE_REASON_CODES.ML_ANOMALY_OPERATOR_APPROVAL_REQUIRED
    );
  });
});

describe("policy-engine/auto-trigger-ladder — evaluation order", () => {
  it("honeypot fires before threshold_rule", () => {
    const f = buildFortress();
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: f.master.public.fortress_id,
      policy_version: 1,
      source_english: [
        "Agent a1 may read outputs from agent a2.",
        "Register honeypot trap on agent a1.",
      ].join("\n"),
    });
    const res = evaluateLadder({
      policy,
      invoked_skill_id: "trap",
      threshold_signal: "egress_volume_3x",
      ml_signal: "drift_high",
    });
    expect(res.fired).toBe("honeypot");
  });

  it("threshold_rule fires before ml_anomaly when honeypot does not fire", () => {
    const policy = compileFixturePolicy({
      agent_id: "a1",
      fortress_id: "f1",
      policy_version: 1,
      source_english: "",
    });
    const res = evaluateLadder({
      policy,
      threshold_signal: "egress_volume_3x",
      ml_signal: "drift_high",
    });
    expect(res.fired).toBe("threshold_rule");
  });
});
