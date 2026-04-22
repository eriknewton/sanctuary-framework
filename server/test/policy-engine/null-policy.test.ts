/**
 * Null policy — hermetic deny-all default (Walkthrough Key 10 LOCKED
 * "Default posture: hermetic.")
 */

import { describe, expect, it } from "vitest";
import { POLICY_SLOTS } from "../../src/policy-engine/constants.js";
import {
  buildNullPolicy,
  isNullPolicy,
} from "../../src/policy-engine/null-policy.js";

describe("policy-engine/null-policy — hermetic default", () => {
  it("emits policy_version 0 so any authored version supersedes it", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    expect(p.policy_version).toBe(0);
    expect(isNullPolicy(p)).toBe(true);
  });

  it("denies every canonical slot", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    for (const slot of POLICY_SLOTS) {
      expect(p.slots[slot].mode).toBe("deny");
      expect(p.slots[slot].grants).toEqual([]);
    }
  });

  it("declares no capabilities and is_sentinel=false", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    expect(p.capabilities.concordia_commitment_classes).toEqual([]);
    expect(p.capabilities.honeypot_skill_ids).toEqual([]);
    expect(p.capabilities.is_sentinel).toBe(false);
  });

  it("defaults the auto-trigger ladder to safe-position (honeypot armed, others operator-approved)", () => {
    const p = buildNullPolicy({ agent_id: "a1", fortress_id: "f1" });
    expect(p.auto_trigger_ladder.honeypot_auto_freeze).toBe(true);
    expect(p.auto_trigger_ladder.threshold_rule_action).toBe("operator_approved");
    expect(p.auto_trigger_ladder.ml_anomaly_action).toBe("operator_approved");
  });
});
