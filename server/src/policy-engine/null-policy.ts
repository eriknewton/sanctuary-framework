/**
 * Sanctuary Policy Engine — Null policy.
 *
 * Walkthrough Key 10 LOCKED: "Default posture: hermetic. Every new agent
 * starts isolated. Operator explicitly opens channels."
 *
 * An agent with no pinned compiled policy MUST be treated as if every slot
 * were mode = "deny". This module returns the canonical null-policy shape
 * for any agent_id + fortress_id so gate code has one path.
 *
 * The null policy carries policy_version = 0, which is below any operator-
 * authored version — that's how receivers distinguish it from a real pinned
 * bundle. policy_version monotonicity guarantees any authored version
 * supersedes it.
 */

import { POLICY_SLOTS } from "./constants.js";
import type { CompiledPolicy, SlotRule } from "./types.js";

/**
 * Build the hermetic null policy for an agent. Deny on all four slots;
 * empty capabilities; auto-trigger ladder in the default (safe) position.
 *
 * The source_english records why the policy exists so operators looking at
 * an audit receipt know "this was the default, the operator has not written
 * anything yet."
 */
export function buildNullPolicy(params: {
  agent_id: string;
  fortress_id: string;
}): CompiledPolicy {
  const denyRule = (slot: (typeof POLICY_SLOTS)[number]): SlotRule => ({
    slot,
    mode: "deny",
    grants: [],
  });
  return {
    schema_version: "0.1",
    agent_id: params.agent_id,
    fortress_id: params.fortress_id,
    policy_version: 0,
    slots: {
      memory: denyRule("memory"),
      credentials: denyRule("credentials"),
      plans: denyRule("plans"),
      outputs: denyRule("outputs"),
    },
    capabilities: {
      concordia_commitment_classes: [],
      honeypot_skill_ids: [],
      is_sentinel: false,
    },
    auto_trigger_ladder: {
      honeypot_auto_freeze: true,
      threshold_rule_action: "operator_approved",
      ml_anomaly_action: "operator_approved",
    },
    source_english:
      "(null policy — no operator authoring yet; hermetic default denies all four slots)",
    compiled_at: "1970-01-01T00:00:00.000Z",
  };
}

/** True iff the given policy is the hermetic null policy (policy_version 0). */
export function isNullPolicy(policy: CompiledPolicy): boolean {
  return policy.policy_version === 0;
}
