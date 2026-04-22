/**
 * Sanctuary Policy Engine — Shared slot-gate evaluator.
 *
 * All four slot gates route through this function. Keeping the logic in one
 * place lets us assert at the test layer that the four gate entry points
 * behave identically on identical input — the only thing that distinguishes
 * them is the slot they key off.
 *
 * Evaluation order (hard — this is the order an auditor will trace):
 *
 *   1. If policy is null → hermetic deny (null_policy_hermetic_deny).
 *   2. Sentinel check: if this agent is_sentinel and counterparty != self →
 *      deny (sentinel_inward_restriction).
 *   3. Auto-trigger ladder: honeypot / threshold / ml in that order. Any
 *      fire short-circuits the gate with the ladder's terminal decision.
 *   4. Slot rule lookup:
 *        - mode = "deny" → deny (slot_mode_deny).
 *        - mode = "grant" + no matching grant → deny (no_matching_grant).
 *        - mode = "grant" + matching grant → allow (rule_allow).
 *
 * A matching grant is one whose counterparty equals the request counterparty
 * (or the wildcard "*") AND whose action equals the request action.
 * Additional scope narrowing is not enforced at the slot gate layer; scope
 * is consumer-side business logic (the gate passes it through in the
 * receipt so consumers see what was claimed).
 */

import {
  COUNTERPARTY_WILDCARD,
  GATE_REASON_CODES,
  type PolicySlot,
} from "../constants.js";
import { buildNullPolicy } from "../null-policy.js";
import { evaluateLadder } from "../auto-trigger-ladder.js";
import { checkSentinelRestriction } from "../sentinel-role.js";
import { issueGateReceipt } from "../gate-receipts.js";
import type { GateContext, GateRequest, GateResult, SlotGrant } from "../types.js";

export interface SlotGateExtendedContext extends GateContext {
  /** Optional upstream threshold signal the ladder's tier 2 evaluates against. */
  threshold_signal?: string;
  /** Optional upstream ML anomaly signal the ladder's tier 3 evaluates against. */
  ml_signal?: string;
  /** Injectable clock for deterministic receipts in tests. */
  now?: () => Date;
}

function findMatchingGrant(
  grants: SlotGrant[],
  counterparty: string,
  action: string
): SlotGrant | undefined {
  return grants.find(
    (g) =>
      (g.counterparty === counterparty || g.counterparty === COUNTERPARTY_WILDCARD) &&
      g.action === action
  );
}

export function evaluateSlotGate(
  slot: PolicySlot,
  ctx: SlotGateExtendedContext,
  req: GateRequest
): GateResult {
  // Step 1: null policy → hermetic deny.
  const policy = ctx.policy ?? buildNullPolicy({
    agent_id: req.agent_id,
    fortress_id: ctx.fortressId,
  });
  const isNull = ctx.policy === null;

  if (isNull) {
    const receipt = issueGateReceipt({
      decision: "deny",
      slot,
      agent_id: req.agent_id,
      counterparty: req.counterparty,
      action: req.action,
      invoked_skill_id: req.invoked_skill_id,
      policy_version: null,
      reason_code: GATE_REASON_CODES.NULL_POLICY_HERMETIC_DENY,
      fortress_id: ctx.fortressId,
      evaluating_node_id: ctx.nodeId,
      node_signing_key: ctx.nodeSigningKey,
      now: ctx.now,
    });
    return {
      decision: "deny",
      reason_code: GATE_REASON_CODES.NULL_POLICY_HERMETIC_DENY,
      receipt,
      explanation: `no pinned policy for ${req.agent_id}; hermetic default denies every slot`,
    };
  }

  // Step 2: sentinel inward-facing check.
  const sentCheck = checkSentinelRestriction(policy, req.counterparty);
  if (!sentCheck.allowed) {
    const receipt = issueGateReceipt({
      decision: "deny",
      slot,
      agent_id: req.agent_id,
      counterparty: req.counterparty,
      action: req.action,
      invoked_skill_id: req.invoked_skill_id,
      policy_version: policy.policy_version,
      reason_code: sentCheck.reason_code!,
      fortress_id: ctx.fortressId,
      evaluating_node_id: ctx.nodeId,
      node_signing_key: ctx.nodeSigningKey,
      now: ctx.now,
    });
    return {
      decision: "deny",
      reason_code: sentCheck.reason_code!,
      receipt,
      explanation: sentCheck.explanation!,
    };
  }

  // Step 3: auto-trigger ladder (honeypot / threshold / ml).
  const ladder = evaluateLadder({
    policy,
    invoked_skill_id: req.invoked_skill_id,
    threshold_signal: ctx.threshold_signal,
    ml_signal: ctx.ml_signal,
  });
  if (ladder.fired) {
    const receipt = issueGateReceipt({
      decision: ladder.decision!,
      slot,
      agent_id: req.agent_id,
      counterparty: req.counterparty,
      action: req.action,
      invoked_skill_id: req.invoked_skill_id,
      policy_version: policy.policy_version,
      reason_code: ladder.reason_code!,
      fortress_id: ctx.fortressId,
      evaluating_node_id: ctx.nodeId,
      ladder_tier_fired: ladder.fired,
      node_signing_key: ctx.nodeSigningKey,
      now: ctx.now,
    });
    return {
      decision: ladder.decision!,
      reason_code: ladder.reason_code!,
      receipt,
      explanation: ladder.explanation!,
    };
  }

  // Step 4: slot rule evaluation.
  const rule = policy.slots[slot];
  if (rule.mode === "deny") {
    const receipt = issueGateReceipt({
      decision: "deny",
      slot,
      agent_id: req.agent_id,
      counterparty: req.counterparty,
      action: req.action,
      invoked_skill_id: req.invoked_skill_id,
      policy_version: policy.policy_version,
      reason_code: GATE_REASON_CODES.SLOT_MODE_DENY,
      fortress_id: ctx.fortressId,
      evaluating_node_id: ctx.nodeId,
      node_signing_key: ctx.nodeSigningKey,
      now: ctx.now,
    });
    return {
      decision: "deny",
      reason_code: GATE_REASON_CODES.SLOT_MODE_DENY,
      receipt,
      explanation: `slot ${slot} is in deny mode for agent ${req.agent_id}`,
    };
  }
  const grant = findMatchingGrant(rule.grants, req.counterparty, req.action);
  if (!grant) {
    const receipt = issueGateReceipt({
      decision: "deny",
      slot,
      agent_id: req.agent_id,
      counterparty: req.counterparty,
      action: req.action,
      invoked_skill_id: req.invoked_skill_id,
      policy_version: policy.policy_version,
      reason_code: GATE_REASON_CODES.NO_MATCHING_GRANT,
      fortress_id: ctx.fortressId,
      evaluating_node_id: ctx.nodeId,
      node_signing_key: ctx.nodeSigningKey,
      now: ctx.now,
    });
    return {
      decision: "deny",
      reason_code: GATE_REASON_CODES.NO_MATCHING_GRANT,
      receipt,
      explanation: `no grant on slot ${slot} for ${req.agent_id} → ${req.counterparty} / ${req.action}`,
    };
  }
  const receipt = issueGateReceipt({
    decision: "allow",
    slot,
    agent_id: req.agent_id,
    counterparty: req.counterparty,
    action: req.action,
    invoked_skill_id: req.invoked_skill_id,
    policy_version: policy.policy_version,
    reason_code: GATE_REASON_CODES.RULE_ALLOW,
    fortress_id: ctx.fortressId,
    evaluating_node_id: ctx.nodeId,
    node_signing_key: ctx.nodeSigningKey,
    now: ctx.now,
  });
  return {
    decision: "allow",
    reason_code: GATE_REASON_CODES.RULE_ALLOW,
    receipt,
    explanation: `slot ${slot} grant matched: ${req.agent_id} may ${req.action} on ${req.counterparty}`,
  };
}
