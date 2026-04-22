/**
 * Sanctuary Policy Engine — Auto-trigger ladder.
 *
 * Walkthrough Key 11 LOCKED:
 *   - Tier 1 (honeypot): auto-freeze on day 1. Any invocation of a registered
 *     honeypot_skill_id trips an immediate DENY with ladder_tier_fired set.
 *     Wired live at v0.1.
 *   - Tier 2 (threshold_rule): operator-approved initially; auto-calibrated
 *     path opens in v1.x once baseline false-positive data is real. Stubbed
 *     here as "always surface operator_approval_required" regardless of
 *     threshold_rule_action — the flag is honored at a later phase.
 *   - Tier 3 (ml_anomaly): always operator-decided. Stub returns
 *     operator_approval_required.
 *
 * The ladder runs BEFORE slot-rule evaluation. A honeypot hit short-circuits
 * the gate to deny even if the slot rule would allow it.
 *
 * Tickets for v1.x calibration are recorded in the build summary.
 */

import { GATE_REASON_CODES } from "./constants.js";
import type { AutoTriggerTier } from "./constants.js";
import type { CompiledPolicy } from "./types.js";

export interface LadderEvaluation {
  /** If set, ladder fired at this tier; gate MUST NOT proceed to slot rules. */
  fired?: AutoTriggerTier;
  /** Terminal decision when fired. */
  decision?: "deny" | "operator_approval_required";
  reason_code?: string;
  explanation?: string;
}

/**
 * Tier 1 — honeypot. The caller's invoked_skill_id is matched against the
 * policy's registered honeypot_skill_ids. Match ⇒ freeze.
 */
export function evaluateHoneypotTier(
  policy: CompiledPolicy,
  invoked_skill_id: string | undefined
): LadderEvaluation {
  if (!invoked_skill_id) return {};
  if (!policy.auto_trigger_ladder.honeypot_auto_freeze) return {};
  if (policy.capabilities.honeypot_skill_ids.includes(invoked_skill_id)) {
    return {
      fired: "honeypot",
      decision: "deny",
      reason_code: GATE_REASON_CODES.HONEYPOT_AUTO_FREEZE,
      explanation: `honeypot skill ${invoked_skill_id} invoked — agent auto-frozen`,
    };
  }
  return {};
}

/**
 * Tier 2 — threshold_rule (stub).
 *
 * v0.1 behavior: if any threshold-based signal is live for this gate call,
 * always surface operator_approval_required. The caller passes
 * `threshold_signal` when a rule-based anomaly detector matched upstream.
 * Absent a signal, the ladder does nothing at this tier.
 *
 * v1.x ticket: open the `threshold_rule_action = "auto"` path once false-
 * positive baselines are calibrated per agent + per operator.
 */
export function evaluateThresholdRuleTier(
  policy: CompiledPolicy,
  threshold_signal?: string
): LadderEvaluation {
  if (!threshold_signal) return {};
  // At v0.1 we explicitly do NOT honor "auto" — the flag is a forward-compat
  // slot in the compiled policy. Read the source_english + flag to see the
  // operator's intent; v1.x opens the auto path.
  return {
    fired: "threshold_rule",
    decision: "operator_approval_required",
    reason_code: GATE_REASON_CODES.THRESHOLD_RULE_OPERATOR_APPROVAL_REQUIRED,
    explanation: `threshold rule "${threshold_signal}" fired on agent ${policy.agent_id}; operator approval required (v0.1 ladder position)`,
  };
}

/**
 * Tier 3 — ml_anomaly (stub). Always surfaces operator_approval_required at
 * v1.0 per Key 11 LOCKED ("always operator-decides"). v1.x may expose
 * `ml_anomaly_action = "auto"` if per-operator baselines make it safe; the
 * flag is preserved in the compiled policy so v1.x senders can declare intent.
 */
export function evaluateMLAnomalyTier(
  policy: CompiledPolicy,
  ml_signal?: string
): LadderEvaluation {
  if (!ml_signal) return {};
  return {
    fired: "ml_anomaly",
    decision: "operator_approval_required",
    reason_code: GATE_REASON_CODES.ML_ANOMALY_OPERATOR_APPROVAL_REQUIRED,
    explanation: `ML anomaly "${ml_signal}" fired on agent ${policy.agent_id}; operator approval required (v1.0 ladder position — Key 11 LOCKED)`,
  };
}

/** Evaluate all three tiers in order; return the first that fires, if any. */
export function evaluateLadder(params: {
  policy: CompiledPolicy;
  invoked_skill_id?: string;
  threshold_signal?: string;
  ml_signal?: string;
}): LadderEvaluation {
  const h = evaluateHoneypotTier(params.policy, params.invoked_skill_id);
  if (h.fired) return h;
  const t = evaluateThresholdRuleTier(params.policy, params.threshold_signal);
  if (t.fired) return t;
  const m = evaluateMLAnomalyTier(params.policy, params.ml_signal);
  if (m.fired) return m;
  return {};
}
