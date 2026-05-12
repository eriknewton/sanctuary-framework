/**
 * Nu-3 Auto-Trigger promotion criteria.
 *
 * Pure arithmetic over per-rule ActionHistoryEntry rows. This module does
 * not mutate rule config and has no dispatcher dependency, so it cannot
 * autonomously promote or demote anything.
 */

import type {
  ActionHistoryEntry,
  AutoTriggerRung,
} from "./types.js";

export interface PromotionRecommendation {
  rule_id: string;
  current_rung: AutoTriggerRung;
  recommended_rung: AutoTriggerRung;
  recommendation_reason: string;
  history_summary: {
    fires_in_window: number;
    operator_approval_rate: number;
    operator_cancel_rate?: number;
    operator_revocation_rate?: number;
  };
  confidence: "high" | "medium" | "low";
}

export interface PromotionCriteriaOptions {
  currentRung?: AutoTriggerRung;
  minFires?: number;
  demotionCancelCount?: number;
  now?: () => Date;
}

export const DEFAULT_PROMOTION_FIRE_COUNT = 20;
export const DEFAULT_PROMOTION_WINDOW_DAYS = 7;
export const DEFAULT_DEMOTION_CANCEL_COUNT = 2;

export function evaluatePromotion(
  rule_id: string,
  history: ActionHistoryEntry[],
  window_days: number,
  opts: PromotionCriteriaOptions = {},
): PromotionRecommendation {
  const now = opts.now ?? (() => new Date());
  const currentRung = opts.currentRung ?? inferCurrentRung(history);
  const minFires = Math.max(
    1,
    Math.floor(opts.minFires ?? DEFAULT_PROMOTION_FIRE_COUNT),
  );
  const demotionCancelCount = Math.max(
    1,
    Math.floor(opts.demotionCancelCount ?? DEFAULT_DEMOTION_CANCEL_COUNT),
  );
  const cutoff = now().getTime() - Math.max(1, window_days) * 86_400_000;
  const inWindow = history.filter((entry) => {
    const t = Date.parse(entry.observed_at);
    return Number.isFinite(t) && t >= cutoff;
  });
  const rungWindow = inWindow.filter((entry) => entry.rung_at_action === currentRung);
  const denominator = Math.max(1, rungWindow.length);
  const approvals = rungWindow.filter((entry) => entry.outcome === "operator_approved").length;
  const cancellations = rungWindow.filter((entry) => entry.outcome === "operator_canceled").length;
  const revocations = inWindow.filter((entry) => entry.outcome === "operator_revoked").length;
  const summary: PromotionRecommendation["history_summary"] = {
    fires_in_window: rungWindow.length,
    operator_approval_rate: approvals / denominator,
  };
  if (currentRung === 2) {
    summary.operator_cancel_rate = cancellations / denominator;
  }
  if (currentRung === 3) {
    summary.operator_revocation_rate = revocations / Math.max(1, inWindow.length);
  }

  if (currentRung === 3 && revocations > 0) {
    return {
      rule_id,
      current_rung: currentRung,
      recommended_rung: 2,
      recommendation_reason:
        "Operator revocation appeared in the evaluation window. Demote to Rung 2 so future fires keep a cancel window.",
      history_summary: summary,
      confidence: "high",
    };
  }

  if (currentRung === 2 && cancellations >= demotionCancelCount) {
    return {
      rule_id,
      current_rung: currentRung,
      recommended_rung: 1,
      recommendation_reason:
        "Repeated operator cancellations appeared in the evaluation window. Demote to Rung 1 so future fires require explicit approval.",
      history_summary: summary,
      confidence: "high",
    };
  }

  if (
    currentRung === 1 &&
    rungWindow.length >= minFires &&
    rungWindow.every((entry) => entry.outcome === "operator_approved")
  ) {
    return {
      rule_id,
      current_rung: currentRung,
      recommended_rung: 2,
      recommendation_reason:
        "This rule met the fire threshold and every fire was operator-approved in the evaluation window.",
      history_summary: summary,
      confidence: "high",
    };
  }

  if (
    currentRung === 2 &&
    rungWindow.length >= minFires &&
    cancellations === 0 &&
    revocations === 0
  ) {
    return {
      rule_id,
      current_rung: currentRung,
      recommended_rung: 3,
      recommendation_reason:
        "This rule met the Rung 2 fire threshold with no operator cancellations or revocations in the evaluation window.",
      history_summary: summary,
      confidence: "high",
    };
  }

  return {
    rule_id,
    current_rung: currentRung,
    recommended_rung: currentRung,
    recommendation_reason:
      "No rung change recommended. The rule has not met the promotion or demotion criteria for the evaluation window.",
    history_summary: summary,
    confidence: "low",
  };
}

function inferCurrentRung(history: ActionHistoryEntry[]): AutoTriggerRung {
  const latest = history
    .slice()
    .sort((a, b) => Date.parse(b.observed_at) - Date.parse(a.observed_at))[0];
  return latest?.rung_at_action ?? 1;
}
