/**
 * Sanctuary v1.3 WP-V1.3-7 Nu-1 Auto-Trigger Ladder types.
 *
 * Operator-configurable thresholds for sentinels and anomaly detectors.
 * Each rule (sentinel ID, or anomaly detector_id + classifier_id
 * composite, or future honeypot trap_id) lives on a 3-rung ladder:
 *
 *   Rung 1: operator-approved (default). Findings land in the inbox;
 *           operator must approve any action. Today's behavior.
 *   Rung 2: auto-action with cancel-window. Finding queues the
 *           configured action; operator has cancel_window_seconds to
 *           revert via inbox; if window expires, action fires.
 *   Rung 3: fully-automatic. Action fires immediately. Operator can
 *           audit and revoke retroactively (revocation is a Nu-1
 *           audit event; the real-action classes that ship in Nu-2+
 *           will define what "revoke" means per class).
 *
 * Nu-1 ships ONE canonical action class: `notify_operator` (info-only;
 * no real enforcement; server-local). Nu-2+ add real-action classes
 * (block_egress, auto_deny_tool, throttle_agent). Future real-action
 * classes that cross Castle Layer 1 (e.g. block_egress hits the
 * Castle Wall) get their own Castle-walking review at spawn time.
 *
 * Sovereignty: state persisted encrypted at rest via the same
 * ClassifierStateStore HKDF + AAD pattern. Multi-fortress isolation
 * by AAD binding to (rule_id, fortress_id).
 */

import type { SentinelFinding } from "../sentinel/types.js";

/** Rung on the 3-rung action ladder. */
export type AutoTriggerRung = 1 | 2 | 3;

/** Rule type tag. */
export type AutoTriggerRuleType = "sentinel" | "anomaly" | "honeypot";

/** Action class an outcome maps to. Nu-1 ships `inbox_only` + `auto_*`. */
export type AutoTriggerActionType =
  | "inbox_only"
  | "auto_with_cancel"
  | "auto_immediate";

/** Outcome status for an action history entry. */
export type AutoTriggerOutcome =
  | "pending"
  | "operator_approved"
  | "operator_canceled"
  | "auto_proceeded"
  | "operator_revoked";

/**
 * Operator-overridable threshold knobs. Default values come from each
 * sentinel/classifier; setting any field here overrides for this rule.
 * Nu-1 supports `warn_sigma` + `alert_sigma`; Nu-2+ can extend.
 */
export interface ThresholdOverrides {
  warn_sigma?: number;
  alert_sigma?: number;
}

/** Default cancel-window for new rung-2 rules. */
export const DEFAULT_CANCEL_WINDOW_SECONDS = 60;

/** Maximum action-history entries retained per rule. Older are dropped. */
export const MAX_HISTORY_PER_RULE = 200;

/**
 * Per-rule config. Persisted under the encrypted `_auto_trigger_rules`
 * namespace, keyed by `{rule_id}`. AAD-bound to (rule_id, fortress_id)
 * so the same rule_id under a different fortress is unreadable.
 */
export interface RuleThresholdConfig {
  /**
   * Stable rule id. For sentinels, the sentinel_id; for anomaly
   * detectors, `${detector_id}__${classifier_id}`; for honeypots,
   * the trap_id. The dispatcher derives this from a finding's
   * `sentinel_id` + classifier_id when one arrives.
   */
  rule_id: string;
  rule_type: AutoTriggerRuleType;
  fortress_id: string;
  current_rung: AutoTriggerRung;
  /** Override defaults; empty object means "use defaults from rule itself". */
  threshold_overrides: ThresholdOverrides;
  /** For rung-2 only; ignored when rung != 2. Default 60s. */
  cancel_window_seconds: number;
  last_promoted_at?: string;
  last_demoted_at?: string;
  /** Bounded ring buffer of recent actions. Older drop. */
  history: ActionHistoryEntry[];
  /** ISO timestamp of the last config update; used for staleness checks. */
  updated_at: string;
}

/** One row in the per-rule action history. */
export interface ActionHistoryEntry {
  /** ISO timestamp when the dispatcher saw the triggering finding. */
  observed_at: string;
  /** Rung the rule sat on when the action was selected. */
  rung_at_action: AutoTriggerRung;
  /** Action class chosen by the dispatcher. */
  action_type: AutoTriggerActionType;
  outcome: AutoTriggerOutcome;
  /** Originating finding_id (SentinelFinding.finding_id). */
  finding_id: string;
  /** Severity at the time of action (info / warn / alert). */
  severity: SentinelFinding["severity"];
}

/**
 * Construct the canonical rule_id for an anomaly finding.
 * Mirrors Chi-3's catalog-key pattern (`{detector}__{classifier}`)
 * so the auto-trigger ladder and the anomaly catalog stay aligned.
 */
export function anomalyRuleId(
  detectorId: string,
  classifierId: string,
): string {
  return `anomaly__${detectorId}__${classifierId}`;
}

/** Construct the canonical rule_id for a sentinel finding. */
export function sentinelRuleId(sentinelId: string): string {
  return `sentinel__${sentinelId}`;
}

/** Construct the canonical rule_id for a honeypot trap. */
export function honeypotRuleId(trapId: string): string {
  return `honeypot__${trapId}`;
}

/**
 * Build a fresh default config at Rung 1 for a newly-discovered rule.
 * Used on first encounter when no config exists yet.
 */
export function defaultRuleConfig(
  ruleId: string,
  ruleType: AutoTriggerRuleType,
  fortressId: string,
  now: () => Date = () => new Date(),
): RuleThresholdConfig {
  return {
    rule_id: ruleId,
    rule_type: ruleType,
    fortress_id: fortressId,
    current_rung: 1,
    threshold_overrides: {},
    cancel_window_seconds: DEFAULT_CANCEL_WINDOW_SECONDS,
    history: [],
    updated_at: now().toISOString(),
  };
}

/**
 * Map a current rung to the action-type that should be emitted on a
 * finding hitting this rule.
 */
export function actionTypeForRung(rung: AutoTriggerRung): AutoTriggerActionType {
  switch (rung) {
    case 1:
      return "inbox_only";
    case 2:
      return "auto_with_cancel";
    case 3:
      return "auto_immediate";
  }
}

/**
 * Append an entry to the history with the bounded ring-buffer trim.
 * Pure; returns a new array.
 */
export function appendHistory(
  history: ActionHistoryEntry[],
  entry: ActionHistoryEntry,
): ActionHistoryEntry[] {
  const next = [...history, entry];
  if (next.length <= MAX_HISTORY_PER_RULE) return next;
  return next.slice(next.length - MAX_HISTORY_PER_RULE);
}

/** Errors */
export class AutoTriggerError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "rule_not_found"
      | "rung_floor"
      | "rung_ceiling"
      | "pending_not_found"
      | "cancel_window_expired"
      | "invalid_rung",
  ) {
    super(message);
    this.name = "AutoTriggerError";
  }
}
