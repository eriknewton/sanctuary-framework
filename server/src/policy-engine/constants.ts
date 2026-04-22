/**
 * Sanctuary Policy Engine — Constants
 *
 * Key 10 LOCKED: four canonical policy slots at v1.0. Schema enforces this.
 * Expanding the slot set later is a v1.x decision — not something the engine
 * accepts at authoring time.
 */

/** Compiled policy artifact schema version. Monotonic across releases. */
export const COMPILED_POLICY_SCHEMA_VERSION = "0.1" as const;

/** Event type the mesh dispatches to this engine. */
export const POLICY_UPDATE_EVENT_TYPE = "policy_update" as const;

/**
 * Four canonical slots per Walkthrough Key 10 LOCKED. Exactly these four;
 * expanding is a spec amendment, not a compile-time extension.
 */
export const POLICY_SLOTS = [
  "memory",
  "credentials",
  "plans",
  "outputs",
] as const;

export type PolicySlot = (typeof POLICY_SLOTS)[number];

/** Runtime membership check for untrusted input. */
export function isPolicySlot(value: unknown): value is PolicySlot {
  return (
    typeof value === "string" &&
    (POLICY_SLOTS as readonly string[]).includes(value)
  );
}

/**
 * Reason codes used on gate receipts. Stable identifiers so audit consumers
 * can filter on them. Operator-facing strings are generated at the console
 * layer — this is the machine-readable surface.
 */
export const GATE_REASON_CODES = {
  NULL_POLICY_HERMETIC_DENY: "null_policy_hermetic_deny",
  RULE_ALLOW: "rule_allow",
  RULE_DENY: "rule_deny",
  SLOT_MODE_DENY: "slot_mode_deny",
  NO_MATCHING_GRANT: "no_matching_grant",
  HONEYPOT_AUTO_FREEZE: "honeypot_auto_freeze",
  SENTINEL_INWARD_RESTRICTION: "sentinel_inward_restriction",
  COMMITMENT_BOUNDARY_MISSING_CAPABILITY:
    "commitment_boundary_missing_capability",
  COMMITMENT_BOUNDARY_UNBOUNDED_SCOPE: "commitment_boundary_unbounded_scope",
  COMMITMENT_BOUNDARY_NO_COUNTERPARTY: "commitment_boundary_no_counterparty",
  COMMITMENT_BOUNDARY_NOT_DELEGATION: "commitment_boundary_not_delegation",
  COMMITMENT_BOUNDARY_ALLOW: "commitment_boundary_allow",
  THRESHOLD_RULE_OPERATOR_APPROVAL_REQUIRED:
    "threshold_rule_operator_approval_required",
  ML_ANOMALY_OPERATOR_APPROVAL_REQUIRED:
    "ml_anomaly_operator_approval_required",
} as const;

export type GateReasonCode =
  (typeof GATE_REASON_CODES)[keyof typeof GATE_REASON_CODES];

/**
 * Auto-trigger ladder tiers per Walkthrough Key 11 LOCKED.
 *
 * v0.1 ships:
 *   - honeypot tier live (auto-freeze on day 1)
 *   - threshold_rule stubbed (always operator-approved; auto-calibrated
 *     path opens at v1.x once baselines accumulate)
 *   - ml_anomaly stubbed (always operator-approved at every tier)
 *
 * The ladder metadata is embedded in the compiled policy so receivers
 * enforce the same tiers the sender pinned — the both-sides check.
 */
export const AUTO_TRIGGER_TIERS = ["honeypot", "threshold_rule", "ml_anomaly"] as const;
export type AutoTriggerTier = (typeof AUTO_TRIGGER_TIERS)[number];

/** Channel-template identifiers per Walkthrough Key 10 LOCKED starter set. */
export const CHANNEL_TEMPLATE_IDS = [
  "read-outputs-only",
  "bidirectional-sync",
  "credential-share-scoped",
  "plan-inspect-read-only",
  "escrow-handoff",
] as const;

export type ChannelTemplateId = (typeof CHANNEL_TEMPLATE_IDS)[number];

/**
 * Wildcard counterparty — grant applies to any agent in the mesh. Explicit
 * in the schema so operators reading a compiled artifact see an explicit
 * token rather than a missing field.
 */
export const COUNTERPARTY_WILDCARD = "*" as const;

// ═══════════════════════════════════════════════════════════════════════
// WP-MVP-6 — Egress, Budget, Retention constants
// ═══════════════════════════════════════════════════════════════════════

/** Budget units supported at v1.0 per Key 16. */
export const BUDGET_UNITS = ["tokens", "usd"] as const;
export type BudgetUnit = (typeof BUDGET_UNITS)[number];

/** Default soft-warn threshold (fraction of budget). */
export const DEFAULT_SOFT_WARN_THRESHOLD = 0.8;

/** Default retention sweep interval in ms (15 minutes). */
export const DEFAULT_RETENTION_SWEEP_INTERVAL_MS = 15 * 60 * 1000;

/** Rolling daily window in ms (24 hours). */
export const ROLLING_DAILY_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Rolling monthly window in ms (30 days). */
export const ROLLING_MONTHLY_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

/** Gate reason codes for WP-MVP-6 controls. */
export const EGRESS_BUDGET_RETENTION_REASON_CODES = {
  EGRESS_ALLOWED: "egress_allowed",
  EGRESS_NO_POLICY: "egress_no_policy",
  EGRESS_DESTINATION_DENIED: "egress_destination_denied",
  EGRESS_METHOD_DENIED: "egress_method_denied",
  BUDGET_WITHIN_LIMITS: "budget_within_limits",
  BUDGET_SOFT_WARN: "budget_soft_warn",
  BUDGET_HARD_STOP: "budget_hard_stop",
  BUDGET_NO_POLICY: "budget_no_policy",
} as const;

export type EgressBudgetRetentionReasonCode =
  (typeof EGRESS_BUDGET_RETENTION_REASON_CODES)[keyof typeof EGRESS_BUDGET_RETENTION_REASON_CODES];
