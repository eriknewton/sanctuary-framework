/**
 * Sanctuary MCP Server — Principal Policy Types
 *
 * Type definitions for the Principal Policy system.
 * The Principal Policy is the human-controlled, agent-immutable
 * configuration that gates operations through approval tiers.
 */

/** Tier 2 anomaly action: what to do when an anomaly is detected */
export type AnomalyAction = "approve" | "log" | "allow";

/** Tier 2 anomaly detection configuration */
export interface Tier2Config {
  /** Action when agent accesses a namespace it hasn't used before */
  new_namespace_access: AnomalyAction;
  /** Action when agent interacts with an unknown counterparty DID */
  new_counterparty: AnomalyAction;
  /** Tool call frequency multiplier that triggers anomaly */
  frequency_spike_multiplier: number;
  /** Maximum signing operations per minute before triggering */
  max_signs_per_minute: number;
  /** Reading more than N keys in a namespace within 60 seconds */
  bulk_read_threshold: number;
  /** Policy for first session when no baseline exists */
  first_session_policy: AnomalyAction;
}

/** Approval channel configuration */
export interface ApprovalChannelConfig {
  type: "stderr" | "webhook" | "callback";
  timeout_seconds: number;
  /**
   * SEC-002: auto_deny is hardcoded to true and not configurable.
   * Timeout on any approval channel ALWAYS results in denial.
   * This field is retained for backward compatibility with existing
   * policy files but is ignored — timeout always denies.
   */
  auto_deny?: boolean;
  webhook_url?: string;
  webhook_secret?: string;
}

/**
 * WP-V1.3-10 Upsilon-2: cross-harness approval-redirect mode.
 *
 * `mode` selects how the underlying channel and the aggregator interact when
 * a Tier 1/2 approval fires for a wrapped agent:
 *
 *  - `replace`: the underlying channel is bypassed; the gate's
 *    `requestApproval()` blocks awaiting the operator's decision through
 *    the aggregator HTTP `approve`/`deny` routes (or any other surface that
 *    calls `aggregator.resolve()`). Default behavior when redirect is
 *    enabled.
 *  - `notify`: both the underlying channel AND the aggregator run; the
 *    first decision wins. Right shape for harnesses (e.g. Mastra) where
 *    full local-prompt suppression is not viable, so the operator still
 *    sees the prompt locally but ALSO can resolve from the unified inbox.
 *
 * `per_agent` is a stub for v1.4 multi-agent fortresses: a map of
 * `agent_id -> {enabled, mode}` overrides. v1.x ignores this field; the
 * fortress-level `enabled` + `mode` apply to every wrapped agent in the
 * fortress (which is currently single-agent in practice). v1.4 adds
 * agent-id propagation through the gate signature and consults this map.
 */
export interface ApprovalRedirectPerAgentOverride {
  enabled?: boolean;
  mode?: "replace" | "notify";
}

export interface ApprovalRedirectConfig {
  /** Master toggle. When false, redirect-mode is off across the fortress. */
  enabled: boolean;
  /** How the underlying channel and the aggregator coexist. */
  mode: "replace" | "notify";
  /**
   * Per-agent overrides. v1.x stub — populated entries are validated and
   * persisted but not enforced. Reserved for v1.4 multi-agent fortresses.
   */
  per_agent?: Record<string, ApprovalRedirectPerAgentOverride>;
}

/** Complete Principal Policy */
export interface PrincipalPolicy {
  version: number;
  /** Operations that always require human approval */
  tier1_always_approve: string[];
  /** Behavioral anomaly detection configuration */
  tier2_anomaly: Tier2Config;
  /** Operations that never require approval (audit only) */
  tier3_always_allow: string[];
  /** How approval requests reach the human */
  approval_channel: ApprovalChannelConfig;
  /**
   * WP-V1.3-9 Tau-1: operator-tunable retention window (days) for the
   * concierge memory store. Per-turn `retention_until` is stamped at
   * append time; fortress-unlock pruning drops expired turns. Default 30
   * days when absent; values <= 0 fall back to the default.
   */
  concierge_memory_retention_days?: number;
  /**
   * WP-V1.3-10 Upsilon-2: cross-harness approval-redirect mode. Optional;
   * defaults to `{ enabled: false, mode: "replace" }` (preserves legacy
   * behavior). Operator-toggled via `sanctuary agents config <tenant>
   * --approval-redirect=<bool>` or by editing principal-policy.yaml.
   */
  approval_redirect?: ApprovalRedirectConfig;
}

/** Approval request sent to the human */
export interface ApprovalRequest {
  operation: string;
  tier: 1 | 2;
  reason: string;
  context: Record<string, unknown>;
  timestamp: string;
  /**
   * Canonical hash of the normalized tool arguments
   * (`normalizedArgsHash` from agent-native/safety-base — the SAME
   * normalization the direct approval-proof envelope binds via
   * `normalized_args_hash`). Present whenever the gate has the raw args in
   * scope (every classified Tier-1/Tier-2 request). The redirect-inbox
   * match key and the aggregator dedup key both fold this in so two
   * same-operation, same-millisecond requests with DIFFERENT args resolve
   * to two distinct inbox cards and two distinct channel waiters — closing
   * the approval-amplification hole where one benign approval settled an
   * unrelated, never-displayed sibling request. A true re-delivery of the
   * SAME request (same op + same args) still produces an identical key, so
   * legitimate dedup is preserved. Absent on the rare argless escalation
   * paths (e.g. injection-escalate), in which case the key falls back to
   * the historic `<timestamp>:<operation>` form.
   */
  args_binding?: string;
}

/** Approval response from the human */
export interface ApprovalResponse {
  decision: "approve" | "deny";
  decided_at: string;
  decided_by: "human" | "timeout" | "auto" | "stderr:non-interactive" | "channel_failure";
}

/** Result of the approval gate evaluation */
export interface GateResult {
  allowed: boolean;
  tier: 1 | 2 | 3;
  reason: string;
  approval_required: boolean;
  approval_response?: ApprovalResponse;
}

/** Behavioral baseline for anomaly detection */
export interface SessionProfile {
  /** Namespaces accessed (read or write) */
  known_namespaces: string[];
  /** Counterparty DIDs seen in reputation operations */
  known_counterparties: string[];
  /** Tool call counts per tool name (lifetime in session) */
  tool_call_counts: Record<string, number>;
  /** Whether this is the first session (no prior baseline) */
  is_first_session: boolean;
  /** Session start time */
  started_at: string;
  /** When the baseline was last saved */
  saved_at?: string;
}
