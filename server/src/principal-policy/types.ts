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
}

/** Approval request sent to the human */
export interface ApprovalRequest {
  operation: string;
  tier: 1 | 2;
  reason: string;
  context: Record<string, unknown>;
  timestamp: string;
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
