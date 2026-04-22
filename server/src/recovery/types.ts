/**
 * Recovery Cascade -- type surface.
 *
 * Key 13 (M-of-N guardian recovery, DMswitch) and Key 14 (multi-principal flow).
 *
 * Wire-shape note: every field is JSON-serializable and signature-stable
 * under the canonical-JSON rules of mesh/canonical-json.ts.
 */

import type { SignatureScheme } from "../mesh/constants.js";
import type { GuardianRoster } from "../mesh/guardian/types.js";
import type { CascadeStateCode, RecoveryAction, RecoveryEventType } from "./constants.js";

/**
 * A single recovery event. Wraps a signed envelope payload for recovery
 * cascade actions (guardian enrollment, DMswitch trigger, approval, etc.).
 */
export interface RecoveryEvent {
  /** Unique event identifier (hex, 128-bit). */
  event_id: string;
  /** Recovery event type (recovery_* prefix). */
  event_type: RecoveryEventType;
  /** ISO8601 timestamp of event creation. */
  created_at: string;
  /** Fortress this event belongs to. */
  fortress_id: string;
  /** Node that emitted the event. */
  emitter_node: string;
  /** Principal that authorized the event. */
  emitter_principal: string;
  /** Event-specific payload. */
  payload: Record<string, unknown>;
  /** SHA-256 hash of canonical payload. */
  payload_hash: string;
  /** Ed25519 signature over canonical event body. */
  signature: string;
  /** Mandatory crypto-agility field. */
  signature_scheme: SignatureScheme;
}

/**
 * Trigger configuration for the dead-man-switch.
 */
export interface DmswitchConfig {
  /** Inactivity window in ms before cascade triggers. Default 30 days. */
  max_offline_window_ms: number;
  /** Whether estate-planning mode is enabled (allows up to 90 days). */
  estate_planning_enabled: boolean;
}

/**
 * Tracks operator activity for DMswitch evaluation.
 */
export interface ActivityRecord {
  /** ISO8601 of last observed operator activity. */
  last_activity_at: string;
  /** ms-since-epoch for arithmetic. */
  last_activity_ms: number;
  /** Source of the activity tick (e.g., "console_login", "policy_update", "manual_heartbeat"). */
  source: string;
}

/**
 * Estate unlock trigger configuration. Operator-provided hooks; the
 * quasi-legal template library is a separate v1.x scope item.
 */
export interface EstateUnlockTrigger {
  /** ISO8601 of when estate unlock was configured. */
  configured_at: string;
  /** Principals designated as estate beneficiaries (Key 14: Estate-Contingent role). */
  beneficiary_principal_ids: string[];
  /** Optional operator-authored instructions stored alongside the trigger. */
  instructions?: string;
}

/**
 * A single guardian's signed approval toward the M-of-N threshold.
 */
export interface GuardianApproval {
  /** Guardian identifier from the roster. */
  guardian_id: string;
  /** What the guardian is approving. */
  recovery_action: RecoveryAction;
  /** The cascade_id this approval targets. */
  cascade_id: string;
  /** ISO8601 of approval. */
  approved_at: string;
  /** Ed25519 signature over canonical approval body. */
  signature: string;
  /** Mandatory crypto-agility field. */
  signature_scheme: SignatureScheme;
}

/**
 * Full cascade state. Given the same inputs (roster, threshold, activity,
 * pending approvals), any honest node computes the same state.
 *
 * Acceptance criterion 4: deterministic.
 */
export interface CascadeState {
  /** Unique cascade instance identifier. */
  cascade_id: string;
  /** Current state of the cascade. */
  state: CascadeStateCode;
  /** The recovery action this cascade will execute. */
  action: RecoveryAction;
  /** Fortress this cascade belongs to. */
  fortress_id: string;
  /** Guardian roster version in effect when cascade started. */
  roster_version: number;
  /** M required for threshold. */
  threshold_m: number;
  /** N total guardians. */
  threshold_n: number;
  /** Approvals received so far. */
  approvals: GuardianApproval[];
  /** ISO8601 of cascade initiation. */
  initiated_at: string;
  /** ISO8601 of threshold met (if reached). */
  threshold_met_at?: string;
  /** ISO8601 of cascade completion (if completed). */
  completed_at?: string;
  /** ISO8601 of cascade failure (if failed). */
  failed_at?: string;
  /** Failure reason (if failed). */
  failure_reason?: string;
  /** DMswitch trigger that initiated this cascade (if DMswitch-initiated). */
  dmswitch_trigger?: {
    last_activity_at: string;
    triggered_at: string;
    window_ms: number;
  };
  /** Events emitted during this cascade. */
  events: RecoveryEvent[];
}

/**
 * Input for multi-principal commitment boundary evaluation.
 * Extends the four-condition check with guardian-group as second principal.
 */
export interface MultiPrincipalBoundaryRequest {
  /** Agent whose commitment is being evaluated. */
  agent_id: string;
  /** The recovery action being committed to. */
  recovery_action: RecoveryAction;
  /** Cascade state including guardian approvals. */
  cascade_state: CascadeState;
  /** Current guardian roster for verification. */
  guardian_roster: GuardianRoster;
}

/**
 * Result of multi-principal boundary evaluation.
 */
export interface MultiPrincipalBoundaryResult {
  /** Whether the boundary check passed. */
  decision: "allow" | "deny";
  /** Machine-readable reason code. */
  reason_code: string;
  /** Human-readable explanation. */
  explanation: string;
  /** Number of valid approvals counted. */
  valid_approvals: number;
  /** Threshold required. */
  threshold_required: number;
}

/**
 * Configuration for the recovery service.
 */
export interface RecoveryConfig {
  /** DMswitch configuration. */
  dmswitch: DmswitchConfig;
  /** Optional estate unlock trigger. */
  estate_unlock?: EstateUnlockTrigger;
}
