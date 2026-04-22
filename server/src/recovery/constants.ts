/**
 * Recovery Cascade -- constants.
 *
 * Key 13 (M-of-N guardian recovery + DMswitch) and Key 14 (multi-principal
 * commitment boundary).
 *
 * Recovery event types use the `recovery_*` prefix, which is NOT reserved
 * by federation v0.1 section 10 (reserved prefixes are `EXTENSION_`, `cross_fortress_`,
 * `multi_master_`). The `recovery_*` prefix is ours to use per spawn prompt.
 *
 * Hard rules:
 *   - No em-dashes in any emitted message or comment.
 *   - `signature_scheme` field mandatory on every signed envelope.
 *   - No naming of specific competitors.
 */

import type { SignatureScheme } from "../mesh/constants.js";

// ===================================================================
// Recovery event types
// ===================================================================

/**
 * Recovery event types emitted by the cascade.
 *
 * These are NOT v0.1 federation protocol event types (those live in
 * mesh/constants.ts V01_EVENT_TYPES). Recovery events ride the same
 * SignedEvent envelope shape but are scoped to the recovery subsystem.
 *
 * Prefix `recovery_` is safe per spawn prompt: reserved namespaces are
 * `EXTENSION_`, `cross_fortress_`, `multi_master_` only.
 */
export const RECOVERY_EVENT_TYPES = {
  /** Guardian enrolled on the roster. */
  GUARDIAN_ENROLL: "recovery_guardian_enroll",
  /** Guardian revoked from the roster. */
  GUARDIAN_REVOKE: "recovery_guardian_revoke",
  /** DMswitch cascade entry emitted (operator absence threshold crossed). */
  DMSWITCH_CASCADE_ENTRY: "recovery_dmswitch_cascade_entry",
  /** Guardian approval registered toward threshold. */
  GUARDIAN_APPROVAL: "recovery_guardian_approval",
  /** Threshold met; cascade action authorized. */
  THRESHOLD_MET: "recovery_threshold_met",
  /** Recovery action executed. */
  RECOVERY_EXECUTED: "recovery_executed",
  /** Recovery action failed. */
  RECOVERY_FAILED: "recovery_failed",
} as const;

export type RecoveryEventType =
  (typeof RECOVERY_EVENT_TYPES)[keyof typeof RECOVERY_EVENT_TYPES];

// ===================================================================
// DMswitch windows
// ===================================================================

/** Default operator inactivity window before cascade entry (30 days). */
export const DEFAULT_DMSWITCH_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

/** Maximum operator inactivity window for estate-planning mode (90 days). */
export const MAX_ESTATE_PLANNING_WINDOW_MS = 90 * 24 * 60 * 60 * 1000;

/** Minimum allowed DMswitch window (7 days). Prevents accidental lockout. */
export const MIN_DMSWITCH_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// ===================================================================
// Guardian defaults
// ===================================================================

/** Default M-of-N threshold: 3 of 5 per Key 13 LOCKED. */
export const DEFAULT_GUARDIAN_THRESHOLD_M = 3;
export const DEFAULT_GUARDIAN_ROSTER_N = 5;

// ===================================================================
// Cascade state codes
// ===================================================================

/**
 * Cascade states. The cascade is a deterministic state machine:
 *   idle -> triggered -> awaiting_threshold -> threshold_met -> executing -> completed | failed
 */
export const CASCADE_STATES = [
  "idle",
  "triggered",
  "awaiting_threshold",
  "threshold_met",
  "executing",
  "completed",
  "failed",
] as const;

export type CascadeStateCode = (typeof CASCADE_STATES)[number];

// ===================================================================
// Recovery action types
// ===================================================================

/**
 * Actions the cascade can execute once threshold is met.
 */
export const RECOVERY_ACTIONS = [
  "key_rotation",
  "estate_unlock",
  "emergency_freeze",
] as const;

export type RecoveryAction = (typeof RECOVERY_ACTIONS)[number];

// ===================================================================
// Multi-principal reason codes
// ===================================================================

/**
 * Reason codes for the multi-principal commitment boundary extension.
 * Extends the policy engine's GATE_REASON_CODES for recovery-specific
 * guardian-group second-principal evaluation.
 */
export const RECOVERY_GATE_REASON_CODES = {
  GUARDIAN_THRESHOLD_NOT_MET: "guardian_threshold_not_met",
  GUARDIAN_THRESHOLD_MET: "guardian_threshold_met",
  GUARDIAN_ROSTER_STALE: "guardian_roster_stale",
  NO_GUARDIAN_ROSTER: "no_guardian_roster",
  RECOVERY_BOUNDARY_ALLOW: "recovery_boundary_allow",
  RECOVERY_BOUNDARY_DENY: "recovery_boundary_deny",
} as const;

export type RecoveryGateReasonCode =
  (typeof RECOVERY_GATE_REASON_CODES)[keyof typeof RECOVERY_GATE_REASON_CODES];

// ===================================================================
// Crypto-agility
// ===================================================================

/** v1.0 signature scheme. Mandatory on every signed envelope. */
export const RECOVERY_SIGNATURE_SCHEME: SignatureScheme = "ed25519-v1";
