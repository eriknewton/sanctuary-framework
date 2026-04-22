/**
 * Sanctuary Attestation UX v1.0 -- Constants
 *
 * Badge states, layer types, failure-mode catalog (9 rows), severity ranks.
 * All operator-facing copy uses fortress vocabulary per design brief section 2, rule 7.
 *
 * Design brief: Review/Sanctuary/Attestation_UX_Design_Brief_2026-04-21.md
 * Scope lock: Review/Sanctuary/Sanctuary_MVP_Scope_Lock_2026-04-21.md WP-MVP-9
 */

import { SIGNATURE_SCHEME_V1, type SignatureScheme } from "../mesh/constants.js";

// Re-export for attestation module consumers
export { SIGNATURE_SCHEME_V1 };
export type { SignatureScheme };

// -----------------------------------------------------------------------
// Badge states (four colors per design brief section 3)
// -----------------------------------------------------------------------

/**
 * Badge states for Layers 1-3. Each state has a color + label pair.
 *
 * - green: all nominal
 * - yellow: degraded, operator should look
 * - red: attested failure, operator action required
 * - offline: no signal, last-known-good shown
 * - local_only: local mode, no TEE claim, valid steady state (Layer 3 only)
 */
export const BADGE_STATES = [
  "green",
  "yellow",
  "red",
  "offline",
  "local_only",
] as const;
export type BadgeStateColor = (typeof BADGE_STATES)[number];

/**
 * Operator-facing labels per badge state. Fortress vocabulary.
 * No em-dashes. No competitor names.
 */
export const BADGE_STATE_LABELS: Record<BadgeStateColor, string> = {
  green: "Walls sound",
  yellow: "Walls watch",
  red: "Walls breached",
  offline: "No signal",
  local_only: "Local mode",
};

// -----------------------------------------------------------------------
// Layer types
// -----------------------------------------------------------------------

export const LAYER_TYPES = [
  "global",
  "per_agent",
  "per_action",
  "custody_provenance",
] as const;
export type LayerType = (typeof LAYER_TYPES)[number];

// -----------------------------------------------------------------------
// Custody provenance states (Layer 4 stub, v1.x Key 17)
// -----------------------------------------------------------------------

export const CUSTODY_PROVENANCE_STATES = [
  "sovereign_signature",
  "custodial_signature",
  "unknown_custody",
] as const;
export type CustodyProvenanceState = (typeof CUSTODY_PROVENANCE_STATES)[number];

// -----------------------------------------------------------------------
// Severity ranks for failure modes
// -----------------------------------------------------------------------

export const SEVERITY_RANKS = ["critical", "warning", "informational"] as const;
export type SeverityRank = (typeof SEVERITY_RANKS)[number];

// -----------------------------------------------------------------------
// Failure-mode codes (9-row catalog, closed enum at v1.0)
// -----------------------------------------------------------------------

export const FAILURE_MODE_CODES = [
  "tcb_drift_annex",
  "binary_signature_revoked",
  "sovereign_node_attestation_fail",
  "canonical_audit_unreachable",
  "policy_sync_lag",
  "annex_approval_pending",
  "verifier_disagreement",
  "local_only_mode",
  "unsigned_code_path",
] as const;
export type FailureModeCode = (typeof FAILURE_MODE_CODES)[number];

// -----------------------------------------------------------------------
// Attestation event-type prefix (reserved namespace)
// -----------------------------------------------------------------------

/**
 * All attestation events use this prefix. Per spawn prompt hard rule:
 * do not reuse policy_*, chat_*, mesh_*, recovery_*, fortress_*, or identity_*.
 */
export const ATTESTATION_EVENT_TYPE_PREFIX = "attestation_" as const;

export const ATTESTATION_EVENT_TYPES = [
  "attestation_state_change",
  "attestation_failure_detected",
  "attestation_verification_complete",
  "attestation_degraded",
  "attestation_recovered",
] as const;
export type AttestationEventType = (typeof ATTESTATION_EVENT_TYPES)[number];

export function isAttestationEventType(s: string): s is AttestationEventType {
  return (ATTESTATION_EVENT_TYPES as readonly string[]).includes(s);
}

// -----------------------------------------------------------------------
// Degrade-not-destroy retry defaults
// -----------------------------------------------------------------------

export const DEGRADE_DEFAULTS = {
  /** Initial retry delay in ms. */
  INITIAL_RETRY_DELAY_MS: 1_000,
  /** Maximum retry delay in ms (exponential backoff cap). */
  MAX_RETRY_DELAY_MS: 60_000,
  /** Backoff multiplier per retry. */
  BACKOFF_MULTIPLIER: 2,
  /** Maximum retries before settling into steady degraded state. */
  MAX_RETRIES: 5,
  /** Cache duration for last-known-good badge state in ms (offline mode). */
  CACHED_BADGE_TTL_MS: 300_000,
} as const;
