/**
 * Sanctuary Fortress Modes -- Types
 *
 * Core type definitions for the three-tier Fortress Mode system.
 * Mode transitions are signed, auditable, and gated by preconditions.
 */

import type { ModeTier, TierSubsystems } from "./constants.js";

// ---------------------------------------------------------------------------
// Tier profile
// ---------------------------------------------------------------------------

/**
 * Static profile describing a tier's capabilities, subsystem activation,
 * and the preconditions required to enter it.
 */
export interface TierProfile {
  tier: ModeTier;
  capability_bits: number;
  capability_ceiling: number;
  subsystems: TierSubsystems;
  description: string;
}

// ---------------------------------------------------------------------------
// Transition preconditions
// ---------------------------------------------------------------------------

/**
 * A named precondition that must be satisfied before a mode transition
 * can be executed. Each precondition has a check function that returns
 * a result indicating pass/fail with a reason string.
 */
export interface TransitionPrecondition {
  id: string;
  description: string;
  check: (ctx: PreconditionContext) => Promise<PreconditionResult>;
}

/**
 * Context provided to precondition checks. Abstracts over the
 * concrete fortress state so preconditions are testable without
 * full server bootstrap.
 */
export interface PreconditionContext {
  /** The current (from) tier. */
  current_tier: ModeTier;
  /** The requested (to) tier. */
  target_tier: ModeTier;
  /** Whether a valid node identity cert exists for this fortress. */
  has_node_identity_cert: boolean;
  /** Whether at least one bootstrap peer is reachable. */
  has_reachable_peer: boolean;
  /** Number of registered external-protocol adapters. */
  registered_adapter_count: number;
  /** Fortress ID. */
  fortress_id: string;
}

export interface PreconditionResult {
  passed: boolean;
  reason: string;
}

// ---------------------------------------------------------------------------
// Mode transition event payload
// ---------------------------------------------------------------------------

/**
 * Payload of a fortress_mode_transition signed event.
 * This is the data embedded inside a SignedEvent envelope.
 */
export interface ModeTransitionPayload {
  from_tier: ModeTier;
  to_tier: ModeTier;
  fortress_id: string;
  reason: string;
  preconditions_checked: string[];
  transitioned_at: string;
}

// ---------------------------------------------------------------------------
// Persisted mode config
// ---------------------------------------------------------------------------

/**
 * The on-disk (encrypted) mode configuration document.
 * Stored in the _fortress_mode reserved namespace.
 */
export interface FortressModeConfig {
  schema_version: "1.0";
  current_tier: ModeTier;
  fortress_id: string;
  capability_bits: number;
  last_transition_at: string | null;
  last_transition_event_id: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * A single entry in the transition history log.
 */
export interface TransitionHistoryEntry {
  event_id: string;
  from_tier: ModeTier;
  to_tier: ModeTier;
  reason: string;
  transitioned_at: string;
}

/**
 * The persisted transition history document.
 */
export interface TransitionHistory {
  entries: TransitionHistoryEntry[];
}

// ---------------------------------------------------------------------------
// Service API types
// ---------------------------------------------------------------------------

/**
 * Input for proposing a mode transition. The proposal is validated
 * against preconditions before execution.
 */
export interface TransitionProposal {
  target_tier: ModeTier;
  reason: string;
  /** Precondition context overrides (for testing). */
  precondition_overrides?: Partial<PreconditionContext>;
}

/**
 * Result of a successful mode transition.
 */
export interface TransitionResult {
  event_id: string;
  from_tier: ModeTier;
  to_tier: ModeTier;
  capability_bits: number;
  transitioned_at: string;
}

/**
 * Current fortress mode status, returned by the public API.
 */
export interface FortressModeStatus {
  tier: ModeTier;
  profile: TierProfile;
  capability_bits: number;
  transitions_history: TransitionHistoryEntry[];
  last_transition_at: string | null;
}

// ---------------------------------------------------------------------------
// External adapter registry (Tier 3 hooks-only at v1.0)
// ---------------------------------------------------------------------------

/**
 * A registered external-protocol adapter stub.
 * At v1.0, adapter implementations are empty; only the registration
 * record exists so the Tier 3 precondition can be satisfied.
 * Real adapters (x402, A2A, AP2, Matrix) ship in v1.x.
 */
export interface ExternalAdapterRegistration {
  adapter_id: string;
  protocol: string;
  registered_at: string;
  /** Capability bit this adapter claims. Must be in bits 3-7. */
  capability_bit: number;
}
