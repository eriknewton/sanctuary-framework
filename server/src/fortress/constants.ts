/**
 * Sanctuary Fortress Modes -- Constants
 *
 * Three-tier Fortress Mode system: Tier 1 Private, Tier 2 Federated, Tier 3 Interop.
 * Each tier declares which capability bits are enabled and which subsystems are active.
 *
 * Architecture walkthrough: Keys 1, 2, 3.
 * Capability bits: Federation Protocol v0.1 spec SS10.2.
 */

import {
  CAP_STANDARD_FORTRESS_NODE,
  CAP_AUDIT_REPLICA_ELIGIBLE,
  CAP_COLD_STORAGE_RECEIPT_REPLICA,
} from "../mesh/constants.js";

// ---------------------------------------------------------------------------
// Mode tiers
// ---------------------------------------------------------------------------

export const MODE_TIERS = [
  "tier_1_private",
  "tier_2_federated",
  "tier_3_interop",
] as const;

export type ModeTier = (typeof MODE_TIERS)[number];

export function isModeTier(s: string): s is ModeTier {
  return (MODE_TIERS as readonly string[]).includes(s);
}

// ---------------------------------------------------------------------------
// Reserved event-type prefix for fortress mode transitions.
// Federation v0.1 SS10.3 reserves EXTENSION_, cross_fortress_, multi_master_.
// fortress_* is ours to use; do NOT reuse policy_*, chat_*, mesh_*,
// recovery_*, or identity_*.
// ---------------------------------------------------------------------------

export const FORTRESS_EVENT_TYPE_PREFIX = "fortress_" as const;

export const FORTRESS_EVENT_TYPES = {
  MODE_TRANSITION: "fortress_mode_transition",
} as const;

// ---------------------------------------------------------------------------
// Per-tier capability bit profiles
//
// Tier 1: standard node only (bit 0). No mesh participation.
// Tier 2: standard + audit replica + cold storage (bits 0-2). Full federation.
// Tier 3: Tier 2 plus reserved bits 3-7 for external-protocol adapters (v1.x).
//         At v1.0, bits 3-7 are registered but adapters are stubs.
// ---------------------------------------------------------------------------

/**
 * Capability bits enabled by default for each tier.
 * Operators can opt into additional v0.1 bits within the tier ceiling.
 */
export const TIER_CAPABILITY_DEFAULTS: Record<ModeTier, number> = {
  tier_1_private: CAP_STANDARD_FORTRESS_NODE,
  tier_2_federated:
    CAP_STANDARD_FORTRESS_NODE |
    CAP_AUDIT_REPLICA_ELIGIBLE |
    CAP_COLD_STORAGE_RECEIPT_REPLICA,
  tier_3_interop:
    CAP_STANDARD_FORTRESS_NODE |
    CAP_AUDIT_REPLICA_ELIGIBLE |
    CAP_COLD_STORAGE_RECEIPT_REPLICA,
};

/**
 * Maximum capability bits each tier is allowed to set.
 * Tier 3 reserves bits 3-7 per Federation v0.1 SS10.2 for
 * external-protocol adapters. At v1.0 these bits are registered
 * but the adapter slots are empty (hooks only).
 */
export const TIER_3_EXTERNAL_ADAPTER_BITS = (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7);

export const TIER_CAPABILITY_CEILING: Record<ModeTier, number> = {
  tier_1_private: CAP_STANDARD_FORTRESS_NODE,
  tier_2_federated:
    CAP_STANDARD_FORTRESS_NODE |
    CAP_AUDIT_REPLICA_ELIGIBLE |
    CAP_COLD_STORAGE_RECEIPT_REPLICA,
  tier_3_interop:
    CAP_STANDARD_FORTRESS_NODE |
    CAP_AUDIT_REPLICA_ELIGIBLE |
    CAP_COLD_STORAGE_RECEIPT_REPLICA |
    TIER_3_EXTERNAL_ADAPTER_BITS,
};

// ---------------------------------------------------------------------------
// Per-tier subsystem activation
// ---------------------------------------------------------------------------

export interface TierSubsystems {
  mesh: boolean;
  federation: boolean;
  chat: boolean;
  external_protocols: boolean;
}

export const TIER_SUBSYSTEMS: Record<ModeTier, TierSubsystems> = {
  tier_1_private: {
    mesh: false,
    federation: false,
    chat: false,
    external_protocols: false,
  },
  tier_2_federated: {
    mesh: true,
    federation: true,
    chat: true,
    external_protocols: false,
  },
  tier_3_interop: {
    mesh: true,
    federation: true,
    chat: true,
    external_protocols: true,
  },
};

// ---------------------------------------------------------------------------
// Legal transition paths
// ---------------------------------------------------------------------------

/**
 * Adjacency matrix of legal mode transitions.
 * Key: from-tier. Value: set of to-tiers.
 *
 * 1->2: join federation. 2->1: leave federation.
 * 2->3: register external adapter. 3->2: deregister all external adapters.
 * 3->1: full withdrawal. 1->3 is ILLEGAL (must pass through 2).
 */
export const LEGAL_TRANSITIONS: Record<ModeTier, ReadonlySet<ModeTier>> = {
  tier_1_private: new Set<ModeTier>(["tier_2_federated"]),
  tier_2_federated: new Set<ModeTier>(["tier_1_private", "tier_3_interop"]),
  tier_3_interop: new Set<ModeTier>(["tier_2_federated", "tier_1_private"]),
};

// ---------------------------------------------------------------------------
// Config persistence
// ---------------------------------------------------------------------------

/** Reserved namespace for fortress mode config. Underscore-prefixed = internal. */
export const FORTRESS_MODE_NAMESPACE = "_fortress_mode" as const;

/** Key within the namespace for the current mode config document. */
export const FORTRESS_MODE_CONFIG_KEY = "current" as const;

/** Key for the transition history log. */
export const FORTRESS_MODE_HISTORY_KEY = "history" as const;

/** HKDF domain separation for fortress mode encryption. */
export const HKDF_FORTRESS_MODE_INFO = "sanctuary-fortress-mode-v1" as const;

/** Maximum transition history entries retained. Oldest are trimmed on write. */
export const MAX_TRANSITION_HISTORY = 1000;
