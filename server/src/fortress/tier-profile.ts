/**
 * Sanctuary Fortress Modes -- Tier Profile
 *
 * Per-tier capability-bit profiles, subsystem activation, and
 * precondition lookups. Pure-logic module; no I/O.
 */

import type { ModeTier } from "./constants.js";
import {
  MODE_TIERS,
  TIER_CAPABILITY_DEFAULTS,
  TIER_CAPABILITY_CEILING,
  TIER_SUBSYSTEMS,
  TIER_3_EXTERNAL_ADAPTER_BITS,
} from "./constants.js";
import type { TierProfile } from "./types.js";

// ---------------------------------------------------------------------------
// Tier descriptions (no em-dashes per style rule)
// ---------------------------------------------------------------------------

const TIER_DESCRIPTIONS: Record<ModeTier, string> = {
  tier_1_private:
    "Fully local. No mesh membership, no federation, no external protocol participation. " +
    "The fortress operates as a fully-operational sovereign node with zero external dependency.",
  tier_2_federated:
    "Operator has joined at least one mesh. Federation v0.1 transport is live. " +
    "Cross-fortress chat, agent federation, policy distribution, and audit batches are enabled.",
  tier_3_interop:
    "Tier 2 plus external-protocol participation (x402, A2A, AP2, ERC-8004, Matrix bridge). " +
    "At v1.0, external-protocol adapters are hooks only; real integrations ship in v1.x.",
};

// ---------------------------------------------------------------------------
// Profile construction
// ---------------------------------------------------------------------------

/**
 * Build the static TierProfile for a given tier.
 */
export function getTierProfile(tier: ModeTier): TierProfile {
  return {
    tier,
    capability_bits: TIER_CAPABILITY_DEFAULTS[tier],
    capability_ceiling: TIER_CAPABILITY_CEILING[tier],
    subsystems: TIER_SUBSYSTEMS[tier],
    description: TIER_DESCRIPTIONS[tier],
  };
}

/**
 * Get all three tier profiles.
 */
export function getAllTierProfiles(): TierProfile[] {
  return MODE_TIERS.map(getTierProfile);
}

// ---------------------------------------------------------------------------
// Capability bit validation
// ---------------------------------------------------------------------------

/**
 * Check whether a capability bitmask is valid for a given tier.
 * A bitmask is valid if every set bit is within the tier's ceiling.
 */
export function isValidCapabilityBits(
  tier: ModeTier,
  bits: number
): boolean {
  const ceiling = TIER_CAPABILITY_CEILING[tier];
  return (bits & ~ceiling) === 0;
}

/**
 * Check whether a specific capability bit is an external-adapter bit (3-7).
 */
export function isExternalAdapterBit(bit: number): boolean {
  return bit >= 3 && bit <= 7;
}

/**
 * Get the bitmask for a specific external-adapter bit index (3-7).
 */
export function externalAdapterBitMask(bit: number): number {
  if (!isExternalAdapterBit(bit)) {
    throw new Error(
      `Capability bit ${bit} is not in the external-adapter range (3-7)`
    );
  }
  return 1 << bit;
}

/**
 * Count the number of external-adapter bits set in a capability mask.
 */
export function countExternalAdapterBits(bits: number): number {
  let count = 0;
  const adapterBits = bits & TIER_3_EXTERNAL_ADAPTER_BITS;
  for (let i = 3; i <= 7; i++) {
    if (adapterBits & (1 << i)) count++;
  }
  return count;
}
