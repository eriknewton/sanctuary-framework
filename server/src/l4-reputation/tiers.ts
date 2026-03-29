/**
 * Sanctuary MCP Server — Sovereignty-Gated Reputation Tiers
 *
 * Attestations carry a sovereignty_tier field reflecting the signer's
 * sovereignty posture at the time of recording. When querying or evaluating
 * reputation, attestations from verified-sovereign agents carry more weight
 * than those from unverified agents.
 *
 * Tier hierarchy (descending credibility):
 *   1. "verified-sovereign"  — signer completed a handshake with full sovereignty
 *   2. "verified-degraded"   — signer completed a handshake with degraded sovereignty
 *   3. "self-attested"       — signer has a Sanctuary identity but no handshake verification
 *   4. "unverified"          — no Sanctuary identity or sovereignty proof
 *
 * Weight multipliers are applied during reputation scoring. They are NOT
 * gatekeeping — unverified attestations still count, just less.
 */

import type { HandshakeResult, TrustTier } from "../handshake/types.js";

// ── Tier Types ──────────────────────────────────────────────────────

export type SovereigntyTier =
  | "verified-sovereign"
  | "verified-degraded"
  | "self-attested"
  | "unverified";

/** Weight multipliers for each tier */
export const TIER_WEIGHTS: Record<SovereigntyTier, number> = {
  "verified-sovereign": 1.0,
  "verified-degraded": 0.8,
  "self-attested": 0.5,
  "unverified": 0.2,
};

/** Tier metadata embedded in attestations */
export interface TierMetadata {
  sovereignty_tier: SovereigntyTier;
  /** If verified, the handshake that established it */
  handshake_completed_at?: string;
  /** Counterparty ID from handshake (if applicable) */
  verified_by?: string;
}

// ── Tier Resolution ─────────────────────────────────────────────────

/**
 * Resolve the sovereignty tier for a counterparty based on handshake history.
 *
 * @param counterpartyId - The counterparty's instance ID
 * @param handshakeResults - Map of counterparty ID → most recent handshake result
 * @param hasSanctuaryIdentity - Whether the counterparty has a known Sanctuary identity
 * @returns TierMetadata for embedding in attestations
 */
export function resolveTier(
  counterpartyId: string,
  handshakeResults: Map<string, HandshakeResult>,
  hasSanctuaryIdentity: boolean
): TierMetadata {
  const handshake = handshakeResults.get(counterpartyId);

  if (handshake && handshake.verified) {
    // Check if handshake has expired
    const expiresAt = new Date(handshake.expires_at);
    if (expiresAt > new Date()) {
      return {
        sovereignty_tier: handshake.trust_tier as SovereigntyTier,
        handshake_completed_at: handshake.completed_at,
        verified_by: handshake.counterparty_id,
      };
    }
    // Expired handshake — fall through to self-attested or unverified
  }

  if (hasSanctuaryIdentity) {
    return { sovereignty_tier: "self-attested" };
  }

  return { sovereignty_tier: "unverified" };
}

/**
 * Map a trust tier from a handshake result to a sovereignty tier.
 */
export function trustTierToSovereigntyTier(trustTier: TrustTier): SovereigntyTier {
  switch (trustTier) {
    case "verified-sovereign":
      return "verified-sovereign";
    case "verified-degraded":
      return "verified-degraded";
    default:
      return "unverified";
  }
}

// ── Weighted Scoring ────────────────────────────────────────────────

/** An attestation with its tier for weighted scoring */
export interface TieredAttestation {
  /** The raw metric value */
  value: number;
  /** The sovereignty tier of the attestation signer */
  tier: SovereigntyTier;
}

/**
 * Compute a weighted reputation score from tiered attestations.
 *
 * Each attestation's contribution is multiplied by its tier weight.
 * The result is normalized by total weight (not count), so adding
 * low-tier attestations doesn't dilute high-tier ones.
 *
 * @param attestations - Array of value + tier pairs
 * @returns Weighted score, or null if no attestations
 */
export function computeWeightedScore(
  attestations: TieredAttestation[]
): number | null {
  if (attestations.length === 0) return null;

  let weightedSum = 0;
  let totalWeight = 0;

  for (const a of attestations) {
    const weight = TIER_WEIGHTS[a.tier];
    weightedSum += a.value * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? weightedSum / totalWeight : null;
}

/**
 * Compute a tier distribution summary for a set of attestations.
 */
export function tierDistribution(
  tiers: SovereigntyTier[]
): Record<SovereigntyTier, number> {
  const dist: Record<SovereigntyTier, number> = {
    "verified-sovereign": 0,
    "verified-degraded": 0,
    "self-attested": 0,
    "unverified": 0,
  };

  for (const tier of tiers) {
    dist[tier]++;
  }

  return dist;
}
