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
import { publicKeyToDid } from "../core/identity.js";
import { fromBase64url } from "../core/encoding.js";

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

/**
 * The maximum sovereignty tier an IMPORTED attestation may carry once trusted
 * locally.
 *
 * A locally recorded attestation's tier is trustworthy because THIS store's
 * resolveTier set it from a handshake this instance actually witnessed. An
 * imported attestation's tier is a claim made by a foreign signer: import
 * proves the signer's identity (their Ed25519 signature over their own data),
 * but it does NOT prove that the importing instance ever witnessed a
 * sovereignty handshake with that signer. Trusting a self-asserted
 * "verified-sovereign"/"verified-degraded" tier at face value would let a
 * malicious exporter self-sign a top-weight (1.0) attestation and have it
 * dominate weighted scoring on every instance that imports it.
 *
 * The honest ceiling for an imported attestation is therefore "self-attested":
 * the signature proves the signer holds the identity, nothing stronger.
 */
export const MAX_IMPORTED_SOVEREIGNTY_TIER: SovereigntyTier = "self-attested";

/**
 * Rank tiers by credibility so a clamp can pick the lower of two tiers without
 * hard-coding pairwise comparisons. Higher number == more credible.
 * Kept in lockstep with the tier enum; an exhaustive Record forces a compile
 * error if a new tier is added without ranking it.
 */
const TIER_RANK: Record<SovereigntyTier, number> = {
  "verified-sovereign": 3,
  "verified-degraded": 2,
  "self-attested": 1,
  "unverified": 0,
};

/**
 * Clamp an imported attestation's self-asserted sovereignty tier to the
 * non-privileged import ceiling (MAX_IMPORTED_SOVEREIGNTY_TIER). A tier at or
 * below the ceiling passes through unchanged; a privileged claim
 * ("verified-sovereign"/"verified-degraded") is lowered to the ceiling.
 *
 * Fail-closed by construction: an undefined tier stays undefined (it already
 * scores as the lowest weight downstream), and an unknown/out-of-enum string is
 * lowered to the ceiling rather than trusted. There is no path by which this
 * function RAISES a tier.
 */
export function clampImportedSovereigntyTier(
  tier: SovereigntyTier | undefined
): SovereigntyTier | undefined {
  if (tier === undefined) return undefined;
  const rank = TIER_RANK[tier];
  const ceilingRank = TIER_RANK[MAX_IMPORTED_SOVEREIGNTY_TIER];
  // An unknown tier (rank undefined) is not trusted above the ceiling.
  if (rank === undefined || rank > ceilingRank) {
    return MAX_IMPORTED_SOVEREIGNTY_TIER;
  }
  return tier;
}

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
  handshakeResults: ReadonlyMap<string, HandshakeResult>,
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
 * Resolve the sovereignty tier when the caller holds a counterparty DID rather
 * than its handshake instance_id. The handshake map is keyed by instance_id, so
 * a DID lookup would always miss and silently under-credit a genuinely verified
 * peer. Match the DID against each handshake's current signing key
 * (`counterparty_shr.signed_by`) via the injective publicKeyToDid mapping, then
 * delegate to resolveTier with the matched instance_id.
 *
 * Fail-safe by construction: publicKeyToDid is 1:1, so a DID matches at most one
 * handshake (never the wrong one — no over-crediting); a miss (including a
 * counterparty whose signing key has rotated away from the DID) falls through to
 * the original instance_id lookup, preserving today's behavior.
 *
 * `localIdentityDids` is a DID-STRING set (this function's contract is
 * DID-shaped throughout), so a caller MUST include every DID encoding for
 * each local identity it is capping — `core/identity.ts`'s
 * `localDidEncodings(identity.public_key)` builds both the canonical and
 * legacy forms from the identity's raw key material. A set built from only
 * `identity.did` covers whichever ONE encoding that identity happens to be
 * persisted under and silently misses the other (the #1194-class defect).
 */
export function resolveTierByDid(
  counterpartyDid: string,
  handshakeResults: ReadonlyMap<string, HandshakeResult>,
  hasSanctuaryIdentity: boolean,
  localIdentityDids?: ReadonlySet<string>
): TierMetadata {
  // REP-01 (register §Z RECHECK) — the self-vouch chokepoint. A handshake entry
  // for a LOCALLY-HELD identity is a self-vouch, never independent verification:
  // this map holds counterparties THIS instance verified, and a genuine remote
  // peer's verification of one of our identities lives in the PEER's map, never
  // ours. So a match against a local DID can only have been minted by handshaking
  // ourselves — with an identical key, OR (the case the same-key protocol guard
  // does NOT catch) two distinct keys the operator holds. Crediting it lets an
  // agent launder its own attestations up to full signer tier. Never credit a
  // local DID: a local signer resolves to self-attested regardless of any
  // handshake entry, which is also the honest posture (its credibility is not
  // established by our own map). This one check closes every self-vouch key
  // variant; the protocol-level same-key rejection is defense-in-depth for the
  // obviously-degenerate case. Callers pass the local DID set; when omitted (a
  // genuine remote-counterparty lookup) the credit path is unchanged.
  if (localIdentityDids?.has(counterpartyDid)) {
    return hasSanctuaryIdentity
      ? { sovereignty_tier: "self-attested" }
      : { sovereignty_tier: "unverified" };
  }
  for (const [instanceId, result] of handshakeResults) {
    try {
      const did = publicKeyToDid(fromBase64url(result.counterparty_shr.signed_by));
      if (did === counterpartyDid) {
        return resolveTier(instanceId, handshakeResults, hasSanctuaryIdentity);
      }
    } catch {
      // Skip a handshake whose signing key cannot be decoded.
    }
  }
  // No DID match — preserve the original behavior (the instance_id lookup misses
  // for a DID key and falls to self-attested/unverified).
  return resolveTier(counterpartyDid, handshakeResults, hasSanctuaryIdentity);
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
    // Fail closed: an unknown/imported-invalid tier (weight undefined) or a
    // non-finite value must not poison the aggregate into NaN. A weight-0 tier
    // already contributes nothing, so skipping it is behavior-preserving.
    const weight = TIER_WEIGHTS[a.tier] ?? 0;
    if (weight <= 0 || !Number.isFinite(a.value)) continue;
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
