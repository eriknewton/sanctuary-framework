/**
 * Fleet entitlement tier model (S1 scaffold).
 *
 * A tier names a capability level for the paid fleet control plane. This
 * file is the ONLY place the tier vocabulary and its ordering live so the
 * verify/resolve core can reason about "strictly less capability" without
 * re-deriving an ordering.
 *
 * COMMUNITY is the floor: it is what every operator gets with no token, and
 * it is what verification degrades to on any failure. Paid tiers sit above
 * it. This is S1 (the tier model + the offline verify/resolve core), not the
 * full control plane; issuance, billing, and revocation are out of scope.
 */

/**
 * The closed set of entitlement tiers, lowest capability first. This array is
 * the tier vocabulary and its canonical declaration order; index 0 is the safe
 * floor.
 *
 * FROZEN ON PURPOSE. The exported array is `Object.freeze`d so a consumer
 * cannot `sort()`, reverse, or splice it. Critically, the capability lattice
 * is NOT read from this live array at comparison time: `tierAtLeast` ranks via
 * a private frozen index map (`TIER_RANK`) captured once at module load, so
 * even if a future refactor handed out a mutable copy, reordering it could not
 * change which tier satisfies a higher-tier gate. The freeze is defense in
 * depth; the private rank map is the actual chokepoint.
 */
export const ENTITLEMENT_TIERS = Object.freeze([
  "community",
  "team",
  "fleet",
  "enterprise",
] as const);

/** A single entitlement tier. */
export type EntitlementTier = (typeof ENTITLEMENT_TIERS)[number];

/**
 * The safe floor tier. Absent, invalid, expired, tampered, or malformed
 * tokens ALL resolve here. Never grant a paid tier on failure.
 */
export const COMMUNITY_TIER: EntitlementTier = "community";

/** True when `value` is one of the known tiers. */
export function isEntitlementTier(value: unknown): value is EntitlementTier {
  return (
    typeof value === "string" &&
    (ENTITLEMENT_TIERS as readonly string[]).includes(value)
  );
}

/**
 * The capability lattice, captured ONCE at module load into a private frozen
 * tier -> rank map. The higher the number, the more capability; COMMUNITY is 0.
 *
 * This map, NOT the live `ENTITLEMENT_TIERS` array, is the source of truth for
 * ordering. It is built from the declaration order at load time and frozen, so
 * no later mutation of the exported array (a `sort()`, reverse, or splice by a
 * consumer) can change any tier's rank. Reordering the public array after load
 * cannot make a lower tier satisfy a higher-tier gate.
 */
const TIER_RANK: Readonly<Record<EntitlementTier, number>> = Object.freeze(
  Object.fromEntries(ENTITLEMENT_TIERS.map((tier, index) => [tier, index])),
) as Readonly<Record<EntitlementTier, number>>;

/**
 * Capability rank of a known tier from the frozen lattice.
 *
 * MODULE-PRIVATE ON PURPOSE. This is NOT a gating primitive and is not
 * exported. It reads `TIER_RANK` (a frozen snapshot), never the live array, so
 * it is immune to post-load reordering. An unknown string yields `undefined`,
 * and a naive `rank(a) >= rank(b)` would fail OPEN on a typo'd required tier;
 * every capability comparison MUST go through `tierAtLeast`, which validates
 * both operands first, so this helper only ever sees known tiers.
 */
function tierRank(tier: EntitlementTier): number {
  return TIER_RANK[tier];
}

/**
 * True when `a` grants at least as much capability as `b`. This is the ONLY
 * exported capability-comparison boundary; callers gate a paid feature with
 * `tierAtLeast(resolved, "fleet")`.
 *
 * Fails CLOSED on any malformed operand. Both operands are validated here
 * (not at each call site) so the raw rank comparison never sees an unknown
 * string: if either operand is not a known tier we deny. This closes the
 * malformed-required-tier fail-open at a single chokepoint.
 */
export function tierAtLeast(
  a: EntitlementTier | string,
  b: EntitlementTier | string,
): boolean {
  if (!isEntitlementTier(a) || !isEntitlementTier(b)) {
    return false;
  }
  return tierRank(a) >= tierRank(b);
}
