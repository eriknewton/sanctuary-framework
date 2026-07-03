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
 * The closed set of entitlement tiers, lowest capability first. The array
 * order IS the capability ordering; index 0 is the safe floor.
 */
export const ENTITLEMENT_TIERS = [
  "community",
  "team",
  "fleet",
  "enterprise",
] as const;

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
 * Capability rank of a tier: the higher the number, the more capability.
 * COMMUNITY is 0. An unknown string ranks below COMMUNITY (-1) so any
 * comparison treats it as strictly less capable than the floor.
 */
export function tierRank(tier: EntitlementTier | string): number {
  const index = (ENTITLEMENT_TIERS as readonly string[]).indexOf(tier);
  return index;
}

/**
 * True when `a` grants at least as much capability as `b`. Used by callers
 * that gate a paid feature: `tierAtLeast(resolved, "fleet")`.
 *
 * Fails CLOSED on any malformed operand. `tierRank` returns -1 for an unknown
 * string, so a comparison that only ranked the operands would fail OPEN when
 * the REQUIRED tier (`b`) is a typo or bad config: `tierRank("community")` (0)
 * is >= `tierRank("fleeet")` (-1), which would grant a paid gate to the floor
 * tier. This is the single boundary that decides "does `a` clear the bar `b`",
 * so both operands are validated here rather than at each call site; if either
 * is not a known tier we deny.
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
