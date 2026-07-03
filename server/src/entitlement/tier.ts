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
 * Capability rank of a known tier: the higher the number, the more capability.
 * COMMUNITY is 0.
 *
 * MODULE-PRIVATE ON PURPOSE. This is NOT a gating primitive and is not
 * exported. `indexOf` returns -1 for an unknown string, and a naive
 * `rank(a) >= rank(b)` fails OPEN when the REQUIRED tier `b` is a typo:
 * `rank("community")` (0) >= `rank("fleeet")` (-1) is true, granting the floor
 * tier a paid gate. Every capability comparison MUST go through `tierAtLeast`,
 * which validates both operands first; this helper is only ever called on
 * inputs already proven to be known tiers, so its -1 branch is unreachable
 * from the public surface.
 */
function tierRank(tier: EntitlementTier): number {
  return (ENTITLEMENT_TIERS as readonly string[]).indexOf(tier);
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
