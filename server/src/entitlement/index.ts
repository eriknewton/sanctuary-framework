/**
 * Fleet entitlement (S1 scaffold): offline Ed25519 entitlement-token verify
 * and tier resolution, fail-closed to the community tier.
 *
 * This barrel is the module surface consumers import; do not reach into the
 * internal files. S1 ships the verify/resolve core + tier model only, NOT
 * the full paid fleet control plane (issuance, billing, revocation).
 */

export {
  ENTITLEMENT_TIERS,
  COMMUNITY_TIER,
  isEntitlementTier,
  tierAtLeast,
  type EntitlementTier,
} from "./tier.js";

export {
  ENTITLEMENT_TOKEN_DOMAIN,
  ENTITLEMENT_TOKEN_VERSION,
  canonicalJson,
  buildEntitlementMessage,
  resolveEntitlement,
  type EntitlementClaims,
  type EntitlementToken,
  type EntitlementResolution,
  type EntitlementDenyReason,
  type ResolveEntitlementOptions,
} from "./token.js";
