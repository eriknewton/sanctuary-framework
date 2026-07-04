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
  ENTITLEMENT_TOKEN_DOMAIN_V2,
  ENTITLEMENT_TOKEN_VERSION_V2,
  canonicalJson,
  buildEntitlementMessage,
  buildEntitlementMessageV2,
  resolveEntitlement,
  type EntitlementClaims,
  type EntitlementClaimsV2,
  type EntitlementToken,
  type EntitlementResolution,
  type EntitlementDenyReason,
  type ResolveEntitlementOptions,
  type PricingUnit,
  type EntitlementPeriod,
  type EntitlementFeatureFlag,
} from "./token.js";

export {
  LEDGER_SCHEMA_VERSION,
  LEDGER_GENESIS,
  LEDGER_REVOCATION_DOMAIN,
  LEDGER_HEAD_DOMAIN,
  emptyLedger,
  issueLicense,
  appendRow,
  listLicenses,
  revokeLicense,
  verifyLedgerIntegrity,
  type Ledger,
  type LedgerRow,
  type LedgerRowMetadata,
  type LicenseToken,
  type LicenseListEntry,
  type LedgerIntegrity,
  type IssueLicenseParams,
  type IssuerSigner,
} from "./ledger.js";

export {
  resolveLedgerPath,
  loadLedger,
  saveLedger,
} from "./ledger-io.js";
