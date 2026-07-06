/**
 * Fleet entitlement: offline Ed25519 entitlement-token verify + tier resolution
 * (fail-closed to the community tier), the issuer license ledger (PR-1), and the
 * activation + node-count enforcement gate (PR-B, on the daemon federation
 * roster).
 *
 * This barrel is the module surface consumers import; do not reach into the
 * internal files. Layers:
 *   - verify/resolve core + tier model (`token.ts`, `tier.ts`).
 *   - issuer license ledger (`ledger.ts`, `ledger-io.ts`, `ledger-antirollback.ts`)
 *     - the Erik-operated sell side (PR-1).
 *   - activation + enforcement (`activation.ts`, `fleet-cap.ts`) - the operator
 *     pastes a license, it is verified + persisted in signed tamper-evident
 *     state, and the CENTRAL fleet roster (the daemon's durable federation
 *     roster) enforces the node-count cap. Payment processing / self-serve
 *     remains out of scope. Enforcement is fail-closed to community on any
 *     failure and NEVER gates a node's Castle Wall, its local dashboard, kill
 *     safety, or free policy-push (PR-B).
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
  withLedgerMutationLock,
  type LedgerLockOptions,
} from "./ledger-io.js";

export {
  LEDGER_GENERATION_ANCHOR_META_KEY,
  readLedgerGenerationAnchor,
  writeLedgerGenerationAnchor,
  checkLedgerFreshness,
  type LedgerGenerationAnchorData,
  type LedgerFreshnessVerdict,
} from "./ledger-antirollback.js";

export {
  COMMUNITY_FREE_NODE_CAP,
  resolveFleetCap,
  applyFleetCap,
  type FleetCap,
  type FleetCapReason,
  type ResolvedEntitlementView,
  type CappedFleetRoster,
} from "./fleet-cap.js";

export {
  FLEET_ACTIVATION_META_KEY,
  readFleetActivation,
  writeFleetActivation,
  clearFleetActivation,
  activateFleet,
  resolveActivation,
  decodeLicense,
  decodeIssuerPublicKey,
  type FleetActivationData,
  type ActivateFleetResult,
} from "./activation.js";

export {
  REVOCATION_LIST_SIGN_ACTION,
  REVOCATION_LIST_META_KEY,
  buildRevocationListMessage,
  canonicalizeRevocationListIds,
  signRevocationList,
  verifyPushedRevocationList,
  readRevocationList,
  writeRevocationList,
  isLicenseRevoked,
  type RevocationListPayload,
  type SignedRevocationList,
  type RevocationListSigner,
  type RevocationListVerifyReason,
  type RevocationListVerification,
  type RevocationStatus,
} from "./revocation-list.js";

export {
  REVOCATION_VERSION_ANCHOR_META_KEY,
  readRevocationVersionAnchor,
  writeRevocationVersionAnchor,
  effectiveRevocationVersionFloor,
  type RevocationVersionAnchorData,
} from "./revocation-antirollback.js";

export {
  DOWNGRADE_LOG_META_KEY,
  MAX_DOWNGRADE_LOG_ENTRIES,
  readDowngradeLog,
  appendDowngradeLog,
  type DowngradeTransitionKind,
  type DowngradeLogEntry,
  type DowngradeLogRead,
} from "./downgrade-log.js";

export {
  diffCapTransition,
  runFleetReResolve,
  type PriorCapState,
  type ReResolveRosterView,
  type CapTransition,
  type ReResolveResult,
} from "./re-resolve.js";
