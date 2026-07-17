/** Public surface of the allowlist module. */

export type {
  AllowlistRule,
  RuleProtocol,
  RuleDisposition,
  RuleMatch,
  RuleScope,
  RuleTimeWindow,
} from "./schema.js";
export { validateRule } from "./schema.js";

export type {
  AllowlistManifest,
  ManifestRuleEntry,
  ManifestSignature,
  SignedManifest,
} from "./manifest.js";

export type { ParseResult, RuleFileBytes } from "./parse.js";
export { verifyManifestSignature, verifyAndParseRules } from "./parse.js";

export {
  canonicalizeConnectAuthority,
  ruleMatchesTarget,
  ruleScopeCoversAgent,
  ruleProtocolMatches,
  allowlistAllowsTarget,
  ConnectAuthorityError,
  type CanonicalConnectAuthority,
  type CanonicalizationErrorCode,
} from "./match.js";

export {
  DERIVED_GATE_RULE_ID,
  GATE_LOOPBACK_CIDR,
  EXCLUSIVE_EGRESS_GATE_FILENAME,
  validateExclusiveEgressGatePolicy,
  deriveGateAllowRule,
  type ExclusiveEgressGatePolicy,
  type DeriveGateAllowRuleOptions,
} from "./gate-derivation.js";

export {
  EXCLUSIVE_ROUTING_COARSE_FALLBACK_AUDIT_OP,
  ExclusiveRoutingViolationError,
  ExclusiveRoutingResidueError,
  allowRuleScopeReachesAgent,
  ruleIsLoopbackOnly,
  assertExclusiveRoutingComposition,
  composeExclusiveRoutingRules,
  type ConfinedAgentIdentity,
  type ExclusiveRoutingPrincipals,
  type ExclusiveRoutingViolation,
  type ExclusiveRoutingCompositionReport,
  type CoarseFallbackAuditRecord,
  type ExclusiveRoutingRequest,
  type ExclusiveRoutingComposition,
} from "./exclusive-routing.js";

// Unified Protect Slice 5 S5-6: the durable exclusive-routing mode marker.
export {
  EXCLUSIVE_ROUTING_MARKER_FILENAME,
  EXCLUSIVE_ROUTING_MARKER_VERSION,
  ExclusiveRoutingMarkerError,
  exclusiveRoutingMarkerPath,
  loadExclusiveRoutingMarker,
  parseExclusiveRoutingMarker,
  renderExclusiveRoutingMarker,
  type ExclusiveRoutingMarker,
} from "./routing-marker.js";
