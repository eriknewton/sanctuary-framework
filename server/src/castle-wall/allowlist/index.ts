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
  allowlistAllowsTarget,
  allowlistAllowsFlow,
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
} from "./gate-derivation.js";
