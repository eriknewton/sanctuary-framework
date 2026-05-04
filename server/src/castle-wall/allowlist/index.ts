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
