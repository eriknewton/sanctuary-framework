/**
 * Plugin substrate — vendor contract surface (slice S1).
 *
 * This is the DEPENDENCY-LIGHT contract surface only: schema, types, verdict algebra, and
 * signed-manifest verification. There is NO host process, NO jail, NO audit wiring in S1 —
 * those are deferred to S2 (plugin-v1 seccomp profile), S3 (launcher), and S4 (supervisor +
 * egress hook + attribution). See Review/Sanctuary/Plugin_Host_Architecture_Design_2026-06-12.md §7.
 *
 * Implements (never weakens) the ratified Plugin Security RFC (Plugin_Security_RFC_2026-06-07).
 * Phase-1 codex adversarial contract review: PASS (all round-1 BLOCKING/HIGH closed).
 */

export { SubstrateError, type SubstrateRejectReason } from "./errors.js";
export { canonicalize, canonicalizeToBytes } from "./canonical-json.js";
export { parseStrictJson } from "./strict-json.js";
export { parseRestrictedYaml, type YamlValue } from "./restricted-yaml.js";
export { validateBundlePath, validateId } from "./paths.js";

export {
  type PluginDecision,
  type EnforcementDecision,
  type HostDecision,
  type ComposedOutcome,
  type PluginVerdict,
  PLUGIN_DECISIONS,
  MAX_RATIONALE_LEN,
  MAX_SIGNAL_STRING_LEN,
  intersectVerdicts,
  parsePluginVerdict,
  parseVerdictFrame,
} from "./verdict.js";

export {
  type HookClass,
  type Sensitivity,
  type FieldSpec,
  FIELD_ALLOWLIST,
  sensitivityOf,
  validateDeclaredFields,
  validateArgumentSelectors,
} from "./fields.js";

export {
  type RequestEnvelope,
  type RequestOrigin,
  type TrustLabel,
  type ToolCallRequest,
  type EgressDecisionRequest,
  type IngressContentRequest,
  type AttestationRequest,
  type HookRequest,
} from "./requests.js";

export {
  type BundleDescriptor,
  type BundleFileEntry,
  type SignatureFile,
  type ObservedBundle,
  type TrustedSigner,
  type VerifyContext,
  BUNDLE_SCHEMA,
  SIGNATURE_FILENAME,
  SUPPORTED_ALG,
  MAX_DESCRIPTOR_BYTES,
  sha256Hex,
  validateDescriptorShape,
  verifyBundle,
} from "./manifest.js";

export {
  type FailMode,
  type DataClass,
  type EndpointDecl,
  type HookDecl,
  type Governance,
  MAX_GOVERNANCE_BYTES,
  parseGovernance,
  governanceHash,
} from "./governance.js";

export {
  type PluginContribution,
  type PluginContributionVerdict,
  boundContributionRationale,
} from "./attribution.js";

export {
  type PluginLifecycleState,
  type PluginSuspensionReason,
  type PluginLifecycleHook,
  type PluginLifecycleRecord,
  type PluginLifecycleAuditSink,
  PLUGIN_AUDIT_OPS,
  PluginLifecycleController,
} from "./lifecycle.js";

export {
  type PluginRuntimeClient,
  type RealizedConfinementReport,
  type PluginLaunchConfig,
  type RunningPluginRegistration,
  type EgressConsultationInput,
  type EgressConsultationResult,
  type PluginHealth,
  type PluginSupervisorOptions,
  PLUGIN_CONFINEMENT_KIND,
  PLUGIN_SECCOMP_PROFILE_ID,
  DEFAULT_INLINE_TIMEOUT_MS,
  DEFAULT_EGRESS_TIMEOUT_MS,
  MAX_VERDICT_FRAME_BYTES,
  MAX_REQUEST_FRAME_BYTES,
  PluginInvocationError,
  FramedJsonPluginClient,
  PluginSupervisor,
  projectEgressDecisionRequest,
  parseConfinementReport,
  validateConfinementReport,
} from "./supervisor.js";
