/**
 * Sanctuary MCP Server — Intelligence Layer Public Barrel
 *
 * Stable import surface for the intelligence substrate selector and the
 * substrate clients beneath it. Consumers (chat / sentinel / gate
 * explanation / privacy filter Tier 2 / template suggestion / dashboard
 * transparency UI) import from this barrel so internal layout shifts
 * stay non-breaking.
 *
 * Audit-event payload contracts live under `contracts/v1.2/` and are
 * re-exported here for callers that need both the selector + the typed
 * payload shapes.
 */

export {
  SubstrateSelector,
  IDENTITY_REDACTOR,
  type SelectorConfig,
} from "./selector.js";

export {
  IntelligenceConfigStore,
  INTELLIGENCE_NAMESPACE,
  SUBSTRATE_CONFIG_KEY,
  type LoadOutcome,
} from "./policy-store.js";

export {
  buildDefaultConfig,
  DEFAULT_OLLAMA_ENDPOINT,
  DEFAULT_PER_SURFACE,
  DEFAULT_LOCAL_MODEL_PICKS,
  DEFAULT_FALLBACK,
} from "./defaults.js";

export {
  INTEL_OPS,
  type IntelOp,
} from "./audit-events.js";

export {
  MODEL_LICENSE_REDISTRIBUTION,
  MODEL_MANIFEST_DELIMITER,
  MODEL_MANIFEST_DOMAIN,
  MODEL_MANIFEST_MAX_JSON_CHARS,
  MODEL_MANIFEST_MAX_MODELS,
  MODEL_MANIFEST_MAX_MODELS_PER_TIER,
  MODEL_MANIFEST_MAX_PARAMS_B,
  MODEL_MANIFEST_MAX_STRING_CHARS,
  MODEL_MANIFEST_MAX_URL_CHARS,
  MODEL_MANIFEST_MAX_VERSION,
  MODEL_MANIFEST_MIN_PARAMS_B,
  MODEL_MANIFEST_RUNTIMES,
  MODEL_MANIFEST_TIERS,
  PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL,
  buildModelManifestMessage,
  loadPinnedModelManifestKey,
  parseModelManifestJson,
  provenanceFromVerifiedModelManifest,
  resolveModelForSurface,
  verifyModelManifest,
  verifyModelManifestWithKey,
  type ModelLicenseMetadata,
  type ModelLicenseRedistribution,
  type ModelManifestBody,
  type ModelManifestRefusalReason,
  type ModelManifestRuntime,
  type ModelManifestSurfaceDefaults,
  type ModelManifestTier,
  type ModelManifestTierBundles,
  type ModelManifestVerificationOptions,
  type ModelManifestVerificationResult,
  type ModelManifestModel,
  type SignedModelManifest,
} from "./model-manifest.js";

export {
  IMMUNE_MODEL_LOAD_SURFACES,
  MODEL_LOAD_INTEGRITY_ASSURANCES,
  MODEL_MANIFEST_V2_DELIMITER,
  MODEL_MANIFEST_V2_DOMAIN,
  MODEL_MANIFEST_V2_REGISTRY,
  MODEL_MANIFEST_V2_SCHEMA_VERSION,
  PINNED_MODEL_MANIFEST_V2_SIGNING_PUBLIC_KEY_B64URL,
  buildModelManifestV2Message,
  computeModelManifestV2BodyDigest,
  deriveOllamaManifestRelativePath,
  deriveOllamaRuntimeTag,
  parseModelManifestV2Json,
  validateLocalIntegrityStateV2,
  verifyModelManifestV2WithKey,
  type LocalIntegrityStateV2,
  type LocalIntegrityStateV2ValidationResult,
  type ModelLoadIntegrityAssurance,
  type ModelManifestBodyV2,
  type ModelManifestModelV2,
  type ModelManifestSurfaceDefaultsV2,
  type ModelManifestTierBundlesV2,
  type ModelManifestV2RefusalReason,
  type ModelManifestV2VerificationResult,
  type SignedModelManifestV2,
  type SignedOllamaIdentityV2,
  type VerifiedLocalBindingV2,
} from "./model-manifest-v2.js";

export {
  BADGE_LABEL_KEYS,
  BADGE_TRADEOFF_KEYS,
  BACKEND_FALLBACK_STRINGS,
  LOCAL_MODEL_LABELS,
  resolveBackendString,
  tradeoffTextHash,
} from "./templates.js";

export type {
  ClassifyRequest,
  FallbackBehavior,
  FrontierProvider,
  FrontierProviderConfig,
  HardwareCapabilityReport,
  HybridRoutingRules,
  LocalModelPick,
  RedactRequest,
  SubstrateBadge,
  SubstrateCapability,
  SubstrateChoice,
  SubstrateConfig,
  SubstrateFailureClass,
  SubstrateHandle,
  SubstrateInvocation,
  SubstrateRequest,
  SubstrateResponse,
  SubstrateStatusReport,
  SummarizeRequest,
  Surface,
  SurfaceStatus,
} from "./types.js";

export {
  FRONTIER_PROVIDERS,
  LOCAL_MODEL_TAGS,
  SUBSTRATE_CHOICES,
  SURFACES,
  TIER2_PINNED_SURFACE,
  TIER2_PIN_ALLOWED_CHOICES,
  Tier2BindingPinnedError,
  isTier2PinViolation,
} from "./types.js";

export {
  LocalSubstrate,
  OllamaClient,
  LOCAL_CAPABILITY,
  type OllamaClientConfig,
  type OllamaMutationResult,
  type OllamaShowResult,
} from "./substrates/local.js";

export {
  MODEL_REGISTRY_PROVIDER_CATEGORY,
  renderLocalProvisioningPlan,
  runLocalIntelligenceProvisioning,
  type LocalProvisioningAuditEvent,
  type LocalProvisioningOps,
  type LocalProvisioningRefusalReason,
  type LocalProvisioningResult,
  type VerifiedProvisioningCommit,
} from "./provisioning.js";

export {
  VeniceClient,
  VeniceSubstrate,
  VENICE_CAPABILITY,
  VENICE_DEFAULT_ENDPOINT,
  VENICE_DEFAULT_MODEL,
  type VeniceClientConfig,
} from "./substrates/venice.js";

export {
  FrontierClient,
  FrontierWithFilterSubstrate,
  FRONTIER_CAPABILITY,
  FRONTIER_DEFAULT_MODELS,
  type FrontierClientConfig,
  type FrontierRedactor,
} from "./substrates/frontier.js";

export {
  resolveHybridChoice,
  buildHybridRules,
  validateHybridRules,
  type HybridResolvedChoice,
} from "./substrates/hybrid/per-surface-router.js";

export {
  buildPrivacyTier2Redactor,
  type Tier2RedactorConfig,
} from "./privacy-tier2-redactor.js";

export type {
  IntelligenceAuditPayload,
  IntelligenceAuditPayloadHeader,
  IntelligenceConfigLoadedPayload,
  IntelligenceConfigResetPayload,
  IntelligencePiiRedactionEventPayload,
  IntelligenceSubstrateChosenPayload,
  IntelligenceSubstrateFailurePayload,
  IntelligenceSubstrateInvokedPayload,
} from "../contracts/v1.2/intelligence-events.js";
