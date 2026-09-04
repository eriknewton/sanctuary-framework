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
  LocalIntegrityStateLoadError,
  Q5_CONFIG_SAVE_LOCK_FILE,
  SUBSTRATE_CONFIG_KEY,
  type IntelligenceConfigStoreOptions,
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
  PINNED_MODEL_CATALOG_ROOT_PUBLIC_KEY_B64URL,
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
  MODEL_LOAD_INTEGRITY_FAILURE_REASONS,
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
  type ModelLoadIntegrityFailureReason,
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
  PACKAGED_MODEL_MANIFEST_AUDIT_STAGE,
  PACKAGED_MODEL_MANIFEST_REFUSAL_REASONS,
  PACKAGED_MODEL_MANIFEST_V2_ASSET_RELATIVE_PATH,
  PACKAGED_MODEL_MANIFEST_V2_ASSET_SHA256,
  PACKAGED_MODEL_MANIFEST_V2_MAX_BYTES,
  loadPackagedModelManifestV2,
  mapModelManifestV2RefusalToAssetRefusal,
  resolveModuleDir,
  resolvePackagedModelManifestV2AssetPath,
  type LoadPackagedModelManifestV2Options,
  type PackagedModelManifestAuditEvent,
  type PackagedModelManifestLoadResult,
  type PackagedModelManifestRefusalReason,
  type PackagedModelManifestSource,
} from "./packaged-model-manifest.js";

export {
  ASSURANCES,
  ASSURANCE_RANK,
  CATALOG_INDEX_V1_DOMAIN,
  CATALOG_SIGNING_BODY_MAX_BYTES,
  CATALOG_SURFACE_ORDER,
  CATALOG_V3_DOMAIN,
  CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256,
  COMPILED_SPDX_TABLE_SHA256,
  COMPILED_CATALOG_KEY_POLICY_DIGEST,
  COMPILED_CATALOG_KEYRING,
  COMPILED_INDEX_CHECKPOINT,
  COMPILED_SURFACE_ASSURANCE_FLOOR,
  HARDWARE_TIERS,
  MAX_CATALOG_ENTRIES,
  MAX_CATALOG_WIRE_JSON_BYTES,
  MAX_INDEX_SEGMENT_ENTRIES,
  MAX_OVERLAY_ENTRIES,
  MAX_SIGNED_VERSION,
  OLLAMA_REGISTRY_V3,
  OVERLAY_V1_DOMAIN,
  SPDX_EXPRESSION_ABNF_SHA256,
  SPDX_LICENSE_LIST_VERSION,
  SIGNATURE_DOMAIN_DELIMITER,
  SURFACE_DEFAULTS_V3,
  TIER_TABLE_V3,
  deriveCatalogKeyringSha256,
  deriveOverlaySignerKeyId,
  parseAssurance,
  parseCatalogBodyV3,
  parseCatalogIndexBodyV1,
  parseCatalogJson,
  parseModelId,
  parseOverlayBodyV1,
  parseSignedOllamaIdentityV3,
  parseSpdxExpression,
  parseSurfaceList,
  parseUntrustedCatalogContinuityObservationV3,
  parseUntrustedCatalogIndexContinuityObservationV1,
  validateCatalogKeyring,
  validateCatalogOverlayCombination,
  verifyAndParseSignedCatalogIndexSegmentV1,
  verifyAndParseSignedCatalogIndexJsonV1,
  verifyAndParseSignedCatalogJsonV3,
  verifyAndParseSignedCatalogV3,
  verifyAndParseSignedOverlayJsonV1,
  verifyAndParseSignedOverlayV1,
  type Assurance,
  type CatalogBodyV3,
  type CatalogIndexBodyV1,
  type CatalogIndexEntryV1,
  type CatalogKeyEpoch,
  type CatalogModelEntryV3,
  type CatalogV3ParseResult,
  type CatalogV3RefusalReason,
  type CompiledIndexCheckpoint,
  type HardwareTier,
  type LicenseEvidenceV3,
  type OverlayBodyV1,
  type OverlayModelEntryV1,
  type SignedCatalogIndexSegmentV1,
  type SignedCatalogV3,
  type SignedOllamaIdentityV3,
  type SignedOverlayV1,
  type SurfaceDefaultV3,
  type SurfaceDefaultsV3,
  type TierSpecV3,
  type TierTableV3,
  type UntrustedCatalogContinuityObservationV3,
  type UntrustedCatalogIndexContinuityObservationV1,
} from "./model-catalog-v3.js";

export {
  LIGHT_RUNTIME_SINGLE_FLIGHT_MAX_ENTRIES,
  OLLAMA_RUNTIME_EVIDENCE_DEFAULT_TIMEOUT_MS,
  OLLAMA_RUNTIME_EVIDENCE_MAX_MODELS,
  OLLAMA_RUNTIME_EVIDENCE_MAX_RESPONSE_BYTES,
  OLLAMA_RUNTIME_TAG_MAX_CHARS,
  RUNTIME_LIGHT_PROTOCOL_STATES,
  OllamaRuntimeEvidenceClient,
  createSingleFlightLightRuntimeVerifier,
  inspectOllamaShowPayload,
  inspectOllamaTagsDigest,
  type OllamaRuntimeEvidenceClientConfig,
  type OllamaShowInspectionResult,
  type OllamaTagsDigestInspectionResult,
  type RuntimeLightProtocolState,
  type RuntimeLightRefusalReason,
  type RuntimeLightVerificationRequest,
  type RuntimeLightVerificationResult,
  type RuntimeLightVerifier,
} from "./runtime-light-verifier.js";

export {
  IMMUNE_FULL_VERIFICATION_CADENCE_MS,
  IMMUNE_HASH_BUFFER_BYTES,
  IMMUNE_HASH_MAX_BUFFER_BYTES,
  IMMUNE_OCI_MANIFEST_MAX_BYTES,
  IMMUNE_OCI_MANIFEST_OVERFLOW_READ_BYTES,
  IMMUNE_OCI_MAX_DESCRIPTOR_BYTES,
  IMMUNE_OCI_MAX_LAYERS,
  IMMUNE_OCI_MAX_MEDIA_TYPE_CHARS,
  IMMUNE_OCI_MAX_TOTAL_DESCRIPTOR_BYTES,
  IMMUNE_VERIFICATION_CACHE_MAX_ENTRIES,
  createCadencedImmuneDiskVerifier,
  createNodeImmuneFileSystemAdapter,
  createOnDiskImmuneVerifier,
  parseBoundedOciManifest,
  type CadencedImmuneDiskVerifier,
  type CadencedImmuneVerifierOptions,
  type ImmuneDiskVerifier,
  type ImmuneFileHandle,
  type ImmuneFileStat,
  type ImmuneFileSystemAdapter,
  type ImmuneVerificationCheckpoint,
  type ImmuneVerificationClock,
  type ImmuneVerificationRefusalReason,
  type ImmuneVerificationRequest,
  type ImmuneVerificationResult,
  type OciDescriptor,
  type OnDiskImmuneVerifierOptions,
  type ParsedOciManifest,
} from "./immune-disk-verifier.js";

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
  SubstrateConfigV1,
  SubstrateConfigV2,
  SubstrateFailureClass,
  SubstrateHandle,
  SubstrateInvocation,
  SubstrateRequest,
  SubstrateResponse,
  SubstrateStatusReport,
  SummarizeRequest,
  SurfaceStatus,
} from "./types.js";

export {
  FRONTIER_PROVIDERS,
  LOCAL_MODEL_TAGS,
  SUBSTRATE_CHOICES,
  TIER2_PINNED_SURFACE,
  TIER2_PIN_ALLOWED_CHOICES,
  Tier2BindingPinnedError,
  isTier2PinViolation,
} from "./types.js";

export { SURFACES, type Surface } from "./surfaces.js";

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
  LocalModelsRootResolutionError,
  Q5_PROVISIONING_LOCK_FILE,
  renderLocalProvisioningPlan,
  runLocalIntelligenceProvisioning,
  type AtomicLocalProvisioningCommit,
  type LocalProvisioningAuditEvent,
  type LocalProvisioningOps,
  type LocalProvisioningRefusalReason,
  type LocalProvisioningResult,
  type ProvenanceProjectionOutcome,
  type VerifiedProvisioningProjection,
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
