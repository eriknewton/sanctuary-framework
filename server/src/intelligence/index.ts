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
  MODEL_MANIFEST_DOMAIN,
  MODEL_MANIFEST_TIERS,
  PINNED_MODEL_MANIFEST_SIGNING_PUBLIC_KEY_B64URL,
  buildModelManifestMessage,
  loadPinnedModelManifestKey,
  provenanceFromModelManifestModel,
  resolveModelForSurface,
  verifyModelManifest,
  verifyModelManifestWithKey,
  type ModelManifestBody,
  type ModelManifestModel,
  type ModelManifestRefusalReason,
  type ModelManifestSurfaceDefaults,
  type ModelManifestTier,
  type ModelManifestTierBundle,
  type ModelManifestVerificationOptions,
  type ModelManifestVerificationResult,
  type ModelRuntime,
  type SignedModelManifest,
} from "./model-manifest.js";

export {
  buildLocalProvisioningPlan,
  type BuildLocalProvisioningPlanParams,
  type LocalProvisioningBlockReason,
  type LocalProvisioningModelPlan,
  type LocalProvisioningModelStatus,
  type LocalProvisioningPlan,
  type LocalProvisioningPlanStatus,
  type LocalProvisioningSurfaceBinding,
} from "./local-provisioning-plan.js";

export {
  buildLocalProvisioningReceipt,
  type BuildLocalProvisioningReceiptParams,
  type LocalProvisioningDeclaredModel,
  type LocalProvisioningReceipt,
  type LocalProvisioningReceiptRefusalReason,
  type LocalProvisioningReceiptStatus,
  type LocalProvisioningRefusedModel,
} from "./local-provisioning-receipt.js";

export {
  applyLocalProvisioningReceiptToStore,
  type ApplyLocalProvisioningReceiptToStoreParams,
  type ApplyLocalProvisioningReceiptToStoreResult,
  type LocalProvisioningStoreApplyRefusalReason,
  type LocalProvisioningStoreApplyStatus,
} from "./local-provisioning-store.js";

export {
  buildLocalProvisioningActionPreview,
  type LocalProvisioningAction,
  type LocalProvisioningActionKind,
  type LocalProvisioningActionPreview,
  type LocalProvisioningActionPreviewStatus,
  type LocalProvisioningActionReason,
} from "./local-provisioning-actions.js";

export {
  buildLocalProvisioningModelPullAuditPayload,
  buildLocalProvisioningRefusalAuditPayload,
  type BuildLocalProvisioningModelPullAuditPayloadParams,
  type BuildLocalProvisioningRefusalAuditPayloadParams,
  type LocalProvisioningAuditOperation,
  type LocalProvisioningAuditPayloadBuildError,
  type LocalProvisioningAuditPayloadBuildResult,
} from "./local-provisioning-audit.js";

export {
  buildLocalProvisioningConsentPacket,
  type LocalProvisioningConsentAction,
  type LocalProvisioningConsentPacket,
  type LocalProvisioningConsentPacketStatus,
  type LocalProvisioningConsentScope,
} from "./local-provisioning-consent.js";

export {
  buildLocalProvisioningDegradedSurfaceStatuses,
  type BuildLocalProvisioningDegradedSurfaceStatusesOptions,
} from "./local-provisioning-status.js";

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
  type OllamaModelDigestReport,
  type OllamaPullResult,
} from "./substrates/local.js";

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
  IntelligenceLocalModelRuntime,
  IntelligenceModelProvisionRefusalReason,
  IntelligenceModelProvisionRefusedPayload,
  IntelligenceModelPullPayload,
  IntelligencePiiRedactionEventPayload,
  IntelligenceSubstrateChosenPayload,
  IntelligenceSubstrateFailurePayload,
  IntelligenceSubstrateInvokedPayload,
} from "../contracts/v1.2/intelligence-events.js";
