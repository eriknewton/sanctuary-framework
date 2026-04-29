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
} from "./types.js";

export {
  LocalSubstrate,
  OllamaClient,
  LOCAL_CAPABILITY,
  type OllamaClientConfig,
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
  IntelligencePiiRedactionEventPayload,
  IntelligenceSubstrateChosenPayload,
  IntelligenceSubstrateFailurePayload,
  IntelligenceSubstrateInvokedPayload,
} from "../contracts/v1.2/intelligence-events.js";
