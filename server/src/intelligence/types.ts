/**
 * Sanctuary MCP Server — Intelligence Substrate Selector Types
 *
 * The substrate selector lets operators pick (and re-pick) the LLM substrate
 * that powers Sanctuary's intelligence-layer surfaces: concierge, sentinel
 * scoring, gate explanation, privacy filter Tier 2, template suggestion,
 * direct-agent gate advisory.
 *
 * Per Erik directive 2026-04-29: the selector IS the architecture. Sanctuary's
 * job is to make the tradeoffs visible and let the operator choose. Multi-option
 * framing is preserved; no single substrate is surfaced as a winner.
 *
 * Per the position paper Intelligence_Layer_Drift_Audit_and_Substrate_Resolution_2026-04-29.md
 * (sections 4 + 5), four substrates ship as operator-pickable:
 *
 *   - local:                  Ollama-hosted local model (Gemma 2 2B / Phi-4 Mini / Llama 3.1 8B)
 *   - venice:                 Venice.ai privacy-respecting hosted relay
 *   - frontier-with-filter:   operator's frontier API account, Privacy Filter Tier 2 pre-egress
 *   - hybrid:                 per-surface routing across the above
 *   - disabled:               surface refuses LLM calls; Tier 1 regex fallback for privacy filter
 *
 * Per-surface defaults (Erik ratification 2026-04-29):
 *   - concierge:                       local (Gemma 2 2B)
 *   - sentinel-scoring:                local (rules + Phi-4 Mini on escalation)
 *   - gate-explanation:                templates v1.2; small LLM v1.3+ for custom policies
 *   - privacy-filter-tier-2:           local (NER + small LLM PII classifier)
 *   - direct-agent-gate-advisor:       same as concierge by default
 *   - template-suggestion:             same as concierge by default
 */

/**
 * The set of intelligence-layer surfaces the selector routes for.
 *
 * The enum is closed. Adding a surface requires updating the selector's
 * default-config builder, the audit emission shape registry, and the
 * transparency UI in the same PR.
 */
export type Surface =
  | "concierge"
  | "direct-agent-gate-advisor"
  | "sentinel-scoring"
  | "gate-explanation"
  | "privacy-filter-tier-2"
  | "template-suggestion";

export const SURFACES: readonly Surface[] = [
  "concierge",
  "direct-agent-gate-advisor",
  "sentinel-scoring",
  "gate-explanation",
  "privacy-filter-tier-2",
  "template-suggestion",
] as const;

/**
 * The substrate choice an operator may bind to a surface.
 */
export type SubstrateChoice =
  | "local"
  | "venice"
  | "frontier-with-filter"
  | "hybrid"
  | "disabled";

export const SUBSTRATE_CHOICES: readonly SubstrateChoice[] = [
  "local",
  "venice",
  "frontier-with-filter",
  "hybrid",
  "disabled",
] as const;

/**
 * Local-model picks for the Ollama-backed local substrate.
 *
 * Bundled tiers per position paper §5 hardware-tier table:
 *   - gemma-2-2b   (Baseline / 8GB RAM)
 *   - phi-4-mini   (Mid / 16GB RAM)
 *   - llama-3.1-8b (Pro / 32GB+ RAM)
 *
 * Custom Ollama-installed models can be specified via `customModelTag` on the
 * substrate config; the selector probes Ollama for availability at runtime.
 */
export type LocalModelPick = "gemma-2-2b" | "phi-4-mini" | "llama-3.1-8b";

export const LOCAL_MODEL_TAGS: Record<LocalModelPick, string> = {
  "gemma-2-2b": "gemma2:2b",
  "phi-4-mini": "phi4-mini",
  "llama-3.1-8b": "llama3.1:8b",
};

/**
 * Frontier providers operator may pick for the frontier-with-filter substrate.
 * v1.2 ships three; v1.3+ may add Mistral / xAI / Cohere.
 */
export type FrontierProvider = "anthropic" | "openai" | "google";

export const FRONTIER_PROVIDERS: readonly FrontierProvider[] = [
  "anthropic",
  "openai",
  "google",
] as const;

/**
 * What the selector does when its chosen substrate fails (e.g. Ollama not
 * running, Venice API unreachable, frontier API key revoked).
 *
 * Per surface, operator-configurable. Defaults per position paper §5:
 *   - concierge:               degrade-silent (next-tier substrate)
 *   - sentinel-scoring:        conservative-deny (refuse rather than route elsewhere)
 *   - privacy-filter-tier-2:   degrade-silent (Tier 1 regex always works)
 *   - others:                  conservative-deny
 */
export type FallbackBehavior =
  | "conservative-deny"
  | "degrade-silent"
  | "disable-surface";

/**
 * Per-surface routing rules for the hybrid substrate.
 *
 * v1.2 ships per-surface routing only — operator pre-binds each surface to a
 * concrete substrate. Per-query sensitivity classification routing is deferred
 * to v1.3+.
 */
export interface HybridRoutingRules {
  perSurface: Record<Surface, Exclude<SubstrateChoice, "hybrid">>;
}

/**
 * Operator-readable status badge for the transparency UI and chat headers.
 *
 * Backends emit a stable shape (no free-form prose); the dashboard's template
 * registry renders it. This mirrors the v1.1 hub `HubDisplayTemplateArg`
 * discipline so secret-leakage into operator-facing copy stays structurally
 * impossible.
 */
export interface SubstrateBadge {
  surface: Surface;
  substrate: SubstrateChoice;
  /** Stable badge label key resolved by dashboard template registry. */
  labelKey: string;
  /** Stable tradeoff body key resolved by dashboard template registry. */
  tradeoffKey: string;
  /** Stable status; green = working; yellow = degraded; red = disabled / failing. */
  status: "green" | "yellow" | "red";
}

/**
 * Frontier provider configs. Operator's API key per provider is stored
 * encrypted; never leaves the fortress except as outbound HTTPS to the
 * provider after Privacy Filter Tier 2 redaction.
 */
export interface FrontierProviderConfig {
  /** Operator's per-provider API key (encrypted at rest). */
  anthropic?: string;
  openai?: string;
  google?: string;
}

/**
 * Operator-overridable substrate config. Persisted encrypted under the
 * fortress master key in storage namespace `_intelligence`.
 *
 * v1.0 of this shape (`version: 1`) is the only shape this PR ships. Future
 * v1.x extensions (per-query sensitivity classifier, MLX runtime pick,
 * per-patron substrate scoping) MUST bump this version and provide a
 * forward-compat migration in the selector.
 */
export interface SubstrateConfig {
  version: 1;
  /** Operator's per-surface choice. Defaults from position paper §5. */
  perSurface: Record<Surface, SubstrateChoice>;
  /** Operator's local-model picks per surface, when 'local' is chosen. */
  localModelPicks: Partial<Record<Surface, LocalModelPick>>;
  /** Custom Ollama model tag override per surface (overrides localModelPicks if set). */
  customLocalModelTags?: Partial<Record<Surface, string>>;
  /** Ollama HTTP endpoint; defaults to http://localhost:11434. */
  ollamaEndpoint?: string;
  /** Venice API key, if 'venice' chosen for any surface. Encrypted at rest. */
  veniceApiKey?: string;
  /** Venice model selection; defaults to llama-3.1-70b. */
  veniceModel?: string;
  /** Frontier provider configs, if 'frontier-with-filter' chosen. */
  frontierConfig: FrontierProviderConfig;
  /** Hybrid routing rules, if 'hybrid' chosen for any surface. */
  hybridRules?: HybridRoutingRules;
  /** Fallback behavior per surface. */
  fallback: Record<Surface, FallbackBehavior>;
  /** ISO8601 timestamp of last operator change. */
  updatedAt: string;
}

/**
 * Per-surface invocation request shape. Surfaces share the request envelope
 * but use only the methods on the handle they need; substrate clients
 * implement the full handle.
 */
export interface SubstrateInvocation {
  surface: Surface;
  /** Operator identity binding the request. */
  identityId: string;
  /** Free-form request body for the underlying client. The client interprets. */
  request: SummarizeRequest | ClassifyRequest | RedactRequest;
}

export interface SummarizeRequest {
  kind: "summarize";
  context: string;
  query: string;
  maxTokens?: number;
}

export interface ClassifyRequest {
  kind: "classify";
  items: string[];
  categories: string[];
  maxTokens?: number;
}

export interface RedactRequest {
  kind: "redact";
  text: string;
}

export type SubstrateRequest = SubstrateInvocation["request"];

/**
 * Per-substrate response envelope. Substrate clients return content + telemetry;
 * audit-emission and badge-rendering happen at the selector layer.
 */
export interface SubstrateResponse {
  /** The substrate that actually served this invocation (may differ from chosen if fallback fired). */
  servedBy: SubstrateChoice;
  /** Stable failure-class enum on failure; null on success. */
  failureClass: SubstrateFailureClass | null;
  /** Body shape varies by request kind. */
  body:
    | { kind: "summarize"; text: string }
    | { kind: "classify"; results: { category: string; confidence: number }[] }
    | { kind: "redact"; redacted: string; placeholders: Record<string, string> }
    | { kind: "failure"; message: string };
  /** ISO8601 of when invocation completed. */
  completedAt: string;
  /** Total wall-clock latency in ms. */
  latencyMs: number;
}

/**
 * Stable failure-class enum. Backends return one of these when a substrate
 * invocation fails; the selector's audit emission carries this verbatim.
 *
 * Adding a new failure class requires updating the audit-event consumer and
 * the dashboard status-mapping in the same PR.
 */
export type SubstrateFailureClass =
  | "substrate_unavailable"
  | "substrate_misconfigured"
  | "substrate_rate_limited"
  | "substrate_auth_failed"
  | "substrate_timeout"
  | "substrate_capability_unsupported"
  | "substrate_disabled"
  | "internal_error";

/**
 * Capability profile for each substrate. Surfaces consult this before
 * invoking; if the substrate cannot serve the request kind, the selector
 * applies the fallback policy.
 */
export interface SubstrateCapability {
  summarize: boolean;
  classify: boolean;
  redact: boolean;
}

/**
 * The handle a surface holds after `selector.getSubstrate(surface)`. The
 * surface invokes via the typed methods; the substrate client implements them.
 *
 * Surfaces MUST treat any thrown error as a `substrate_unavailable` failure;
 * the selector's invoke wrapper catches and emits the audit event.
 */
export interface SubstrateHandle {
  surface: Surface;
  substrate: SubstrateChoice;
  badge: SubstrateBadge;
  capability: SubstrateCapability;
  /**
   * Optional operator-readable display string for the chat / dashboard headers.
   * Resolved from the badge labelKey; produced by the selector at handle issue,
   * not by the substrate client.
   */
  displayLabel: string;
  summarize?: (req: SummarizeRequest) => Promise<SubstrateResponse>;
  classify?: (req: ClassifyRequest) => Promise<SubstrateResponse>;
  redact?: (req: RedactRequest) => Promise<SubstrateResponse>;
}

/**
 * Operator-visible per-surface status report rendered by the transparency UI.
 *
 * The dashboard SPA consumes this via the `/api/hub/intelligence/status`
 * route; the picker modal consumes it before substrate selection to surface
 * hardware-capability hints.
 */
export interface SubstrateStatusReport {
  version: "1.2";
  generatedAt: string;
  surfaces: SurfaceStatus[];
  hardware: HardwareCapabilityReport;
}

export interface SurfaceStatus {
  surface: Surface;
  chosen: SubstrateChoice;
  badge: SubstrateBadge;
  /** Substrate-side health probe result. */
  health: "ok" | "degraded" | "unavailable";
  /** Stable failure class when health != "ok"; null when "ok". */
  failureClass: SubstrateFailureClass | null;
}

export interface HardwareCapabilityReport {
  /** Detected total RAM in GB. Self-reported via os.totalmem(). */
  totalRamGb: number;
  /** Apple Silicon family if detectable, or "other". */
  cpuArch: "apple-silicon-m1" | "apple-silicon-m2" | "apple-silicon-m3" | "apple-silicon-m4" | "apple-silicon-other" | "x86_64" | "other";
  /** Computed tier per position paper §5 (baseline / mid / pro / below-baseline). */
  tier: "below-baseline" | "baseline" | "mid" | "pro";
  /** Recommended local model tier per detected hardware. */
  recommendedLocalModel: LocalModelPick | null;
  /** Whether Ollama is reachable at the configured endpoint. */
  ollamaReachable: boolean;
  /** Models present in Ollama at the time of the report. Empty if not reachable. */
  ollamaModels: string[];
}

/**
 * Audit-event details payloads. Stable shapes per the operator hub event
 * contract discipline (typed, no free-form text).
 */
export interface IntelligenceSubstrateChosenDetails {
  surface: Surface;
  substrate: SubstrateChoice;
  /** Hash of the operator-readable tradeoff text the operator saw at choice time. */
  tradeoffTextHash: string;
  /** Whether the operator overrode a default vs. accepted the default. */
  wasDefault: boolean;
}

export interface IntelligenceSubstrateInvokedDetails {
  surface: Surface;
  substrate: SubstrateChoice;
  servedBy: SubstrateChoice;
  /** Hash of the request body, never the body itself. */
  requestHash: string;
  /** Hash of the response body, never the body itself. */
  responseHash: string | null;
  latencyMs: number;
}

export interface IntelligenceSubstrateFailureDetails {
  surface: Surface;
  substrate: SubstrateChoice;
  failureClass: SubstrateFailureClass;
  /** Operator-action taken: which fallback fired, or which surface was disabled. */
  fallbackTaken: "next-substrate" | "deny" | "disable-surface";
}

export interface IntelligencePiiRedactionEventDetails {
  surface: Surface;
  /** Substrate the redaction was performed for (always pre-egress). */
  substrate: SubstrateChoice;
  /** Number of PII matches found. */
  matchCount: number;
  /** Filter tier that produced the result; tier 1 = regex, tier 2 = NER + LLM classifier. */
  filterTier: 1 | 2;
}
