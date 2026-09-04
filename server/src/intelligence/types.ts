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

import type { LocalIntegrityStateV2 } from "./model-manifest-v2.js";
import type { Surface } from "./surfaces.js";

export { SURFACES, type Surface } from "./surfaces.js";

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
 * Ratified posture (Erik, 2026-07-23): the `privacy-filter-tier-2`
 * surface is PINNED local-only. This surface is the internal plumbing
 * of a privacy feature (Tier B PII rewrite LLM-assist + smart-mode
 * intent classification): text still bearing PII residuals flows
 * through it, so binding it to a remote substrate would turn the
 * privacy filter itself into an egress channel. Same prohibition on
 * silent relaxation as everywhere else in the codebase; there is NO
 * override flag.
 *
 * Enforced at two layers:
 *   1. Config-write: `setPerSurfaceChoice` refuses a non-local binding
 *      for this surface (`Tier2BindingPinnedError`), and
 *      `applyChoiceToAllSurfaces` skips it (reported, not fatal).
 *   2. Invoke-time: the selector resolves this surface to `local`
 *      regardless of what a persisted (pre-existing or tampered)
 *      config says, with a one-time per-process
 *      `query_anonymity_tier2_binding_pinned` audit event.
 *
 * `disabled` stays allowed: the pin means never-remote, not must-LLM.
 * With no local substrate the Rho-2 caller degrades to regex-only.
 */
export const TIER2_PINNED_SURFACE: Surface = "privacy-filter-tier-2";

/** The only substrate choices the pinned surface may bind to. */
export const TIER2_PIN_ALLOWED_CHOICES: readonly SubstrateChoice[] = [
  "local",
  "disabled",
] as const;

/**
 * Whether binding `substrate` to `surface` violates the tier-2 local
 * pin. THE single predicate for the ratified posture; the config-write
 * gate, the fan-out skip, and the invoke-time chokepoint all call this
 * so the pin can never be half-enforced.
 */
export function isTier2PinViolation(
  surface: Surface,
  substrate: SubstrateChoice,
): boolean {
  return (
    surface === TIER2_PINNED_SURFACE &&
    !TIER2_PIN_ALLOWED_CHOICES.includes(substrate)
  );
}

/**
 * Raised when a config write asks to bind the pinned
 * `privacy-filter-tier-2` surface to a non-local substrate. The
 * message names the ratified posture so the refusal is actionable.
 */
export class Tier2BindingPinnedError extends Error {
  readonly code = "tier2_pinned_local" as const;
  constructor(substrate: SubstrateChoice) {
    super(
      "The privacy-filter-tier-2 surface is pinned local-only (ratified " +
        "posture 2026-07-23) and cannot be bound to " +
        substrate +
        ": a privacy feature's internal plumbing must not be " +
        "configurable into an egress channel. Allowed choices for this " +
        "surface: " +
        TIER2_PIN_ALLOWED_CHOICES.join(", ") +
        ".",
    );
    this.name = "Tier2BindingPinnedError";
  }
}

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
 * Version 1 is legacy-unarmed. Q5D creates version 2 only as part of the
 * injected signed-V2 provisioning commit, so ordinary production loads do
 * not silently arm or migrate legacy fortresses without a live catalog.
 */
interface SubstrateConfigFields {
  /** Operator's per-surface choice. Defaults from position paper §5. */
  perSurface: Record<Surface, SubstrateChoice>;
  /** Operator's local-model picks per surface, when 'local' is chosen. */
  localModelPicks: Partial<Record<Surface, LocalModelPick>>;
  /** Custom Ollama model tag override per surface (overrides localModelPicks if set). */
  customLocalModelTags?: Partial<Record<Surface, string>>;
  /**
   * Durable provisioning refusals surfaced through the existing bounded
   * `RecentFailureEntry` status shape. No request/model content is retained.
   */
  provisioningFailures?: Partial<Record<Surface, RecentFailureEntry[]>>;
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
  /**
   * Operator preference for the picker modal: when true, picking a
   * substrate + key for any one surface fans out to every surface in one
   * save (Finding SS, v1.2.0-rc.1). Defaults to true; operators wanting
   * per-surface granularity flip the picker toggle off and the next
   * single-surface choice persists this back to false.
   */
  applyToAllSurfaces?: boolean;
  /** ISO8601 timestamp of last operator change. */
  updatedAt: string;
}

export interface SubstrateConfigV1 extends SubstrateConfigFields {
  version: 1;
  /** A V1 config is unarmed by construction; V1 can never carry Q5 authority. */
  localIntegrityState?: never;
}

export interface SubstrateConfigV2 extends SubstrateConfigFields {
  version: 2;
  /** The complete Q5 record is mandatory so a stripped V2 cannot read as legacy. */
  localIntegrityState: LocalIntegrityStateV2;
}

export type SubstrateConfig = SubstrateConfigV1 | SubstrateConfigV2;

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
  /**
   * Declares that `context` holds ONLY bytes this runtime assembled itself:
   * its own prompt template plus this fortress's own local records. The
   * compiled-context scanner uses it to size that contributor by trust class
   * instead of counting a locally compiled fortress briefing against the
   * untrusted prompt-stuffing budget.
   *
   * INVARIANT: a caller may set this only when it can prove every byte of
   * `context`; the moment raw agent- or operator-authored payload text is
   * embedded, the field must be omitted. `query` is never covered by it, and
   * omitting it is always the safe choice, because absent reads as untrusted.
   * It exempts nothing but the stuffing size heuristic: injection, evasion,
   * exfiltration and the hard byte ceiling still apply to `context`.
   */
  contextProvenance?: "first_party_runtime";
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
  /**
   * Compiled-context screening refused the assembled artifact before any
   * substrate was selected. Distinct from `internal_error` because the two
   * demand opposite operator responses: this one means the prompt was held
   * back on purpose and nothing is wrong with the provider, so an operator
   * who cannot tell them apart goes looking for an outage that is not there.
   */
  | "substrate_context_refused"
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
  /**
   * Recent runtime + validation failures for this surface, capped at 5
   * entries and time-windowed to 24 hours. Sourced from real chat-call
   * outcomes (and validateKey results for substrates that expose it),
   * NOT from the static probe-time misconfig check.
   *
   * Per Finding VV (v1.2.0-rc.1): the operator-visible badge degrades to
   * "yellow" / "degraded" whenever this array is non-empty even if the
   * static probe still says ok. This closes the truth-telling gap where
   * the dashboard reported all surfaces healthy after the runtime chat
   * had already failed against the same substrate.
   */
  recentFailures: RecentFailureEntry[];
}

/**
 * One observed substrate failure surfaced via `/api/hub/intelligence/status`.
 * Carries enough metadata for the operator to triage (when, what failure
 * class, brief operator-safe snippet) without leaking request bodies,
 * response bodies, or operator credentials.
 *
 * Snippets are bounded human-readable strings (e.g. "venice configured
 * model not found") drawn from the substrate failure-message field; the
 * selector strips anything resembling an API key or PII before retention.
 * Operators wanting full forensic detail consult the L2 audit log; this
 * surface is the at-a-glance triage path.
 */
export interface RecentFailureEntry {
  /** ISO8601 timestamp of when the failure was observed. */
  ts: string;
  /** Stable failure-class enum carried verbatim from the substrate response. */
  failureClass: SubstrateFailureClass;
  /** Bounded operator-safe snippet describing the failure. */
  snippet: string;
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
  /** Operator-action taken: which fallback fired, or why no fallback served. */
  fallbackTaken: "next-substrate" | "primary-failed" | "all-exhausted" | "deny" | "disable-surface";
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
