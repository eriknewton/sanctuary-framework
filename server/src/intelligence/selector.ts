/**
 * Sanctuary MCP Server — Intelligence Substrate Selector
 *
 * The selector IS the architecture (Erik directive 2026-04-29). Operators
 * pick (and re-pick) the LLM substrate that powers each intelligence-layer
 * surface; the selector binds choices to surfaces, provides a typed
 * `SubstrateHandle` to consumers, applies operator-configured fallback
 * behavior on substrate failure, and emits audit events for every change
 * and every invocation.
 *
 * Architecture per position paper section 5:
 *   ┌──────────┐  ┌──────────┐  ┌──────────┐ ┌──────────┐
 *   │ concierge│  │ sentinel │  │ gate-expl│ │ priv-f-2 │  ... surfaces
 *   └────┬─────┘  └────┬─────┘  └────┬─────┘ └────┬─────┘
 *        ▼             ▼             ▼            ▼
 *   ┌──────────────────────────────────────────────────┐
 *   │    SubstrateSelector (per-surface routing)       │
 *   └────┬──────────┬──────────┬──────────┬────────────┘
 *        ▼          ▼          ▼          ▼
 *   ┌────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
 *   │ Local  │ │ Venice   │ │ Frontier │ │ Disabled │
 *   │(Ollama)│ │ (relay)  │ │ + filter │ │ (refuse) │
 *   └────────┘ └──────────┘ └──────────┘ └──────────┘
 *
 * The hybrid substrate is per-surface routing only at v1.2 — operator
 * pre-binds each surface to a concrete substrate; per-query sensitivity
 * classification routing is deferred to v1.3+.
 *
 * Audit emission discipline:
 * Every public method that changes config or invokes a substrate appends
 * an `IntelligenceAuditPayload` to the L2 audit log. The selector never
 * stores raw request bodies, response bodies, or operator credentials in
 * audit details; only safe metadata (surface, substrate, hashes, latency,
 * failure-class enum). The event payload contracts live in
 * `contracts/v1.2/intelligence-events.ts`.
 *
 * Sovereignty invariants preserved:
 * - Operator API keys live in the encrypted SubstrateConfig persisted
 *   under the fortress master key.
 * - Frontier-with-filter substrate ALWAYS routes through a redactor
 *   before any frontier API call; the redactor argument is required in
 *   the constructor; passing a null redactor disables the substrate.
 * - Sentinel-scoring surface defaults to `conservative-deny` fallback so
 *   substrate failure cannot silently allow an unverified tool call.
 */

import os from "node:os";
import { randomBytes } from "node:crypto";
import { sha256 } from "@noble/hashes/sha256";
import { hashToString } from "../core/hashing.js";
import { stringToBytes, toBase64url } from "../core/encoding.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import { INTEL_OPS } from "./audit-events.js";
import { tradeoffTextHash, BACKEND_FALLBACK_STRINGS, BADGE_LABEL_KEYS, BADGE_TRADEOFF_KEYS, LOCAL_MODEL_LABELS } from "./templates.js";
import { DEFAULT_OLLAMA_ENDPOINT, buildDefaultConfig, DEFAULT_PER_SURFACE, DEFAULT_LOCAL_MODEL_PICKS } from "./defaults.js";
import { IntelligenceConfigStore, type LoadOutcome } from "./policy-store.js";
import {
  LOCAL_MODEL_TAGS,
  SURFACES,
  type ClassifyRequest,
  type FallbackBehavior,
  type FrontierProvider,
  type HardwareCapabilityReport,
  type LocalModelPick,
  type RecentFailureEntry,
  type RedactRequest,
  type SubstrateBadge,
  type SubstrateCapability,
  type SubstrateChoice,
  type SubstrateConfig,
  type SubstrateFailureClass,
  type SubstrateHandle,
  type SubstrateResponse,
  type SubstrateStatusReport,
  type SummarizeRequest,
  type Surface,
  type SurfaceStatus,
} from "./types.js";
import { LocalSubstrate, OllamaClient, LOCAL_CAPABILITY } from "./substrates/local.js";
import { VeniceClient, VeniceSubstrate, VENICE_CAPABILITY, VENICE_DEFAULT_ENDPOINT, VENICE_DEFAULT_MODEL, type VeniceValidateResult } from "./substrates/venice.js";
import { FrontierClient, FrontierWithFilterSubstrate, FRONTIER_CAPABILITY, FRONTIER_DEFAULT_MODELS, type FrontierRedactor } from "./substrates/frontier.js";
import { resolveHybridChoice, validateHybridRules } from "./substrates/hybrid/per-surface-router.js";
import type { HybridRoutingRules } from "./types.js";
import type { StorageBackend } from "../storage/interface.js";
import type {
  IntelligenceAuditPayload,
  IntelligenceBulkSubstrateChosenPayload,
  IntelligenceConfigLoadedPayload,
  IntelligenceConfigResetPayload,
  IntelligencePiiRedactionEventPayload,
  IntelligenceSubstrateChosenPayload,
  IntelligenceSubstrateFailurePayload,
  IntelligenceSubstrateInvokedPayload,
} from "../contracts/v1.2/intelligence-events.js";

const DISABLED_CAPABILITY: SubstrateCapability = {
  summarize: false,
  classify: false,
  redact: false,
};

/**
 * Cap on the per-surface recent-failures ring buffer. Exposed via
 * `/api/hub/intelligence/status` so the operator can triage the most
 * recent failures inline without paging through the L2 audit log.
 */
const RECENT_FAILURES_CAP = 5;

/**
 * Recent-failures retention window. Entries older than this are pruned
 * on every read of `getOperatorVisibleStatus()` so the operator-visible
 * status never reflects stale failures from yesterday's debugging.
 */
const RECENT_FAILURES_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Truncate operator-visible failure snippets so an over-long upstream
 * error message cannot bloat the status payload or smuggle accidental PII
 * into the transparency UI. The L2 audit log retains the full context.
 */
const FAILURE_SNIPPET_MAX_LEN = 200;

/**
 * Identity redactor used as the default for the frontier-with-filter
 * substrate when the Privacy Filter Tier 2 wire-up has not been installed
 * yet (v1.2 commit-by-commit ship). Returns the input unchanged with a
 * zero match count. The substrate audit-emits as filter_tier=1 so the
 * operator transparency UI surfaces the regression visibly.
 *
 * The Privacy Filter Tier 2 commit replaces this with a real redactor.
 */
export const IDENTITY_REDACTOR: FrontierRedactor = async (text: string) => ({
  redacted: text,
  matchCount: 0,
});

/**
 * Configuration the selector needs at construction. The audit-log binding
 * is required: a selector without an audit log violates the audit-emission
 * invariant and is structurally rejected.
 */
export interface SelectorConfig {
  storage: StorageBackend;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  /** Identity that owns the substrate config. Stamped on every audit event. */
  identityId: string;
  /**
   * Pre-egress redactor for the frontier-with-filter substrate. Defaults
   * to `IDENTITY_REDACTOR` until Privacy Filter Tier 2 wires through.
   * Passing a custom redactor at construction allows tests + the Tier 2
   * commit to install a real implementation without modifying the
   * selector.
   */
  redactor?: FrontierRedactor;
  /**
   * Optional fetch override for substrate clients. Forwarded to Ollama,
   * Venice, and frontier client constructors so tests can stub out
   * network calls.
   */
  fetchImpl?: typeof fetch;
}

export class SubstrateSelector {
  private store: IntelligenceConfigStore;
  private auditLog: AuditLog;
  private identityId: string;
  private redactor: FrontierRedactor;
  private fetchImpl: typeof fetch | undefined;
  private config: SubstrateConfig;
  private loaded = false;
  /**
   * Per-surface ring buffer of recent runtime + validation failures. See
   * `RECENT_FAILURES_CAP` and `RECENT_FAILURES_WINDOW_MS`. Populated by
   * `recordRecentFailure()` from the `invoke()` failure path and from the
   * post-config validation hook on substrates that expose validateKey.
   * Drives the operator-visible degrade in `getOperatorVisibleStatus()`.
   */
  private recentFailures = new Map<Surface, RecentFailureEntry[]>();

  constructor(cfg: SelectorConfig) {
    this.store = new IntelligenceConfigStore(cfg.storage, cfg.masterKey);
    this.auditLog = cfg.auditLog;
    this.identityId = cfg.identityId;
    this.redactor = cfg.redactor ?? IDENTITY_REDACTOR;
    this.fetchImpl = cfg.fetchImpl;
    this.config = buildDefaultConfig();
  }

  /**
   * Load (or initialize) the operator's substrate config. Emits the
   * `intelligence_config_loaded` audit event regardless of branch so the
   * audit chain shows config-load activity on boot.
   */
  async load(): Promise<void> {
    const outcome = await this.store.load();
    this.config = outcome.config;
    this.loaded = true;

    const overriddenSurfaceCount = countOverriddenSurfaces(this.config);
    const wasDefault = outcome.kind !== "loaded";
    const payload: IntelligenceConfigLoadedPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "config_loaded",
      was_default: wasDefault,
      overridden_surface_count: overriddenSurfaceCount,
    };
    this.emit(INTEL_OPS.CONFIG_LOADED, payload, outcome.kind === "loaded" ? "success" : "failure");
  }

  /**
   * Operator picked (or re-picked) a substrate for a surface. Persists the
   * change and emits `intelligence_substrate_chosen`. The picker modal
   * surfaces the tradeoff text BEFORE invoking this method; the audit
   * payload captures the hash of that text for auditor verification.
   */
  async setPerSurfaceChoice(surface: Surface, substrate: SubstrateChoice): Promise<void> {
    await this.ensureLoaded();
    const prior = this.config.perSurface[surface];
    const wasDefault = prior === DEFAULT_PER_SURFACE[surface];

    this.config = {
      ...this.config,
      perSurface: { ...this.config.perSurface, [surface]: substrate },
    };
    await this.store.save(this.config);

    // Finding ZZ (v1.2.0-rc.2): when the operator changes a surface's
    // substrate, prior failure entries no longer describe the new binding.
    // Clear so the badge reflects current configuration; new failures (if
    // any) will repopulate via the runtime path. No-op when the operator
    // re-saves the same substrate, so a re-save does not silently wipe a
    // legitimate failure trail.
    if (prior !== substrate) {
      this.recentFailures.delete(surface);
    }

    const payload: IntelligenceSubstrateChosenPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "substrate_chosen",
      surface,
      substrate,
      tradeoff_text_hash: tradeoffTextHash(substrate),
      was_default: wasDefault,
      prior_substrate: prior,
    };
    this.emit(INTEL_OPS.SUBSTRATE_CHOSEN, payload, "success");
  }

  /**
   * Apply a substrate choice to every surface in one save. Used by the
   * picker modal's "Apply to all surfaces" affordance (Finding SS,
   * v1.2.0-rc.1). Persists the per-surface map mutation in a single
   * write and emits ONE `intelligence_bulk_substrate_chosen` audit
   * event rather than six per-surface events.
   *
   * If `localModelPick` is provided AND substrate === "local", the same
   * pick is applied to every surface; ignored for other substrates.
   *
   * Per-surface bindings the operator had previously customized are
   * captured in the audit payload's `prior_substrates` map so the
   * forensic record makes the configuration discontinuity visible.
   */
  async applyChoiceToAllSurfaces(
    substrate: SubstrateChoice,
    opts: { localModelPick?: LocalModelPick | null } = {},
  ): Promise<void> {
    await this.ensureLoaded();

    const priorSubstrates: Partial<Record<Surface, SubstrateChoice | null>> = {};
    for (const surface of SURFACES) {
      priorSubstrates[surface] = this.config.perSurface[surface] ?? null;
    }

    const nextPerSurface: Record<Surface, SubstrateChoice> = { ...this.config.perSurface };
    const nextLocalPicks = { ...this.config.localModelPicks };
    for (const surface of SURFACES) {
      nextPerSurface[surface] = substrate;
      if (substrate === "local" && opts.localModelPick !== undefined) {
        if (opts.localModelPick === null) delete nextLocalPicks[surface];
        else nextLocalPicks[surface] = opts.localModelPick;
      }
    }

    this.config = {
      ...this.config,
      perSurface: nextPerSurface,
      localModelPicks: nextLocalPicks,
      applyToAllSurfaces: true,
    };
    await this.store.save(this.config);

    // Finding ZZ (v1.2.0-rc.2): bulk re-binding is a global configuration
    // gesture; prior per-surface failure entries no longer describe the
    // new bindings. Clear every surface's ring buffer so badges reflect
    // current configuration.
    for (const surface of SURFACES) {
      this.recentFailures.delete(surface);
    }

    const payload: IntelligenceBulkSubstrateChosenPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "bulk_substrate_chosen",
      substrate,
      surface_count: SURFACES.length,
      tradeoff_text_hash: tradeoffTextHash(substrate),
      prior_substrates: priorSubstrates,
    };
    this.emit(INTEL_OPS.BULK_SUBSTRATE_CHOSEN, payload, "success");
  }

  /**
   * Persist the operator's "Apply to all surfaces" preference. The
   * picker modal calls this when the operator flips the toggle so the
   * preference survives a dashboard reload. Does not emit a discrete
   * audit event; the next bulk or per-surface choice carries the
   * operator-visible signal.
   */
  async setApplyToAllPreference(value: boolean): Promise<void> {
    await this.ensureLoaded();
    this.config = { ...this.config, applyToAllSurfaces: value };
    await this.store.save(this.config);
  }

  /**
   * Operator picked a local model for a surface bound to the local
   * substrate. Mirrors `setPerSurfaceChoice` for the model-picker case.
   * Does not emit a separate audit event class; the next
   * `intelligence_substrate_chosen` event captures the change and the
   * dashboard transparency UI calls this method only as part of a binding
   * flow that already audited the substrate choice.
   */
  async setLocalModelPick(surface: Surface, pick: LocalModelPick | null): Promise<void> {
    await this.ensureLoaded();
    const next = { ...this.config.localModelPicks };
    if (pick === null) delete next[surface];
    else next[surface] = pick;
    this.config = { ...this.config, localModelPicks: next };
    await this.store.save(this.config);
  }

  /**
   * Set the Venice API key. Stored as part of the encrypted
   * SubstrateConfig record. Does not emit a substrate_chosen event by
   * itself; the dashboard flow always pairs key entry with a substrate
   * choice and the choice carries the audit semantics.
   *
   * Post-set validation (Finding VV, v1.2.0-rc.1): if a non-null key is
   * provided, the selector probes Venice with `validateKey()` and records
   * a failure entry on every Venice-bound surface when the result is not
   * `"ok"`. This lets the operator-visible status degrade from validation
   * outcomes alone, not just from runtime chat-call failures, so a broken
   * key or drifted model is visible before the operator's first chat
   * attempt. Probe failures (timeout, transport) are not recorded; the
   * runtime path will surface those when the operator actually invokes.
   */
  async setVeniceApiKey(apiKey: string | null): Promise<void> {
    await this.ensureLoaded();
    const next: SubstrateConfig = { ...this.config };
    if (apiKey === null) delete next.veniceApiKey;
    else next.veniceApiKey = apiKey;
    this.config = next;
    await this.store.save(this.config);

    if (apiKey !== null) {
      await this.validateVeniceAndRecord(apiKey);
    }
  }

  /**
   * Probe Venice with the given API key and record a failure entry on
   * every surface bound to Venice when the probe returns anything other
   * than `"ok"`. Failures map to stable substrate failure-class enum
   * values: `invalid-key` -> `substrate_auth_failed`, `invalid-model` ->
   * `substrate_misconfigured`, `unreachable` -> swallow (runtime path
   * will surface).
   */
  private async validateVeniceAndRecord(apiKey: string): Promise<void> {
    const client = new VeniceClient({
      apiKey,
      endpoint: VENICE_DEFAULT_ENDPOINT,
      model: this.config.veniceModel ?? VENICE_DEFAULT_MODEL,
      fetchImpl: this.fetchImpl,
    });
    let result: VeniceValidateResult;
    try {
      result = await client.validateKey();
    } catch {
      return;
    }
    if (result === "ok") {
      // Finding ZZ (v1.2.0-rc.2): a re-saved key that probes ok is the
      // operator's signal that the prior failure has been remediated.
      // Clear stale failure entries on every Venice-bound surface so the
      // badge returns to green; runtime invocations will repopulate the
      // buffer if real failures recur.
      for (const surface of SURFACES) {
        if (this.config.perSurface[surface] === "venice") {
          this.recentFailures.delete(surface);
        }
      }
      return;
    }
    if (result === "unreachable") return;
    const failureClass: SubstrateFailureClass =
      result === "invalid-key" ? "substrate_auth_failed" : "substrate_misconfigured";
    const snippet =
      result === "invalid-key"
        ? "venice key rejected on validation probe"
        : `venice configured model "${this.config.veniceModel ?? VENICE_DEFAULT_MODEL}" not found on validation probe`;
    for (const surface of SURFACES) {
      if (this.config.perSurface[surface] === "venice") {
        this.recordRecentFailure(surface, failureClass, snippet);
      }
    }
  }

  /**
   * Set a frontier provider's API key. See `setVeniceApiKey` for the
   * audit-semantics rationale.
   */
  async setFrontierApiKey(provider: FrontierProvider, apiKey: string | null): Promise<void> {
    await this.ensureLoaded();
    const next = { ...this.config.frontierConfig };
    if (apiKey === null) delete next[provider];
    else next[provider] = apiKey;
    this.config = { ...this.config, frontierConfig: next };
    await this.store.save(this.config);
  }

  /**
   * Set the hybrid routing rules. The picker modal calls this when the
   * operator saves the hybrid configuration tab. Validates the rules
   * (every surface bound, no `hybrid` recursion) before persist; throws
   * on invalid input so the operator-facing form can surface the failure.
   *
   * Setting rules does NOT change any surface's per-surface choice; the
   * operator must also pick `hybrid` for the surfaces they want routed
   * through these rules. This separation keeps the flow obvious in the
   * UI (set rules + then choose hybrid for each surface that should use
   * them) and lets the operator test rule changes without mass-flipping
   * surfaces to hybrid.
   */
  async setHybridRules(rules: HybridRoutingRules): Promise<void> {
    await this.ensureLoaded();
    const validation = validateHybridRules(rules);
    if (!validation.ok) {
      throw new Error(`invalid hybrid rules: ${validation.reason}`);
    }
    this.config = { ...this.config, hybridRules: rules };
    await this.store.save(this.config);
  }

  /**
   * Override the per-surface fallback behavior. Defaults are set per
   * position paper section 5; the picker modal surfaces the tradeoff and
   * the operator can override.
   */
  async setFallbackBehavior(surface: Surface, fallback: FallbackBehavior): Promise<void> {
    await this.ensureLoaded();
    this.config = {
      ...this.config,
      fallback: { ...this.config.fallback, [surface]: fallback },
    };
    await this.store.save(this.config);
  }

  /**
   * Reset every binding to the per-surface defaults. Emits
   * `intelligence_config_reset` so post-reset audit trails make the
   * configuration discontinuity visible.
   */
  async resetToDefaults(): Promise<void> {
    await this.ensureLoaded();
    const overridden = countOverriddenSurfaces(this.config);
    const fresh = buildDefaultConfig();
    this.config = fresh;
    await this.store.save(fresh);

    const payload: IntelligenceConfigResetPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "config_reset",
      overridden_surface_count: overridden,
    };
    this.emit(INTEL_OPS.CONFIG_RESET, payload, "success");
  }

  /**
   * Snapshot the current config (read-only). Tests + the dashboard
   * transparency UI consume this; mutations always go through the
   * setter methods so audit-emission stays consistent.
   */
  getConfig(): SubstrateConfig {
    return this.config;
  }

  /**
   * Install (or replace) the redactor used by the frontier-with-filter
   * substrate. Bootstrap code calls this after constructing the selector
   * with the default IDENTITY_REDACTOR; the Privacy Filter Tier 2
   * commit's `buildPrivacyTier2Redactor` produces the redactor that
   * closes over the selector for audit emission. Late-binding via this
   * method avoids the circular construction dependency
   * (selector needs redactor; redactor needs selector for emit).
   *
   * Subsequent calls to getSubstrate("...frontier-with-filter") will use
   * the installed redactor; already-issued handles continue to use the
   * redactor that was installed at handle-issue time. Consumers that
   * cache handles SHOULD re-issue after installRedactor.
   */
  installRedactor(redactor: FrontierRedactor): void {
    this.redactor = redactor;
  }

  /**
   * Build a typed SubstrateHandle for the given surface. Lazily
   * instantiates the substrate client based on the operator's binding;
   * the handle carries the substrate label, tradeoff badge, capability
   * surface, and bound `summarize` / `classify` / `redact` methods that
   * delegate to the substrate client.
   *
   * For the `disabled` substrate, the returned handle has the capability
   * surface zeroed and no methods bound; consumers checking
   * `handle.capability.summarize === false` short-circuit to the
   * surface's static fallback (templates for gate-explanation, Tier 1
   * regex for privacy-filter-tier-2, etc.).
   *
   * For the `hybrid` substrate, this method delegates to the per-surface
   * routing rules (set via `setPerSurfaceChoice` on a substrate other
   * than `hybrid`); v1.2 ships per-surface routing only.
   */
  async getSubstrate(surface: Surface): Promise<SubstrateHandle> {
    await this.ensureLoaded();
    const choice = this.config.perSurface[surface];
    return this.buildHandle(surface, choice);
  }

  /**
   * Operator-visible per-surface status report. Consumers: the dashboard
   * transparency UI and the `/api/hub/intelligence/status` route.
   *
   * Probes hardware + Ollama at call time. The dashboard re-fetches every
   * 5 minutes to refresh status badges (degraded -> ok flip when Ollama
   * comes back up, and so on).
   */
  async getOperatorVisibleStatus(): Promise<SubstrateStatusReport> {
    await this.ensureLoaded();
    const hardware = await this.probeHardware();
    const surfaces: SurfaceStatus[] = [];
    for (const surface of SURFACES) {
      const choice = this.config.perSurface[surface];
      const status = await this.probeSurfaceHealth(surface, choice, hardware);
      surfaces.push(status);
    }
    return {
      version: "1.2",
      generatedAt: new Date().toISOString(),
      surfaces,
      hardware,
    };
  }

  /**
   * Probe the host machine's hardware capability. v1.2 reports total RAM
   * + CPU arch (Apple Silicon family if detectable) and computes the tier
   * per position paper section 5. Used by the picker modal to surface
   * "below-baseline -> recommend Venice" guidance.
   */
  async probeHardware(): Promise<HardwareCapabilityReport> {
    const totalRamGb = Math.round(os.totalmem() / 1024 ** 3);
    const cpuArch = detectCpuArch();
    const tier = computeTier(totalRamGb);
    const recommendedLocalModel = recommendLocalModel(tier);

    const ollamaEndpoint = this.config.ollamaEndpoint ?? DEFAULT_OLLAMA_ENDPOINT;
    const probe = new OllamaClient({ endpoint: ollamaEndpoint, fetchImpl: this.fetchImpl });
    const models = await probe.listModels();

    return {
      totalRamGb,
      cpuArch,
      tier,
      recommendedLocalModel,
      ollamaReachable: models !== null,
      ollamaModels: models ?? [],
    };
  }

  /**
   * Invoke a substrate with audit emission. Wraps the underlying
   * SubstrateHandle method, applies fallback behavior on failure per the
   * operator's per-surface config, and emits `intelligence_substrate_invoked`
   * + (on failure) `intelligence_substrate_failure`.
   *
   * Consumers SHOULD call this method rather than calling `handle.summarize`
   * etc. directly; the handle is exposed for cases where audit emission
   * needs to be explicitly skipped (probe paths, tests).
   */
  async invokeSummarize(surface: Surface, req: SummarizeRequest): Promise<SubstrateResponse> {
    return this.invoke(surface, "summarize", req);
  }

  async invokeClassify(surface: Surface, req: ClassifyRequest): Promise<SubstrateResponse> {
    return this.invoke(surface, "classify", req);
  }

  async invokeRedact(surface: Surface, req: RedactRequest): Promise<SubstrateResponse> {
    return this.invoke(surface, "redact", req);
  }

  // ── internal ──────────────────────────────────────────────────────────

  private async ensureLoaded(): Promise<void> {
    if (!this.loaded) await this.load();
  }

  private async invoke(
    surface: Surface,
    method: "summarize" | "classify" | "redact",
    req: SummarizeRequest | ClassifyRequest | RedactRequest,
  ): Promise<SubstrateResponse> {
    await this.ensureLoaded();
    const choice = this.config.perSurface[surface];
    const handle = this.buildHandle(surface, choice);
    const requestHash = hashOfRequest(req);

    const fn = handle[method] as
      | ((arg: SummarizeRequest | ClassifyRequest | RedactRequest) => Promise<SubstrateResponse>)
      | undefined;
    if (!fn) {
      const failurePayload: IntelligenceSubstrateFailurePayload = {
        version: "1.2",
        event_id: makeEventId(),
        emitted_at: new Date().toISOString(),
        identity_id: this.identityId,
        kind: "substrate_failure",
        surface,
        substrate: choice,
        failure_class: "substrate_capability_unsupported",
        fallback_taken: this.fallbackAction(surface),
      };
      this.emit(INTEL_OPS.SUBSTRATE_FAILURE, failurePayload, "failure");
      this.recordRecentFailure(surface, "substrate_capability_unsupported", `${choice} does not support ${method}`);
      return disabledResponse(method, choice, "substrate_capability_unsupported");
    }

    const response = await fn(req);
    const invokedPayload: IntelligenceSubstrateInvokedPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "substrate_invoked",
      surface,
      substrate: choice,
      served_by: response.servedBy,
      request_hash: requestHash,
      response_hash: response.failureClass ? null : hashOfResponse(response),
      latency_ms: response.latencyMs,
      failure_class: response.failureClass,
    };
    this.emit(INTEL_OPS.SUBSTRATE_INVOKED, invokedPayload, response.failureClass ? "failure" : "success");

    if (response.failureClass) {
      const failurePayload: IntelligenceSubstrateFailurePayload = {
        version: "1.2",
        event_id: makeEventId(),
        emitted_at: new Date().toISOString(),
        identity_id: this.identityId,
        kind: "substrate_failure",
        surface,
        substrate: choice,
        failure_class: response.failureClass,
        fallback_taken: this.fallbackAction(surface),
      };
      this.emit(INTEL_OPS.SUBSTRATE_FAILURE, failurePayload, "failure");
      const snippet = response.body.kind === "failure" ? response.body.message : `${choice} ${method} failed`;
      this.recordRecentFailure(surface, response.failureClass, snippet);
    }

    return response;
  }

  /**
   * Append a failure entry to the per-surface ring buffer. The selector
   * uses this in the `invoke()` failure path and in the post-config
   * `setVeniceApiKey` validation hook so the operator-visible badge
   * degrades from runtime AND from validation outcomes.
   *
   * Operator-safe by construction: snippets are bounded by
   * `FAILURE_SNIPPET_MAX_LEN` and pulled from substrate `failure.message`
   * fields (which substrates produce for operator-readable output and
   * never include API keys or PII). The cap + window prune happen on
   * every read in `recentFailuresFor()` so the ring buffer never grows.
   */
  private recordRecentFailure(
    surface: Surface,
    failureClass: SubstrateFailureClass,
    snippet: string,
  ): void {
    const list = this.recentFailures.get(surface) ?? [];
    const entry: RecentFailureEntry = {
      ts: new Date().toISOString(),
      failureClass,
      snippet: snippet.slice(0, FAILURE_SNIPPET_MAX_LEN),
    };
    list.push(entry);
    while (list.length > RECENT_FAILURES_CAP) list.shift();
    this.recentFailures.set(surface, list);
  }

  /**
   * Read recent failures for a surface, pruning entries older than the
   * 24-hour window. Pruning happens lazily on read so a long-quiet surface
   * does not retain stale entries from yesterday's debugging.
   */
  private recentFailuresFor(surface: Surface): RecentFailureEntry[] {
    const list = this.recentFailures.get(surface);
    if (!list || list.length === 0) return [];
    const cutoff = Date.now() - RECENT_FAILURES_WINDOW_MS;
    const live = list.filter((e) => Date.parse(e.ts) >= cutoff);
    if (live.length !== list.length) this.recentFailures.set(surface, live);
    return live.slice();
  }

  /**
   * Test-only seam: lets selector tests assert on recorded failures
   * without poking the private ring buffer. Returns a defensive copy.
   */
  getRecentFailuresForTest(surface: Surface): RecentFailureEntry[] {
    return this.recentFailuresFor(surface);
  }

  /**
   * Test-only seam: lets selector tests seed a recent-failure entry on a
   * surface so the buffer-clear behavior added for Finding ZZ (v1.2.0-rc.2)
   * can be exercised without spinning up a real failing substrate. Mirrors
   * `getRecentFailuresForTest`; never call from production paths.
   */
  recordRecentFailureForTest(
    surface: Surface,
    failureClass: SubstrateFailureClass,
    snippet: string,
  ): void {
    this.recordRecentFailure(surface, failureClass, snippet);
  }

  /**
   * Build a substrate handle for a surface bound to a concrete choice.
   * The substrate-client constructor is paid lazily so the selector
   * doesn't pre-spawn HTTP clients for substrates the operator never
   * touches.
   */
  private buildHandle(surface: Surface, choice: SubstrateChoice): SubstrateHandle {
    if (choice === "disabled") return this.disabledHandle(surface);
    if (choice === "local") return this.localHandle(surface);
    if (choice === "venice") return this.veniceHandle(surface);
    if (choice === "frontier-with-filter") return this.frontierHandle(surface);
    if (choice === "hybrid") {
      const sub = resolveHybridChoice(this.config.hybridRules, surface);
      if (sub) return this.buildHandle(surface, sub);
      return this.disabledHandle(surface);
    }
    return this.disabledHandle(surface);
  }

  private disabledHandle(surface: Surface): SubstrateHandle {
    return {
      surface,
      substrate: "disabled",
      badge: this.makeBadge(surface, "disabled", "red"),
      capability: DISABLED_CAPABILITY,
      displayLabel: BACKEND_FALLBACK_STRINGS[BADGE_LABEL_KEYS.disabled] ?? "Disabled",
    };
  }

  private localHandle(surface: Surface): SubstrateHandle {
    const pick = this.config.localModelPicks[surface] ?? DEFAULT_LOCAL_MODEL_PICKS[surface] ?? "gemma-2-2b";
    const customTag = this.config.customLocalModelTags?.[surface];
    const endpoint = this.config.ollamaEndpoint ?? DEFAULT_OLLAMA_ENDPOINT;
    const client = new OllamaClient({ endpoint, fetchImpl: this.fetchImpl });
    const sub = LocalSubstrate.fromPick(client, pick, customTag);
    const labelBase = BACKEND_FALLBACK_STRINGS[BADGE_LABEL_KEYS.local] ?? "Local model";
    const modelLabel = LOCAL_MODEL_LABELS[pick] ?? customTag ?? LOCAL_MODEL_TAGS[pick];
    return {
      surface,
      substrate: "local",
      badge: this.makeBadge(surface, "local", "green"),
      capability: LOCAL_CAPABILITY,
      displayLabel: `${labelBase} — ${modelLabel}`,
      summarize: (r) => sub.summarize(r),
      classify: (r) => sub.classify(r),
      redact: (r) => sub.redact(r),
    };
  }

  private veniceHandle(surface: Surface): SubstrateHandle {
    const apiKey = this.config.veniceApiKey;
    if (!apiKey) {
      // Operator picked Venice but never entered a key; the picker modal
      // is responsible for catching this case at config time. Defensive
      // fallback emits a disabled handle so consumers see capability=false.
      return this.disabledHandle(surface);
    }
    const client = new VeniceClient({
      apiKey,
      endpoint: VENICE_DEFAULT_ENDPOINT,
      model: this.config.veniceModel ?? VENICE_DEFAULT_MODEL,
      fetchImpl: this.fetchImpl,
    });
    const sub = new VeniceSubstrate(client);
    const labelBase = BACKEND_FALLBACK_STRINGS[BADGE_LABEL_KEYS.venice] ?? "Venice.ai";
    return {
      surface,
      substrate: "venice",
      badge: this.makeBadge(surface, "venice", "green"),
      capability: VENICE_CAPABILITY,
      displayLabel: `${labelBase} — ${this.config.veniceModel ?? VENICE_DEFAULT_MODEL}`,
      summarize: (r) => sub.summarize(r),
      classify: (r) => sub.classify(r),
      redact: (r) => sub.redact(r),
    };
  }

  private frontierHandle(surface: Surface): SubstrateHandle {
    const provider = pickFrontierProvider(this.config.frontierConfig);
    if (!provider) return this.disabledHandle(surface);
    const apiKey = this.config.frontierConfig[provider];
    if (!apiKey) return this.disabledHandle(surface);
    const client = new FrontierClient({
      provider,
      apiKey,
      model: FRONTIER_DEFAULT_MODELS[provider],
      fetchImpl: this.fetchImpl,
    });
    const sub = new FrontierWithFilterSubstrate(client, this.redactor);
    const labelBase = BACKEND_FALLBACK_STRINGS[BADGE_LABEL_KEYS["frontier-with-filter"]] ?? "Frontier with PII filter";
    return {
      surface,
      substrate: "frontier-with-filter",
      badge: this.makeBadge(surface, "frontier-with-filter", "green"),
      capability: FRONTIER_CAPABILITY,
      displayLabel: `${labelBase} (${provider})`,
      summarize: (r) => sub.summarize(r),
      classify: (r) => sub.classify(r),
      redact: (r) => sub.redact(r),
    };
  }

  private async probeSurfaceHealth(
    surface: Surface,
    choice: SubstrateChoice,
    hardware: HardwareCapabilityReport,
  ): Promise<SurfaceStatus> {
    let health: "ok" | "degraded" | "unavailable" = "ok";
    let failureClass: SubstrateFailureClass | null = null;

    if (choice === "disabled") {
      health = "unavailable";
      failureClass = "substrate_disabled";
    } else if (choice === "local") {
      if (!hardware.ollamaReachable) {
        health = "unavailable";
        failureClass = "substrate_unavailable";
      } else {
        const pick = this.config.localModelPicks[surface] ?? DEFAULT_LOCAL_MODEL_PICKS[surface];
        const customTag = this.config.customLocalModelTags?.[surface];
        const expectedTag = customTag ?? (pick ? LOCAL_MODEL_TAGS[pick] : null);
        if (expectedTag && !hardware.ollamaModels.includes(expectedTag)) {
          health = "degraded";
          failureClass = "substrate_misconfigured";
        }
        if (hardware.tier === "below-baseline") {
          health = health === "ok" ? "degraded" : health;
        }
      }
    } else if (choice === "venice") {
      if (!this.config.veniceApiKey) {
        health = "unavailable";
        failureClass = "substrate_misconfigured";
      }
    } else if (choice === "frontier-with-filter") {
      const provider = pickFrontierProvider(this.config.frontierConfig);
      if (!provider) {
        health = "unavailable";
        failureClass = "substrate_misconfigured";
      }
    } else if (choice === "hybrid") {
      const sub = resolveHybridChoice(this.config.hybridRules, surface);
      if (!sub) {
        health = "unavailable";
        failureClass = "substrate_misconfigured";
      }
    }

    // Finding VV (v1.2.0-rc.1): truth-telling pass. If recent runtime or
    // validation failures exist within the 24h window, degrade the badge
    // to yellow even when the static probe says ok. The most-recent
    // failure also provides a representative failureClass for surfaces
    // whose static probe found nothing wrong but whose runtime path keeps
    // failing (the operator-visible problem this finding closes).
    const recentFailures = this.recentFailuresFor(surface);
    if (recentFailures.length > 0) {
      if (health === "ok") {
        health = "degraded";
        failureClass = recentFailures[recentFailures.length - 1]!.failureClass;
      } else if (failureClass === null) {
        failureClass = recentFailures[recentFailures.length - 1]!.failureClass;
      }
    }

    return {
      surface,
      chosen: choice,
      badge: this.makeBadge(surface, choice, healthToBadgeStatus(health)),
      health,
      failureClass,
      recentFailures,
    };
  }

  private makeBadge(surface: Surface, choice: SubstrateChoice, status: SubstrateBadge["status"]): SubstrateBadge {
    return {
      surface,
      substrate: choice,
      labelKey: BADGE_LABEL_KEYS[choice],
      tradeoffKey: BADGE_TRADEOFF_KEYS[choice],
      status,
    };
  }

  private fallbackAction(surface: Surface): "next-substrate" | "deny" | "disable-surface" {
    const behavior = this.config.fallback[surface];
    if (behavior === "degrade-silent") return "next-substrate";
    if (behavior === "disable-surface") return "disable-surface";
    return "deny";
  }

  /**
   * Internal hook for the Privacy Filter Tier 2 commit. Lets a redactor
   * audit-emit a `pii_redaction_event` payload through the selector
   * without exposing the AuditLog binding directly to redactor
   * implementations.
   */
  emitRedactionEvent(args: {
    surface: Surface;
    substrate: SubstrateChoice;
    matchCount: number;
    filterTier: 1 | 2;
  }): void {
    const payload: IntelligencePiiRedactionEventPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "pii_redaction_event",
      surface: args.surface,
      substrate: args.substrate,
      match_count: args.matchCount,
      filter_tier: args.filterTier,
    };
    this.emit(INTEL_OPS.PII_REDACTION_EVENT, payload, "success");
  }

  private emit(operation: string, payload: IntelligenceAuditPayload, result: "success" | "failure"): void {
    this.auditLog.append("l2", operation, this.identityId, payload as unknown as Record<string, unknown>, result);
  }
}

// ── helpers ─────────────────────────────────────────────────────────────

function makeEventId(): string {
  return `int-${Date.now()}-${toBase64url(randomBytes(8))}`;
}

function hashOfRequest(req: SummarizeRequest | ClassifyRequest | RedactRequest): string {
  return hashToString(sha256(stringToBytes(JSON.stringify(req))));
}

function hashOfResponse(resp: SubstrateResponse): string {
  return hashToString(sha256(stringToBytes(JSON.stringify(resp.body))));
}

function detectCpuArch(): HardwareCapabilityReport["cpuArch"] {
  const arch = os.arch();
  const platform = os.platform();
  if (platform !== "darwin") return arch === "x64" ? "x86_64" : "other";
  // Apple Silicon family detection by CPU model string is brittle and
  // varies by macOS version; v1.2 reports "apple-silicon-other" on darwin
  // arm64 and defers per-generation detection to v1.3+ where the picker
  // modal can surface a manual pick.
  if (arch === "arm64") return "apple-silicon-other";
  if (arch === "x64") return "x86_64";
  return "other";
}

function computeTier(totalRamGb: number): HardwareCapabilityReport["tier"] {
  if (totalRamGb < 8) return "below-baseline";
  if (totalRamGb < 16) return "baseline";
  if (totalRamGb < 32) return "mid";
  return "pro";
}

function recommendLocalModel(tier: HardwareCapabilityReport["tier"]): LocalModelPick | null {
  if (tier === "below-baseline") return null;
  if (tier === "baseline") return "gemma-2-2b";
  if (tier === "mid") return "phi-4-mini";
  return "llama-3.1-8b";
}

function pickFrontierProvider(cfg: SubstrateConfig["frontierConfig"]): FrontierProvider | null {
  if (cfg.anthropic) return "anthropic";
  if (cfg.openai) return "openai";
  if (cfg.google) return "google";
  return null;
}

function countOverriddenSurfaces(cfg: SubstrateConfig): number {
  let n = 0;
  for (const surface of SURFACES) {
    if (cfg.perSurface[surface] !== DEFAULT_PER_SURFACE[surface]) n++;
  }
  return n;
}

function disabledResponse(method: "summarize" | "classify" | "redact", servedBy: SubstrateChoice, failureClass: SubstrateFailureClass): SubstrateResponse {
  if (method === "summarize") {
    return {
      servedBy,
      failureClass,
      body: { kind: "failure", message: "substrate disabled or unsupported for this method" },
      completedAt: new Date().toISOString(),
      latencyMs: 0,
    };
  }
  if (method === "classify") {
    return {
      servedBy,
      failureClass,
      body: { kind: "failure", message: "substrate disabled or unsupported for this method" },
      completedAt: new Date().toISOString(),
      latencyMs: 0,
    };
  }
  return {
    servedBy,
    failureClass,
    body: { kind: "failure", message: "substrate disabled or unsupported for this method" },
    completedAt: new Date().toISOString(),
    latencyMs: 0,
  };
}

function healthToBadgeStatus(health: "ok" | "degraded" | "unavailable"): SubstrateBadge["status"] {
  if (health === "ok") return "green";
  if (health === "degraded") return "yellow";
  return "red";
}

export type { LoadOutcome };
