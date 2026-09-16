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
import { isIP } from "node:net";
import { sha256 } from "@noble/hashes/sha256";
import { hashToString } from "../core/hashing.js";
import { stringToBytes, toBase64url } from "../core/encoding.js";
import type { AuditLog } from "../operational/audit-log.js";
import { INTEL_OPS } from "./audit-events.js";
import { tradeoffTextHash, BACKEND_FALLBACK_STRINGS, BADGE_LABEL_KEYS, BADGE_TRADEOFF_KEYS, LOCAL_MODEL_LABELS } from "./templates.js";
import { DEFAULT_OLLAMA_ENDPOINT, buildDefaultConfig, DEFAULT_PER_SURFACE, DEFAULT_LOCAL_MODEL_PICKS } from "./defaults.js";
import {
  IntelligenceConfigStore,
  IntelligenceConfigUnreadableError,
  LocalIntegrityStateLoadError,
  type LoadOutcome,
} from "./policy-store.js";
// Imported, never re-typed: the operator line the ceremony prints and the badge
// label this file renders must truncate the same digest to the same width, or
// two surfaces describing one binding disagree by a character count.
import { ARMED_DIGEST_PREFIX_CHARS } from "./provisioning.js";
import {
  IMMUNE_MODEL_LOAD_SURFACES,
  type LocalIntegrityStateV2,
  type ModelLoadIntegrityFailureReason,
  type VerifiedLocalBindingV2,
} from "./model-manifest-v2.js";
import {
  OllamaRuntimeEvidenceClient,
  createSingleFlightLightRuntimeVerifier,
  type RuntimeLightVerificationResult,
  type RuntimeLightVerifier,
} from "./runtime-light-verifier.js";
import {
  IMMUNE_FULL_VERIFICATION_CADENCE_MS,
  createCadencedImmuneDiskVerifier,
  createNodeImmuneFileSystemAdapter,
  createOnDiskImmuneVerifier,
  type CadencedImmuneDiskVerifier,
  type ImmuneVerificationCheckpoint,
  type ImmuneVerificationClock,
  type ImmuneVerificationResult,
} from "./immune-disk-verifier.js";
import {
  LOCAL_MODEL_TAGS,
  SURFACES,
  type ClassifyRequest,
  type FallbackBehavior,
  type FrontierProvider,
  type HardwareCapabilityReport,
  type LocalModelPick,
  type LocalOnlyRequest,
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
  TIER2_PINNED_SURFACE,
  Tier2BindingPinnedError,
  isTier2PinViolation,
} from "./types.js";
import { LocalSubstrate, OllamaClient, LOCAL_CAPABILITY } from "./substrates/local.js";
import { VeniceClient, VeniceSubstrate, VENICE_CAPABILITY, VENICE_DEFAULT_ENDPOINT, VENICE_DEFAULT_MODEL, type VeniceValidateResult } from "./substrates/venice.js";
import { FrontierClient, FrontierWithFilterSubstrate, FRONTIER_CAPABILITY, FRONTIER_DEFAULT_MODELS, type FrontierRedactor } from "./substrates/frontier.js";
import {
  QUERY_ANONYMITY_AUDIT_OPS,
  createAnonymizedFetch,
} from "../query-anonymity/header-strip.js";
import {
  DISARMED_TIER3_CONFIG,
  TIER3_AUDIT_OPS,
  createTunneledFetch,
  type Tier3TransportConfig,
} from "../query-anonymity/tier3-transport.js";
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
  IntelligenceTier2BindingPinnedPayload,
} from "../contracts/v1.2/intelligence-events.js";
import { compileSubstrateContext } from "../compiled-context/compiler.js";
import {
  createUnwiredCompiledContextScanner,
  type CompiledContextScanner,
} from "../compiled-context/scanner.js";

const DISABLED_CAPABILITY: SubstrateCapability = {
  summarize: false,
  classify: false,
  redact: false,
};

/**
 * THE single authority for the request-scoped local-only constraint
 * (fix-round-4, item 5; generalized fix-round-5 item 5 to cover a THIRD
 * call site). Every enforcement site — `invoke()`'s pre-emptive check
 * (before any handle exists, given the concrete substrate a handle WOULD
 * be issued for), `guardDirectHandleCall` (given an already-issued
 * handle's own `raw.substrate`), and `getOrIssueHandle`'s defense-in-depth
 * guard (given `opts.localOnly` from a `getSubstrate()` caller, no full
 * request object available) — calls this SAME function rather than each
 * re-implementing the comparison. There is one predicate and three call
 * sites, not predicates that happen to agree today.
 *
 * Pure and stateless: takes the concrete substrate identity to judge
 * (never re-derives it, never reads selector state) and the ALREADY-READ
 * `localOnly` boolean, never a request/opts object (fix-round-8: see
 * `readLocalOnlyOnce`'s doc comment for why this predicate stopped
 * accepting a `LocalOnlyRequest` and reading `.localOnly` off it
 * internally). Every call site has already read the flag exactly once, at
 * its own entry point, before reaching here. A substrate is refused iff
 * the carrier is local-only AND that substrate is not `"local"`.
 */
function refusesLocalOnly(
  handleSubstrate: SubstrateChoice,
  localOnly: boolean,
): boolean {
  return localOnly && handleSubstrate !== "local";
}

/**
 * Fix-round-8 (P1 regression fix, subtracting fix-round-7's own defect):
 * reads `request.localOnly` EXACTLY ONCE, at an entry point's first
 * statement, and returns ONLY that value — never a copy of `request`
 * itself. The PRIOR version of this fix (`freezeLocalOnlyRequest`) built
 * a copy via `{ ...rest, localOnly }` to dodge double-reading an
 * accessor, which was sound for the FLAG but unsound for the REQUEST: a
 * class-backed request (fields defined as getters on the prototype, or
 * non-enumerable instance fields) loses every field a plain-object
 * rest/spread cannot see, so the "frozen copy" a caller downstream
 * received could be missing `context`/`query`/etc. entirely —
 * `compileSubstrateContext` then threw on the mangled object before the
 * typed refusal ever ran. The fix is smaller: never copy `request` at
 * all. Every entry point (`invoke()`, `getSubstrate()`,
 * `getOrIssueHandle()`, each `chokepointHandle` bound method) calls this
 * once, keeps its OWN request/opts object unchanged for content, and
 * threads the RESULT — not the request — to every guard, predicate,
 * audit, and fallback decision from that line on. Nothing downstream
 * reads `.localOnly` off the original object again: every function that
 * used to accept a `LocalOnlyRequest` purely to re-derive this boolean
 * (`refusesLocalOnly`, `guardDirectHandleCall`) now accepts a boolean
 * parameter instead.
 *
 * Fix-round-10 (P1, item 2): returns the RAW read value
 * (`boolean | undefined`), NOT pre-coerced to a boolean. Every call site
 * except `invoke()` immediately coerces it (`readLocalOnlyOnce(x) ===
 * true`) and never looks at the raw value again, so this is not a
 * behavior change for them. `invoke()` is the one caller that needs the
 * RAW value too: the LEGACY `request_hash` preimage (see `hashOfRequest`)
 * must stay byte-identical to what `JSON.stringify(req)` produced before
 * this file coerced `localOnly` at all -- an omitted `localOnly` (the
 * overwhelming majority of historical production requests, which never
 * set the field) must still serialize with NO `localOnly` key, not a
 * coerced `false`. Returning the raw value here, once, is what lets
 * `invoke()` serve both needs (the coerced DECISION boolean, and the
 * raw-preserving HASH input) from the SAME single property read, rather
 * than reading `.localOnly` a second time to recover what coercion threw
 * away.
 */
function readLocalOnlyOnce(request: LocalOnlyRequest): boolean | undefined {
  const { localOnly: rawFlag } = request;
  return rawFlag;
}

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
const FALLBACK_CHAIN = ["local", "venice", "frontier-with-filter"] as const;

type InvocationMethod = "summarize" | "classify" | "redact";
type SubstrateInvoker = (arg: SummarizeRequest | ClassifyRequest | RedactRequest) => Promise<SubstrateResponse>;
type FallbackTaken = IntelligenceSubstrateFailurePayload["fallback_taken"];
type IntegrityGateStage =
  | "selector_load"
  | "first_invocation"
  | "runtime_invocation"
  | "cadence";

interface HandleIssueResult {
  handle: SubstrateHandle;
  cacheable: boolean;
}

/** Result of attempting to write a local-only refusal's audit event; see `auditLocalOnlyRefusal`. */
interface LocalOnlyAuditResult {
  recorded: boolean;
  errorClass?: string;
}

interface IntegrityFailureState {
  reason: ModelLoadIntegrityFailureReason;
  observedAt: string;
  contentMismatchLatched: boolean;
}

interface IntegrityGateSuccess {
  ok: true;
  completedMonotonicMs: number;
  completedWallMs: number;
}

interface IntegrityGateFailure {
  ok: false;
  reason: ModelLoadIntegrityFailureReason;
}

type IntegrityGateResult = IntegrityGateSuccess | IntegrityGateFailure;

const CONTENT_MISMATCH_REASONS = new Set<ModelLoadIntegrityFailureReason>([
  "manifest_signature_invalid",
  "binding_mismatch",
  "runtime_manifest_digest_invalid",
  "runtime_manifest_digest_mismatch",
  "disk_manifest_invalid",
  "disk_manifest_digest_mismatch",
  "descriptor_bounds_exceeded",
  "layer_size_mismatch",
  "layer_digest_mismatch",
]);

const IMMUNE_SURFACE_SET = new Set<Surface>(IMMUNE_MODEL_LOAD_SURFACES);

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
  /**
   * Tier 3a (WP-V1.x-QUERY-LAYER-ANONYMITY) network-path anonymity
   * transport config. Defaults to disarmed: Tier 3 is opt-in and a no-op
   * for operators who have not enabled it, so behavior and latency are
   * unchanged. When armed, the two-hop egress-proxy tunnel is composed
   * BENEATH the Tier 1 anonymized fetch (see selector constructor), so the
   * wrapped fetch remains the sole outbound channel that Castle Wall
   * governs (AC-1). Slice 1 delivers IP-decoupling / path-linkage removal
   * (Property 1) only.
   */
  tier3?: Tier3TransportConfig;
  /**
   * Shared final-artifact screening boundary. Production constructors must
   * supply the dispatcher-wired scanner; the fallback still scans clean test
   * traffic and fails closed if a finding needs the absent reporter.
   */
  compiledContextScanner?: CompiledContextScanner;
  /** Fixture seam for Q5D; production revalidates with the pinned release key. */
  modelManifestV2PublicKey?: Uint8Array;
  /** Q5E test seam; production builds the bounded single-flight runtime verifier. */
  runtimeIntegrityVerifier?: RuntimeLightVerifier;
  /** Q5E test seam; production builds the bounded cadenced on-disk verifier. */
  immuneIntegrityVerifier?: CadencedImmuneDiskVerifier;
  /** Monotonic/wall clock seam for deterministic six-hour cadence tests. */
  integrityClock?: ImmuneVerificationClock;
}

export class SubstrateSelector {
  private store: IntelligenceConfigStore;
  private auditLog: AuditLog;
  private identityId: string;
  private redactor: FrontierRedactor;
  private fetchImpl: typeof fetch | undefined;
  private config: SubstrateConfig;
  private loaded = false;
  private loadPromise: Promise<void> | null = null;
  /**
   * Per-surface ring buffer of recent runtime + validation failures. See
   * `RECENT_FAILURES_CAP` and `RECENT_FAILURES_WINDOW_MS`. Populated by
   * `recordRecentFailure()` from the `invoke()` failure path and from the
   * post-config validation hook on substrates that expose validateKey.
   * Drives the operator-visible degrade in `getOperatorVisibleStatus()`.
   */
  private recentFailures = new Map<Surface, RecentFailureEntry[]>();
  private compiledContextScanner: CompiledContextScanner;
  private localIntegrityConfigSaveLockDepth = 0;
  private readonly runtimeIntegrityVerifierOverride?: RuntimeLightVerifier;
  private runtimeIntegrityVerifier: RuntimeLightVerifier | null = null;
  private runtimeIntegrityVerifierEndpoint: string | null = null;
  private readonly immuneIntegrityVerifier: CadencedImmuneDiskVerifier;
  private readonly integrityClock: ImmuneVerificationClock;
  private integrityConfigEpoch = 0;
  private readonly issuedHandles = new Map<string, {
    epoch: number;
    promise: Promise<HandleIssueResult>;
  }>();
  private readonly auditedIntegrityPromises = new WeakSet<object>();
  private readonly integrityFailures = new Map<Surface, IntegrityFailureState>();

  /**
   * One-time-per-process latch for the tier-2 pin override audit event
   * (`query_anonymity_tier2_binding_pinned`). See `effectiveChoice`.
   */
  private tier2PinOverrideAudited = false;

  constructor(cfg: SelectorConfig) {
    this.store = new IntelligenceConfigStore(cfg.storage, cfg.masterKey, {
      ...(cfg.modelManifestV2PublicKey === undefined
        ? {}
        : { modelManifestV2PublicKey: cfg.modelManifestV2PublicKey }),
    });
    this.auditLog = cfg.auditLog;
    this.identityId = cfg.identityId;
    this.compiledContextScanner =
      cfg.compiledContextScanner ?? createUnwiredCompiledContextScanner();
    this.redactor = cfg.redactor ?? IDENTITY_REDACTOR;
    // Rho-1 (WP-V1.x-QUERY-LAYER-ANONYMITY foundation): wrap the
    // substrate-client fetch with the Tier A header-strip transform.
    // Default-on, structurally unconditional — no operator opt-out.
    // Every outbound substrate call now goes through stripHeaders +
    // undici-defaults defeat, and emits a `query_anonymity_headers_
    // stripped` audit event with the per-call removed-header summary.
    // Bypass would require editing this constructor.
    //
    // Tier 3a (WP-V1.x-QUERY-LAYER-ANONYMITY network path, Slice 1): the
    // two-hop egress-proxy tunnel is composed BENEATH the anonymized fetch
    // so the substrate clients still receive a single wrapped fetch that is
    // the sole outbound channel Castle Wall governs (AC-1). When the Tier 3
    // config is disarmed (the default), `createTunneledFetch` returns the
    // base fetch unchanged, so there is zero behavioral/latency change.
    // When armed, the tunnel routes the request through the relay→egress
    // chain and fails closed if the anonymous path is unavailable (it never
    // silently connects direct). Order matters: anonymize(tunnel(base)).
    const baseFetch = cfg.fetchImpl ?? globalThis.fetch;
    const tunneledFetch = createTunneledFetch(
      baseFetch,
      cfg.tier3 ?? DISARMED_TIER3_CONFIG,
      (event) => {
        void this.auditLog.append(
          "l2",
          event.op,
          this.identityId,
          {
            destination_host: event.destinationHost,
            mode: event.mode,
            posture: event.posture,
            dialer_label: event.dialerLabel,
            egress_ip: event.egressIp,
          },
          event.op === TIER3_AUDIT_OPS.FAIL_CLOSED ? "failure" : "success",
        );
      },
    );
    this.fetchImpl = createAnonymizedFetch(tunneledFetch, (event) => {
      void this.auditLog.append(
        "l2",
        QUERY_ANONYMITY_AUDIT_OPS.HEADERS_STRIPPED,
        this.identityId,
        {
          url: event.url,
          method: event.method,
          stripped_count: event.stripped_count,
          removed: event.removed,
          required_preserved: event.required_preserved,
        },
      );
    });
    this.integrityClock = cfg.integrityClock ?? {
      monotonicNow: () => performance.now(),
      wallNow: () => Date.now(),
    };
    this.runtimeIntegrityVerifierOverride = cfg.runtimeIntegrityVerifier;
    this.immuneIntegrityVerifier = cfg.immuneIntegrityVerifier ??
      createCadencedImmuneDiskVerifier(
        createOnDiskImmuneVerifier({
          fs: createNodeImmuneFileSystemAdapter(),
          clock: this.integrityClock,
        }),
        { clock: this.integrityClock },
      );
    this.config = buildDefaultConfig();
  }

  /** Install the production dispatcher-wired scanner before any invocation. */
  setCompiledContextScanner(scanner: CompiledContextScanner): void {
    this.compiledContextScanner = scanner;
  }

  /**
   * Load (or initialize) the operator's substrate config, and act as the
   * boot-time local-intelligence load checkpoint.
   *
   * THE CLASSIFICATION THIS MAKES, and it is the whole point of the method:
   * a durable record is ABSENT, READABLE, or INDETERMINATE, and only the first
   * two may start a fortress. Absent loads the honest legacy-unarmed default
   * and emits `intelligence_config_loaded` with `was_default: true`. Readable
   * loads as authority. Indeterminate covers an armed record that fails Q5
   * validation, a record that does not decrypt or parse, and a record written
   * by a newer build: each refuses with a typed error and its own audited
   * `intelligence_load_integrity` row naming which classification refused it.
   *
   * `intelligence_config_loaded` is emitted on every branch that RETURNS, so
   * the audit chain shows config-load activity on boot; a branch that refuses
   * emits the load-integrity row instead, because a load that did not complete
   * must not appear in the chain as one that did.
   */
  async load(): Promise<void> {
    const outcome = await this.store.load();
    if (outcome.kind === "integrity-state-invalid") {
      // An armed record is one indivisible authority. Falling back to defaults
      // here would reinterpret a stripped/tampered record as legacy-unarmed.
      try {
        await this.auditLog.append(
          "l2",
          INTEL_OPS.LOAD_INTEGRITY,
          this.identityId,
          {
            stage: "state_validation",
            reason: outcome.reason,
            generation_refused: true,
          },
          "failure",
        );
      } catch {
        // Invalid authority still refuses when its derived audit cannot persist.
      }
      throw new LocalIntegrityStateLoadError(outcome.reason);
    }
    if (outcome.kind === "corrupt" || outcome.kind === "version-too-new") {
      // A durable record EXISTS and this build cannot read it. That is
      // indeterminate, not absent, and the two must never collapse into one
      // another: absent means no operator ever armed this fortress, while
      // unreadable means an operator may have armed it and the evidence is
      // unavailable. Falling through to `outcome.config` here reported the
      // second as the first, so a fortress whose armed record had been
      // corrupted or written by a newer build started clean, audited
      // `was_default: true`, and told nobody that anything was wrong.
      //
      // The refusal carries the recovery verb because there IS a remedy and it
      // is not obvious: `IntelligenceConfigUnreadableError.message` names
      // `INTELLIGENCE_CONFIG_RESET_VERB`, which quarantines the bytes and
      // reinitializes the config. `config-reset` itself reads the record
      // through `IntelligenceConfigStore.load` rather than through this
      // selector, so this refusal never blocks the one command that clears it.
      const refusal = new IntelligenceConfigUnreadableError(
        outcome.kind,
        outcome.kind === "version-too-new" ? outcome.persistedVersion : null,
      );
      try {
        await this.auditLog.append(
          "l2",
          INTEL_OPS.LOAD_INTEGRITY,
          this.identityId,
          {
            // Distinct from the armed-record `state_validation` stage above:
            // an operator reading this row must be able to tell "the record
            // failed its integrity check" from "the record could not be read
            // at all", because the two have different remedies.
            stage: "record_readability",
            classification: outcome.kind,
            reason: refusal.reason,
            ...(outcome.kind === "version-too-new"
              ? { persisted_version: outcome.persistedVersion }
              : {}),
            remedy: refusal.remedy,
            generation_refused: true,
          },
          "failure",
        );
      } catch {
        // An unreadable record still refuses when its derived audit cannot persist.
      }
      throw refusal;
    }
    this.config = outcome.config;
    this.invalidateIssuedIntegrityHandles();
    this.recentFailures.clear();
    for (const surface of SURFACES) {
      const persisted = this.config.provisioningFailures?.[surface] ?? [];
      if (persisted.length > 0) {
        this.recentFailures.set(surface, persisted.slice(-RECENT_FAILURES_CAP));
      }
    }
    this.loaded = true;

    const overriddenSurfaceCount = countOverriddenSurfaces(this.config);
    // INVARIANT: `was_default` means the record was genuinely ABSENT. Only
    // `loaded` and `default` can reach this line now, so the flag no longer
    // doubles as a bucket for records that exist but could not be read; those
    // refuse above. A reader of this audit row may treat `was_default: true`
    // as "nobody had armed this fortress", which is the claim it makes.
    const wasDefault = outcome.kind === "default";
    const payload: IntelligenceConfigLoadedPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "config_loaded",
      was_default: wasDefault,
      overridden_surface_count: overriddenSurfaceCount,
    };
    // INVARIANT: awaited, unlike the fire-and-forget `emit` used on the hot
    // invocation paths. `load()` is a BOOT step and the composition root
    // returns as soon as it resolves, so an unawaited append here outlives the
    // call: the audit write lands in the fortress state directory after the
    // caller believes startup finished. Failure mode from the outside, which
    // is how this was found: a test or a CLI that tears its temp fortress down
    // right after boot fails with `ENOTEMPTY` on a directory it just emptied,
    // naming a file nothing in the test wrote. The refusal branch above awaits
    // its append for the same reason; both must stay awaited.
    try {
      await this.auditLog.append(
        "l2",
        INTEL_OPS.CONFIG_LOADED,
        this.identityId,
        payload as unknown as Record<string, unknown>,
        outcome.kind === "loaded" ? "success" : "failure",
      );
    } catch {
      // A completed load is still complete when its derived audit cannot persist.
    }
  }

  /**
   * Re-read the durable config for a provisioning ceremony that already owns
   * the cross-process lock. This intentionally bypasses the loaded snapshot.
   * Must match the `reloadAuthority` adapter in `wrap/local-intelligence.ts`.
   */
  async reloadLocalProvisioningAuthority(): Promise<SubstrateConfig> {
    const config = await this.store.loadAuthoritative() ?? buildDefaultConfig();
    this.config = config;
    this.invalidateIssuedIntegrityHandles();
    this.recentFailures.clear();
    for (const surface of SURFACES) {
      const persisted = config.provisioningFailures?.[surface] ?? [];
      if (persisted.length > 0) {
        this.recentFailures.set(surface, persisted.slice(-RECENT_FAILURES_CAP));
      }
    }
    this.loaded = true;
    return config;
  }

  /**
   * Hold the distinct Q5 config-save lock across provisioning's authority
   * reload through its one commit. The outer provisioning lock is acquired
   * first by the composition root; this method never acquires it in reverse.
   */
  async withLocalIntegrityConfigSaveLock<T>(
    operation: () => Promise<T>,
  ): Promise<T> {
    return this.store.withSaveLock(async () => {
      this.localIntegrityConfigSaveLockDepth += 1;
      try {
        return await operation();
      } finally {
        this.localIntegrityConfigSaveLockDepth -= 1;
      }
    });
  }

  /**
   * Operator picked (or re-picked) a substrate for a surface. Persists the
   * change and emits `intelligence_substrate_chosen`. The picker modal
   * surfaces the tradeoff text BEFORE invoking this method; the audit
   * payload captures the hash of that text for auditor verification.
   */
  async setPerSurfaceChoice(surface: Surface, substrate: SubstrateChoice): Promise<void> {
    // Ratified 2026-07-23: the privacy-filter-tier-2 surface is pinned
    // local-only. Refused HERE, before any persist, so a violating
    // binding never exists on disk via this path. See
    // `isTier2PinViolation` in types.ts for the posture rationale.
    if (isTier2PinViolation(surface, substrate)) {
      throw new Tier2BindingPinnedError(substrate);
    }
    await this.ensureLoaded();
    const prior = this.config.perSurface[surface];
    const wasDefault = prior === DEFAULT_PER_SURFACE[surface];

    const next: SubstrateConfig = {
      ...this.config,
      perSurface: { ...this.config.perSurface, [surface]: substrate },
    };
    await this.persistNext(next);

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
  ): Promise<{ skippedPinnedSurfaces: Surface[] }> {
    await this.ensureLoaded();

    const priorSubstrates: Partial<Record<Surface, SubstrateChoice | null>> = {};
    for (const surface of SURFACES) {
      priorSubstrates[surface] = this.config.perSurface[surface] ?? null;
    }

    // Ratified 2026-07-23: the fan-out skips a pinned surface rather
    // than failing the whole bulk apply. The skip is reported in the
    // return value AND stamped on the bulk audit payload so the
    // operator can see the fan-out did not cover the pinned surface.
    const skippedPinnedSurfaces: Surface[] = [];
    const nextPerSurface: Record<Surface, SubstrateChoice> = { ...this.config.perSurface };
    const nextLocalPicks = { ...this.config.localModelPicks };
    for (const surface of SURFACES) {
      if (isTier2PinViolation(surface, substrate)) {
        skippedPinnedSurfaces.push(surface);
        continue;
      }
      nextPerSurface[surface] = substrate;
      if (substrate === "local" && opts.localModelPick !== undefined) {
        if (opts.localModelPick === null) delete nextLocalPicks[surface];
        else nextLocalPicks[surface] = opts.localModelPick;
      }
    }

    const next: SubstrateConfig = {
      ...this.config,
      perSurface: nextPerSurface,
      localModelPicks: nextLocalPicks,
      applyToAllSurfaces: true,
    };
    await this.persistNext(next);

    // Finding ZZ (v1.2.0-rc.2): bulk re-binding is a global configuration
    // gesture; prior per-surface failure entries no longer describe the
    // new bindings. Clear every surface's ring buffer so badges reflect
    // current configuration. A pin-skipped surface kept its binding, so
    // its failure trail stays (mirrors the same-substrate no-op rule in
    // setPerSurfaceChoice).
    for (const surface of SURFACES) {
      if (skippedPinnedSurfaces.includes(surface)) continue;
      this.recentFailures.delete(surface);
    }

    const payload: IntelligenceBulkSubstrateChosenPayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "bulk_substrate_chosen",
      substrate,
      surface_count: SURFACES.length - skippedPinnedSurfaces.length,
      tradeoff_text_hash: tradeoffTextHash(substrate),
      prior_substrates: priorSubstrates,
      ...(skippedPinnedSurfaces.length > 0
        ? { pinned_surfaces_skipped: skippedPinnedSurfaces }
        : {}),
    };
    this.emit(INTEL_OPS.BULK_SUBSTRATE_CHOSEN, payload, "success");
    return { skippedPinnedSurfaces };
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
    await this.persistNext({ ...this.config, applyToAllSurfaces: value });
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
    await this.persistNext({ ...this.config, localModelPicks: next });
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
    await this.persistNext(next);

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
    await this.persistNext({ ...this.config, frontierConfig: next });
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
    await this.persistNext({ ...this.config, hybridRules: rules });
  }

  /**
   * Override the per-surface fallback behavior. Defaults are set per
   * position paper section 5; the picker modal surfaces the tradeoff and
   * the operator can override.
   */
  async setFallbackBehavior(surface: Surface, fallback: FallbackBehavior): Promise<void> {
    await this.ensureLoaded();
    const next: SubstrateConfig = {
      ...this.config,
      fallback: { ...this.config.fallback, [surface]: fallback },
    };
    await this.persistNext(next);
  }

  /**
   * Reset every binding to the per-surface defaults. Emits
   * `intelligence_config_reset` so post-reset audit trails make the
   * configuration discontinuity visible.
   */
  async resetToDefaults(): Promise<void> {
    await this.ensureLoaded();
    const overridden = countOverriddenSurfaces(this.config);
    const legacyFresh = buildDefaultConfig();
    const fresh: SubstrateConfig = this.config.version === 2
      ? {
        ...legacyFresh,
        version: 2,
        // Resetting operator choices is not a reviewed Q5 disarm ceremony;
        // the armed record survives and the save refuses if choices diverge.
        localIntegrityState: this.config.localIntegrityState,
        customLocalModelTags: this.config.customLocalModelTags,
      }
      : legacyFresh;
    await this.persistNext(fresh);

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
   * Persist a bounded, operator-safe provisioning refusal without changing
   * the configured substrate. A failed local setup must remain local and
   * visibly degraded; it never authorizes a Venice/frontier fallback.
   */
  async recordLocalProvisioningFailure(
    surfaces: readonly Surface[],
    failureClass: SubstrateFailureClass,
    snippet: string,
  ): Promise<void> {
    await this.ensureLoaded();
    const next = { ...(this.config.provisioningFailures ?? {}) };
    const ts = new Date().toISOString();
    for (const surface of surfaces) {
      const entry: RecentFailureEntry = {
        ts,
        failureClass,
        snippet: snippet.slice(0, FAILURE_SNIPPET_MAX_LEN),
      };
      const entries = [...(next[surface] ?? []), entry].slice(-RECENT_FAILURES_CAP);
      next[surface] = entries;
    }
    await this.persistNext({ ...this.config, provisioningFailures: next });
    for (const surface of surfaces) {
      const entries = next[surface];
      if (entries !== undefined) this.recentFailures.set(surface, entries.slice());
    }
  }

  /**
   * Commit runtime tags, cleared failures, and the complete Q5 record in one
   * encrypted config write. The in-process view changes only after save wins,
   * so a thrown/failed save leaves both memory and durable authority old.
   */
  async commitLocalIntegrityProvisioning(
    integrityState: LocalIntegrityStateV2,
    runtimeTags: Readonly<Partial<Record<Surface, string>>>,
  ): Promise<void> {
    await this.ensureLoaded();
    if (
      this.config.version === 2 &&
      integrityState.manifest_version_floor <
        this.config.localIntegrityState.manifest_version_floor
    ) {
      throw new LocalIntegrityStateLoadError("manifest_rollback");
    }
    const customLocalModelTags = { ...(this.config.customLocalModelTags ?? {}) };
    const provisioningFailures = { ...(this.config.provisioningFailures ?? {}) };
    for (const surface of SURFACES) {
      const binding = integrityState.bindings[surface];
      const runtimeTag = runtimeTags[surface];
      if (binding === undefined && runtimeTag === undefined) continue;
      if (
        binding === undefined || runtimeTag === undefined ||
        binding.runtime_tag !== runtimeTag || this.effectiveChoice(surface) !== "local"
      ) {
        throw new LocalIntegrityStateLoadError("binding_mismatch");
      }
      customLocalModelTags[surface] = runtimeTag;
      delete provisioningFailures[surface];
    }
    const next: SubstrateConfig = {
      ...this.config,
      version: 2,
      customLocalModelTags,
      provisioningFailures,
      localIntegrityState: integrityState,
    };
    await this.persistNext(next);
    for (const surface of Object.keys(integrityState.bindings) as Surface[]) {
      this.recentFailures.delete(surface);
    }
  }

  private async persistNext(next: SubstrateConfig): Promise<void> {
    const saved = this.localIntegrityConfigSaveLockDepth > 0
      ? await this.store.saveWhileLocked(next)
      : await this.store.save(next);
    this.config = saved;
    this.invalidateIssuedIntegrityHandles();
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
   * the installed redactor; already-held handles remain snapshots, but the
   * selector never serves a pre-install handle from its issuance cache.
   */
  installRedactor(redactor: FrontierRedactor): void {
    this.redactor = redactor;
    this.invalidateIssuedIntegrityHandles();
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
  async getSubstrate(
    surface: Surface,
    opts?: { localOnly?: boolean },
  ): Promise<SubstrateHandle> {
    // P0 fix-round-8: `opts.localOnly` is read here, as the literal first
    // statement, via `readLocalOnlyOnce` — exactly once, whether `opts`
    // holds a plain boolean or a getter. `localOnly` (the boolean) is what
    // `getOrIssueHandle` receives below, never `opts` itself.
    const localOnly = readLocalOnlyOnce(opts ?? {}) === true;
    await this.ensureLoaded();
    const raw = await this.getOrIssueHandle(surface, this.effectiveChoice(surface), { localOnly });
    return this.chokepointHandle(surface, raw);
  }

  /**
   * Wrap a raw, internally-issued handle so every bound method a CALLER
   * might invoke directly (`handle.summarize(req)`) is guarded by
   * `refusesLocalOnly` before it can reach the raw handle's own method.
   *
   * Without this wrapper, `getSubstrate()` handed out the raw handle from
   * `getOrIssueHandle`, whose bound methods call the substrate client
   * directly (see `gatedLocalHandle`/`veniceHandle`/`frontierHandle`).
   * Those methods have no knowledge of a per-request `localOnly`
   * constraint. A caller that obtained a hosted-bound handle via
   * `getSubstrate("concierge")` and then called `handle.summarize({ ...,
   * localOnly: true })` directly reached the hosted substrate anyway,
   * bypassing every local-only guarantee.
   *
   * Each bound method calls `guardDirectHandleCall`, which judges
   * `raw.substrate` — the identity the HANDLE itself carries — against
   * `refusesLocalOnly`, the ONE predicate `invoke()`'s own pre-emptive
   * check also calls (see that method). `capability` comes from `raw` so
   * a caller's `handle.capability.summarize === false` short-circuit sees
   * the same answer it always did.
   *
   * `invoke()` itself never goes through this wrapper: it obtains its
   * handle from `getOrIssueHandle` directly (see `invoke()` and
   * `tryNextSubstrate()`), calling the substrate client without another
   * hop back through itself.
   */
  private chokepointHandle(surface: Surface, raw: SubstrateHandle): SubstrateHandle {
    return {
      surface: raw.surface,
      substrate: raw.substrate,
      badge: raw.badge,
      capability: raw.capability,
      displayLabel: raw.displayLabel,
      // Fix-round-9 (P1, item 2): `raw` can be the disabled handle
      // `getOrIssueHandle`'s own local-only precheck refusal returns,
      // carrying `auditRecorded`/`auditError` when that refusal's audit
      // write failed. This wrapper otherwise rebuilds an entirely NEW
      // object from `raw`'s named fields (so its bound methods can be
      // chokepoint-guarded), which would silently drop those two fields
      // if they were not forwarded explicitly here -- exactly the
      // regression this fix-round exists to close.
      ...(raw.auditRecorded !== undefined ? { auditRecorded: raw.auditRecorded, auditError: raw.auditError } : {}),
      ...(raw.summarize
        ? {
            summarize: async (req: SummarizeRequest) => {
              // P0 fix-round-8: `req.localOnly` is read HERE, once, via
              // `readLocalOnlyOnce` — never as a copy of `req` itself
              // (fix-round-7's `freezeLocalOnlyRequest` copy silently
              // dropped a class-backed request's prototype-getter/
              // non-enumerable fields, which `compileSubstrateContext`
              // then choked on before the typed refusal could run). `req`
              // is threaded on to `guardDirectHandleCall` and
              // `raw.summarize!()` UNCHANGED, for its content only;
              // `guardDirectHandleCall` takes the already-read boolean
              // directly and never touches `req.localOnly` again.
              const localOnly = readLocalOnlyOnce(req) === true;
              const response =
                (await this.guardDirectHandleCall(surface, raw.substrate, localOnly)) ??
                (await raw.summarize!(req));
              return this.normalizeDirectHandleLocalFailure(surface, response, localOnly);
            },
          }
        : {}),
      ...(raw.classify
        ? {
            classify: async (req: ClassifyRequest) => {
              // P0 fix-round-8: same construction as `summarize` above —
              // read once via `readLocalOnlyOnce`, `req` threaded onward
              // unchanged. See `summarize`'s comment for the failure mode
              // this removes.
              const localOnly = readLocalOnlyOnce(req) === true;
              const response =
                (await this.guardDirectHandleCall(surface, raw.substrate, localOnly)) ??
                (await raw.classify!(req));
              return this.normalizeDirectHandleLocalFailure(surface, response, localOnly);
            },
          }
        : {}),
      ...(raw.redact
        ? {
            redact: async (req: RedactRequest) => {
              // P0 fix-round-8: same construction as `summarize` above —
              // read once via `readLocalOnlyOnce`, `req` threaded onward
              // unchanged. See `summarize`'s comment for the failure mode
              // this removes.
              const localOnly = readLocalOnlyOnce(req) === true;
              const response =
                (await this.guardDirectHandleCall(surface, raw.substrate, localOnly)) ??
                (await raw.redact!(req));
              return this.normalizeDirectHandleLocalFailure(surface, response, localOnly);
            },
          }
        : {}),
    };
  }

  /**
   * P1 fix-round-6, item 2: a directly held handle whose `raw.substrate`
   * IS `"local"` (so `guardDirectHandleCall` returned `null` — refusing
   * was never in question) but whose local invocation itself fails must
   * read the SAME way `invoke()`'s P2-4 normalization already makes it
   * read for the exact same failure shape: `local_only_violation` /
   * `local_unavailable`, with an audit event. Before this fix, the raw
   * substrate's own failure class (`substrate_unavailable`, etc.) passed
   * through unchanged and unaudited — a caller going through
   * `invokeSummarize` and a caller holding the handle directly saw two
   * different outcomes for the identical failure.
   *
   * Only normalizes a REAL raw failure: a response `guardDirectHandleCall`
   * already refused (`failureClass === "local_only_violation"`) is left
   * untouched, or this would re-audit and overwrite its
   * `binding_conflict` reason with `local_unavailable`.
   */
  private async normalizeDirectHandleLocalFailure(
    surface: Surface,
    response: SubstrateResponse,
    localOnly: boolean,
  ): Promise<SubstrateResponse> {
    if (!localOnly || !response.failureClass || response.failureClass === "local_only_violation") {
      return response;
    }
    const audit = await this.auditLocalOnlyRefusal(surface, "local", "local", "local_unavailable");
    return failureResponse(
      "local",
      "local_only_violation",
      `local-only request refused: local generation failed (${response.failureClass})`,
      "local_unavailable",
      audit,
    );
  }

  /**
   * The local-only check `chokepointHandle`'s bound methods run BEFORE
   * falling through to the raw handle's own method. Returns a refusal
   * `SubstrateResponse` when `refusesLocalOnly(handleSubstrate, localOnly)`
   * is true, or `null` when the raw method may proceed unmodified. Takes
   * the ALREADY-READ boolean (fix-round-8), never the request itself —
   * this function has no use for the request's content, only the flag its
   * caller already extracted via `readLocalOnlyOnce`.
   *
   * `handleSubstrate` is `raw.substrate` — the identity `raw` itself
   * carries, captured at the moment `getSubstrate()` issued it — passed
   * in by the caller, never re-derived here or in `refusesLocalOnly`.
   * `raw.summarize`/`classify`/`redact` are closures already bound to
   * whichever substrate `raw` was issued for (e.g. a `VeniceClient`
   * captured in a `veniceHandle()` closure); judging anything other than
   * that captured identity (the surface's current binding, say) would let
   * a held handle's answer diverge from which closure it actually
   * invokes. See `test/intelligence/selector-local-only.test.ts`'s
   * held-handle trigger and mirror tests for the failure mode this
   * closes and its converse.
   *
   * Deliberately does NOT delegate to `this.invoke()`: routing every
   * bound method through `invoke()` would re-derive a brand-new handle at
   * call time instead of using the held one, breaking the Q5E
   * integrity-gate tests that hold a raw handle across a config change
   * specifically to exercise that handle's OWN closure-captured
   * epoch/staleness self-check in isolation (`gatedLocalHandle`'s
   * `beforeInvocation`), and changing audit-emission behavior (a direct
   * handle call is documented, on `invokeSummarize` above, as a probe
   * path that skips audit emission on purpose). This guard preserves
   * every other property of the raw handle (fallback exemptions,
   * integrity gating, audit skipping) and adds exactly one thing, judged
   * by the one shared predicate: a request-scoped local-only constraint
   * can never be satisfied by falling through to a non-local closure.
   */
  private async guardDirectHandleCall(
    surface: Surface,
    handleSubstrate: SubstrateChoice,
    localOnly: boolean,
  ): Promise<SubstrateResponse | null> {
    if (!refusesLocalOnly(handleSubstrate, localOnly)) return null;
    const audit = await this.auditLocalOnlyRefusal(surface, handleSubstrate, handleSubstrate, "binding_conflict");
    return failureResponse(
      "disabled",
      "local_only_violation",
      `local-only request refused: this handle is bound to "${handleSubstrate}", not local`,
      "binding_conflict",
      audit,
    );
  }

  /**
   * Invoke-time chokepoint for the ratified 2026-07-23 tier-2 local
   * pin (defense in depth behind the config-write gate). Resolves the
   * pinned `privacy-filter-tier-2` surface to `local` regardless of
   * what the persisted config says: a pre-existing or tampered
   * non-local binding is never honored, and the first override in this
   * process emits a `query_anonymity_tier2_binding_pinned` audit event
   * recording the persisted value. The persisted config itself is left
   * untouched so the operator can see and correct it. Every persisted
   * read that feeds an invocation or an operator-visible status MUST
   * route through this method.
   */
  private effectiveChoice(surface: Surface): SubstrateChoice {
    const persisted = this.config.perSurface[surface];
    if (!isTier2PinViolation(surface, persisted)) return persisted;
    if (!this.tier2PinOverrideAudited) {
      this.tier2PinOverrideAudited = true;
      const payload: IntelligenceTier2BindingPinnedPayload = {
        version: "1.2",
        event_id: makeEventId(),
        emitted_at: new Date().toISOString(),
        identity_id: this.identityId,
        kind: "tier2_binding_pinned",
        surface,
        persisted_substrate: persisted,
        pinned_to: "local",
      };
      this.emit(INTEL_OPS.TIER2_BINDING_PINNED, payload, "success");
    }
    return "local";
  }

  /**
   * Resolve `choice` to the concrete substrate a request would actually
   * reach: `hybrid` fans out through the per-surface routing rules (an
   * unresolvable hybrid binding is treated as `disabled`, matching
   * `issueHandle`'s own fallback), every other choice is already concrete.
   * The local-only guard (see `invoke()` and `getOrIssueHandle()`) checks
   * THIS, not the raw `choice`, so a hybrid binding that routes to a
   * hosted substrate is refused exactly like a direct hosted binding.
   */
  private resolveConcreteChoice(surface: Surface, choice: SubstrateChoice): SubstrateChoice {
    if (choice !== "hybrid") return choice;
    return resolveHybridChoice(this.config.hybridRules, surface) ?? "disabled";
  }

  /**
   * ATTEMPT to audit a request-scoped local-only refusal or a held-local-
   * handle's local-generation failure under local-only. Shared by every
   * enforcement site — `invoke()`'s pre-emptive check,
   * `getOrIssueHandle()`'s defense-in-depth guard, `guardDirectHandleCall`,
   * and the held-handle local-failure normalization — so a local-only
   * decision has exactly ONE audit code path regardless of which site
   * fired.
   *
   * Fix-round-6 (P1, item 3): an earlier version of this doc unconditionally
   * promised a row per decision, phrased as "writes exactly one" rather
   * than "attempts one". That was false whenever this write itself failed:
   * the catch block swallowed
   * the error and the row simply never existed, with nothing in the
   * response or anywhere else recording that the claim had not held.
   * Building the durability to make "writes" true (retries, a dead-letter
   * queue, ...) is out of scope for what this method is; the claim is
   * SUBTRACTED instead, to the version that is actually true: every
   * refusal ATTEMPTS an audit event. The refusal itself is unconditional
   * either way — fail-closed always wins, a failed audit write never
   * turns a refusal into an allow — but the ATTEMPT's own outcome is now
   * returned so the caller can surface it (`auditRecorded: false` +
   * `auditError` on the response `failureResponse` builds) rather than
   * drop it, and one line reaches stderr here so an operator watching the
   * process directly (not just the audit log the write failed to reach)
   * has a chance to see it too.
   */
  private async auditLocalOnlyRefusal(
    surface: Surface,
    boundChoice: SubstrateChoice,
    resolvedChoice: SubstrateChoice,
    reason: "binding_conflict" | "local_unavailable" = "binding_conflict",
  ): Promise<LocalOnlyAuditResult> {
    const payload: IntelligenceSubstrateFailurePayload = {
      version: "1.2",
      event_id: makeEventId(),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "substrate_failure",
      surface,
      substrate: boundChoice,
      failure_class: "local_only_violation",
      // "binding_conflict": no substrate was contacted and no fallback may
      // be tried, matching the `substrate_context_refused` precedent.
      // "local_unavailable": a local invocation WAS attempted (this row is
      // reached only from the post-attempt normalization path in that
      // case), so `fallback_taken: "deny"` here means "none was permitted
      // afterward", not "none was attempted".
      fallback_taken: "deny",
      local_only: true,
    };
    try {
      await this.auditLog.append(
        "l2",
        INTEL_OPS.SUBSTRATE_FAILURE,
        this.identityId,
        {
          ...(payload as unknown as Record<string, unknown>),
          resolved_substrate: resolvedChoice,
          local_only_reason: reason,
        },
        "failure",
      );
      return { recorded: true };
    } catch (error) {
      const errorClass = error instanceof Error ? error.constructor.name : typeof error;
      process.stderr.write(
        `[sanctuary:local-only-audit-failed] surface=${surface} reason=${reason} error=${errorClass}\n`,
      );
      return { recorded: false, errorClass };
    }
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
      // Status reports the EFFECTIVE choice (tier-2 pin applied) so
      // badges describe what invocations actually do; the raw persisted
      // config remains visible via the config read for correction.
      const choice = this.effectiveChoice(surface);
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
    if (this.loaded) return;
    const pending = this.loadPromise ?? this.load();
    this.loadPromise = pending;
    try {
      await pending;
    } finally {
      if (this.loadPromise === pending) this.loadPromise = null;
    }
  }

  private async invoke(
    surface: Surface,
    method: InvocationMethod,
    req: SummarizeRequest | ClassifyRequest | RedactRequest,
  ): Promise<SubstrateResponse> {
    // P0 fix-round-8 (subtracting fix-round-7's own regression):
    // `req.localOnly` is read HERE, as the literal first statement, via
    // `readLocalOnlyOnce` — exactly once, whether `req` is a plain object
    // or a class instance with a prototype getter. See `readLocalOnlyOnce`'s
    // doc comment for the full account, including fix-round-10's addition
    // (below) of why the RAW read value is kept alongside the coerced one.
    const requestLocalOnlyRaw = readLocalOnlyOnce(req);
    const requestLocalOnly = requestLocalOnlyRaw === true;
    // P1 fix-round-10, item 3: every NAMED CONTENT FIELD is read from
    // `req` EXACTLY ONCE too, right here, immediately after the single
    // `localOnly` read and before this method's first `await` — mirroring
    // exactly why `localOnly` itself is read once. Without this, a
    // STATEFUL getter (one that returns different content on successive
    // reads) could present one value to the pre-egress context scanner
    // below, a DIFFERENT value to the audit hash further down, and a
    // THIRD value to the substrate actually invoked — the thing screened,
    // the thing recorded, and the thing sent would then be three
    // different values, which defeats the entire purpose of screening
    // and auditing a request's content. `content` (the materialized
    // snapshot `materializeRequestContent` returns) is what every one of
    // those three steps consumes from here on; `req` itself is never read
    // for its content fields again. See `materializeRequestContent`'s own
    // doc comment for why field VALUES are preserved as read (including
    // `undefined` for an omitted optional field) rather than coerced.
    const content = materializeRequestContent(req);
    await this.ensureLoaded();
    const screened = await this.compiledContextScanner.screen(
      compileSubstrateContext(surface, content),
    );
    // Resolved once, before the screening branch, so the refusal row names the
    // same substrate a served invocation would have named and the one-time
    // tier-2 pin audit inside cannot fire twice for one invocation.
    const choice = this.effectiveChoice(surface);
    if (
      screened.outcome !== "clean" &&
      screened.outcome !== "detector_disabled_by_policy"
    ) {
      // The sentinel finding the scanner reports records WHAT was seen; this
      // row records that an invocation was refused because of it, so the
      // intelligence audit stream shows the refusal on the same op family an
      // operator already reads for substrate outcomes rather than only in the
      // sentinel stream.
      const refusalPayload: IntelligenceSubstrateFailurePayload = {
        version: "1.2",
        event_id: makeEventId(),
        emitted_at: new Date().toISOString(),
        identity_id: this.identityId,
        kind: "substrate_failure",
        surface,
        substrate: choice,
        failure_class: "substrate_context_refused",
        // No substrate was contacted and no fallback may be tried: a refused
        // artifact is refused for every substrate, so falling through would
        // hand the same bytes to the next provider.
        fallback_taken: "deny",
        local_only: requestLocalOnly,
      };
      try {
        await this.auditLog.append(
          "l2",
          INTEL_OPS.SUBSTRATE_FAILURE,
          this.identityId,
          refusalPayload as unknown as Record<string, unknown>,
          "failure",
        );
      } catch {
        // A refusal still refuses when its derived audit cannot persist.
      }
      return failureResponse(
        "disabled",
        "substrate_context_refused",
        `compiled-context screening refused provider invocation (${screened.outcome})`,
      );
    }

    // Request-scoped local-only constraint (2026-09-15 slice; MUST-NEVER 5:
    // never silently degrade). `choice` is what the OPERATOR bound this
    // surface to; `req.localOnly` is what THIS request requires, and the
    // request wins. Judged against the CONCRETE substrate a handle would
    // be issued for (hybrid rules resolved) via `refusesLocalOnly` — the
    // SAME predicate `guardDirectHandleCall` uses against an
    // already-issued handle's `raw.substrate` — so a hybrid binding that
    // would route to Venice/frontier is refused exactly like a direct
    // hosted binding, by the one authority both sites share. This check
    // runs BEFORE `getOrIssueHandle` below, which is the sole place a
    // Venice/frontier client constructor is called: a conflicting binding
    // is refused here and never reaches that constructor, so a local-only
    // request can never cause a hosted client to be built, let alone
    // contacted.
    const resolvedChoice = this.resolveConcreteChoice(surface, choice);
    if (refusesLocalOnly(resolvedChoice, requestLocalOnly)) {
      const audit = await this.auditLocalOnlyRefusal(surface, choice, resolvedChoice, "binding_conflict");
      return failureResponse(
        "disabled",
        "local_only_violation",
        `local-only request refused: surface "${surface}" is bound to "${resolvedChoice}", not local`,
        "binding_conflict",
        audit,
      );
    }

    const startedAt = Date.now();
    // All local generation reaches the async selector-load chokepoint; a
    // direct synchronous local-handle construction would bypass Q5E.
    const handle = await this.getOrIssueHandle(surface, choice, { localOnly: requestLocalOnly });
    // Fix-round-10, item 2: `requestHash` is the LEGACY preimage (byte-
    // identical to what this file hashed before fix-round-9), built from
    // the single materialized `content` snapshot plus the RAW (not
    // coerced) `localOnly` read — see `hashOfRequest`'s doc comment.
    // `requestProjectionHash` is the NEW, more complete projection (bound
    // to `surface`, coerced `localOnly`, explicit nulls for omitted
    // fields) under its own field, `request_projection_hash`, so nothing
    // historical breaks while the more correct hash is still committed.
    const requestHash = hashOfRequest(content, requestLocalOnlyRaw);
    const requestProjectionHash = hashOfRequestProjection(surface, requestLocalOnly, content);
    const primary = await this.invokeHandle(surface, handle, method, content);
    let response = primary.response;
    let primaryFailure: { response: SubstrateResponse; fallbackTaken: FallbackTaken } | null = null;
    let emitInvoked = primary.methodAvailable;

    if (primary.response.failureClass) {
      const fallback = await this.tryNextSubstrate(surface, handle.substrate, method, content, requestLocalOnly);
      if (fallback && !fallback.response.failureClass) {
        response = fallback.response;
        primaryFailure = { response: primary.response, fallbackTaken: "next-substrate" };
        emitInvoked = true;
      } else {
        const settled = fallback?.response ?? primary.response;
        // Request-scoped local-only constraint (2026-09-15 slice, P2-4: one
        // truth, not two). The pre-emptive refusal above (a conflicting
        // BINDING, refused before any handle is issued) already returns
        // `local_only_violation`. This is the other way a local-only
        // request can fail to be served locally: the binding WAS local,
        // but local generation itself failed, and `tryNextSubstrate`
        // refused to fall back to a hosted substrate because the request
        // forbids it. A caller filtering responses on `local_only_violation`
        // must see BOTH shapes, not just the pre-emptive one — otherwise
        // "local unavailable" and "local unreachable" look identical to a
        // caller that never inspects the message text. The original
        // substrate failure class survives in the message and in
        // `recordRecentFailure`'s snippet below for operator diagnosis;
        // only the class an external caller sees is normalized.
        //
        // P1 fix-round-7: this branch must return the SAME way every other
        // local-only refusal in this file returns — through
        // `auditLocalOnlyRefusal`, which never throws. Below this `if`, the
        // method falls through to the shared `emitAwaited` calls, which DO
        // throw on a failed audit write (by design, for the non-local-only
        // paths that share that call). Routing a local-only request through
        // that shared path would mean a failing audit backend crashes the
        // whole call for exactly the callers who most need a typed,
        // fail-closed refusal instead of an exception. So this case is
        // handled here, fully, with its own audit + return, and never
        // reaches `emitInvoked`/`emitAwaited` at all.
        if (requestLocalOnly) {
          const audit = await this.auditLocalOnlyRefusal(
            surface,
            handle.substrate,
            handle.substrate,
            "local_unavailable",
          );
          const normalized = withTotalLatency(
            failureResponse(
              settled.servedBy,
              "local_only_violation",
              `local-only request refused: local generation failed (${settled.failureClass ?? "internal_error"})`,
              "local_unavailable",
              audit,
            ),
            startedAt,
          );
          // P1 fix-round-10, item 4: this method promises ONE
          // `substrate_invoked` event per `invoke()` call, carrying the
          // fields NO other event shape carries (`request_hash`,
          // `response_hash`, `latency_ms`) — `auditLocalOnlyRefusal`
          // above writes only a `substrate_failure` row, which has none
          // of those fields. Before this fix, this early return skipped
          // the invoked event entirely: a local-only request whose local
          // generation genuinely failed left NO audit row anywhere
          // carrying the request hash or latency for that invocation,
          // silently thinner evidence than every other `invoke()`
          // outcome (including the non-local-only local-failure path,
          // which falls through to the shared `emitInvoked`/`emitAwaited`
          // machinery further below and always gets one). Written via a
          // local try/catch, never `emitAwaited` (which throws by
          // design for non-local-only paths) — this branch's whole
          // contract is an unconditional typed return, so a failed
          // audit WRITE here must never become a thrown exception; the
          // refusal's OWN audit attempt (`audit`, above) already
          // surfaces its failure via `normalized.auditRecorded`/
          // `auditError`, and that is unaffected by this write's outcome
          // either way.
          const invokedPayload: IntelligenceSubstrateInvokedPayload = {
            version: "1.2",
            event_id: makeEventId(),
            emitted_at: new Date().toISOString(),
            identity_id: this.identityId,
            kind: "substrate_invoked",
            surface,
            substrate: choice,
            served_by: normalized.servedBy,
            request_hash: requestHash,
            request_projection_hash: requestProjectionHash,
            response_hash: null,
            latency_ms: normalized.latencyMs,
            failure_class: normalized.failureClass,
            local_only: true,
          };
          try {
            await this.auditLog.append(
              "l2",
              INTEL_OPS.SUBSTRATE_INVOKED,
              this.identityId,
              invokedPayload as unknown as Record<string, unknown>,
              "failure",
            );
          } catch {
            // Fail-closed always wins: the refusal itself (already built
            // above) is unconditional and does not depend on this write.
          }
          const snippet =
            normalized.body.kind === "failure" ? normalized.body.message : "local-only request refused";
          this.recordRecentFailure(surface, "local_only_violation", snippet);
          return normalized;
        }
        response = settled;
        primaryFailure = {
          response,
          fallbackTaken: fallback?.exhausted ? "all-exhausted" : this.fallbackFailureAction(surface, handle.substrate),
        };
        if (fallback) emitInvoked = true;
      }
    }

    response = withTotalLatency(response, startedAt);
    // Persist invocation audit rows before returning to short-lived callers.
    // Storage failure must remain observable without exposing storage details.
    if (!emitInvoked) {
      if (primaryFailure) {
        const failurePayload: IntelligenceSubstrateFailurePayload = {
          version: "1.2",
          event_id: makeEventId(),
          emitted_at: new Date().toISOString(),
          identity_id: this.identityId,
          kind: "substrate_failure",
          surface,
          substrate: choice,
          failure_class: primaryFailure.response.failureClass ?? "internal_error",
          fallback_taken: primaryFailure.fallbackTaken,
          local_only: requestLocalOnly,
        };
        await this.emitAwaited(INTEL_OPS.SUBSTRATE_FAILURE, failurePayload, "failure");
        const snippet = primaryFailure.response.body.kind === "failure"
          ? primaryFailure.response.body.message
          : `${choice} ${method} failed`;
        this.recordRecentFailure(surface, primaryFailure.response.failureClass ?? "internal_error", snippet);
      }
      return response;
    }

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
      request_projection_hash: requestProjectionHash,
      response_hash: response.failureClass ? null : hashOfResponse(response),
      latency_ms: response.latencyMs,
      failure_class: response.failureClass,
      local_only: requestLocalOnly,
    };
    await this.emitAwaited(INTEL_OPS.SUBSTRATE_INVOKED, invokedPayload, response.failureClass ? "failure" : "success");

    if (primaryFailure) {
      const failurePayload: IntelligenceSubstrateFailurePayload = {
        version: "1.2",
        event_id: makeEventId(),
        emitted_at: new Date().toISOString(),
        identity_id: this.identityId,
        kind: "substrate_failure",
        surface,
        substrate: choice,
        failure_class: primaryFailure.response.failureClass ?? "internal_error",
        fallback_taken: primaryFailure.fallbackTaken,
        local_only: requestLocalOnly,
      };
      await this.emitAwaited(INTEL_OPS.SUBSTRATE_FAILURE, failurePayload, "failure");
      const snippet = primaryFailure.response.body.kind === "failure"
        ? primaryFailure.response.body.message
        : `${choice} ${method} failed`;
      this.recordRecentFailure(surface, primaryFailure.response.failureClass ?? "internal_error", snippet);
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

  private async invokeHandle(
    surface: Surface,
    handle: SubstrateHandle,
    method: InvocationMethod,
    req: SummarizeRequest | ClassifyRequest | RedactRequest,
  ): Promise<{ response: SubstrateResponse; methodAvailable: boolean }> {
    const fn = handle[method] as SubstrateInvoker | undefined;
    if (!fn) {
      const integrityFailure = handle.substrate === "local"
        ? this.integrityFailures.get(surface)
        : undefined;
      if (integrityFailure !== undefined) {
        return {
          response: integrityFailureResponse(integrityFailure.reason),
          methodAvailable: true,
        };
      }
      return {
        response: disabledResponse(
          handle.substrate,
          "substrate_capability_unsupported",
        ),
        methodAvailable: false,
      };
    }
    try {
      return { response: await fn(req), methodAvailable: true };
    } catch {
      return {
        response: failureResponse(
          handle.substrate,
          "substrate_unavailable",
          `${handle.substrate} ${surface} invocation failed`,
        ),
        methodAvailable: true,
      };
    }
  }

  private async tryNextSubstrate(
    surface: Surface,
    primary: SubstrateChoice,
    method: InvocationMethod,
    req: SummarizeRequest | ClassifyRequest | RedactRequest,
    requestLocalOnly: boolean,
  ): Promise<{
    handle: SubstrateHandle;
    response: SubstrateResponse;
    exhausted: boolean;
  } | null> {
    // Request-scoped local-only constraint (2026-09-15 slice; P0
    // fix-round-6): checked first, ahead of every other fallback gate,
    // using `requestLocalOnly` — the CALLER's snapshot, taken before
    // `invoke()`'s first await — never `req.localOnly`/
    // `isLocalOnlyRequest(req)` re-read here. This call happens after
    // `invokeHandle`'s await in `invoke()`, well after that snapshot; a
    // caller who mutated `req.localOnly` during that await must not be
    // able to flip this gate. Checked via the single authority
    // `refusesLocalOnly` (the substrate argument is a fixed non-local
    // placeholder: every later candidate substrate this function would
    // try, sliced from the fallback chain below, is, by construction,
    // never `"local"`, the fallback chain only ever moves forward, so the
    // boolean this produces is identical for any non-local placeholder;
    // it exists so this gate shares the ONE predicate rather than
    // checking `requestLocalOnly` bare). A local-only request's primary
    // local invocation failing is a terminal local-generation failure,
    // never a signal to try Venice/frontier next — the operator's
    // degrade-silent preference does not override a stricter per-request
    // requirement.
    if (refusesLocalOnly("venice", requestLocalOnly)) return null;
    if (this.config.fallback[surface] !== "degrade-silent") return null;
    if (primary === "disabled" || primary === "hybrid") return null;
    // An immune integrity refusal is a terminal local denial: operator fallback
    // preferences may route ordinary substrate failures, never failed model
    // identity evidence from the reviewed closed immune-surface set.
    if (
      primary === "local" &&
      IMMUNE_SURFACE_SET.has(surface) &&
      this.integrityFailures.has(surface)
    ) return null;
    // Ratified 2026-07-23: the pinned tier-2 surface never escapes
    // local via the fallback chain (local -> venice -> frontier would
    // be a remote egress of PII-residual-bearing text). The pin means
    // never-remote, not must-LLM: on local failure the Rho-2 caller
    // degrades to the regex-only result.
    if (surface === TIER2_PINNED_SURFACE) return null;
    const primaryIndex = FALLBACK_CHAIN.findIndex((choice) => choice === primary);
    if (primaryIndex < 0) return null;

    let lastFailure: { handle: SubstrateHandle; response: SubstrateResponse } | null = null;
    for (const choice of FALLBACK_CHAIN.slice(primaryIndex + 1)) {
      // Defense in depth (2026-09-15 slice, lens-B): this loop is already
      // unreachable for a local-only request via the early `return null`
      // above, but the handle-issuance guard in `getOrIssueHandle` is
      // passed the same opts here too, so the hosted-client-construction
      // defense does not rest on that one early return alone — a future
      // refactor that weakens or reorders the early return still cannot
      // let this call construct a hosted client for a local-only request.
      const handle = await this.getOrIssueHandle(surface, choice, {
        localOnly: requestLocalOnly,
      });
      if (handle.substrate !== choice) continue;
      const fn = handle[method] as SubstrateInvoker | undefined;
      if (!fn) continue;
      const attempt = await this.invokeHandle(surface, handle, method, req);
      if (!attempt.response.failureClass) {
        return { handle, response: attempt.response, exhausted: false };
      }
      lastFailure = { handle, response: attempt.response };
    }
    return lastFailure ? { ...lastFailure, exhausted: true } : null;
  }

  /**
   * Build a substrate handle for a surface bound to a concrete choice.
   * The substrate-client constructor is paid lazily so the selector
   * doesn't pre-spawn HTTP clients for substrates the operator never
   * touches.
   */
  private async getOrIssueHandle(
    surface: Surface,
    choice: SubstrateChoice,
    opts?: { localOnly?: boolean },
  ): Promise<SubstrateHandle> {
    // Defense in depth for the local-only constraint (2026-09-15 slice):
    // `invoke()` already refuses a conflicting binding before it ever calls
    // this method, so a caller that goes through `invoke()` never reaches
    // here with a mismatched `opts.localOnly`. But `getSubstrate()` is ALSO
    // a public entry point that consumers (concierge, operator chat) call
    // directly to read capability/display metadata before deciding whether
    // to invoke at all; without this guard, a capability pre-check on a
    // venice/frontier-bound surface would construct that hosted client here
    // (in `issueHandle` below) purely to answer "can I use this?", even
    // though the eventual invocation would be refused. Short-circuiting
    // BEFORE the `issuedHandles` cache lookup and BEFORE `issueHandle` means
    // a hosted client constructor is never reached for a local-only request
    // via this path either.
    //
    // P0 fix-round-8: `opts.localOnly` is read here, as the literal first
    // statement, via `readLocalOnlyOnce` — exactly once. Every caller of
    // this private method already passes a plain `{ localOnly }` object it
    // built itself (see `invoke`, `tryNextSubstrate`, `getSubstrate`), so
    // this is defense in depth for the entry point's own contract, not a
    // response to a known caller shape, per "every entry point" rather
    // than "every entry point that currently needs it."
    const localOnly = readLocalOnlyOnce(opts ?? {}) === true;
    const resolvedForOpts = this.resolveConcreteChoice(surface, choice);
    if (refusesLocalOnly(resolvedForOpts, localOnly)) {
      const audit = await this.auditLocalOnlyRefusal(surface, choice, resolvedForOpts, "binding_conflict");
      // Fix-round-9 (P1): this refusal's audit ATTEMPT result must reach
      // the caller the same way every other local-only refusal in this
      // file surfaces it (`failureResponse`'s `auditRecorded`/
      // `auditError` pair) — carrying only the content fields of
      // `disabledHandle(surface)` forward and discarding `audit` here
      // would leave a caller of the `getSubstrate()` capability-precheck
      // path with NO signal that a failing audit backend swallowed this
      // decision's own audit row, unlike `invoke()`'s equivalent refusal.
      return {
        ...this.disabledHandle(surface),
        ...(audit.recorded ? {} : { auditRecorded: false, auditError: audit.errorClass ?? "unknown" }),
      };
    }
    const key = `${surface}:${choice}`;
    const existing = this.issuedHandles.get(key);
    if (existing !== undefined && existing.epoch === this.integrityConfigEpoch) {
      return (await existing.promise).handle;
    }
    const epoch = this.integrityConfigEpoch;
    const promise = this.issueHandle(surface, choice, epoch);
    this.issuedHandles.set(key, { epoch, promise });
    let issued: HandleIssueResult;
    try {
      issued = await promise;
    } catch (error) {
      if (this.issuedHandles.get(key)?.promise === promise) {
        this.issuedHandles.delete(key);
      }
      throw error;
    }
    const current = this.issuedHandles.get(key);
    if (
      !issued.cacheable || epoch !== this.integrityConfigEpoch ||
      current?.promise !== promise
    ) {
      if (current?.promise === promise) this.issuedHandles.delete(key);
    }
    return issued.handle;
  }

  private async issueHandle(
    surface: Surface,
    choice: SubstrateChoice,
    epoch: number,
  ): Promise<HandleIssueResult> {
    if (choice === "disabled") {
      return { handle: this.disabledHandle(surface), cacheable: true };
    }
    if (choice === "local") return this.issueLocalHandle(surface, epoch);
    if (choice === "venice") {
      return { handle: this.veniceHandle(surface), cacheable: true };
    }
    if (choice === "frontier-with-filter") {
      return { handle: this.frontierHandle(surface), cacheable: true };
    }
    if (choice === "hybrid") {
      const sub = resolveHybridChoice(this.config.hybridRules, surface);
      if (sub) return this.issueHandle(surface, sub, epoch);
    }
    return { handle: this.disabledHandle(surface), cacheable: true };
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

  private async issueLocalHandle(
    surface: Surface,
    epoch: number,
  ): Promise<HandleIssueResult> {
    if (this.config.version === 1) {
      return {
        handle: this.gatedLocalHandle(surface, undefined, epoch),
        cacheable: true,
      };
    }
    const binding = this.config.localIntegrityState.bindings[surface];
    if (binding === undefined) {
      await this.recordIntegrityRefusal(
        surface,
        "integrity_state_invalid",
        "selector_load",
        undefined,
      );
      return {
        handle: this.integrityRefusalHandle(surface),
        cacheable: false,
      };
    }
    const gate = await this.runIntegrityGate({
      surface,
      binding,
      epoch,
      stage: "selector_load",
      diskCheckpoint: "selector_load",
    });
    if (!gate.ok) {
      return {
        handle: this.integrityRefusalHandle(surface),
        cacheable: false,
      };
    }
    return {
      handle: this.gatedLocalHandle(surface, binding, epoch, gate),
      cacheable: true,
    };
  }

  /**
   * The sole local-generation handle constructor. Structural tests prohibit
   * LocalSubstrate construction anywhere else in production selector code.
   */
  private gatedLocalHandle(
    surface: Surface,
    binding: VerifiedLocalBindingV2 | undefined,
    epoch: number,
    selectorLoadGate?: IntegrityGateSuccess,
  ): SubstrateHandle {
    const pick = this.config.localModelPicks[surface] ?? DEFAULT_LOCAL_MODEL_PICKS[surface] ?? "gemma-2-2b";
    const customTag = this.config.customLocalModelTags?.[surface];
    const endpoint = this.config.ollamaEndpoint ?? DEFAULT_OLLAMA_ENDPOINT;
    const client = new OllamaClient({ endpoint, fetchImpl: this.fetchImpl });
    const sub = LocalSubstrate.fromPick(client, pick, customTag);
    const labelBase = BACKEND_FALLBACK_STRINGS[BADGE_LABEL_KEYS.local] ?? "Local model";
    // With no verified binding, whatever `LocalSubstrate.fromPick` invokes IS
    // this handle's model. The shared invariant with that constructor
    // (`intelligence/substrates/local.ts`) is narrow and exact: the custom tag
    // wins on both sides. Only the second arm differs, and deliberately, since
    // the two are answering different questions: with no custom tag the label
    // shows the pick's HUMAN name from `LOCAL_MODEL_LABELS` while the runtime
    // calls the pick's TAG from `LOCAL_MODEL_TAGS`.
    // No `?? LOCAL_MODEL_TAGS[pick]` tail here: `LOCAL_MODEL_LABELS` is a total
    // `Record<LocalModelPick, string>`, so such a tail would be dead code, and
    // reading that table BEFORE `customTag` is what once made the custom-tag
    // arm unreachable and showed the friendly name of a pick nothing called.
    const unarmedLabel = customTag ?? LOCAL_MODEL_LABELS[pick];
    // INVARIANT: on an armed fortress the verified binding is what this surface
    // actually invokes — `commitLocalIntegrityProvisioning` writes the binding's
    // tag into `customLocalModelTags` while `pick` stays at its configured
    // default — so naming the pick here would name a model that is not running.
    // The manifest digest prefix travels WITH the tag because a tag alone names
    // a subject with nothing to check it against; the prefix is the public
    // manifest root the binding was verified to, and it is the same value, at
    // the same width, that the ceremony's "Local intelligence armed" line and
    // `sanctuary intelligence diagnose` print.
    const modelLabel = binding === undefined
      ? unarmedLabel
      : `${binding.runtime_tag} (armed binding, manifest sha256 ` +
        `${binding.ollama_identity.ollama_manifest_sha256.slice(0, ARMED_DIGEST_PREFIX_CHARS)})`;
    let firstInvocationPassed = false;
    let lastFullMonotonicMs = selectorLoadGate?.completedMonotonicMs;
    let lastFullWallMs = selectorLoadGate?.completedWallMs;

    const beforeInvocation = async (): Promise<IntegrityGateResult> => {
      if (binding === undefined) {
        if (epoch !== this.integrityConfigEpoch && this.config.version === 2) {
          await this.recordIntegrityRefusal(
            surface,
            "binding_mismatch",
            "first_invocation",
            undefined,
          );
          return { ok: false, reason: "binding_mismatch" };
        }
        const completedMonotonicMs = this.integrityClock.monotonicNow();
        const completedWallMs = this.integrityClock.wallNow();
        return { ok: true, completedMonotonicMs, completedWallMs };
      }

      if (!firstInvocationPassed) {
        const result = await this.runIntegrityGate({
          surface,
          binding,
          epoch,
          stage: "first_invocation",
          diskCheckpoint: "first_invocation",
        });
        if (result.ok) {
          firstInvocationPassed = true;
          lastFullMonotonicMs = result.completedMonotonicMs;
          lastFullWallMs = result.completedWallMs;
        }
        return result;
      }

      // A held handle never outranks current V2 authority: epoch, exact binding,
      // assurance class, and loopback endpoint remain reuse terminators even
      // while the light six-hour verification result is otherwise reusable.
      if (!this.integrityAuthorityMatches(surface, binding, epoch)) {
        await this.recordIntegrityRefusal(
          surface,
          "binding_mismatch",
          "runtime_invocation",
          binding,
        );
        return { ok: false, reason: "binding_mismatch" };
      }

      if (binding.assurance === "immune") {
        const result = await this.runIntegrityGate({
          surface,
          binding,
          epoch,
          stage: "runtime_invocation",
          diskCheckpoint: "cadence",
        });
        if (result.ok) {
          lastFullMonotonicMs = result.completedMonotonicMs;
          lastFullWallMs = result.completedWallMs;
        }
        return result;
      }

      const monotonicNow = this.integrityClock.monotonicNow();
      const wallNow = this.integrityClock.wallNow();
      if (!lightVerificationIsDue(
        lastFullMonotonicMs,
        lastFullWallMs,
        monotonicNow,
        wallNow,
      )) {
        return {
          ok: true,
          completedMonotonicMs: monotonicNow,
          completedWallMs: wallNow,
        };
      }
      const result = await this.runIntegrityGate({
        surface,
        binding,
        epoch,
        stage: "cadence",
      });
      if (result.ok) {
        lastFullMonotonicMs = result.completedMonotonicMs;
        lastFullWallMs = result.completedWallMs;
      }
      return result;
    };

    const invokeGated = async (invoke: () => Promise<SubstrateResponse>) => {
      const gate = await beforeInvocation();
      if (!gate.ok) return integrityFailureResponse(gate.reason);
      // There is no application-controlled await after this final gate. This
      // closes the selector-to-first-invoke gap, but not a malicious-runtime
      // race after the final check; only the HTTP client's own scheduling remains.
      return invoke();
    };
    return {
      surface,
      substrate: "local",
      badge: this.makeBadge(surface, "local", "green"),
      capability: LOCAL_CAPABILITY,
      displayLabel: `${labelBase} — ${modelLabel}`,
      summarize: (r) => invokeGated(() => sub.summarize(r)),
      classify: (r) => invokeGated(() => sub.classify(r)),
      redact: (r) => invokeGated(() => sub.redact(r)),
    };
  }

  private integrityRefusalHandle(surface: Surface): SubstrateHandle {
    const labelBase = BACKEND_FALLBACK_STRINGS[BADGE_LABEL_KEYS.local] ?? "Local model";
    return {
      surface,
      substrate: "local",
      badge: this.makeBadge(surface, "local", "yellow"),
      capability: DISABLED_CAPABILITY,
      displayLabel: labelBase,
    };
  }

  private runtimeVerifierForCurrentEndpoint(): RuntimeLightVerifier {
    if (this.runtimeIntegrityVerifierOverride !== undefined) {
      return this.runtimeIntegrityVerifierOverride;
    }
    const endpoint = this.config.ollamaEndpoint ?? DEFAULT_OLLAMA_ENDPOINT;
    if (
      this.runtimeIntegrityVerifier === null ||
      this.runtimeIntegrityVerifierEndpoint !== endpoint
    ) {
      this.runtimeIntegrityVerifier = createSingleFlightLightRuntimeVerifier(
        new OllamaRuntimeEvidenceClient({
          endpoint,
          fetchImpl: this.fetchImpl,
        }),
      );
      this.runtimeIntegrityVerifierEndpoint = endpoint;
    }
    return this.runtimeIntegrityVerifier;
  }

  private async runIntegrityGate(args: {
    surface: Surface;
    binding: VerifiedLocalBindingV2;
    epoch: number;
    stage: IntegrityGateStage;
    diskCheckpoint?: ImmuneVerificationCheckpoint;
  }): Promise<IntegrityGateResult> {
    const { surface, binding, epoch, stage } = args;
    if (!this.integrityAuthorityMatches(surface, binding, epoch)) {
      await this.recordIntegrityRefusal(surface, "binding_mismatch", stage, binding);
      return { ok: false, reason: "binding_mismatch" };
    }
    const integrityState = this.config.version === 2
      ? this.config.localIntegrityState
      : undefined;
    // `integrityAuthorityMatches` proved the V2 authority above; this guard
    // keeps the narrowing explicit if its implementation is later refactored.
    if (integrityState === undefined) {
      await this.recordIntegrityRefusal(surface, "binding_mismatch", stage, binding);
      return { ok: false, reason: "binding_mismatch" };
    }

    const request = {
      rootReal: integrityState.ollama_models_root,
      binding,
    };
    const runtimePromise = this.runtimeVerifierForCurrentEndpoint().verify(request);
    const runtime = await runtimePromise;
    if (!runtime.ok) {
      await this.recordIntegrityRefusal(
        surface,
        runtime.reason,
        stage,
        binding,
        runtimePromise,
        runtime,
      );
      return { ok: false, reason: runtime.reason };
    }
    if (epoch !== this.integrityConfigEpoch) {
      await this.recordIntegrityRefusal(surface, "binding_mismatch", stage, binding);
      return { ok: false, reason: "binding_mismatch" };
    }

    if (binding.assurance === "light") {
      const completed = this.completedIntegrityGate();
      if (!completed.ok) {
        await this.recordIntegrityRefusal(
          surface,
          completed.reason,
          stage,
          binding,
          runtimePromise,
          runtime,
        );
        return completed;
      }
      this.integrityFailures.delete(surface);
      if (stage === "selector_load" || stage === "cadence") {
        await this.recordIntegritySuccess(
          surface,
          stage,
          binding,
          runtimePromise,
          runtime,
        );
      }
      return completed;
    }

    const diskCheckpoint = args.diskCheckpoint ?? "cadence";
    const diskPromise = this.immuneIntegrityVerifier.verify({
      ...request,
      checkpoint: diskCheckpoint,
    });
    const disk = await diskPromise;
    const diskStage: IntegrityGateStage = diskCheckpoint === "cadence"
      ? "cadence"
      : stage;
    if (!disk.ok) {
      await this.recordIntegrityRefusal(
        surface,
        disk.reason,
        diskStage,
        binding,
        diskPromise,
        undefined,
        disk,
      );
      return { ok: false, reason: disk.reason };
    }
    if (epoch !== this.integrityConfigEpoch) {
      await this.recordIntegrityRefusal(surface, "binding_mismatch", diskStage, binding);
      return { ok: false, reason: "binding_mismatch" };
    }

    const completed = this.completedIntegrityGate();
    if (!completed.ok) {
      await this.recordIntegrityRefusal(
        surface,
        completed.reason,
        diskStage,
        binding,
        diskPromise,
        runtime,
        disk,
      );
      return completed;
    }
    this.integrityFailures.delete(surface);
    if (
      stage === "selector_load" ||
      (diskCheckpoint === "cadence" && !disk.cached)
    ) {
      await this.recordIntegritySuccess(
        surface,
        diskStage,
        binding,
        diskPromise,
        runtime,
        disk,
      );
    }
    return completed;
  }

  private integrityAuthorityMatches(
    surface: Surface,
    binding: VerifiedLocalBindingV2,
    epoch: number,
  ): boolean {
    if (this.config.version !== 2) return false;
    const expectedAssurance = IMMUNE_SURFACE_SET.has(surface) ? "immune" : "light";
    return epoch === this.integrityConfigEpoch &&
      this.config.localIntegrityState.bindings[surface] === binding &&
      binding.assurance === expectedAssurance &&
      isLoopbackOllamaEndpoint(
        this.config.ollamaEndpoint ?? DEFAULT_OLLAMA_ENDPOINT,
      );
  }

  private completedIntegrityGate(): IntegrityGateResult {
    const completedMonotonicMs = this.integrityClock.monotonicNow();
    const completedWallMs = this.integrityClock.wallNow();
    if (
      !Number.isFinite(completedMonotonicMs) || completedMonotonicMs < 0 ||
      !Number.isFinite(completedWallMs) || completedWallMs < 0
    ) {
      return { ok: false, reason: "integrity_io_unavailable" };
    }
    return { ok: true, completedMonotonicMs, completedWallMs };
  }

  private async recordIntegritySuccess(
    surface: Surface,
    stage: IntegrityGateStage,
    binding: VerifiedLocalBindingV2,
    gatePromise: object,
    runtime: Extract<RuntimeLightVerificationResult, { ok: true }>,
    disk?: Extract<ImmuneVerificationResult, { ok: true }>,
  ): Promise<void> {
    if (this.auditedIntegrityPromises.has(gatePromise)) return;
    this.auditedIntegrityPromises.add(gatePromise);
    const details: Record<string, string | number | boolean> = {
      surface,
      model_id: binding.model_id,
      manifest_version: binding.manifest_version,
      assurance: binding.assurance,
      stage,
      expected_manifest_digest: binding.ollama_identity.ollama_manifest_sha256,
      observed_manifest_digest: runtime.observedManifestDigest,
      generation_refused: false,
    };
    if (disk !== undefined) {
      details.descriptor_count = disk.descriptorCount;
      details.bytes_hashed = disk.bytesHashed;
    }
    try {
      await this.auditLog.append(
        "l2",
        INTEL_OPS.LOAD_INTEGRITY,
        this.identityId,
        details,
        "success",
      );
    } catch {
      // Verification authority is the signed state plus gate result; audit is derived evidence.
    }
  }

  private async recordIntegrityRefusal(
    surface: Surface,
    reason: ModelLoadIntegrityFailureReason,
    stage: IntegrityGateStage,
    binding?: VerifiedLocalBindingV2,
    gatePromise?: object,
    runtime?: RuntimeLightVerificationResult,
    disk?: ImmuneVerificationResult,
  ): Promise<void> {
    const prior = this.integrityFailures.get(surface);
    const incomingContentMismatch = CONTENT_MISMATCH_REASONS.has(reason);
    // A transient outage cannot erase the last content mismatch; only a later
    // complete successful verification clears this process's degraded latch.
    if (!(prior?.contentMismatchLatched && !incomingContentMismatch)) {
      this.integrityFailures.set(surface, {
        reason,
        observedAt: new Date().toISOString(),
        contentMismatchLatched: incomingContentMismatch,
      });
    }
    if (gatePromise !== undefined) {
      if (this.auditedIntegrityPromises.has(gatePromise)) return;
      this.auditedIntegrityPromises.add(gatePromise);
    }
    const details: Record<string, string | number | boolean> = {
      surface,
      stage,
      reason,
      generation_refused: true,
    };
    if (binding !== undefined) {
      details.model_id = binding.model_id;
      details.manifest_version = binding.manifest_version;
      details.assurance = binding.assurance;
      details.expected_manifest_digest =
        binding.ollama_identity.ollama_manifest_sha256;
    }
    if (
      runtime !== undefined && "observedManifestDigest" in runtime &&
      typeof runtime.observedManifestDigest === "string"
    ) {
      details.observed_manifest_digest = runtime.observedManifestDigest;
    }
    if (disk?.ok) {
      details.descriptor_count = disk.descriptorCount;
      details.bytes_hashed = disk.bytesHashed;
    }
    try {
      await this.auditLog.append(
        "l2",
        INTEL_OPS.LOAD_INTEGRITY,
        this.identityId,
        details,
        "failure",
      );
    } catch {
      // Refusal remains fail-closed even when derived audit persistence is unavailable.
    }
  }

  private invalidateIssuedIntegrityHandles(): void {
    this.integrityConfigEpoch += 1;
    this.issuedHandles.clear();
    this.runtimeIntegrityVerifier = null;
    this.runtimeIntegrityVerifierEndpoint = null;
    this.immuneIntegrityVerifier.invalidate();
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
        if (expectedTag && !ollamaHasModel(hardware.ollamaModels, expectedTag)) {
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
    const integrityFailure = this.integrityFailures.get(surface);
    if (integrityFailure !== undefined) {
      health = "degraded";
      failureClass = integrityFailure.reason === "integrity_io_unavailable"
        ? "substrate_unavailable"
        : "substrate_misconfigured";
      recentFailures.push({
        ts: integrityFailure.observedAt,
        failureClass,
        snippet: `local load refused: ${integrityFailure.reason}`,
      });
      while (recentFailures.length > RECENT_FAILURES_CAP) recentFailures.shift();
    }
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

  private fallbackFailureAction(surface: Surface, primary: SubstrateChoice): FallbackTaken {
    if (primary === "disabled") return "disable-surface";
    const behavior = this.config.fallback[surface];
    if (behavior === "degrade-silent") return "primary-failed";
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
    void this.auditLog.append("l2", operation, this.identityId, payload as unknown as Record<string, unknown>, result);
  }

  /**
   * Awaited variant of `emit` for the `invoke()` path. Substrate-invocation
   * audit rows must be persisted before the response reaches the caller,
   * so a short-lived caller can safely exit after awaiting the invocation.
   * A failed audit write is
   * re-thrown as a generic error (no raw storage details) so the caller
   * exits nonzero; the record of what happened must reach persistent storage.
   */
  private async emitAwaited(
    operation: string,
    payload: IntelligenceAuditPayload,
    result: "success" | "failure",
  ): Promise<void> {
    try {
      await this.auditLog.append("l2", operation, this.identityId, payload as unknown as Record<string, unknown>, result);
    } catch {
      // Re-throw a generic error without raw storage details or private
      // paths; the raw cause is intentionally discarded to avoid leaking
      // storage internals through the concierge error surface.
      throw new Error("intelligence audit persistence failed");
    }
  }
}

// ── helpers ─────────────────────────────────────────────────────────────

function makeEventId(): string {
  return `int-${Date.now()}-${toBase64url(randomBytes(8))}`;
}

/**
 * Fix-round-10 (P1, item 3): reads every one of `req`'s NAMED CONTENT
 * FIELDS exactly once, via ordinary property access (which works
 * identically on a plain data property or a prototype getter, enumerable
 * or not), and returns a plain object holding those single-read values.
 * `invoke()` calls this ONCE, immediately after its own single
 * `localOnly` read, and uses the RESULT for screening, both hashes, and
 * the actual substrate invocation from that point on -- `req` itself is
 * never read for its content again. Without this, a STATEFUL getter
 * (one that returns different content on each read) could present
 * DIFFERENT content to the pre-egress context scanner, the audit hash,
 * and the substrate actually invoked: the thing screened, the thing
 * recorded, and the thing sent would then be three different values,
 * which is not auditable at all.
 *
 * Field VALUES are preserved exactly as read -- including `undefined`
 * for an omitted optional field -- rather than coerced or defaulted.
 * This is what keeps `hashOfRequest`'s LEGACY preimage byte-identical to
 * what `JSON.stringify(req)` produced for any well-formed (non-stateful)
 * caller: `JSON.stringify` itself already skips an `undefined`-valued
 * property, so a materialized object that preserves `undefined` exactly
 * where the original had it serializes identically to the original.
 */
function materializeRequestContent(
  req: SummarizeRequest | ClassifyRequest | RedactRequest,
): SummarizeRequest | ClassifyRequest | RedactRequest {
  if (req.kind === "summarize") {
    return {
      kind: "summarize",
      context: req.context,
      query: req.query,
      maxTokens: req.maxTokens,
      contextProvenance: req.contextProvenance,
    };
  }
  if (req.kind === "classify") {
    return { kind: "classify", items: req.items, categories: req.categories, maxTokens: req.maxTokens };
  }
  return { kind: "redact", text: req.text };
}

/**
 * Fix-round-10 (P1, item 2): reverted to the EXACT preimage shape this
 * function had before fix-round-9 (Codex round-5 finding: fix-round-9's
 * version silently changed `request_hash`'s MEANING -- adding `surface`,
 * coercing `localOnly` to an always-present boolean, and turning omitted
 * optional fields into explicit `null`s -- with no version bump, so an
 * identical HISTORICAL request would hash differently after that round,
 * and a request that never set `localOnly` at all, the common case for
 * every pre-2026-09-15 caller, would suddenly hash as `localOnly: false`
 * instead of omitting the key). This function's ONLY job is to reproduce
 * what `JSON.stringify(req)` produced originally: the request's own named
 * fields (from `content`, the fix-round-10 single-read materialization --
 * see `materializeRequestContent`), `undefined`-valued/omitted fields
 * skipped (`JSON.stringify`'s own behavior, not special-cased here), and
 * `localOnly` present ONLY when the original request actually set it
 * (`rawLocalOnly`, the UNCOERCED value `readLocalOnlyOnce` returned --
 * seeing `undefined` here reproduces "the caller never set this field"
 * exactly, where a pre-coerced `false` could not).
 *
 * `content` and `rawLocalOnly` are both read ONCE, at `invoke()`'s entry,
 * never re-read here -- this function hashes the MATERIALIZED snapshot,
 * never the caller's live object, so a stateful getter cannot make this
 * hash disagree with what was actually screened and invoked, while a
 * well-behaved caller's historical hash is unaffected byte-for-byte.
 *
 * The NEW, more complete projection (surface-bound, coerced-boolean,
 * explicit-null) lives separately in `hashOfRequestProjection`, under a
 * NEW audit field, `request_projection_hash`, documented there and on
 * the contract as preimage version 2 -- so nothing historical breaks
 * while the more correct hash is still committed to.
 */
function hashOfRequest(
  content: SummarizeRequest | ClassifyRequest | RedactRequest,
  rawLocalOnly: boolean | undefined,
): string {
  return hashToString(sha256(stringToBytes(JSON.stringify({ ...content, localOnly: rawLocalOnly }))));
}

/**
 * Fix-round-9 (P1), retained under a NEW name (fix-round-10, P1, item 2):
 * explicit, named-field projection of a request's audited content, bound
 * to the surface it was submitted against, with `localOnly` coerced to a
 * real boolean (never omitted) and every omitted optional content field
 * made an EXPLICIT `null` (never silently absent). This is preimage
 * VERSION 2: more complete than `hashOfRequest`'s legacy preimage, but
 * under its OWN field (`request_projection_hash`) so it never collides
 * with or silently reinterprets the legacy one. `content` (the
 * fix-round-10 single-read materialization) is what this hashes, never
 * `req` directly, for the same stateful-getter reason `hashOfRequest`
 * documents.
 */
function canonicalRequestProjection(
  surface: Surface,
  localOnly: boolean,
  content: SummarizeRequest | ClassifyRequest | RedactRequest,
): Record<string, unknown> {
  const base = { surface, kind: content.kind, localOnly };
  if (content.kind === "summarize") {
    return {
      ...base,
      context: content.context,
      query: content.query,
      maxTokens: content.maxTokens ?? null,
      contextProvenance: content.contextProvenance ?? null,
    };
  }
  if (content.kind === "classify") {
    return { ...base, items: content.items, categories: content.categories, maxTokens: content.maxTokens ?? null };
  }
  return { ...base, text: content.text };
}

function hashOfRequestProjection(
  surface: Surface,
  localOnly: boolean,
  content: SummarizeRequest | ClassifyRequest | RedactRequest,
): string {
  return hashToString(sha256(stringToBytes(JSON.stringify(canonicalRequestProjection(surface, localOnly, content)))));
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

function disabledResponse(servedBy: SubstrateChoice, failureClass: SubstrateFailureClass): SubstrateResponse {
  return failureResponse(
    servedBy,
    failureClass,
    "substrate disabled or unsupported for this method",
  );
}

function failureResponse(
  servedBy: SubstrateChoice,
  failureClass: SubstrateFailureClass,
  message: string,
  localOnlyReason?: "binding_conflict" | "local_unavailable",
  auditResult?: LocalOnlyAuditResult,
): SubstrateResponse {
  return {
    servedBy,
    failureClass,
    body: { kind: "failure", message },
    completedAt: new Date().toISOString(),
    latencyMs: 0,
    ...(localOnlyReason ? { localOnlyReason } : {}),
    // Fix-round-6 (P1, item 3): only ever set when the refusal's audit
    // write FAILED; a successful write (or a response this helper builds
    // for a non-local-only refusal, where `auditResult` is never passed)
    // leaves both fields absent.
    ...(auditResult && !auditResult.recorded
      ? { auditRecorded: false, auditError: auditResult.errorClass ?? "unknown" }
      : {}),
  };
}

function integrityFailureResponse(
  reason: ModelLoadIntegrityFailureReason,
): SubstrateResponse {
  return failureResponse(
    "local",
    reason === "integrity_io_unavailable"
      ? "substrate_unavailable"
      : "substrate_misconfigured",
    `local load refused: ${reason}`,
  );
}

function lightVerificationIsDue(
  completedMonotonicMs: number | undefined,
  completedWallMs: number | undefined,
  monotonicNow: number,
  wallNow: number,
): boolean {
  if (
    completedMonotonicMs === undefined || completedWallMs === undefined ||
    !Number.isFinite(completedMonotonicMs) ||
    !Number.isFinite(completedWallMs) ||
    !Number.isFinite(monotonicNow) || !Number.isFinite(wallNow)
  ) {
    return true;
  }
  const elapsed = monotonicNow - completedMonotonicMs;
  // Design sections 7.1/7.3: performance.now() owns the six-hour cache;
  // wall-clock rollback can only make verification due, never extend trust.
  return elapsed < 0 || wallNow < completedWallMs ||
    elapsed >= IMMUNE_FULL_VERIFICATION_CADENCE_MS;
}

function isLoopbackOllamaEndpoint(endpoint: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return false;
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) return false;
  const rawHost = parsed.hostname.toLowerCase();
  const host = rawHost.startsWith("[") && rawHost.endsWith("]")
    ? rawHost.slice(1, -1)
    : rawHost;
  if (host === "localhost" || host === "::1") return true;
  if (isIP(host) !== 4) return false;
  // Design section 5.3 accepts the complete IPv4 127.0.0.0/8 loopback block.
  return host.split(".")[0] === "127";
}

function withTotalLatency(resp: SubstrateResponse, startedAt: number): SubstrateResponse {
  return {
    ...resp,
    completedAt: new Date().toISOString(),
    latencyMs: Date.now() - startedAt,
  };
}

function healthToBadgeStatus(health: "ok" | "degraded" | "unavailable"): SubstrateBadge["status"] {
  if (health === "ok") return "green";
  if (health === "degraded") return "yellow";
  return "red";
}

/**
 * Finding ZZ (v1.2.0-rc.6): Ollama returns model names with their full
 * `name:tag` form via `/api/tags`. A model pulled with `ollama pull phi4-mini`
 * (no explicit tag) is stored under the default `latest` tag and listed as
 * `phi4-mini:latest`. The probe's `expectedTag` from `LOCAL_MODEL_TAGS` may
 * lack the explicit `:latest` suffix (e.g. `"phi4-mini"`), so a strict
 * `includes(expectedTag)` check produced `substrate_misconfigured` even when
 * the model was actually present and inference would succeed.
 *
 * Match policy: exact match wins; when `expectedTag` lacks a colon, also
 * accept the `${expectedTag}:latest` form. Operator-supplied custom tags
 * (which always carry an explicit tag) keep exact-match semantics.
 */
function ollamaHasModel(models: readonly string[], expectedTag: string): boolean {
  if (models.includes(expectedTag)) return true;
  if (!expectedTag.includes(":")) return models.includes(`${expectedTag}:latest`);
  return false;
}

export type { LoadOutcome };
