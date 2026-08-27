/**
 * v1.1 Server Wiring (v1.1.1 hotfix; agent-registry persistence in v1.1.5)
 *
 * v1.1.0 shipped the v1.1 module suite (dashboard / hub API / exit bundle
 * endpoints / coordination) but no entry-point server imported any of it.
 * This module builds the canonical HubService construction the dashboard
 * entry points share so the routes light up at boot without forcing each
 * caller to know the deps shape.
 *
 * The wiring is deliberately minimal at v1.1.1:
 *
 *   - Local agent registry rehydrates from the required fortress
 *     `storagePath` (`<storagePath>/state/_hub/local-agents.json`),
 *     written by `sanctuary wrap` for each successfully wrapped harness.
 *     Real harness-discovery via `discoverTenants()` remains v1.2 work.
 *   - Inbox sources return empty arrays. The privacy chokepoint already
 *     emits audit events through PR #69 / PR #71; the inbox aggregator is
 *     the v1.2 work to project those into operator cards.
 *   - Activity feed reads from the real audit log. This is the one source
 *     that's already complete in v1.1.0 and just needs to be plugged in.
 *   - Agent controller errors on runtime harness actions that v1.1 cannot
 *     honestly execute. Channel-template binding is registry-local in v1.2,
 *     so its controller hook is a no-op and HubService persists the binding
 *     after Tier 1 approval.
 */

import { createHash, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { defaultConfig, type SanctuaryConfig } from "../../config.js";
import { exportExitBundle } from "../../exit/bundle.js";
import type { AuditLog } from "../../operational/audit-log.js";
import {
  auditEntryAgentId,
  type AuditAttributionOptionsResolver,
} from "../../castle-wall/audit-attribution.js";
import {
  loadFortressProducerKey,
  type ProducerKeyLoad,
} from "../../castle-wall/runtime/producer-signature.js";
import { IdentityManager } from "../../cognitive/tools.js";
import { StateStore } from "../../cognitive/state-store.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
} from "../../hub/index.js";
import {
  readPersistedLocalAgents,
  writePersistedLocalAgents,
} from "../../hub/agent-registry-persistence.js";
import {
  CastleWallAgentController,
  type CastleWallAgentControllerDeps,
} from "./castle-wall-agent-controller.js";
import {
  agentRecordAttributionIds,
  publicAgentIdForVerifiedAttribution,
} from "../../hub/agent-attribution.js";
import type { LocalAgentRecord } from "../../contracts/v1.1/local-agent-records.js";
import type { SubstrateSelector } from "../../intelligence/selector.js";
import type { ReputationStore } from "../../reputation/reputation-store.js";
import { loadPrincipalPolicy } from "../../principal-policy/loader.js";
import type { PrincipalPolicy } from "../../principal-policy/types.js";
import type { StorageBackend } from "../../storage/interface.js";
import {
  ConciergeService,
  SanctuaryContextReader,
} from "../../concierge/index.js";
import {
  ConciergeMemoryStore,
  AgentContextCache,
  OperatorChatService,
  OperatorChatStore,
  type ConciergeContextProviders,
  type ConciergePiiFilter,
} from "../../chat/operator-chat-index.js";
import type {
  ContextFetchers,
  LlmAssistClassifier,
  ContextCategory,
} from "../../chat/concierge-context-router.js";
import {
  detectSensitiveSpans,
  detectorClassForSpan,
} from "../../operational/privacy-filter.js";
import { listTemplates } from "../../templates/registry.js";
import type { ConsoleService } from "../../console/console-service.js";
import { SentinelFindingStore } from "../../sentinel/sentinel-finding-store.js";
import { AnomalyPipelineDispatcher } from "../../anomaly-detection/anomaly-pipeline.js";
import { EnglishPolicyDraftStore } from "../../policy-engine/english-policy-routes.js";
import { EnglishPolicyCompiler } from "../../policy-engine/english-policy-compiler.js";
import type { EnglishPolicyActivator } from "../../policy-engine/english-policy-activator.js";
import { PiiConfigStore } from "../../query-anonymity/pii-config-store.js";
import { ReverseMappingStore } from "../../query-anonymity/reverse-mapping-store.js";
import {
  DID_WEB_AUDIT_OPS,
  dropExpiredDidWebKeys,
  identifierFromFortressDidWebRecord,
  loadFortressDidWebRecord,
  publishDidWebDocument,
  type DidWebIdentifier,
} from "../../recognition/did-web.js";

export interface BuildV11BindingsInputs {
  /** Operator identity id this hub is scoped to. */
  identityId: string;
  /** Stable fortress id surfaced through the API + dashboard top bar. */
  fortressId: string;
  /** Underlying audit log; powers the activity feed projection. */
  auditLog: AuditLog;
  /**
   * Fortress storage root. The agent registry rehydrates
   * from `<storagePath>/state/_hub/local-agents.json` (best-effort; a
   * missing or unparseable file degrades to an empty registry rather
   * than failing construction). Required because the live Castle Wall
   * controller cannot safely mutate enforcement without a fortress path.
   */
  storagePath: string;
  /**
   * Test seam for the Castle Wall network stop. Production omits this and
   * uses the real stop actuator constructed by `CastleWallAgentController`.
   */
  stopAgentEgress?: CastleWallAgentControllerDeps["stopAgentEgress"];
  /**
   * Optional Intelligence Substrate Selector. When present, the dashboard
   * dispatch layer mounts `/api/hub/intelligence/*` against this selector
   * and the v1.1 SPA renders the Intelligence panel from its config.
   *
   * The selector is constructed by the entry point (which has access to
   * the fortress storage backend, master key, and audit log) and passed
   * through here so this wiring layer stays storage-agnostic.
   *
   * Callers that omit it (early v1.2 boots, ephemeral test harnesses)
   * still get a working hub binding; the dashboard's Intelligence panel
   * surfaces a "not configured" state instead of failing to render.
   */
  intelligenceSelector?: SubstrateSelector;
  /**
   * Fortress storage backend. Required to wire the v1.2 operator chat
   * surfaces (encrypted thread persistence under the reserved `_chat`
   * namespace). Omit at construction time if the caller wants the v1.1
   * hub surface only; chat routes return HubCapabilityError until the
   * service is wired.
   */
  storage?: StorageBackend;
  /**
   * Fortress master key. Required to wire the v1.2 operator chat
   * surfaces (HKDF-derived purpose key for encrypted thread storage).
   * Omit and the chat service is not constructed.
   */
  masterKey?: Uint8Array;
  /** Optional loaded identity manager for fortress-scope export wiring. */
  identityManager?: IdentityManager;
  /** Optional loaded reputation store for fortress-scope export wiring. */
  reputationStore?: ReputationStore;
  /** Optional already-loaded principal policy for fortress-scope export. */
  policy?: PrincipalPolicy;
  /** Optional loaded config for fortress-scope export metadata. */
  config?: SanctuaryConfig;
  /**
   * Operator-tunable retention window for the WP-V1.3-9 Tau-1 concierge
   * memory store. Defaults to 30 days when omitted. Wired through from
   * `principal-policy.yaml` `concierge_memory_retention_days`.
   */
  conciergeMemoryRetentionDays?: number;
  /**
   * Operator Console domain service. The console (`/api/console/*`,
   * `/console` static) is mounted behind the shared dashboard auth
   * chokepoint when this is present. Constructed by the entry point
   * (which owns the FortressService + node/principal signing keys); the
   * dashboard wiring layer stays storage-agnostic and does not build it.
   * Omit and the prefix answers 503 "not configured" (after auth).
   */
  consoleService?: ConsoleService;
  /**
   * Optional static asset dir for the console SPA, threaded to
   * `handleConsoleRoute`'s `publicDir`.
   */
  consolePublicDir?: string;
  /**
   * Optional English-authored-policy activation lifecycle. When present
   * it is threaded into the `/api/policy/*` routes so activate / revoke /
   * status work; absent, the compile-only review surface still works and
   * the lifecycle routes return 503.
   */
  englishPolicyActivator?: EnglishPolicyActivator;
  /**
   * Whether the entry point installed the consent-gated Tier B PII
   * redactor (`buildConsentGatedTier2Redactor`) on the production
   * substrate selector for this fortress. Threaded into the
   * `/api/query-anonymity/pii` route so `effective_tier_b_enabled`
   * reports the truthful active state. Defaults to false; an unwired
   * binding reports inactive.
   */
  tierBPiiRedactorInstalled?: boolean;
  /**
   * Optional fixed Castle Wall producer public key for read-side audit
   * attribution. Production callers usually omit this and let the wiring load
   * from `storagePath`; tests can inject a deterministic key.
   */
  pinnedProducerKeyB64url?: string | null;
  /**
   * Optional live attribution resolver. When supplied it wins over the fixed
   * key/storage loader and lets an entry point share an already-loaded key cache.
   */
  resolveAuditAttribution?: AuditAttributionOptionsResolver;
  /**
   * Optional warning sink for producer-key load failures. Default is stderr via
   * `console.error`; tests can inject a no-op when exercising unreadable keys.
   */
  warnProducerKeyUnavailable?: (reason: string) => void;
  /**
   * Optional PRE-CONSTRUCTED SentinelFindingStore for this fortress (MUST-FIX
   * 5, fix-round-2 RECHECK). When supplied — as index.ts's embedded-server
   * boot path does — the anomaly-detection binding below REUSES this
   * instance instead of constructing its own. A caller that also runs an
   * independent sentinel-dispatch boot path against the SAME fortress (only
   * index.ts does; `dashboard-standalone.ts` does not) MUST supply this,
   * because two independent `SentinelFindingStore` instances maintain two
   * DISJOINT in-memory filter indexes over the same storage namespace — a
   * write through one is invisible to a `listFindings`/`listFindingMetadata`
   * call through the other until that record ages past retention, which
   * silently hides findings from whichever surface did not receive the
   * write. Omit when this wiring layer owns the only store for the fortress
   * (dashboard-standalone.ts, and every other caller of `buildV11Bindings`);
   * a fresh instance is then constructed exactly as before.
   */
  sentinelFindingStore?: SentinelFindingStore;
}

/** Anomaly-detection binding mounted behind the dashboard auth chokepoint. */
export interface V11AnomalyBinding {
  dispatcher: AnomalyPipelineDispatcher;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  identityId: string;
  storage: StorageBackend;
  masterKey: Uint8Array;
  fortressId: string;
}

/**
 * Tier B PII-rewrite binding mounted behind the dashboard auth
 * chokepoint at `/api/query-anonymity/pii`. The `redactorInstalled`
 * flag carries whether the production substrate selector actually has
 * the consent-gated redactor installed, so the route reports the
 * truthful `effective_tier_b_enabled`.
 */
export interface V11PiiRewriteBinding {
  store: PiiConfigStore;
  auditLog: AuditLog;
  identityId: string;
  fortressId: string;
  redactorInstalled: boolean;
}

/** English-policy binding mounted behind the dashboard auth chokepoint. */
export interface V11EnglishPolicyBinding {
  compiler: EnglishPolicyCompiler;
  store: EnglishPolicyDraftStore;
  activator?: EnglishPolicyActivator;
  defaultOperatorId?: string;
}

export interface V11Bindings {
  hubService: HubService;
  identityId: string;
  fortressId: string;
  storagePath: string;
  masterKey?: Uint8Array;
  /**
   * Optional Intelligence Substrate Selector. Dispatch layer routes
   * `/api/hub/intelligence/*` here when set; absent means the routes
   * 503 with a "selector not configured" body.
   */
  intelligenceSelector?: SubstrateSelector;
  /**
   * Optional Operator Chat Service. Constructed when storage + masterKey
   * are passed to `buildV11Bindings`. The HubService accepts this
   * directly via its `operatorChat` dep; callers that want the harness-
   * side `recordAgentReply` integration also need the service handle.
   */
  operatorChatService?: OperatorChatService;
  /**
   * Optional Operator Console domain service. When present the dispatch
   * layer mounts `/api/console/*` (+ `/console`) behind the shared auth
   * chokepoint; absent, the prefix answers 503 after auth.
   */
  consoleService?: ConsoleService;
  /** Optional static asset dir for the console SPA. */
  consolePublicDir?: string;
  /**
   * Optional Anomaly-detection binding. Constructed when storage +
   * masterKey are passed to `buildV11Bindings`. Dispatch mounts
   * `/api/anomaly/*` behind the shared auth chokepoint when set.
   */
  anomaly?: V11AnomalyBinding;
  /**
   * Optional English-authored-policy binding. Constructed when storage +
   * masterKey are passed to `buildV11Bindings`. Dispatch mounts
   * `/api/policy/*` behind the shared auth chokepoint when set.
   */
  englishPolicy?: V11EnglishPolicyBinding;
  /**
   * Optional Tier B PII-rewrite binding. Constructed when storage +
   * masterKey are passed to `buildV11Bindings`. Dispatch mounts
   * `/api/query-anonymity/pii` behind the shared auth chokepoint when
   * set; absent, the prefix answers 503 after auth.
   */
  pii?: V11PiiRewriteBinding;
}

async function pruneExpiredDidWebKeysOnUnlock(
  inputs: BuildV11BindingsInputs,
): Promise<void> {
  if (!inputs.storagePath) return;
  const record = await loadFortressDidWebRecord(inputs.storagePath);
  if (!record) return;
  const identifier = identifierFromFortressDidWebRecord(record);
  const pruned = dropExpiredDidWebKeys(identifier);
  if (pruned.dropped.length === 0) return;

  const prunedIdentifier: DidWebIdentifier = {
    ...identifier,
    did_document: pruned.did_document,
  };
  const artifact = publishDidWebDocument(prunedIdentifier);
  const updated = {
    ...record,
    identifier: {
      ...record.identifier,
      did_document: pruned.did_document,
    },
    artifact: {
      url: artifact.url,
      publish_path: artifact.publish_path,
      sha256: artifact.sha256,
    },
  };

  const persistDir = join(inputs.storagePath, "recognition");
  await mkdir(persistDir, { recursive: true, mode: 0o700 });
  await writeFile(join(persistDir, "did-web.json"), JSON.stringify(updated, null, 2), {
    mode: 0o600,
  });
  await writeFile(join(persistDir, "did.json"), artifact.artifact, { mode: 0o644 });

  for (const dropped of pruned.dropped) {
    void inputs.auditLog.append("l1", DID_WEB_AUDIT_OPS.OLD_KEY_DROPPED, inputs.identityId, {
      did: record.identifier.did,
      verification_method_id: dropped.verification_method_id,
      public_key_b64u: dropped.public_key_b64u,
      dropped_at: dropped.dropped_at,
    });
  }
  await inputs.auditLog.flush();
}

function buildAuditAttributionResolver(
  inputs: BuildV11BindingsInputs,
): AuditAttributionOptionsResolver {
  if (inputs.resolveAuditAttribution) return inputs.resolveAuditAttribution;
  const staticKey = inputs.pinnedProducerKeyB64url ?? null;
  const subjectFortressId = inputs.fortressId;
  if (staticKey !== null) {
    return () => ({
      pinnedProducerKeyB64url: staticKey,
      subjectFortressId,
    });
  }

  const storagePath = inputs.storagePath;
  let cached: ProducerKeyLoad | undefined;
  let lastWarnedReason: string | null = null;
  const warn =
    inputs.warnProducerKeyUnavailable ??
    ((reason: string) => {
      // SAFETY: stderr is the only operator-visible channel available in this
      // sync wiring helper; no key material is printed, only the load status.
      // Visible fail-honest path: a present-but-unusable key means Castle Wall
      // agent attribution is deliberately omitted until the key can be read.
      console.error(
        `Warning: Castle Wall audit attribution unavailable (${reason}).`,
      );
    });

  return async () => {
    if (cached?.status === "present") {
      return {
        pinnedProducerKeyB64url: cached.keyB64url,
        subjectFortressId,
      };
    }
    let load: ProducerKeyLoad;
    try {
      load = await loadFortressProducerKey(storagePath);
    } catch {
      load = { status: "unreadable", reason: "producer_key_load_threw" };
    }
    if (load.status === "present") {
      cached = load;
      lastWarnedReason = null;
      return {
        pinnedProducerKeyB64url: load.keyB64url,
        subjectFortressId,
      };
    }
    if (load.status === "unreadable" && load.reason !== lastWarnedReason) {
      lastWarnedReason = load.reason;
      warn(load.reason);
    }
    return {
      pinnedProducerKeyB64url: null,
      subjectFortressId,
    };
  };
}

/**
 * Construct the v1.1 hub bindings the dashboard entry points share. Caller
 * keeps ownership of the returned `HubService`; pass it through to the
 * dashboard layer's `setV11Bindings` setter.
 */
export function buildV11Bindings(
  inputs: BuildV11BindingsInputs,
): V11Bindings {
  // v1.1.5 (Finding Z): seed the registry from the persisted hub-layer
  // file from the fortress storage path. Reads are best-effort; the
  // persistence helper returns [] on missing-file or parse-error, so a
  // first-boot or corrupted-file fortress simply starts with an empty
  // registry instead of failing construction.
  const seed = readPersistedLocalAgents(inputs.storagePath);
  const registry = new InMemoryLocalAgentRegistry(seed);
  const storagePath = inputs.storagePath;
  const readPersisted = () => readPersistedLocalAgents(storagePath);
  const writePersisted = (records: ReturnType<typeof readPersistedLocalAgents>) =>
    writePersistedLocalAgents(storagePath, records);
  void pruneExpiredDidWebKeysOnUnlock(inputs).catch(() => {
    // Best-effort unlock pruning must not block dashboard construction.
  });
  const resolveAuditAttribution = buildAuditAttributionResolver(inputs);

  // WP-V1.2-4: construct the operator-chat service when the caller has
  // wired the fortress storage + master key. Concierge surface depends
  // on the substrate selector for the LLM call; when no selector is
  // wired the service still works for direct-agent and concierge
  // returns the honest "Concierge unavailable; substrate not configured"
  // surface so the chat history reflects exactly what the operator sees.
  // Rho-2.5: per-fortress Tier B PII-rewrite config store. Constructed
  // once when storage + master key are wired, then shared by (a) the
  // chat service (smart-mode rewrite gate, read at invocation time) and
  // (b) the `/api/query-anonymity/pii` route binding. Sharing one store
  // means the operator's PATCH /config and the live scrubbing path read
  // the same persisted state.
  let piiConfigStore: PiiConfigStore | undefined;
  if (inputs.storage && inputs.masterKey) {
    piiConfigStore = new PiiConfigStore({
      storage: inputs.storage,
      masterKey: inputs.masterKey,
      fortressId: inputs.fortressId,
    });
  }

  let operatorChatService: OperatorChatService | undefined;
  if (inputs.storage && inputs.masterKey) {
    const chatStore = new OperatorChatStore(inputs.storage, inputs.masterKey);
    // WP-V1.3-9 Tau-1: foundation memory store. Constructed alongside
    // the existing single-thread store; sendConcierge dual-writes into
    // both. Tau-2 wires the read-side context-fold into the substrate
    // selector. pruneExpired fires once at construction so the fortress-
    // unlock cycle drops expired turns before any operator interaction.
    const conciergeMemory = new ConciergeMemoryStore({
      storage: inputs.storage,
      masterKey: inputs.masterKey,
      fortressId: inputs.fortressId,
      ...(inputs.conciergeMemoryRetentionDays !== undefined
        ? { retentionDays: inputs.conciergeMemoryRetentionDays }
        : {}),
    });
    void conciergeMemory.pruneExpired().catch(() => {
      // Pruning is best-effort on fortress-unlock; a transient storage
      // hiccup should not block hub construction. The next unlock
      // re-runs the prune.
    });
    const agentContextCache = new AgentContextCache({
      identityId: inputs.identityId,
      agentRegistry: registry,
      auditLog: inputs.auditLog,
      resolveAuditAttribution,
      onRefreshError: (error) => {
        const message =
          error instanceof Error ? error.message : String(error);
        const warn =
          inputs.warnProducerKeyUnavailable ??
          ((reason: string) => {
            // SAFETY: startup/degradation warning to local server stderr only.
            console.error(
              `Warning: Castle Wall audit attribution unavailable (${reason}).`,
            );
          });
        warn(`agent_context_cache_refresh_failed:${message}`);
      },
    });
    void agentContextCache.refresh();
    operatorChatService = new OperatorChatService({
      store: chatStore,
      auditLog: inputs.auditLog,
      identityId: inputs.identityId,
      ...(inputs.intelligenceSelector
        ? { substrateSelector: inputs.intelligenceSelector }
        : {}),
      conciergeContextProviders: buildConciergeContextProviders({
        auditLog: inputs.auditLog,
        identityId: inputs.identityId,
        registry,
        resolveAuditAttribution,
      }),
      conciergePiiFilter: buildConciergePiiFilter(),
      // Rho-2.5: thread the live Tier B config so the concierge rewrite
      // path reads the gates (`evaluateForQuery()`) at invocation time:
      // smart mode when `smart_mode_enabled`, basic anonymize-all when
      // only `enabled`. The reverse-mapping store (encrypted,
      // per-fortress) is required for the smart-mode path to fire
      // end-to-end (store mappings -> restore at render); wired here when
      // storage + master key + a storage path are available. Without it,
      // smart mode degrades to the basic anonymize-all rewrite.
      ...(piiConfigStore
        ? {
            queryAnonymityConfig: piiConfigStore,
            queryAnonymityFortressId: inputs.fortressId,
          }
        : {}),
      ...(piiConfigStore && inputs.storage && inputs.masterKey
        ? {
            queryAnonymityReverseMappingStore: new ReverseMappingStore({
              fortressPath: inputs.storagePath,
              masterKey: inputs.masterKey,
              storage: inputs.storage,
            }),
          }
        : {}),
      conciergeMemory,
      conciergeContextFetchers: buildConciergeContextFetchers({
        auditLog: inputs.auditLog,
        identityId: inputs.identityId,
        registry,
        resolveAuditAttribution,
      }),
      ...(inputs.intelligenceSelector
        ? {
            conciergeContextLlmAssist: buildConciergeContextLlmAssist({
              selector: inputs.intelligenceSelector,
              identityId: inputs.identityId,
            }),
          }
        : {}),
      conciergeAgentContextCache: agentContextCache,
    });
  }

  // Anomaly-detection binding: constructible whenever the fortress
  // storage + master key are wired (same trigger as the chat service).
  // Mounted by the dispatch layer behind the shared auth chokepoint.
  let anomaly: V11AnomalyBinding | undefined;
  if (inputs.storage && inputs.masterKey) {
    // MUST-FIX 5 (fix-round-2 RECHECK): reuse the caller's SentinelFindingStore
    // when supplied — see `sentinelFindingStore`'s doc on
    // BuildV11BindingsInputs for why a second independent instance silently
    // hides findings between this binding and the caller's own sentinel-
    // dispatch boot path. `pruneExpired` is skipped for a REUSED instance:
    // the owner that constructed it already schedules pruning (index.ts's
    // boot path); running it again here would just be redundant work
    // against the same store.
    const reusingSharedStore = inputs.sentinelFindingStore !== undefined;
    const findingStore =
      inputs.sentinelFindingStore ??
      new SentinelFindingStore({
        storage: inputs.storage,
        masterKey: inputs.masterKey,
        fortressId: inputs.fortressId,
        auditLog: inputs.auditLog,
      });
    if (!reusingSharedStore) {
      // Register Z-HNY-02: fire-and-forget at construction, same pattern as
      // conciergeMemory.pruneExpired() above — the fortress-unlock cycle
      // drops expired findings before any dashboard read of this store.
      void findingStore.pruneExpired().catch(() => {
        // Best-effort; a transient storage hiccup should not block hub
        // construction. The next unlock re-runs the prune.
      });
    }
    const dispatcher = new AnomalyPipelineDispatcher({
      findingStore,
      auditLog: inputs.auditLog,
      storage: inputs.storage,
      masterKey: inputs.masterKey,
      fortressId: inputs.fortressId,
      identityId: inputs.identityId,
      // Dashboard-mounted dispatcher serves the read/subscribe HTTP
      // surface; the background tick lifecycle is owned by the sentinel
      // boot path, so disable auto-tick here to avoid a duplicate timer.
      tickIntervalMs: 0,
    });
    anomaly = {
      dispatcher,
      findingStore,
      auditLog: inputs.auditLog,
      identityId: inputs.identityId,
      storage: inputs.storage,
      masterKey: inputs.masterKey,
      fortressId: inputs.fortressId,
    };
  }

  // Rho-2.5: Tier B PII-rewrite binding. Constructible whenever the
  // fortress storage + master key are wired (same trigger as the chat
  // service + anomaly binding). Mounted by the dispatch layer behind the
  // shared auth chokepoint. `redactorInstalled` reports whether the
  // entry point actually installed the consent-gated redactor on the
  // selector, so the route surfaces the truthful effective state.
  let pii: V11PiiRewriteBinding | undefined;
  if (piiConfigStore) {
    pii = {
      store: piiConfigStore,
      auditLog: inputs.auditLog,
      identityId: inputs.identityId,
      fortressId: inputs.fortressId,
      redactorInstalled: inputs.tierBPiiRedactorInstalled ?? false,
    };
  }

  // English-authored-policy binding: compiler + in-memory review-draft
  // store. The substrate selector (when present) powers the LLM-assist
  // compile path; absent it, the deterministic matcher still works. The
  // activation lifecycle is optional and threaded through when supplied.
  const englishPolicy: V11EnglishPolicyBinding = {
    compiler: new EnglishPolicyCompiler({
      auditLog: inputs.auditLog,
      fortressId: inputs.fortressId,
      selector: inputs.intelligenceSelector ?? null,
    }),
    store: new EnglishPolicyDraftStore(),
    ...(inputs.englishPolicyActivator
      ? { activator: inputs.englishPolicyActivator }
      : {}),
    defaultOperatorId: inputs.identityId,
  };

  const inboxSources = {
    listPendingApprovals: () => [],
    listRecentBlockedEgress: () => [],
    listRecentPrivacyEvents: () => [],
    listActiveBudgetWarnings: () => [],
    listActiveRecoveryPrompts: () => [],
    listRecentAgentErrors: () => [],
  };
  const policyBudgetSources = {
    listPolicySummaries: () => [],
    listBudgetSummaries: () => [],
  };

  // P3 concierge unification: the frozen stateless hub routes keep their
  // request/response envelope, but their only inference authority is the
  // same selector instance used by persisted operator chat. Construction is
  // deliberately conditional on the full unlocked-fortress graph; a missing
  // dependency keeps the existing honest capability error instead of
  // inventing a provider fallback.
  let statelessConcierge: ConciergeService | undefined;
  if (
    inputs.intelligenceSelector &&
    inputs.storage &&
    inputs.masterKey &&
    inputs.identityManager
  ) {
    statelessConcierge = new ConciergeService({
      reader: new SanctuaryContextReader({
        auditLog: inputs.auditLog,
        identityManager: inputs.identityManager,
        stateStore: new StateStore(inputs.storage, inputs.masterKey),
        config: inputs.config,
        storagePath: inputs.storagePath,
        fortressId: inputs.fortressId,
        identityId: inputs.identityId,
        inboxSources,
        policyBudgetSources,
      }),
      selector: inputs.intelligenceSelector,
    });
  }

  const hubService = new HubService({
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
    agentRegistry: registry,
    readPersistedLocalAgents: readPersisted,
    writePersistedLocalAgents: writePersisted,
    storagePath: inputs.storagePath,
    inboxSources,
    activitySources: {
      auditLog: inputs.auditLog,
      identityId: inputs.identityId,
      subjectFortressId: inputs.fortressId,
      resolveAuditAttribution,
    },
    policyBudgetSources,
    agentController: new CastleWallAgentController({
      storagePath: inputs.storagePath,
      fortressPath: inputs.storagePath,
      fortressId: inputs.fortressId,
      auditLog: inputs.auditLog,
      now: () => new Date(),
      getAgentRecord: (agentId) => registry.get(agentId),
      ...(inputs.stopAgentEgress
        ? { stopAgentEgress: inputs.stopAgentEgress }
        : {}),
    }),
    ...(inputs.storage && inputs.masterKey
      ? {
          fortressExportBundle: async (approvalAuditId?: string) => {
            const storage = inputs.storage!;
            const masterKey = inputs.masterKey!;
            const storagePath = inputs.storagePath;
            const identityManager =
              inputs.identityManager ??
              new IdentityManager(storage, masterKey);
            if (!inputs.identityManager) await identityManager.load();
            const policy =
              inputs.policy ?? (await loadPrincipalPolicy(storagePath));
            const config =
              inputs.config ??
              {
                ...defaultConfig(),
                storage_path: storagePath,
              };
            const stamp = new Date()
              .toISOString()
              .replace(/[:.]/g, "-");
            const bundleDir = join(
              storagePath,
              "exit-bundles",
              `${stamp}-${randomUUID()}`,
            );
            const exported = await exportExitBundle({
              bundleDir,
              storage,
              masterKey,
              identityManager,
              auditLog: inputs.auditLog,
              ...(inputs.reputationStore
                ? { reputationStore: inputs.reputationStore }
                : {}),
              policy,
              config,
              stateStoragePath: join(storagePath, "state"),
              keySource: "unknown",
              // Operator-driven full-fortress export (dashboard exit endpoint):
              // the exit-machinery Slice 1 ownership partition is deliberately
              // not applied. Named acknowledgement, not a silent skip.
              unpartitionedLegacyExport: true,
              // `mintStateRekeyKey` is DELIBERATELY absent (A10): this path's
              // results are persisted into the hub inbox `resolution_payload`,
              // and key material must never be persisted (CLAUDE.md #6). A
              // minted key here would either be persisted with the result
              // (forbidden) or destroyed while the bundle advertises a re-key
              // path the operator can never satisfy. Must match the
              // non-minting-caller pin on `mintStateRekeyKey` in
              // exit/bundle.ts.
              ...(approvalAuditId !== undefined
                ? { exportApprovalAuditId: approvalAuditId }
                : {}),
            });
            return {
              bundle_dir: exported.bundle_dir,
              manifest_hash: exported.manifest_hash,
              artifact_count: exported.artifact_count,
              // A7: carry trusted export values through so the dashboard can
              // surface an honest count and prevent "Bundle ready" from masking
              // a zero-state export. Must match HubFortressExportResult in
              // hub/types.ts and resolution_payload in hub-events.ts.
              state_entry_count: exported.state_entry_count,
              ...(exported.warnings !== undefined
                ? { warnings: exported.warnings }
                : {}),
            };
          },
        }
      : {}),
    ...(operatorChatService ? { operatorChat: operatorChatService } : {}),
    ...(statelessConcierge ? { concierge: statelessConcierge } : {}),
  });
  return {
    hubService,
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
    storagePath: inputs.storagePath,
    ...(inputs.masterKey !== undefined ? { masterKey: inputs.masterKey } : {}),
    ...(inputs.intelligenceSelector
      ? { intelligenceSelector: inputs.intelligenceSelector }
      : {}),
    ...(operatorChatService ? { operatorChatService } : {}),
    ...(inputs.consoleService ? { consoleService: inputs.consoleService } : {}),
    ...(inputs.consolePublicDir !== undefined
      ? { consolePublicDir: inputs.consolePublicDir }
      : {}),
    ...(anomaly ? { anomaly } : {}),
    englishPolicy,
    ...(pii ? { pii } : {}),
  };
}

/**
 * Stitch fortress state into plain text for the concierge prompt. Each
 * provider returns a free-form string; the chat service folds the three
 * together with newlines. Keeping the prompt-shape decisions out of the
 * chat service (which stays storage/registry-agnostic) lets the
 * dashboard team iterate concierge prompts without touching the service
 * layer.
 */
function buildConciergeContextProviders(args: {
  auditLog: AuditLog;
  identityId: string;
  registry: InMemoryLocalAgentRegistry;
  resolveAuditAttribution: AuditAttributionOptionsResolver;
}): ConciergeContextProviders {
  return {
    recentActivity: async () => {
      const result = await args.auditLog.query({ limit: 30 });
      const auditAttribution = await args.resolveAuditAttribution();
      const records = args.registry.list({ identity_id: args.identityId });
      const lines = result.entries
        .filter((e) =>
          entryBelongsToConciergeScope(
            e,
            args.identityId,
            records,
            auditAttribution,
          ),
        )
        .slice(-30)
        .map((e) => formatConciergeActivityLine(e, auditAttribution, records));
      if (lines.length === 0) return "(no recent activity)";
      return lines.join("\n");
    },
    agentInventory: async () => {
      const records = args.registry.list({ identity_id: args.identityId });
      if (records.length === 0) return "(no wrapped agents)";
      const lines = records.map((r) => {
        const tmpl =
          typeof r.channel_template_id === "string"
            ? r.channel_template_id
            : "no_template";
        return `${r.agent_id}  harness=${r.harness}  status=${r.status}  template=${tmpl}`;
      });
      return lines.join("\n");
    },
    openInbox: async () => {
      // The inbox sources in v1.1.x wiring return empty arrays by
      // default; the concierge surface degrades to an honest "(no
      // open inbox items)" until the inbox aggregator is wired.
      return "(no open inbox items)";
    },
  };
}

/**
 * WP-V1.3-9 Tau-3 dynamic-context fetcher table. Wires the eight
 * categories the concierge-context-router routes against to concrete
 * data sources. Categories with no v1.3 source ship as placeholder
 * fetchers that return the empty string so the router drops them
 * cleanly; v1.3+ work threads add real sources without changing the
 * shape on this side.
 *
 * Failure-mode shape: each fetcher SHOULD throw on real data-source
 * errors; the chat-service wrapper catches and routes through
 * `onFetcherFailure` so the per-category audit event fires and the
 * surviving categories continue rendering.
 */
function buildConciergeContextFetchers(args: {
  auditLog: AuditLog;
  identityId: string;
  registry: InMemoryLocalAgentRegistry;
  resolveAuditAttribution: AuditAttributionOptionsResolver;
}): ContextFetchers {
  const empty = async () => "";
  return {
    templates: async () => {
      const entries = listTemplates();
      if (entries.length === 0) return "(no templates installed)";
      const lines = entries.map((e) => {
        const m = e.metadata;
        return `${m.name} (tier ${m.tier}, channel ${m.channel}, target ${m.target_archetype})`;
      });
      return lines.join("\n");
    },
    agent_state: async (agentNameHint) => {
      const records = args.registry.list({ identity_id: args.identityId });
      if (records.length === 0) return "(no wrapped agents)";
      const filtered = agentNameHint
        ? records.filter(
            (r) =>
              r.agent_id.toLowerCase().includes(agentNameHint.toLowerCase()) ||
              r.harness.toLowerCase().includes(agentNameHint.toLowerCase()),
          )
        : records;
      const target = filtered.length > 0 ? filtered : records;
      const lines = target.slice(0, 20).map((r) => {
        const tmpl =
          typeof r.channel_template_id === "string"
            ? r.channel_template_id
            : "no_template";
        return `${r.agent_id}  harness=${r.harness}  status=${r.status}  template=${tmpl}`;
      });
      return lines.join("\n");
    },
    agent_activity: async (agentNameHint) => {
      const result = await args.auditLog.query({ limit: 50 });
      const auditAttribution = await args.resolveAuditAttribution();
      const records = args.registry.list({ identity_id: args.identityId });
      const owned = result.entries.filter((e) =>
        entryBelongsToConciergeScope(
          e,
          args.identityId,
          records,
          auditAttribution,
        ),
      );
      const filtered = agentNameHint
        ? owned.filter((e) => {
            const agentId =
              publicAgentIdForConciergeActivity(
                e,
                auditAttribution,
                records,
              ) ?? "";
            return agentId
              .toLowerCase()
              .includes(agentNameHint.toLowerCase());
          })
        : owned;
      const tail = (filtered.length > 0 ? filtered : owned).slice(-20);
      if (tail.length === 0) return "(no activity)";
      return tail
        .map((e) => formatConciergeActivityLine(e, auditAttribution, records))
        .join("\n");
    },
    audit_log: async () => {
      const result = await args.auditLog.query({ limit: 30 });
      const auditAttribution = await args.resolveAuditAttribution();
      const records = args.registry.list({ identity_id: args.identityId });
      const owned = result.entries.filter((e) =>
        entryBelongsToConciergeScope(
          e,
          args.identityId,
          records,
          auditAttribution,
        ),
      );
      if (owned.length === 0) return "(no audit log entries)";
      return owned
        .slice(-30)
        .map(
          (e) =>
            `${e.timestamp}  ${e.layer}.${e.operation}  result=${e.result}`,
        )
        .join("\n");
    },
    sentinel_findings: empty,
    anomaly_alerts: empty,
    recent_receipts: async () => {
      const result = await args.auditLog.query({ limit: 100 });
      const owned = result.entries.filter(
        (e) =>
          e.identity_id === args.identityId &&
          e.operation.startsWith("composition_"),
      );
      if (owned.length === 0) return "(no recent composition events)";
      return owned
        .slice(-15)
        .map((e) => `${e.timestamp}  ${e.operation}  result=${e.result}`)
        .join("\n");
    },
    verascore_deltas: empty,
  };
}

type ConciergeAuditAttribution = Awaited<
  ReturnType<AuditAttributionOptionsResolver>
>;

function publicAgentIdForConciergeActivity(
  entry: Parameters<typeof auditEntryAgentId>[0],
  auditAttribution: ConciergeAuditAttribution,
  records: ReadonlyArray<LocalAgentRecord>,
): string | null {
  const verifiedSubject = auditEntryAgentId(entry, auditAttribution);
  return verifiedSubject === null
    ? null
    : publicAgentIdForVerifiedAttribution(verifiedSubject, records);
}

function formatConciergeActivityLine(
  entry: Parameters<typeof auditEntryAgentId>[0],
  auditAttribution: ConciergeAuditAttribution,
  records: ReadonlyArray<LocalAgentRecord>,
): string {
  const agentId =
    publicAgentIdForConciergeActivity(entry, auditAttribution, records) ??
    "_fortress";
  return `${entry.timestamp}  ${entry.layer}.${entry.operation}  agent=${agentId}  result=${entry.result}`;
}

function entryBelongsToConciergeScope(
  entry: Parameters<typeof auditEntryAgentId>[0],
  identityId: string,
  records: ReadonlyArray<LocalAgentRecord>,
  auditAttribution: ConciergeAuditAttribution,
): boolean {
  if (entry.identity_id === identityId) return true;
  const agentId = auditEntryAgentId(entry, auditAttribution);
  if (agentId === null) return false;
  return records.some((record) => agentRecordAttributionIds(record).has(agentId));
}

/**
 * WP-V1.3-9 Tau-3 LLM-assist classifier. Routes the auxiliary
 * classification call through the substrate selector at the concierge
 * surface so the operator's substrate choice carries through and no
 * new outbound channel opens. Returns `"none"` on substrate failure
 * or when the response cannot be parsed into one of the known
 * categories; the router treats `"none"` as no classification.
 *
 * The prompt deliberately constrains output to a single token from
 * the closed enum so even small local models (Gemma 2 2B) hit the
 * accept path predictably.
 */
function buildConciergeContextLlmAssist(args: {
  selector: SubstrateSelector;
  identityId: string;
}): LlmAssistClassifier {
  return async (query, categories) => {
    const labelList = categories.map((c) => `- ${c}`).join("\n");
    const prompt =
      `You are a router. Classify the operator's query into one of the categories below or "none".\n` +
      `Reply with exactly one token: one category name or "none".\n\n` +
      `Categories:\n${labelList}\n\n` +
      `Query: ${query}\n\n` +
      `Category:`;
    try {
      const handle = await args.selector.getSubstrate("concierge");
      if (!handle.capability.summarize) return "none";
      const response = await args.selector.invokeSummarize("concierge", {
        kind: "summarize",
        context: prompt,
        query: "Output the single category token.",
        maxTokens: 16,
      });
      if (response.failureClass || response.body.kind !== "summarize") {
        return "none";
      }
      const raw = response.body.text.trim().toLowerCase();
      const head = raw.split(/\s|[.,!?:;]/)[0] ?? "";
      const normalized = head.replace(/[^a-z_]/g, "");
      const known = categories as readonly string[];
      if (known.includes(normalized)) {
        return normalized as ContextCategory;
      }
      return "none";
    } catch {
      return "none";
    }
  };
}

/**
 * Tier 1 regex-only PII redactor for the concierge query path. Wraps
 * the existing `detectSensitiveSpans` shipped in
 * `operational/privacy-filter.ts`. Tier 2 NER + LLM redaction lives
 * in the substrate-selector layer (substrate-routed); the concierge
 * surface invokes Tier 1 here as defense-in-depth pre-substrate.
 *
 * Replacement strategy: each detected span is replaced with
 * `[REDACTED:CLASS]` markers (e.g. `[REDACTED:EMAIL]`) so the substrate
 * sees the structure of the redaction without the underlying value.
 */
function buildConciergePiiFilter(): ConciergePiiFilter {
  return {
    filter(input: string): { filtered: string; redactions: number } {
      const spans = detectSensitiveSpans(input);
      if (spans.length === 0) return { filtered: input, redactions: 0 };
      const sorted = [...spans].sort((a, b) => b.start - a.start);
      let result = input;
      for (const span of sorted) {
        const cls = detectorClassForSpan(span.class).toUpperCase();
        result =
          result.slice(0, span.start) +
          `[REDACTED:${cls}]` +
          result.slice(span.end);
      }
      return { filtered: result, redactions: spans.length };
    },
  };
}

/**
 * Synthesize a stable fortress id from the storage path. Until v1.2 lands
 * a canonical fortress id source, the storage path hash is stable across
 * boots of the same fortress and unique across distinct fortresses on the
 * same host. This value is the local fortress namespace and the comparison
 * basis for fortress-scoped liveness checks. It is not remote evidence, but it
 * is a local trust anchor for separating one storage-backed fortress from
 * another.
 */
export function fortressIdFromStoragePath(storagePath: string): string {
  const digest = createHash("sha256").update(storagePath).digest("hex");
  return `fortress-${digest.slice(0, 16)}`;
}
