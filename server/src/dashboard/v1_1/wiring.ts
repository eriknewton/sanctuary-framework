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
 *   - Local agent registry starts empty by default. v1.1.5 (Finding Z)
 *     adds an optional `storagePath` input that rehydrates the registry
 *     from `<storagePath>/state/_hub/local-agents.json`, written by
 *     `sanctuary wrap` for each successfully wrapped harness. Callers
 *     that pass `storagePath` get the wrap-populated set; callers that
 *     omit it (legacy) keep the empty-by-default behavior. Real
 *     harness-discovery via `discoverTenants()` remains v1.2 work.
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
import { IdentityManager } from "../../cognitive/tools.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  type HubAgentController,
} from "../../hub/index.js";
import { HubCapabilityError } from "../../hub/errors.js";
import {
  readPersistedLocalAgents,
  writePersistedLocalAgents,
} from "../../hub/agent-registry-persistence.js";
import type { ChannelTemplateId } from "../../policy-engine/constants.js";
import type { HubAgentStatus } from "../../contracts/v1.1/constants.js";
import type { SubstrateSelector } from "../../intelligence/selector.js";
import type { ReputationStore } from "../../reputation/reputation-store.js";
import { loadPrincipalPolicy } from "../../principal-policy/loader.js";
import type { PrincipalPolicy } from "../../principal-policy/types.js";
import type { StorageBackend } from "../../storage/interface.js";
import {
  ConciergeMemoryStore,
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
   * Fortress storage root. When provided, the agent registry rehydrates
   * from `<storagePath>/state/_hub/local-agents.json` (best-effort; a
   * missing or unparseable file degrades to an empty registry rather
   * than failing construction). Omit for callers that intentionally
   * want an empty registry (e.g. unit tests, future ephemeral modes).
   */
  storagePath?: string;
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
}

export interface V11Bindings {
  hubService: HubService;
  identityId: string;
  fortressId: string;
  storagePath?: string;
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

class CapabilityErrorAgentController implements HubAgentController {
  private fail(action: string): never {
    throw new HubCapabilityError(
      `agent_control_${action}_not_wired_in_v1.1.1`,
    );
  }
  async pause(_agentId: string): Promise<HubAgentStatus> {
    this.fail("pause");
  }
  async resume(_agentId: string): Promise<HubAgentStatus> {
    this.fail("resume");
  }
  async restart(_agentId: string): Promise<HubAgentStatus> {
    this.fail("restart");
  }
  async unwrap(_agentId: string): Promise<HubAgentStatus> {
    this.fail("unwrap");
  }
  async lockdown(_agentId: string): Promise<HubAgentStatus> {
    this.fail("lockdown");
  }
  async bindPolicy(_agentId: string, _policyId: string): Promise<void> {
    this.fail("bindPolicy");
  }
  async bindChannelTemplate(
    _agentId: string,
    _templateId: ChannelTemplateId,
  ): Promise<void> {
    return;
  }
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
  // file when a storage path is supplied. Reads are best-effort; the
  // persistence helper returns [] on missing-file or parse-error, so a
  // first-boot or corrupted-file fortress simply starts with an empty
  // registry instead of failing construction.
  const seed =
    inputs.storagePath !== undefined
      ? readPersistedLocalAgents(inputs.storagePath)
      : [];
  const registry = new InMemoryLocalAgentRegistry(seed);
  const storagePath = inputs.storagePath;
  const readPersisted =
    storagePath !== undefined
      ? () => readPersistedLocalAgents(storagePath)
      : undefined;
  const writePersisted =
    storagePath !== undefined
      ? (records: ReturnType<typeof readPersistedLocalAgents>) =>
          writePersistedLocalAgents(storagePath, records)
      : undefined;
  void pruneExpiredDidWebKeysOnUnlock(inputs).catch(() => {
    // Best-effort unlock pruning must not block dashboard construction.
  });

  // WP-V1.2-4: construct the operator-chat service when the caller has
  // wired the fortress storage + master key. Concierge surface depends
  // on the substrate selector for the LLM call; when no selector is
  // wired the service still works for direct-agent and concierge
  // returns the honest "Concierge unavailable; substrate not configured"
  // surface so the chat history reflects exactly what the operator sees.
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
      }),
      conciergePiiFilter: buildConciergePiiFilter(),
      conciergeMemory,
      conciergeContextFetchers: buildConciergeContextFetchers({
        auditLog: inputs.auditLog,
        identityId: inputs.identityId,
        registry,
      }),
      ...(inputs.intelligenceSelector
        ? {
            conciergeContextLlmAssist: buildConciergeContextLlmAssist({
              selector: inputs.intelligenceSelector,
              identityId: inputs.identityId,
            }),
          }
        : {}),
    });
  }

  const hubService = new HubService({
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
    agentRegistry: registry,
    ...(readPersisted ? { readPersistedLocalAgents: readPersisted } : {}),
    ...(writePersisted ? { writePersistedLocalAgents: writePersisted } : {}),
    ...(inputs.storagePath !== undefined ? { storagePath: inputs.storagePath } : {}),
    inboxSources: {
      listPendingApprovals: () => [],
      listRecentBlockedEgress: () => [],
      listRecentPrivacyEvents: () => [],
      listActiveBudgetWarnings: () => [],
      listActiveRecoveryPrompts: () => [],
      listRecentAgentErrors: () => [],
    },
    activitySources: {
      auditLog: inputs.auditLog,
      identityId: inputs.identityId,
    },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    agentController: new CapabilityErrorAgentController(),
    ...(inputs.storage && inputs.masterKey && inputs.storagePath
      ? {
          fortressExportBundle: async (approvalAuditId?: string) => {
            const storage = inputs.storage!;
            const masterKey = inputs.masterKey!;
            const storagePath = inputs.storagePath!;
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
              ...(approvalAuditId !== undefined
                ? { exportApprovalAuditId: approvalAuditId }
                : {}),
            });
            return {
              bundle_dir: exported.bundle_dir,
              manifest_hash: exported.manifest_hash,
              artifact_count: exported.artifact_count,
            };
          },
        }
      : {}),
    ...(operatorChatService ? { operatorChat: operatorChatService } : {}),
  });
  return {
    hubService,
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
    ...(inputs.storagePath !== undefined ? { storagePath: inputs.storagePath } : {}),
    ...(inputs.masterKey !== undefined ? { masterKey: inputs.masterKey } : {}),
    ...(inputs.intelligenceSelector
      ? { intelligenceSelector: inputs.intelligenceSelector }
      : {}),
    ...(operatorChatService ? { operatorChatService } : {}),
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
}): ConciergeContextProviders {
  return {
    recentActivity: async () => {
      const result = await args.auditLog.query({ limit: 30 });
      const lines = result.entries
        .filter((e) => e.identity_id === args.identityId)
        .slice(-30)
        .map((e) => {
          const agentId =
            (e.details && typeof e.details["agent_id"] === "string"
              ? (e.details["agent_id"] as string)
              : null) ?? "_fortress";
          return `${e.timestamp}  ${e.layer}.${e.operation}  agent=${agentId}  result=${e.result}`;
        });
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
      const owned = result.entries.filter(
        (e) => e.identity_id === args.identityId,
      );
      const filtered = agentNameHint
        ? owned.filter((e) => {
            const agentId =
              e.details && typeof e.details["agent_id"] === "string"
                ? (e.details["agent_id"] as string)
                : "";
            return agentId
              .toLowerCase()
              .includes(agentNameHint.toLowerCase());
          })
        : owned;
      const tail = (filtered.length > 0 ? filtered : owned).slice(-20);
      if (tail.length === 0) return "(no activity)";
      return tail
        .map((e) => {
          const agentId =
            (e.details && typeof e.details["agent_id"] === "string"
              ? (e.details["agent_id"] as string)
              : null) ?? "_fortress";
          return `${e.timestamp}  ${e.layer}.${e.operation}  agent=${agentId}  result=${e.result}`;
        })
        .join("\n");
    },
    audit_log: async () => {
      const result = await args.auditLog.query({ limit: 30 });
      const owned = result.entries.filter(
        (e) => e.identity_id === args.identityId,
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
 * same host. Display only; not used for trust decisions.
 */
export function fortressIdFromStoragePath(storagePath: string): string {
  const digest = createHash("sha256").update(storagePath).digest("hex");
  return `fortress-${digest.slice(0, 16)}`;
}
