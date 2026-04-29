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

import { createHash } from "node:crypto";

import type { AuditLog } from "../../l2-operational/audit-log.js";
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
import type { StorageBackend } from "../../storage/interface.js";
import {
  OperatorChatService,
  OperatorChatStore,
  type ConciergeContextProviders,
  type ConciergePiiFilter,
} from "../../chat/operator-chat-index.js";
import {
  detectSensitiveSpans,
  detectorClassForSpan,
} from "../../l2-operational/privacy-filter.js";

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
}

export interface V11Bindings {
  hubService: HubService;
  identityId: string;
  fortressId: string;
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

  // WP-V1.2-4: construct the operator-chat service when the caller has
  // wired the fortress storage + master key. Concierge surface depends
  // on the substrate selector for the LLM call; when no selector is
  // wired the service still works for direct-agent and concierge
  // returns the honest "Concierge unavailable; substrate not configured"
  // surface so the chat history reflects exactly what the operator sees.
  let operatorChatService: OperatorChatService | undefined;
  if (inputs.storage && inputs.masterKey) {
    const chatStore = new OperatorChatStore(inputs.storage, inputs.masterKey);
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
    });
  }

  const hubService = new HubService({
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
    agentRegistry: registry,
    ...(readPersisted ? { readPersistedLocalAgents: readPersisted } : {}),
    ...(writePersisted ? { writePersistedLocalAgents: writePersisted } : {}),
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
    ...(operatorChatService ? { operatorChat: operatorChatService } : {}),
  });
  return {
    hubService,
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
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
 * Tier 1 regex-only PII redactor for the concierge query path. Wraps
 * the existing `detectSensitiveSpans` shipped in
 * `l2-operational/privacy-filter.ts`. Tier 2 NER + LLM redaction lives
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
