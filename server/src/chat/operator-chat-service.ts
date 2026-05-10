/**
 * Sanctuary MCP Server — Operator Chat Service
 *
 * The operator-fortress concierge surface. Distinct from the
 * agent-to-agent mesh chat (`chat-service.ts`) which handles libp2p +
 * OpenMLS group sessions among wrapped agents.
 *
 * The direct-agent surface (operator-to-wrapped-agent conversation) was
 * removed in the v1.2 reshape; the concierge surface is the only
 * operator-chat surface in v1.2.
 *
 * Concierge surface (path: `sendConcierge`):
 *   1. PII-filter the operator query (Tier 1 regex).
 *   2. Build fortress context from audit log + activity feed +
 *      agent registry (`assembleConciergeContext`).
 *   3. Invoke the substrate selector at `surface: "concierge"`.
 *   4. Persist operator query + concierge response in the concierge
 *      thread under `_chat/concierge.<sentinel>`.
 *   5. Emit `operator_concierge_chat` audit event with safe metadata.
 *
 * Sovereignty invariants:
 * - Audit emission is non-optional on every public method that mutates
 *   the chat state. Construction with no audit log is structurally
 *   rejected.
 * - The substrate selector is OPTIONAL: a service constructed without
 *   one degrades to "Concierge unavailable; substrate not configured".
 *   The wiring layer can instantiate the service before the substrate
 *   selector when bootstrap order requires it.
 * - The PII filter is the Tier 1 regex shipped in
 *   `l2-operational/privacy-filter.ts`; Tier 2 NER+LLM redaction lives
 *   in the substrate-selector layer (substrate-routed), not here.
 */

import { randomUUID } from "node:crypto";
import { sha256 } from "@noble/hashes/sha256";
import { hashToString } from "../core/hashing.js";
import { stringToBytes } from "../core/encoding.js";
import type { AuditLog } from "../l2-operational/audit-log.js";
import type {
  SubstrateSelector,
} from "../intelligence/index.js";
import type { SubstrateChoice } from "../intelligence/types.js";
import { OPERATOR_CHAT_OPS } from "./operator-chat-audit-events.js";
import {
  CONCIERGE_THREAD_KEY,
  type ConciergeResponse,
  type OperatorChatMessage,
  type OperatorChatRole,
  type OperatorChatThread,
} from "./operator-chat-types.js";
import { OperatorChatStore } from "./operator-chat-store.js";
import type {
  ConciergeMemoryReadFailure,
  ConciergeMemoryStore,
  ConciergeThreadSummary,
  ConciergeTurn,
  ListThreadsOptions,
  ReadThreadOptions,
} from "./concierge-memory-store.js";
import type {
  OperatorChatAuditPayload,
  OperatorConciergeChatPayload,
  OperatorConciergeContextFetcherFailedPayload,
  OperatorConciergeHistoryReadPayload,
  OperatorConciergeMemoryReadFailedPayload,
  OperatorConciergeThreadDeletedPayload,
} from "../contracts/v1.2/operator-chat-events.js";
import {
  foldContext,
  type ContextCategory,
  type ContextFetchers,
  type LlmAssistClassifier,
} from "./concierge-context-router.js";

/**
 * Snapshot of fortress state surfaces the concierge consults to
 * answer operator queries. Caller (the hub-service wiring) supplies
 * the providers; the service wires them into the substrate prompt.
 *
 * Each provider returns plain strings the substrate selector folds
 * into a single context blob; the service does not attempt to
 * structure the prompt beyond stitching with newlines. Keeping the
 * prompt-shape decisions in the service-construction layer (rather
 * than in the wiring) lets the dashboard team iterate concierge
 * prompts without touching server code.
 */
export interface ConciergeContextProviders {
  /** Recent activity-feed entries as a free-form string, oldest first. */
  recentActivity: () => Promise<string>;
  /** Wrapped-agent inventory as a free-form string. */
  agentInventory: () => Promise<string>;
  /** Open inbox items as a free-form string. */
  openInbox: () => Promise<string>;
}

/**
 * PII filter the concierge applies to operator queries before passing
 * them to the substrate. v1.2 wires the Tier 1 regex; the substrate
 * selector handles Tier 2 NER+LLM redaction internally on egress paths.
 *
 * Returns the filtered query plus the count of redactions performed
 * (surfaced in the audit event for operator visibility).
 */
export interface ConciergePiiFilter {
  filter(input: string): { filtered: string; redactions: number };
}

/**
 * Construction inputs for the operator chat service.
 */
export interface OperatorChatServiceDeps {
  /** Encrypted at-rest store; built from fortress master key. */
  store: OperatorChatStore;
  /** Audit log for `operator_concierge_chat` events. */
  auditLog: AuditLog;
  /** Operator identity that owns the chat session. */
  identityId: string;
  /**
   * Substrate selector for concierge LLM calls. Optional: when omitted
   * the concierge surface degrades to a "substrate not configured"
   * response.
   */
  substrateSelector?: SubstrateSelector;
  /**
   * Concierge context providers. Required when a substrate selector
   * is wired; otherwise unused. Wiring layer assembles these from the
   * activity feed, agent registry, and inbox aggregator.
   */
  conciergeContextProviders?: ConciergeContextProviders;
  /**
   * PII filter applied to concierge queries pre-substrate. Optional;
   * when omitted the service still works (no redactions performed).
   * v1.2 wiring passes the Tier 1 regex.
   */
  conciergePiiFilter?: ConciergePiiFilter;
  /**
   * Stable max tokens for concierge responses. Defaults to 512 (small
   * enough for snappy local-model latency, large enough for a useful
   * summary). Operator-tunable via dashboard config.
   */
  conciergeMaxTokens?: number;
  /**
   * WP-V1.3-9 Tau-1: optional foundation memory store. When wired,
   * `sendConcierge` dual-writes each operator+concierge turn pair into
   * the memory store under a session-scoped thread_id. Tau-2 adds a
   * read-fold path that surfaces the prior turns to the substrate so
   * the concierge maintains coherence across a multi-turn session.
   *
   * Omit at construction time to disable memory-side persistence; the
   * existing `OperatorChatStore` write keeps working unchanged.
   */
  conciergeMemory?: ConciergeMemoryStore;
  /**
   * WP-V1.3-9 Tau-2: maximum prior turns folded into the substrate
   * context per round-trip. Defaults to
   * `DEFAULT_CONCIERGE_HISTORY_WINDOW_TURNS` (10). The current operator
   * turn is always present; this caps history only.
   */
  conciergeHistoryWindowTurns?: number;
  /**
   * WP-V1.3-9 Tau-2: prior turns older than this many milliseconds are
   * excluded from the active fold even when they remain on disk.
   * Defaults to `DEFAULT_CONCIERGE_HISTORY_FRESHNESS_MS` (24h).
   */
  conciergeHistoryFreshnessMs?: number;
  /**
   * WP-V1.3-9 Tau-2: rough token budget for the prior-conversation
   * portion of the substrate context. Estimated as ~4 chars per token.
   * Defaults to `DEFAULT_CONCIERGE_HISTORY_TOKEN_BUDGET` (500). The
   * static reference block + fortress sections are NOT subject to this
   * budget; only the prior-conversation fold is pruned oldest-first.
   */
  conciergeHistoryTokenBudget?: number;
  /**
   * WP-V1.3-9 Tau-2: how long an active session may stay quiet before
   * the next `sendConcierge` allocates a fresh thread_id. Defaults to
   * `DEFAULT_CONCIERGE_SESSION_TTL_MS` (24h). Does not delete the prior
   * thread; it remains readable through the memory store.
   */
  conciergeSessionTtlMs?: number;
  /**
   * Optional clock for the session-TTL + freshness checks. Tests inject
   * a deterministic clock; production lets the default `Date.now`-based
   * implementation run.
   */
  conciergeClock?: () => number;
  /**
   * WP-V1.3-9 Tau-3: caller-supplied fetchers for dynamic context
   * injection. When wired alongside the substrate selector, every
   * `sendConcierge` round-trip routes the operator's query through the
   * concierge-context-router and folds matching live data into the
   * substrate prompt between the static Sanctuary reference and the
   * prior-turns fold. Omit to disable dynamic context (the static
   * reference + prior-turns paths keep working unchanged).
   */
  conciergeContextFetchers?: ContextFetchers;
  /**
   * WP-V1.3-9 Tau-3: optional LLM-assist classifier for queries that
   * fail keyword classification. Coordinator-CTO bake: when wired, the
   * service routes the auxiliary classifier call through the substrate
   * selector at the same `concierge` surface, so the auxiliary call
   * shares the operator's substrate choice and never opens a new
   * outbound surface.
   */
  conciergeContextLlmAssist?: LlmAssistClassifier;
  /**
   * WP-V1.3-9 Tau-3: rough token budget for the dynamic-context fold.
   * Defaults to `DEFAULT_CONCIERGE_DYNAMIC_CONTEXT_BUDGET` (2000).
   */
  conciergeDynamicContextBudget?: number;
}

const DEFAULT_CONCIERGE_MAX_TOKENS = 512;

/**
 * WP-V1.3-9 Tau-2 defaults. Coordinator-CTO baked: 10-turn window, 24h
 * freshness, ~500-token history budget, 24h session TTL. Operators tune
 * via the service-construction options surface (no dashboard knob in
 * Tau-2; Tau-3+ exposes a config panel).
 */
export const DEFAULT_CONCIERGE_HISTORY_WINDOW_TURNS = 10;
export const DEFAULT_CONCIERGE_HISTORY_FRESHNESS_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_CONCIERGE_HISTORY_TOKEN_BUDGET = 500;
export const DEFAULT_CONCIERGE_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * WP-V1.3-9 Tau-3 default token budget for the dynamic-context fold.
 * Sized to leave room for static reference + prior-turns + per-provider
 * sections within the substrate's nominal 4k-token concierge prompt.
 */
export const DEFAULT_CONCIERGE_DYNAMIC_CONTEXT_BUDGET = 2000;

/**
 * Approximate-token estimator. The substrate selector does not expose a
 * tokenizer to consumers; chars / 4 is the canonical proxy used by the
 * Sanctuary domain reference test (`reference block is within token
 * budget`) and matches the substrate prompt budget shape.
 */
function approxTokenLen(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Static Sanctuary domain reference injected into the concierge context
 * so the substrate can answer operator questions about Sanctuary concepts,
 * channel templates, policy slots, and architecture.
 *
 * v1.3 replaces this with dynamic context injection (pre-fetch live
 * template list + policy schema at chat time).
 */
export const SANCTUARY_DOMAIN_REFERENCE = `\
Castle Architecture (four enforcement layers):
1. Castle Wall: OS-boundary egress filter enforced at the kernel level. Blocks unauthorized outbound calls even from prompt-injected agents.
2. Sentinels: internal observation via process introspection. Surfaces anomalies to the operator; does not enforce.
3. Charter (Cooperative MCP): the sovereignty surface for compliant agents. Policy gates, approval tiers, audit logging, and encrypted state all live here.
4. Heralds: Concordia receipts and Verascore reputation. Cross-fortress accountability after an action completes.

Five channel templates (canonical names):
- request-approve-act: agent proposes an action, operator approves or denies before execution.
- read-then-report: agent reads outputs from a data source and reports summaries to the operator.
- scheduled-digest: agent runs on a schedule and delivers a periodic digest.
- plan-draft-only: agent drafts plans; operator reviews before any execution step.
- fortress-relay: agent relays messages between fortresses under operator-scoped policy.

Four canonical policy slots:
- memory: governs what the agent may persist and retrieve from encrypted state.
- credentials: governs access to secrets, API keys, and tokens held in the broker.
- plans: governs the agent's ability to create, modify, or execute plans.
- outputs: governs what the agent may emit to external surfaces (files, APIs, messages).

Key concepts:
- Fortress: the operator-owned sovereignty harness. All state is encrypted at rest under the cocoon.
- Cocoon: master-key-wrapped storage derived from the operator's passphrase via Argon2id.
- Identity: Ed25519 keypair with a DID, owned by the operator. Private keys never leave the cocoon.
- Audit log: append-only encrypted blobs, sequential, recording every gate decision and tool call.
- Wrapped agent: any agent runtime that connects to Sanctuary as an MCP client. Tier A (native), Tier B (adapter-wrapped), Tier C (escape hatch).

Note: this is a static reference block (v1.2.x). Dynamic context injection (live template list, policy schema) ships in v1.3.`;

export class OperatorChatService {
  private store: OperatorChatStore;
  private auditLog: AuditLog;
  private identityId: string;
  private substrateSelector?: SubstrateSelector;
  private contextProviders?: ConciergeContextProviders;
  private piiFilter?: ConciergePiiFilter;
  private conciergeMaxTokens: number;
  private memory?: ConciergeMemoryStore;
  private historyWindowTurns: number;
  private historyFreshnessMs: number;
  private historyTokenBudget: number;
  private sessionTtlMs: number;
  private clock: () => number;
  private contextFetchers?: ContextFetchers;
  private contextLlmAssist?: LlmAssistClassifier;
  private dynamicContextBudget: number;
  /**
   * In-memory thread_id assigned to the active concierge session.
   * The first sendConcierge call after construction allocates a fresh
   * UUID; subsequent calls reuse it so multi-turn coherence (Tau-2)
   * folds the prior turns into context. Cleared by `resetConciergeMemoryThread`.
   */
  private activeMemoryThreadId?: string;
  /**
   * Wall-clock ms of the most recent sendConcierge that touched the
   * active session thread. Drives the WP-V1.3-9 Tau-2 session-TTL
   * check: a fresh sendConcierge after `sessionTtlMs` of quiet
   * allocates a new thread_id even though the prior one is still
   * readable from the memory store.
   */
  private lastInteractionAt?: number;

  constructor(deps: OperatorChatServiceDeps) {
    this.store = deps.store;
    this.auditLog = deps.auditLog;
    this.identityId = deps.identityId;
    if (deps.substrateSelector) this.substrateSelector = deps.substrateSelector;
    if (deps.conciergeContextProviders) {
      this.contextProviders = deps.conciergeContextProviders;
    }
    if (deps.conciergePiiFilter) this.piiFilter = deps.conciergePiiFilter;
    this.conciergeMaxTokens =
      deps.conciergeMaxTokens ?? DEFAULT_CONCIERGE_MAX_TOKENS;
    if (deps.conciergeMemory) this.memory = deps.conciergeMemory;
    this.historyWindowTurns =
      deps.conciergeHistoryWindowTurns !== undefined &&
      deps.conciergeHistoryWindowTurns > 0
        ? deps.conciergeHistoryWindowTurns
        : DEFAULT_CONCIERGE_HISTORY_WINDOW_TURNS;
    this.historyFreshnessMs =
      deps.conciergeHistoryFreshnessMs !== undefined &&
      deps.conciergeHistoryFreshnessMs > 0
        ? deps.conciergeHistoryFreshnessMs
        : DEFAULT_CONCIERGE_HISTORY_FRESHNESS_MS;
    this.historyTokenBudget =
      deps.conciergeHistoryTokenBudget !== undefined &&
      deps.conciergeHistoryTokenBudget > 0
        ? deps.conciergeHistoryTokenBudget
        : DEFAULT_CONCIERGE_HISTORY_TOKEN_BUDGET;
    this.sessionTtlMs =
      deps.conciergeSessionTtlMs !== undefined && deps.conciergeSessionTtlMs > 0
        ? deps.conciergeSessionTtlMs
        : DEFAULT_CONCIERGE_SESSION_TTL_MS;
    this.clock = deps.conciergeClock ?? (() => Date.now());
    if (deps.conciergeContextFetchers) {
      this.contextFetchers = deps.conciergeContextFetchers;
    }
    if (deps.conciergeContextLlmAssist) {
      this.contextLlmAssist = deps.conciergeContextLlmAssist;
    }
    this.dynamicContextBudget =
      deps.conciergeDynamicContextBudget !== undefined &&
      deps.conciergeDynamicContextBudget > 0
        ? deps.conciergeDynamicContextBudget
        : DEFAULT_CONCIERGE_DYNAMIC_CONTEXT_BUDGET;
  }

  // ── Concierge ─────────────────────────────────────────────────────────

  /**
   * Operator submit on the concierge surface. Persists the operator's
   * query, fans out to the substrate selector, persists the response,
   * and emits the audit event.
   *
   * On substrate failure or absence: persists an honest "concierge
   * unavailable" response and audit-emits with `outcome` = the
   * appropriate failure class. The chat history reflects what the
   * operator sees on the page (no silent dropping).
   */
  async sendConcierge(query: string): Promise<ConciergeResponse> {
    const trimmed = query.trim();
    if (trimmed.length === 0) {
      throw new Error("concierge query must not be empty");
    }

    // Operator's message in. Filter PII before persist + before egress.
    const filterResult = this.piiFilter
      ? this.piiFilter.filter(trimmed)
      : { filtered: trimmed, redactions: 0 };

    // WP-V1.3-9 Tau-2: rotate the active session thread when the prior
    // round-trip is older than `sessionTtlMs`. Allocation of the fresh
    // thread_id happens lazily inside `ensureActiveMemoryThread()` once
    // the rotation cleared the in-memory pointer.
    const nowMs = this.clock();
    if (
      this.activeMemoryThreadId &&
      this.lastInteractionAt !== undefined &&
      nowMs - this.lastInteractionAt > this.sessionTtlMs
    ) {
      this.activeMemoryThreadId = undefined;
    }

    const operatorMessage: OperatorChatMessage = {
      message_id: randomUUID(),
      surface: "concierge",
      role: "operator",
      body: trimmed,
      created_at: new Date().toISOString(),
    };
    await this.store.appendMessage(
      "concierge",
      CONCIERGE_THREAD_KEY,
      operatorMessage,
    );

    // WP-V1.3-9 Tau-2 read-fold path. Loaded BEFORE the operator turn
    // hits the memory store so the prior-turn window does not include
    // the current query. The fold is fail-soft: a corrupted bundle
    // emits a degradation audit event and the substrate call proceeds
    // single-turn, never breaking the user-facing query.
    let priorTurns: ConciergeTurn[] = [];
    let memoryReadFailureReason: ConciergeMemoryReadFailure | null = null;
    let activeThreadIdForRound: string | undefined;
    if (this.memory) {
      activeThreadIdForRound = this.ensureActiveMemoryThread();
      // Pull the full bundle (capped by the store's MAX_BUNDLE_BYTES);
      // freshness + window slicing happen here in the service so the
      // service-side window stays semantically tied to the freshness
      // filter (slice newest-first AFTER stale entries drop out).
      const result = await this.memory
        .readThreadStrict(activeThreadIdForRound)
        .catch(() => ({ ok: false as const, reason: "io_failed" as const }));
      if (result.ok) {
        const cutoff = nowMs - this.historyFreshnessMs;
        const fresh = result.turns.filter((t) => {
          const ts = Date.parse(t.created_at);
          return Number.isFinite(ts) && ts >= cutoff;
        });
        const recent =
          fresh.length > this.historyWindowTurns
            ? fresh.slice(fresh.length - this.historyWindowTurns)
            : fresh;
        priorTurns = recent;
      } else {
        memoryReadFailureReason = result.reason;
        this.emitMemoryReadFailed(activeThreadIdForRound, result.reason);
      }
    }

    // WP-V1.3-9 Tau-1: foundation memory write-side. Append the
    // operator turn to the active session thread.
    if (this.memory) {
      const threadId = this.ensureActiveMemoryThread();
      await this.memory.appendTurn(threadId, "user", trimmed).catch(() => {
        // Memory persistence failure must not break the concierge
        // round-trip. The existing OperatorChatStore write above
        // covers the in-session render; the audit log captures the
        // event regardless. Tau-3 will surface persistence health to
        // the operator.
      });
    }

    const start = Date.now();
    let conciergeBody: string;
    let servedBy: SubstrateChoice = "disabled";
    let displayLabel = "Concierge: substrate not configured";
    let outcome: "ok" | "substrate_failure" | "substrate_disabled" =
      "substrate_disabled";
    let dynamicCategoriesIncluded: ContextCategory[] = [];

    if (!this.substrateSelector) {
      conciergeBody =
        "Concierge unavailable. The substrate selector is not configured for this fortress. Pick a substrate in the Policy center to enable concierge replies.";
    } else {
      try {
        const handle = await this.substrateSelector.getSubstrate("concierge");
        servedBy = handle.substrate;
        displayLabel = handle.displayLabel;

        if (!handle.capability.summarize) {
          conciergeBody =
            "Concierge unavailable. The chosen substrate does not support summarization. Pick a different substrate in the Policy center.";
          outcome = "substrate_disabled";
        } else {
          const dynamicResult = await this.runDynamicContextFold(
            filterResult.filtered,
          );
          dynamicCategoriesIncluded = dynamicResult.categoriesIncluded;
          const context = await this.assembleConciergeContext(
            priorTurns,
            dynamicResult.section,
          );
          const response = await this.substrateSelector.invokeSummarize(
            "concierge",
            {
              kind: "summarize",
              context,
              query: filterResult.filtered,
              maxTokens: this.conciergeMaxTokens,
            },
          );
          if (response.failureClass || response.body.kind !== "summarize") {
            conciergeBody = `Concierge call failed: ${response.failureClass ?? "unknown"}. The substrate selector logged the failure detail.`;
            outcome = "substrate_failure";
          } else {
            conciergeBody = response.body.text;
            outcome = "ok";
            servedBy = response.servedBy;
          }
        }
      } catch (err) {
        conciergeBody = `Concierge call failed: ${
          err instanceof Error ? err.message : String(err)
        }.`;
        outcome = "substrate_failure";
      }
    }

    const latencyMs = Date.now() - start;

    const responseMessage: OperatorChatMessage = {
      message_id: randomUUID(),
      surface: "concierge",
      role: "concierge",
      body: conciergeBody,
      created_at: new Date().toISOString(),
      served_by: servedBy,
      substrate_latency_ms: latencyMs,
    };
    await this.store.appendMessage(
      "concierge",
      CONCIERGE_THREAD_KEY,
      responseMessage,
    );

    // Tau-1 dual-write of the assistant turn. Same memory store, same
    // session thread_id assigned for the operator turn above. The
    // assistant turn id is captured for the audit payload's
    // `turn_index` field.
    let assistantTurnId: number | undefined;
    if (this.memory) {
      const threadId = this.ensureActiveMemoryThread();
      const persisted = await this.memory
        .appendTurn(threadId, "assistant", conciergeBody)
        .catch(() => undefined);
      if (persisted) assistantTurnId = persisted.turn_id;
    }

    // Mark the round-trip's wall-clock for the next session-TTL check.
    if (this.memory && activeThreadIdForRound) {
      this.lastInteractionAt = nowMs;
    }

    const payload: OperatorConciergeChatPayload = {
      version: "1.2",
      event_id: makeEventId("conc"),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "operator_concierge_chat",
      surface: "concierge",
      query_hash: hashOf(trimmed),
      response_hash: outcome === "ok" ? hashOf(conciergeBody) : null,
      substrate: servedBy,
      latency_ms: latencyMs,
      outcome,
      ...(activeThreadIdForRound !== undefined
        ? { thread_id: activeThreadIdForRound }
        : {}),
      ...(assistantTurnId !== undefined ? { turn_index: assistantTurnId } : {}),
      ...(this.memory
        ? {
            prior_turns_folded:
              memoryReadFailureReason === null ? priorTurns.length : 0,
          }
        : {}),
      ...(this.contextFetchers
        ? { dynamic_context_categories: [...dynamicCategoriesIncluded] }
        : {}),
    };
    this.emit(OPERATOR_CHAT_OPS.CONCIERGE_CHAT, payload, outcome === "ok" ? "success" : "failure");

    return {
      message: responseMessage,
      served_by: servedBy,
      display_label: displayLabel,
      outcome,
    };
  }

  /**
   * Emit the WP-V1.3-9 Tau-2 graceful-degradation audit event. Pulled
   * out of `sendConcierge` so the read-fold path stays readable. Emits
   * with `result: "failure"` since the concierge fell back to
   * single-turn mode for this round-trip.
   */
  private emitMemoryReadFailed(
    threadId: string,
    reason: ConciergeMemoryReadFailure,
  ): void {
    const payload: OperatorConciergeMemoryReadFailedPayload = {
      version: "1.2",
      event_id: makeEventId("conc-memfail"),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "operator_concierge_memory_read_failed",
      surface: "concierge",
      thread_id: threadId,
      failure_reason: reason,
    };
    this.emit(OPERATOR_CHAT_OPS.CONCIERGE_MEMORY_READ_FAILED, payload, "failure");
  }

  /**
   * Read the persisted concierge thread, oldest message first. Returns
   * an empty array when no thread exists yet.
   */
  async getConciergeHistory(): Promise<OperatorChatMessage[]> {
    const thread = await this.store.loadThread(
      "concierge",
      CONCIERGE_THREAD_KEY,
    );
    return thread ? thread.messages : [];
  }

  // ── WP-V1.3-9 Tau-1 memory accessors ─────────────────────────────────

  /**
   * Whether the foundation memory store is wired. Routes use this to
   * 503 cleanly when called against an unwired service.
   */
  hasConciergeMemory(): boolean {
    return this.memory !== undefined;
  }

  /**
   * List concierge memory threads, newest-first. Emits the
   * `operator_concierge_history_read` audit event with `thread_id="*"`.
   */
  async listConciergeMemoryThreads(
    opts?: ListThreadsOptions,
  ): Promise<ConciergeThreadSummary[]> {
    if (!this.memory) {
      throw new Error("concierge memory store not configured");
    }
    const summaries = await this.memory.listThreads(opts);
    const totalTurns = summaries.reduce((acc, s) => acc + s.turn_count, 0);
    const payload: OperatorConciergeHistoryReadPayload = {
      version: "1.2",
      event_id: makeEventId("conc-hist"),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "operator_concierge_history_read",
      surface: "concierge",
      thread_id: "*",
      turn_count: totalTurns,
    };
    this.emit(OPERATOR_CHAT_OPS.CONCIERGE_HISTORY_READ, payload, "success");
    return summaries;
  }

  /**
   * Read a concierge memory thread, oldest turn first. Emits the
   * `operator_concierge_history_read` audit event with the named
   * thread_id and the count of turns surfaced.
   */
  async readConciergeMemoryThread(
    threadId: string,
    opts?: ReadThreadOptions,
  ): Promise<ConciergeTurn[]> {
    if (!this.memory) {
      throw new Error("concierge memory store not configured");
    }
    const turns = await this.memory.readThread(threadId, opts);
    const payload: OperatorConciergeHistoryReadPayload = {
      version: "1.2",
      event_id: makeEventId("conc-hist"),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "operator_concierge_history_read",
      surface: "concierge",
      thread_id: threadId,
      turn_count: turns.length,
    };
    this.emit(OPERATOR_CHAT_OPS.CONCIERGE_HISTORY_READ, payload, "success");
    return turns;
  }

  /**
   * Delete a concierge memory thread. Emits
   * `operator_concierge_thread_deleted` only when a bundle was actually
   * removed; absent threads return false without an audit event.
   */
  async deleteConciergeMemoryThread(threadId: string): Promise<boolean> {
    if (!this.memory) {
      throw new Error("concierge memory store not configured");
    }
    const turnsBefore = await this.memory.readThread(threadId);
    if (turnsBefore.length === 0) {
      // No bundle, or empty bundle. Delete is idempotent; we do not
      // emit an audit event for a no-op deletion.
      return await this.memory.deleteThread(threadId);
    }
    const removed = await this.memory.deleteThread(threadId);
    if (!removed) return false;

    if (this.activeMemoryThreadId === threadId) {
      this.activeMemoryThreadId = undefined;
    }

    const payload: OperatorConciergeThreadDeletedPayload = {
      version: "1.2",
      event_id: makeEventId("conc-del"),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "operator_concierge_thread_deleted",
      surface: "concierge",
      thread_id: threadId,
      turn_count: turnsBefore.length,
    };
    this.emit(OPERATOR_CHAT_OPS.CONCIERGE_THREAD_DELETED, payload, "success");
    return true;
  }

  /**
   * Reset the active session memory thread. Subsequent sendConcierge
   * calls allocate a fresh thread_id. Surfaced for tests + future "new
   * conversation" affordance; not currently called by the dashboard.
   */
  resetConciergeMemoryThread(): void {
    this.activeMemoryThreadId = undefined;
  }

  private ensureActiveMemoryThread(): string {
    if (!this.activeMemoryThreadId) {
      this.activeMemoryThreadId = randomUUID();
    }
    return this.activeMemoryThreadId;
  }

  /**
   * Stitch fortress state into a single context blob the substrate
   * folds into its summarization prompt.
   *
   * The blob is intentionally plain text (not structured JSON) because
   * small local models (Gemma 2 2B) handle plain text more reliably
   * than nested structures. Format:
   *
   *   ```
   *   ## Sanctuary reference
   *   <static domain reference block>
   *
   *   ## Live fortress context          ← WP-V1.3-9 Tau-3, when present
   *   ### <Category>
   *   <fetcher payload>
   *
   *   ## Prior conversation             ← WP-V1.3-9 Tau-2, when present
   *   OPERATOR: ...
   *   CONCIERGE: ...
   *
   *   ## Recent activity
   *   <recentActivity output>
   *
   *   ## Wrapped agents
   *   <agentInventory output>
   *
   *   ## Open inbox
   *   <openInbox output>
   *   ```
   *
   * The substrate selector ships a `context: string` shape (not a
   * messages array), so multi-turn coherence is folded as a structured
   * prior-conversation section with explicit OPERATOR / CONCIERGE
   * boundaries. Coordinator-CTO guidance: prefer messages-array shape
   * if available; the v1.2 selector does not expose one, so structured
   * serialization is the canonical path for v1.3.
   */
  private async assembleConciergeContext(
    priorTurns: ConciergeTurn[] = [],
    dynamicSection = "",
  ): Promise<string> {
    const ref = `## Sanctuary reference\n${SANCTUARY_DOMAIN_REFERENCE}`;
    const priorSection = this.formatPriorTurnsSection(priorTurns);

    if (!this.contextProviders) {
      return [
        ref,
        ...(dynamicSection ? [dynamicSection] : []),
        ...(priorSection ? [priorSection] : []),
        "## Recent activity\n(no providers wired)",
        "## Wrapped agents\n(no providers wired)",
        "## Open inbox\n(no providers wired)",
      ].join("\n\n");
    }
    const [activity, agents, inbox] = await Promise.all([
      this.contextProviders.recentActivity(),
      this.contextProviders.agentInventory(),
      this.contextProviders.openInbox(),
    ]);
    return [
      ref,
      ...(dynamicSection ? [dynamicSection] : []),
      ...(priorSection ? [priorSection] : []),
      `## Recent activity\n${activity}`,
      `## Wrapped agents\n${agents}`,
      `## Open inbox\n${inbox}`,
    ].join("\n\n");
  }

  /**
   * Run the WP-V1.3-9 Tau-3 dynamic-context fold for a single round-
   * trip. Fail-soft on every axis: missing fetchers short-circuit to
   * an empty fold, fetcher failures emit a per-category audit event
   * and are omitted from the rendered section, an LLM-assist failure
   * proceeds with no fold. Returns the rendered section + the list of
   * categories whose data made it into the section (used for the
   * round-trip audit emission).
   */
  private async runDynamicContextFold(query: string): Promise<{
    section: string;
    categoriesIncluded: ContextCategory[];
  }> {
    if (!this.contextFetchers) {
      return { section: "", categoriesIncluded: [] };
    }
    const result = await foldContext(query, this.contextFetchers, {
      maxTokens: this.dynamicContextBudget,
      ...(this.contextLlmAssist
        ? { llmAssistClassify: this.contextLlmAssist }
        : {}),
      onFetcherFailure: (category, error) => {
        this.emitContextFetcherFailed(category, classifyFetcherError(error));
      },
    });
    return result;
  }

  /**
   * Emit the WP-V1.3-9 Tau-3 fetcher-failure audit event. Pulled out
   * of the fold path so the dynamic-context handler stays readable.
   * Emits with `result: "failure"` since the named category dropped
   * from the rendered section for this round-trip.
   */
  private emitContextFetcherFailed(
    category: ContextCategory,
    failureReason: OperatorConciergeContextFetcherFailedPayload["failure_reason"],
  ): void {
    const payload: OperatorConciergeContextFetcherFailedPayload = {
      version: "1.2",
      event_id: makeEventId("conc-ctxfail"),
      emitted_at: new Date().toISOString(),
      identity_id: this.identityId,
      kind: "operator_concierge_context_fetcher_failed",
      surface: "concierge",
      category,
      failure_reason: failureReason,
    };
    this.emit(
      OPERATOR_CHAT_OPS.CONCIERGE_CONTEXT_FETCHER_FAILED,
      payload,
      "failure",
    );
  }

  /**
   * Render the prior-conversation section with token-budget enforcement
   * (WP-V1.3-9 Tau-2). Drops oldest turns first when the rendered
   * section exceeds `historyTokenBudget`. Returns an empty string when
   * the input is empty or when the budget excludes every turn.
   */
  private formatPriorTurnsSection(turns: ConciergeTurn[]): string {
    if (turns.length === 0) return "";
    const HEADER = "## Prior conversation";
    // Format every turn into a single block; budget against the lines
    // joined with their separators.
    const lines = turns.map(formatPriorTurnLine);

    const headerTokens = approxTokenLen(`${HEADER}\n`);
    const sepTokens = approxTokenLen("\n");
    let runningTokens = headerTokens;
    let runningLines: string[] = [];

    // Walk newest-first so we keep the most recent turns in budget;
    // reverse the kept list at render time to preserve chronological
    // order. Older turns drop out first.
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i]!;
      const tokens =
        approxTokenLen(line) + (runningLines.length > 0 ? sepTokens : 0);
      if (runningTokens + tokens > this.historyTokenBudget) break;
      runningTokens += tokens;
      runningLines.push(line);
    }
    if (runningLines.length === 0) return "";

    runningLines = runningLines.reverse();
    return `${HEADER}\n${runningLines.join("\n")}`;
  }

  // ── audit helpers ────────────────────────────────────────────────────

  private emit(
    operation: string,
    payload: OperatorChatAuditPayload,
    result: "success" | "failure",
  ): void {
    this.auditLog.append(
      "l2",
      operation,
      this.identityId,
      payload as unknown as Record<string, unknown>,
      result,
    );
  }
}

// ── helpers ──────────────────────────────────────────────────────────────

function makeEventId(prefix: string): string {
  return `${prefix}-${Date.now()}-${randomUUID().slice(0, 8)}`;
}

/**
 * Map a thrown fetcher error into the stable failure-reason enum used
 * by `OperatorConciergeContextFetcherFailedPayload`. Coordinator-CTO
 * bake: keep the mapping conservative so dashboards can group by
 * cause; opaque errors surface as `unknown` so they remain visible
 * without being mis-classified. Future fetcher implementations may
 * throw typed errors that this helper extends to recognize.
 */
function classifyFetcherError(
  error: unknown,
): OperatorConciergeContextFetcherFailedPayload["failure_reason"] {
  const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  if (msg.includes("timeout") || msg.includes("timed out")) return "timeout";
  if (msg.includes("schema") || msg.includes("invalid shape")) {
    return "schema_mismatch";
  }
  if (
    msg.includes("io") ||
    msg.includes("read") ||
    msg.includes("enoent") ||
    msg.includes("eacces")
  ) {
    return "io_failed";
  }
  return "unknown";
}

/**
 * Render a single `ConciergeTurn` as a `OPERATOR:` / `CONCIERGE:` line
 * for the multi-turn fold (WP-V1.3-9 Tau-2). Coordinator-CTO format
 * choice: explicit role labels + content on the same logical line so
 * small local models parse the boundary cleanly. Multi-line content is
 * preserved (the model sees a literal newline inside the line) because
 * stripping it would lose the operator's intent.
 */
function formatPriorTurnLine(turn: ConciergeTurn): string {
  const label = turn.role === "user" ? "OPERATOR" : "CONCIERGE";
  return `${label}: ${turn.content}`;
}

/**
 * SHA-256 of the input string, encoded as base64url (43 chars, no
 * padding). Matches the intelligence-events hashing discipline.
 */
function hashOf(input: string): string {
  return hashToString(sha256(stringToBytes(input)));
}

/**
 * Helper exported for hub-service consumers that need to rehydrate the
 * persisted thread into a sender-role label without re-deriving the
 * map. Keeps display-label semantics co-located with the role enum.
 */
export function operatorChatRoleLabel(
  role: OperatorChatRole,
): string {
  if (role === "operator") return "you";
  if (role === "concierge") return "Sanctuary Fortress concierge";
  return role;
}

export type {
  OperatorChatThread,
};
