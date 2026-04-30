/**
 * Sanctuary MCP Server — Operator Chat Service
 *
 * The operator-fortress chat surface (concierge + direct-agent). Distinct
 * from the agent-to-agent mesh chat (`chat-service.ts`) which handles
 * libp2p + OpenMLS group sessions among wrapped agents.
 *
 * Concierge surface (path: `sendConcierge`):
 *   1. PII-filter the operator query (Tier 1 regex).
 *   2. Build fortress context from audit log + activity feed +
 *      agent registry (`buildConciergeContext`).
 *   3. Invoke the substrate selector at `surface: "concierge"`.
 *   4. Persist operator query + concierge response in the concierge
 *      thread under `_chat/concierge.<sentinel>`.
 *   5. Emit `operator_concierge_chat` audit event with safe metadata.
 *
 * Direct-agent surface (paths: `startSession`, `sendToAgent`, `recordAgentReply`):
 *   1. `startSession` is gated by the hub's Tier 1 inbox approval flow
 *      (see HubService.requestDirectAgentSessionOpen). On approval,
 *      this service receives the `session_id` and creates an in-memory
 *      session record + emits `direct_agent_session_open` audit event.
 *   2. `sendToAgent` persists the operator's message in the per-agent
 *      thread; emits `operator_direct_agent_chat` audit event. The
 *      agent-side delivery mechanism (harness MCP integration) lands
 *      as v1.2.x follow-up; v1.2 ships the operator-side primitives.
 *   3. `recordAgentReply` is the contract for the v1.2.x harness-side
 *      hooks: when an agent's runtime emits a reply through the chosen
 *      delivery mechanism, this method persists + audit-emits.
 *   4. `closeSession` ends the session (operator click, timeout, or
 *      fortress lockdown).
 *
 * Sovereignty invariants:
 * - Audit emission is non-optional on every public method that mutates
 *   the chat state (concierge submit, direct-agent send, session
 *   open/close). Construction with no audit log is structurally
 *   rejected.
 * - The substrate selector is OPTIONAL: a service constructed without
 *   one (concierge degrades to "Concierge unavailable; substrate not
 *   configured") works for direct-agent only. This lets the wiring
 *   layer instantiate the service before the substrate selector when
 *   bootstrap order requires it.
 * - The PII filter is the Tier 1 regex shipped in `l2-operational/privacy-filter.ts`;
 *   Tier 2 NER+LLM redaction lives in the substrate-selector layer
 *   (substrate-routed), not in this service.
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
  DEFAULT_SESSION_TIMEOUT_MS,
  type ConciergeResponse,
  type DirectAgentSendResponse,
  type OperatorChatMessage,
  type OperatorChatRole,
  type OperatorChatSession,
  type OperatorChatSessionState,
  type OperatorChatThread,
} from "./operator-chat-types.js";
import { OperatorChatStore } from "./operator-chat-store.js";
import type {
  AgentDirectAgentReplyPayload,
  OperatorChatAuditPayload,
  OperatorConciergeChatPayload,
  OperatorDirectAgentChatPayload,
  OperatorDirectAgentSessionClosePayload,
  OperatorDirectAgentSessionOpenPayload,
} from "../contracts/v1.2/operator-chat-events.js";

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
  /** Audit log for `operator_*` and `direct_agent_session_*` events. */
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
}

const DEFAULT_CONCIERGE_MAX_TOKENS = 512;

/**
 * Bookkeeping for in-memory direct-agent sessions. v1.2.x F9 added
 * fortress-encrypted persistence so the chat-server subprocess (a
 * separate process spawned by the harness's MCP runtime) can read +
 * mutate the cursor on the same session record. The in-memory Map is
 * a hot-path cache for the dashboard's sync `listActiveSessions()`
 * surface; mutations write through to persistence so the chat-server
 * picks them up on its next poll.
 *
 * Cross-process consistency model:
 *  - Dashboard process: owns session lifecycle (open + close). Writes
 *    persistence + cache on every mutation. Reads from cache on hot
 *    paths; falls back to persistence when cache misses.
 *  - Chat-server subprocess: constructs its own service instance
 *    pointed at the same fortress storage. Cache starts empty;
 *    persistence-fallback hydrates on first lookup. Only the
 *    `last_polled_message_id` cursor is written by the chat-server
 *    (via `advancePollCursor`) — never the lifecycle fields. The two
 *    writer roles don't overlap on the same field by design.
 *  - Restart of the dashboard process: in-flight sessions persist on
 *    disk. v1.2.x ships fresh-fortress acceptance only; full hydration
 *    of pre-existing sessions on dashboard boot is a v1.3 polish item.
 */
type SessionMap = Map<string, OperatorChatSession>;

export class OperatorChatService {
  private store: OperatorChatStore;
  private auditLog: AuditLog;
  private identityId: string;
  private substrateSelector?: SubstrateSelector;
  private contextProviders?: ConciergeContextProviders;
  private piiFilter?: ConciergePiiFilter;
  private conciergeMaxTokens: number;
  private sessions: SessionMap = new Map();

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

    const start = Date.now();
    let conciergeBody: string;
    let servedBy: SubstrateChoice = "disabled";
    let displayLabel = "Concierge: substrate not configured";
    let outcome: "ok" | "substrate_failure" | "substrate_disabled" =
      "substrate_disabled";

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
          const context = await this.assembleConciergeContext();
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

  /**
   * Stitch fortress state into a single context blob the substrate
   * folds into its summarization prompt.
   *
   * The blob is intentionally plain text (not structured JSON) because
   * small local models (Gemma 2 2B) handle plain text more reliably
   * than nested structures. Format:
   *
   *   ```
   *   ## Recent activity
   *   <recentActivity output>
   *
   *   ## Wrapped agents
   *   <agentInventory output>
   *
   *   ## Open inbox
   *   <openInbox output>
   *   ```
   */
  private async assembleConciergeContext(): Promise<string> {
    if (!this.contextProviders) {
      return "## Recent activity\n(no providers wired)\n\n## Wrapped agents\n(no providers wired)\n\n## Open inbox\n(no providers wired)";
    }
    const [activity, agents, inbox] = await Promise.all([
      this.contextProviders.recentActivity(),
      this.contextProviders.agentInventory(),
      this.contextProviders.openInbox(),
    ]);
    return `## Recent activity\n${activity}\n\n## Wrapped agents\n${agents}\n\n## Open inbox\n${inbox}`;
  }

  // ── Direct-agent ─────────────────────────────────────────────────────

  /**
   * Begin a direct-agent chat session. v1.2.x: opened synchronously on the
   * operator's click in the dashboard. The click affordance IS the
   * affirmative action; no Tier 1 inbox approval ask. The deprecated
   * inbox-routed path (kept for back-compat callers) sets
   * `approvalInboxItemId` to the resolved item id; the click-to-chat path
   * passes null.
   *
   * The `expiresAt` argument is the operator-configured expiry; the
   * service does NOT auto-time-out (the hub or a periodic sweeper
   * checks `expires_at` and calls `closeSession` with reason
   * "session_timeout"). Keeping expiry policy out of this service
   * leaves the v1.2.x sweeper clean to land later.
   */
  async openDirectAgentSession(args: {
    agentId: string;
    /** Tier 1 inbox item id; null on click-to-chat path. */
    approvalInboxItemId?: string | null;
    channelTemplateId: string | null;
    expiresAtIsoOverride?: string;
  }): Promise<OperatorChatSession> {
    const approvalInboxItemId = args.approvalInboxItemId ?? null;
    const sessionId = `chat-session-${randomUUID()}`;
    const createdAt = new Date();
    const expiresAtIso =
      args.expiresAtIsoOverride ??
      new Date(createdAt.getTime() + DEFAULT_SESSION_TIMEOUT_MS).toISOString();
    const session: OperatorChatSession = {
      session_id: sessionId,
      agent_id: args.agentId,
      approval_inbox_item_id: approvalInboxItemId,
      created_at: createdAt.toISOString(),
      expires_at: expiresAtIso,
      last_polled_message_id: null,
    };
    this.sessions.set(sessionId, session);
    // v1.2.x F9: write-through to fortress persistence so the chat-server
    // subprocess sees the new session on its next poll. Index-by-agent
    // gives the chat-server O(1) "is there an active session for this
    // agent?" lookup without scanning every session record.
    await this.store.writeSession(session);
    await this.store.setActiveSessionIdForAgent(args.agentId, sessionId);

    const payload: OperatorDirectAgentSessionOpenPayload = {
      version: "1.2",
      event_id: makeEventId("sess-open"),
      emitted_at: createdAt.toISOString(),
      identity_id: this.identityId,
      kind: "direct_agent_session_open",
      agent_id: args.agentId,
      session_id: sessionId,
      channel_template_id: args.channelTemplateId,
      approval_inbox_item_id: approvalInboxItemId,
      expires_at: expiresAtIso,
    };
    this.emit(OPERATOR_CHAT_OPS.DIRECT_AGENT_SESSION_OPEN, payload, "success");

    return session;
  }

  /**
   * Close a direct-agent chat session. Idempotent on already-closed
   * sessions (returns the existing closed record without emitting a
   * second close event). Returns null if the session id is unknown.
   */
  async closeDirectAgentSession(
    sessionId: string,
    reason:
      | "operator_close"
      | "session_timeout"
      | "fortress_lockdown"
      | "agent_unwrapped",
  ): Promise<OperatorChatSession | null> {
    const session = await this.resolveSession(sessionId);
    if (!session) return null;
    if (session.closed_at) return session;
    const closedAt = new Date().toISOString();
    const closed: OperatorChatSession = {
      ...session,
      closed_at: closedAt,
      close_reason: reason,
    };
    this.sessions.set(sessionId, closed);
    // v1.2.x F9: persist the closed-state record so the chat-server
    // subprocess returns generic-error "No active session" on its next
    // poll, and clear the per-agent active-session index so a fresh
    // session on the same agent can rebind cleanly.
    await this.store.writeSession(closed);
    await this.store.setActiveSessionIdForAgent(session.agent_id, null);

    const payload: OperatorDirectAgentSessionClosePayload = {
      version: "1.2",
      event_id: makeEventId("sess-close"),
      emitted_at: closedAt,
      identity_id: this.identityId,
      kind: "direct_agent_session_close",
      agent_id: session.agent_id,
      session_id: sessionId,
      close_reason: reason,
    };
    this.emit(OPERATOR_CHAT_OPS.DIRECT_AGENT_SESSION_CLOSE, payload, "success");

    return closed;
  }

  /**
   * Snapshot of the in-memory session map. Used by the hub routes for
   * session-state queries and by tests.
   */
  listActiveSessions(): OperatorChatSession[] {
    return Array.from(this.sessions.values()).filter((s) => !s.closed_at);
  }

  /**
   * Look up a session by id from the in-memory cache only. Sync — used
   * by the dashboard's hot path (hub-service `sendDirectAgentMessage`,
   * route handlers). Returns null when the session is not in cache,
   * including the cross-process case where the chat-server has just
   * advanced a cursor on a session this instance has never seen. For
   * cross-process consistency use `resolveSession` (async).
   */
  getSession(sessionId: string): OperatorChatSession | null {
    return this.sessions.get(sessionId) ?? null;
  }

  /**
   * Look up a session by id, falling back to fortress persistence on
   * cache miss. Used by every public method that needs the latest
   * session state (open/close/send/reply). The chat-server subprocess's
   * service instance starts with an empty cache and resolves on first
   * call; the dashboard process's instance cache is hot from session
   * lifecycle and only falls back when the chat-server has advanced
   * a cursor between calls.
   *
   * Populates the cache on persistence-fallback hit so subsequent reads
   * of the same session id are O(1).
   */
  async resolveSession(
    sessionId: string,
  ): Promise<OperatorChatSession | null> {
    const cached = this.sessions.get(sessionId);
    if (cached) return cached;
    const persisted = await this.store.loadSession(sessionId);
    if (persisted) this.sessions.set(sessionId, persisted);
    return persisted;
  }

  /**
   * Look up the active session bound to an agent. Reads the per-agent
   * index from persistence. Returns null when no active session exists
   * (or when the indexed session is closed). Used by the chat-server's
   * `chat/poll_inbox` handler.
   */
  async findActiveSessionForAgent(
    agentId: string,
  ): Promise<OperatorChatSession | null> {
    const sessionId = await this.store.getActiveSessionIdForAgent(agentId);
    if (!sessionId) return null;
    const session = await this.resolveSession(sessionId);
    if (!session) return null;
    if (session.closed_at) return null;
    return session;
  }

  /**
   * Advance the per-session poll cursor to a new message id. Used by
   * the chat-server's `chat/poll_inbox` handler after returning a
   * batch of operator messages to the wrapped agent. Last-write-wins;
   * concurrent advances on the same session resolve to whichever value
   * the storage backend's tail accepts last (the chat-server is the
   * only writer of this field, so concurrent writers don't actually
   * arise in v1.2.x).
   *
   * Persists the new cursor and refreshes the in-memory cache.
   */
  async advancePollCursor(
    sessionId: string,
    lastSeenMessageId: string,
  ): Promise<void> {
    const session = await this.resolveSession(sessionId);
    if (!session) return;
    if (session.closed_at) return;
    const next: OperatorChatSession = {
      ...session,
      last_polled_message_id: lastSeenMessageId,
    };
    this.sessions.set(sessionId, next);
    await this.store.writeSession(next);
  }

  /**
   * Operator submit on a direct-agent session. Persists the operator's
   * message, audit-emits, and returns the persisted record + session
   * state. The agent-side delivery mechanism is harness integration
   * shipping as v1.2.x follow-up; v1.2 ships the operator-side
   * primitives so the contract is stable when harness hooks land.
   *
   * Throws if the session id is unknown or already closed; the chat
   * surface catches and surfaces "session expired; reopen with Tier 1
   * approval" inline.
   */
  async sendToAgent(args: {
    sessionId: string;
    body: string;
  }): Promise<DirectAgentSendResponse> {
    const session = await this.resolveSession(args.sessionId);
    if (!session) {
      throw new Error("unknown chat session");
    }
    if (session.closed_at) {
      throw new Error("chat session already closed");
    }
    const trimmed = args.body.trim();
    if (trimmed.length === 0) {
      throw new Error("direct-agent message must not be empty");
    }

    const message: OperatorChatMessage = {
      message_id: randomUUID(),
      surface: "direct-agent",
      agent_id: session.agent_id,
      session_id: args.sessionId,
      role: "operator",
      body: trimmed,
      created_at: new Date().toISOString(),
    };
    await this.store.appendMessage(
      "direct-agent",
      session.agent_id,
      message,
    );

    const payload: OperatorDirectAgentChatPayload = {
      version: "1.2",
      event_id: makeEventId("op-msg"),
      emitted_at: message.created_at,
      identity_id: this.identityId,
      kind: "operator_direct_agent_chat",
      agent_id: session.agent_id,
      session_id: args.sessionId,
      message_hash: hashOf(trimmed),
      sender_role: "operator",
      direction: "operator_to_agent",
    };
    this.emit(OPERATOR_CHAT_OPS.DIRECT_AGENT_CHAT, payload, "success");

    return {
      message,
      session,
      session_state: this.computeSessionState(session),
    };
  }

  /**
   * Record an agent reply in a direct-agent session. The harness-side
   * v1.2.x integration calls this when the wrapped agent's runtime
   * emits a response to the operator. Persists the message, audit-
   * emits, and returns the persisted record.
   *
   * Throws if the session id is unknown or already closed; the harness
   * caller surfaces the failure to its own logs.
   */
  async recordAgentReply(args: {
    sessionId: string;
    body: string;
  }): Promise<OperatorChatMessage> {
    const session = await this.resolveSession(args.sessionId);
    if (!session) {
      throw new Error("unknown chat session");
    }
    if (session.closed_at) {
      throw new Error("chat session already closed");
    }
    const trimmed = args.body.trim();
    if (trimmed.length === 0) {
      throw new Error("agent reply must not be empty");
    }

    const message: OperatorChatMessage = {
      message_id: randomUUID(),
      surface: "direct-agent",
      agent_id: session.agent_id,
      session_id: args.sessionId,
      role: "agent",
      body: trimmed,
      created_at: new Date().toISOString(),
    };
    await this.store.appendMessage(
      "direct-agent",
      session.agent_id,
      message,
    );

    const payload: AgentDirectAgentReplyPayload = {
      version: "1.2",
      event_id: makeEventId("ag-reply"),
      emitted_at: message.created_at,
      identity_id: this.identityId,
      kind: "agent_direct_agent_reply",
      agent_id: session.agent_id,
      session_id: args.sessionId,
      response_hash: hashOf(trimmed),
      sender_role: "agent",
      direction: "agent_to_operator",
    };
    this.emit(OPERATOR_CHAT_OPS.DIRECT_AGENT_REPLY, payload, "success");

    return message;
  }

  /**
   * Read the persisted per-agent direct-agent chat history. Returns an
   * empty array when no thread exists yet. Operator's chat surface
   * calls this on session-open.
   */
  async getDirectAgentHistory(
    agentId: string,
  ): Promise<OperatorChatMessage[]> {
    const thread = await this.store.loadThread("direct-agent", agentId);
    return thread ? thread.messages : [];
  }

  /**
   * Compute the operator-visible session state from the in-memory
   * record. Surface-rendered in the chat header.
   */
  private computeSessionState(
    session: OperatorChatSession,
  ): OperatorChatSessionState {
    if (session.closed_at) return "closed";
    const expiresAt = Date.parse(session.expires_at);
    if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
      return "expired";
    }
    return "active";
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
  agentId?: string,
): string {
  if (role === "operator") return "you";
  if (role === "concierge") return "Sanctuary Fortress concierge";
  if (role === "agent") return agentId ?? "agent";
  return role;
}

export type {
  OperatorChatThread,
};
