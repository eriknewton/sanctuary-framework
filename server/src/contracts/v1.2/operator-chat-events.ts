/**
 * Sanctuary v1.2 — Operator Chat Audit Payload Contracts
 *
 * Shared payload shapes emitted by the operator chat service and consumed
 * by audit-query callers, the dashboard activity feed, and the chat
 * routes' history endpoint.
 *
 * The direct-agent surface (operator-to-wrapped-agent conversation) was
 * removed in the v1.2 reshape. Only the concierge payload shape ships in
 * v1.2; the click-to-inspect repurpose emits the
 * `agent_inspect_panel_opened` event whose payload shape lives alongside
 * the hub-events contract surface.
 *
 * Local-only invariant:
 * Payloads describe operator-fortress chat activity inside a single
 * fortress on a single operator's machine. v1.2 ships single-operator
 * scope; cross-fortress federation surfaces ship later.
 *
 * Enclosure-and-signing model:
 * Operator chat events are NOT signed objects on their own. They are
 * payloads carried inside an enclosing audit-chain entry
 * (`l2-operational/audit-log` AuditEntry encrypted-at-rest under L1). The
 * enclosing audit entry carries the signature scheme; this file
 * deliberately does not declare a signature field on any payload type.
 *
 * Operation-name registry:
 * The string operation names emitted into AuditEntry.operation are the
 * `OPERATOR_CHAT_OPS` constants in `server/src/chat/operator-chat-audit-events.ts`.
 *
 * Safe-metadata invariant:
 * Raw message bodies, response bodies, raw audit-log slices used as
 * concierge context, and operator queries MUST NEVER appear in any field
 * of any payload defined in this file. Only safe metadata is permitted:
 * surface enum, message-id, hashes of bodies, latency, substrate-id,
 * identity id, fallback action enum, message counts.
 *
 * Hashing discipline:
 * Concierge payloads carry hashes of the message body and response body,
 * never the bodies themselves. v1.2 uses the existing
 * `core/hashing.hashToString(sha256(stringToBytes(...)))` SHA-256 hash
 * encoded as base64url — same shape as `intelligence-events.ts`.
 */

import type {
  Surface,
  SubstrateChoice,
} from "../../intelligence/types.js";
import type { ParsedQueryAuditSummary } from "../../chat/concierge-query-grammar.js";
import type { ProactiveStarterTrigger } from "../../chat/agent-context-cache.js";

/**
 * Common metadata header on every v1.2 operator-chat audit payload.
 *
 * `event_id` is the audit-chain id assigned by the enclosing AuditEntry.
 * `identity_id` is the operator identity that owns the chat session.
 */
export interface OperatorChatAuditPayloadHeader {
  /** v1.2 payload-shape version. */
  version: "1.2";
  /** Unique event id; SHOULD match the enclosing audit-chain id. */
  event_id: string;
  /** ISO8601 timestamp of the chat event. */
  emitted_at: string;
  /** Identity the chat session is bound to (the operator's principal). */
  identity_id: string;
}

/**
 * Operator sent a message to the concierge. Emitted once per submit.
 *
 * `query_hash` is a SHA-256 of the operator's typed query, never the
 * query itself. The substrate selector emits its own
 * `intelligence_substrate_invoked` event for the underlying LLM call;
 * this event is the chat-layer record above it.
 */
export interface OperatorConciergeChatPayload extends OperatorChatAuditPayloadHeader {
  kind: "operator_concierge_chat";
  /** Always "concierge" in v1.2; structurally typed for forward-compat. */
  surface: Extract<Surface, "concierge">;
  /** Hash of the operator's query body. */
  query_hash: string;
  /** Hash of the substrate's response body. Null on substrate failure. */
  response_hash: string | null;
  /** Substrate that served the query (operator's per-surface choice). */
  substrate: SubstrateChoice;
  /** Total wall-clock latency of the submit-to-render round trip in ms. */
  latency_ms: number;
  /** Whether the substrate call returned a real summary or fell back. */
  outcome: "ok" | "substrate_failure" | "substrate_disabled";
  /**
   * Concierge memory thread the round-trip belongs to (WP-V1.3-9 Tau-2).
   * Present when the foundation memory store is wired; absent on services
   * that have not opted in to memory-backed concierge sessions.
   */
  thread_id?: string;
  /**
   * Monotonic turn id of the assistant message that closed the round-trip
   * (WP-V1.3-9 Tau-2). Operator turn id is `turn_index - 1`. Absent when
   * the memory store is not wired or when the assistant persistence step
   * failed.
   */
  turn_index?: number;
  /**
   * Number of prior turns folded into the substrate context for this
   * round-trip (WP-V1.3-9 Tau-2). Zero on the first turn of a session,
   * and zero when memory-backed history was unavailable. Excludes the
   * current operator query.
   */
  prior_turns_folded?: number;
  /**
   * Dynamic context categories whose fetcher data folded into the
   * substrate context for this round-trip (WP-V1.3-9 Tau-3). Empty
   * array on turns where keyword classification produced no matches
   * and the LLM-assist fallback declined or was not configured.
   * Absent on services constructed without a dynamic context router
   * (additive forward-compat, no new event class).
   */
  dynamic_context_categories?: string[];
  /**
   * Operator-query grammar parse summary (WP-V1.3-9 Tau-4). Carries
   * the structured time range, agent names, event types, ambiguity
   * flags, and parse confidence the grammar layer extracted from the
   * operator's query before the round-trip. Audit-safe by construction:
   * the runtime `ParsedQuery.intent_phrase` field (free-form residual
   * carrying raw operator query content) is stripped at projection;
   * see `auditSafeSummary` in `chat/concierge-query-grammar.ts`.
   *
   * Absent on services constructed without the grammar wired (additive
   * forward-compat, no new event class).
   */
  parsed_grammar?: ParsedQueryAuditSummary;
  /**
   * Number of agent-context snapshots folded into the substrate prompt
   * for this round-trip (WP-V1.3-9 Tau-5). Zero when the concierge
   * agent-context cache is not wired or when the operator has no
   * wrapped agents. Counts post-budget-prune snapshots (the number
   * actually rendered into the "Current agent state" section), not the
   * raw cache size.
   */
  agent_context_snapshot_count?: number;
}

/**
 * Concierge surfaced a proactive starter when a fresh conversation
 * thread opened (WP-V1.3-9 Tau-5). Emitted once per starter, never on
 * follow-up turns within the same thread. `trigger` is the stable enum
 * the agent-context cache used to choose the suggestion class;
 * `triggered_agents_count` is how many agents contributed to the
 * trigger (e.g., the count of stuck agents when trigger is
 * `stuck_agent`).
 *
 * The starter text body is intentionally NOT carried here: trigger +
 * count are sufficient for dashboard grouping, and keeping the body
 * off the audit surface protects fortress-internal agent ids that may
 * appear inside the operator-visible suggestion copy.
 */
export interface OperatorConciergeProactiveSuggestionOfferedPayload
  extends OperatorChatAuditPayloadHeader {
  kind: "operator_concierge_proactive_suggestion_offered";
  surface: Extract<Surface, "concierge">;
  /** Concierge memory thread the starter was offered for. */
  thread_id: string;
  /** Stable trigger-class enum chosen by the cache. */
  trigger: ProactiveStarterTrigger;
  /** Count of agents whose state contributed to the trigger. */
  triggered_agents_count: number;
}

/**
 * Operator viewed concierge thread history (WP-V1.3-9 Tau-1). Emitted on
 * list-threads and read-thread routes. `thread_id` carries the requested
 * id, or the literal `*` for the list endpoint where no single thread is
 * named. `turn_count` is the number of turns surfaced by the call (0 on
 * an empty thread or empty list); raw turn content NEVER appears here.
 */
export interface OperatorConciergeHistoryReadPayload
  extends OperatorChatAuditPayloadHeader {
  kind: "operator_concierge_history_read";
  surface: Extract<Surface, "concierge">;
  thread_id: string;
  turn_count: number;
}

/**
 * Operator deleted a concierge thread (WP-V1.3-9 Tau-1). Emitted on
 * successful thread removal. `turn_count` records how many turns were
 * dropped at delete time; the audit log retains the per-event history
 * regardless.
 */
export interface OperatorConciergeThreadDeletedPayload
  extends OperatorChatAuditPayloadHeader {
  kind: "operator_concierge_thread_deleted";
  surface: Extract<Surface, "concierge">;
  thread_id: string;
  turn_count: number;
}

/**
 * Concierge memory read failed during multi-turn fold (WP-V1.3-9 Tau-2).
 * Emitted when the substrate-context fold path attempts to load the active
 * thread's prior turns and the load fails (decryption error, schema
 * mismatch, oversize bundle). The concierge MUST degrade to single-turn
 * after emitting; this payload records the degradation for forensic
 * triage. `failure_reason` is a stable enum so dashboards can group by
 * cause without parsing free-form text.
 */
export interface OperatorConciergeMemoryReadFailedPayload
  extends OperatorChatAuditPayloadHeader {
  kind: "operator_concierge_memory_read_failed";
  surface: Extract<Surface, "concierge">;
  thread_id: string;
  failure_reason:
    | "decrypt_failed"
    | "schema_mismatch"
    | "oversize_bundle"
    | "io_failed"
    | "unknown";
}

/**
 * Concierge dynamic-context fetcher failed (WP-V1.3-9 Tau-3). Emitted
 * when the dynamic context router runs a category fetcher that throws.
 * The concierge MUST omit that category's fold and continue rendering
 * the surviving categories; the user-facing query is never broken by
 * a context-assembly failure. `category` carries the fetcher that
 * failed; `failure_reason` is a stable enum so dashboards can group
 * by cause without parsing free-form text. The error message itself
 * is intentionally not included to keep operator queries + raw audit
 * payloads off the audit surface.
 */
export interface OperatorConciergeContextFetcherFailedPayload
  extends OperatorChatAuditPayloadHeader {
  kind: "operator_concierge_context_fetcher_failed";
  surface: Extract<Surface, "concierge">;
  /**
   * Dynamic context category whose fetcher threw. Stable enum; aligns
   * with the concierge-context-router category surface.
   */
  category:
    | "templates"
    | "agent_state"
    | "agent_activity"
    | "audit_log"
    | "sentinel_findings"
    | "anomaly_alerts"
    | "recent_receipts"
    | "verascore_deltas";
  /** Stable failure-reason enum; defaults to `unknown` on opaque errors. */
  failure_reason: "unknown" | "io_failed" | "schema_mismatch" | "timeout";
}

/**
 * Discriminated union of every operator-chat payload shape v1.2 emits.
 */
export type OperatorChatAuditPayload =
  | OperatorConciergeChatPayload
  | OperatorConciergeHistoryReadPayload
  | OperatorConciergeThreadDeletedPayload
  | OperatorConciergeMemoryReadFailedPayload
  | OperatorConciergeContextFetcherFailedPayload
  | OperatorConciergeProactiveSuggestionOfferedPayload;
