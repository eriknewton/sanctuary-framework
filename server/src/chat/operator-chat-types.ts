/**
 * Sanctuary MCP Server — Operator Chat Types
 *
 * Distinct from the existing agent-to-agent mesh chat (`chat-service.ts`).
 * Operator chat is the operator-fortress concierge surface: an operator
 * types into the v1.1 dashboard, Sanctuary persists the conversation,
 * audits every message, and routes responses through the substrate
 * selector.
 *
 * The direct-agent surface (operator-to-wrapped-agent conversation) was
 * removed in the v1.2 reshape. The concierge surface (operator-to-
 * Sanctuary) is the only operator chat surface that ships in v1.2.
 *
 * Sovereignty invariants:
 * - Conversation history is encrypted at rest under the fortress master
 *   key via an HKDF-derived purpose key.
 * - Audit emission is non-optional: every operator submit and every
 *   concierge reply lands in the L2 audit log.
 * - No raw message bodies are stored in audit `details`; only message
 *   hashes and safe metadata. Bodies live in the encrypted chat store
 *   that the operator can export, delete, or rotate.
 */

import type { SubstrateChoice } from "../intelligence/types.js";

/**
 * The chat surface a message belongs to. Concierge is the only operator
 * chat surface in v1.2; the type stays a single-member union for
 * forward-compatibility if additional Sanctuary-side surfaces land later.
 */
export type OperatorChatSurface = "concierge";

/**
 * Message-role enum. Concierge has two roles: `operator` (the human) and
 * `concierge` (Sanctuary's response).
 */
export type OperatorChatRole = "operator" | "concierge";

/**
 * One message in a concierge thread. The body is stored encrypted at
 * rest; the in-memory shape carries the cleartext for service consumers,
 * and the audit emission carries only `message_hash` + safe metadata.
 */
export interface OperatorChatMessage {
  /** Stable message id (uuid) assigned at create time. */
  message_id: string;
  /** Surface this message belongs to. */
  surface: OperatorChatSurface;
  /** Sender role. */
  role: OperatorChatRole;
  /** Cleartext body. NEVER appears in audit `details`. */
  body: string;
  /** ISO8601 timestamp the message was created. */
  created_at: string;
  /**
   * For concierge response messages: which substrate served the response.
   * Null on operator-sent messages. Surfaces in the chat header badge.
   */
  served_by?: SubstrateChoice;
  /**
   * For concierge response messages: latency of the substrate call in ms.
   * Operator-side surfaces this in the message tooltip / activity feed.
   */
  substrate_latency_ms?: number;
}

/**
 * The shape persisted to disk under `_chat/<surface>/<thread-key>`.
 *
 * Threads are append-only; the persisted record is read-rewritten on
 * every message append. v1.2 caps thread length at
 * `OPERATOR_CHAT_MAX_THREAD_LENGTH`; older messages drop off when the
 * cap is exceeded.
 */
export interface OperatorChatThread {
  /** Forward-compat field. v1.2 uses 1; bump on schema change. */
  version: 1;
  /** Surface (concierge in v1.2). */
  surface: OperatorChatSurface;
  /** Thread key; concierge is fortress-scoped under `CONCIERGE_THREAD_KEY`. */
  thread_key: string;
  /** Append-only message log; oldest first. */
  messages: OperatorChatMessage[];
  /** ISO8601 timestamp the thread was last updated. */
  updated_at: string;
}

/**
 * Concierge response envelope. Carries the substrate response (or
 * fallback message) plus the operator-visible substrate badge.
 */
export interface ConciergeResponse {
  /** The response message persisted into the concierge thread. */
  message: OperatorChatMessage;
  /** The substrate that served this query. */
  served_by: SubstrateChoice;
  /** Operator-visible label rendered next to the response. */
  display_label: string;
  /** Outcome class for activity-feed projection. */
  outcome: "ok" | "substrate_failure" | "substrate_disabled";
}

/**
 * Maximum thread length retained in the persisted store. Older messages
 * fall off when the cap is exceeded; the audit log retains the full
 * history regardless. Set conservatively at v1.2; tunable via storage
 * pressure if operators report churn.
 */
export const OPERATOR_CHAT_MAX_THREAD_LENGTH = 500;

/**
 * Stable concierge thread key. Concierge is fortress-scoped (no agent
 * id), so the thread-key namespace uses a sentinel.
 */
export const CONCIERGE_THREAD_KEY = "_fortress" as const;
