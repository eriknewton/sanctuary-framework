/**
 * Sanctuary MCP Server — Operator Chat Types
 *
 * Distinct from the existing agent-to-agent mesh chat (`chat-service.ts`).
 * Operator chat is the operator-fortress surface: an operator types into
 * the v1.1 dashboard, Sanctuary persists the conversation, audits every
 * message, and (concierge) routes through the substrate selector.
 *
 * Two surfaces:
 *
 *   1. **Concierge** — operator asks the fortress about itself. Substrate
 *      selector summarizes audit log + activity feed + agent registry.
 *      No session model; concierge is always available.
 *
 *   2. **Direct-agent** — operator opens a Tier 1-gated session with one
 *      wrapped agent and exchanges messages. The agent-side response
 *      mechanism is harness integration shipping as a v1.2.x follow-up;
 *      v1.2 ships the operator-side persistence + audit + Tier 1 gate +
 *      UI surface so the agent-side work has a stable contract to land
 *      against.
 *
 * Sovereignty invariants:
 * - Conversation history is encrypted at rest under the fortress master
 *   key via an HKDF-derived purpose key (one per surface).
 * - Audit emission is non-optional: every operator submit and every
 *   agent reply lands in the L2 audit log.
 * - No raw message bodies are stored in audit `details`; only message
 *   hashes and safe metadata. Bodies live in the encrypted chat store
 *   that the operator can export, delete, or rotate.
 */

import type { SubstrateChoice } from "../intelligence/types.js";

/**
 * The chat surface a message belongs to. Concierge is fortress-wide;
 * direct-agent is per-agent.
 */
export type OperatorChatSurface = "concierge" | "direct-agent";

/**
 * Message-role enum. v1.2 ships `operator` and `agent`; the concierge
 * surface uses `concierge` as the agent-side role for clarity in the
 * persisted chat log.
 */
export type OperatorChatRole = "operator" | "concierge" | "agent";

/**
 * One message in a chat thread. The body is stored encrypted at rest;
 * the in-memory shape carries the cleartext for service consumers, and
 * the audit emission carries only `message_hash` + safe metadata.
 */
export interface OperatorChatMessage {
  /** Stable message id (uuid) assigned at create time. */
  message_id: string;
  /** Surface this message belongs to. */
  surface: OperatorChatSurface;
  /**
   * For direct-agent: the wrapped agent's id.
   * For concierge: omitted (the surface is fortress-scoped).
   */
  agent_id?: string;
  /**
   * For direct-agent: the Tier 1 approved session id.
   * For concierge: omitted (no session model).
   */
  session_id?: string;
  /** Sender role. */
  role: OperatorChatRole;
  /** Cleartext body. NEVER appears in audit `details`. */
  body: string;
  /** ISO8601 timestamp the message was created. */
  created_at: string;
  /**
   * For concierge messages: which substrate served the response. Null on
   * operator-sent messages. Surfaces in the chat header badge.
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
  /** Surface (concierge | direct-agent). */
  surface: OperatorChatSurface;
  /** For direct-agent: agent id. For concierge: "_fortress". */
  thread_key: string;
  /** Append-only message log; oldest first. */
  messages: OperatorChatMessage[];
  /** ISO8601 timestamp the thread was last updated. */
  updated_at: string;
}

/**
 * Direct-agent chat session. Created on Tier 1 inbox approval; closes on
 * operator click, timeout, or fortress lockdown.
 */
export interface OperatorChatSession {
  /** Stable session id (uuid). */
  session_id: string;
  /** The wrapped agent the session is bound to. */
  agent_id: string;
  /** Tier 1 inbox item the session was approved through. */
  approval_inbox_item_id: string;
  /** ISO8601 created at. */
  created_at: string;
  /** ISO8601 expires at (operator-configurable; default 1h after create). */
  expires_at: string;
  /** ISO8601 closed at, or undefined while session is active. */
  closed_at?: string;
  /** Reason the session ended. */
  close_reason?:
    | "operator_close"
    | "session_timeout"
    | "fortress_lockdown"
    | "agent_unwrapped";
}

/**
 * Stable session-state enum the dashboard surfaces in the chat header.
 */
export type OperatorChatSessionState =
  | "approval_pending"
  | "active"
  | "expired"
  | "closed";

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
 * Direct-agent send response. Carries the persisted operator message;
 * the agent's reply arrives later through the harness integration path
 * and surfaces as a separate message in the thread.
 */
export interface DirectAgentSendResponse {
  /** The operator message persisted into the per-agent thread. */
  message: OperatorChatMessage;
  /** Session this message belongs to. */
  session: OperatorChatSession;
  /** Stable session state at the time of send. */
  session_state: OperatorChatSessionState;
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

/**
 * Default direct-agent session timeout in milliseconds. Operator-
 * configurable per-session via the start-session payload; 1 hour matches
 * the spawn-prompt default.
 */
export const DEFAULT_SESSION_TIMEOUT_MS = 60 * 60 * 1000;
