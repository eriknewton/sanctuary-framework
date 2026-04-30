/**
 * Sanctuary v1.2 — Operator Chat Audit Payload Contracts
 *
 * Shared payload shapes emitted by the operator chat service and consumed
 * by audit-query callers, the dashboard activity feed, and the chat
 * routes' history endpoint.
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
 * surface enum, agent-id (the wrapped agent's id is fortress-local
 * non-secret), session-id, message-id, hashes of bodies, latency,
 * substrate-id, identity id, fallback action enum, message counts.
 *
 * Hashing discipline:
 * Concierge and direct-agent payloads carry hashes of the message body
 * and response body, never the bodies themselves. v1.2 uses the existing
 * `core/hashing.hashToString(sha256(stringToBytes(...)))` SHA-256 hash
 * encoded as base64url — same shape as `intelligence-events.ts`.
 */

import type {
  Surface,
  SubstrateChoice,
} from "../../intelligence/types.js";

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
}

/**
 * Operator sent a message to a wrapped agent in a direct-agent chat
 * session. Emitted once per submit.
 *
 * `agent_id` identifies the wrapped agent the message was addressed to.
 * `session_id` is the Tier 1 approved session this message belongs to.
 * `message_hash` is a SHA-256 of the operator's message body.
 *
 * Direct-agent chat is pass-through to the wrapped agent's MCP at v1.2
 * (no Sanctuary-side LLM involved in the chat itself); the substrate
 * selector is consulted only for the optional Tier 1 advisory check at
 * session-open time, not per message.
 */
export interface OperatorDirectAgentChatPayload extends OperatorChatAuditPayloadHeader {
  kind: "operator_direct_agent_chat";
  /** The wrapped agent the message was addressed to. */
  agent_id: string;
  /** The Tier 1 approved session this message belongs to. */
  session_id: string;
  /** Hash of the operator's message body. */
  message_hash: string;
  /** Stable sender role; always "operator" for this event. */
  sender_role: "operator";
  /** Direction of the message in the chat history. */
  direction: "operator_to_agent";
}

/**
 * Wrapped agent responded to a direct-agent chat message. Emitted once
 * per agent reply.
 *
 * The wrapped agent's response surface to operator chat is harness-side
 * integration that ships as v1.2.x follow-up; this payload shape is
 * stable so the audit chain stays consistent when the harness-side hooks
 * land.
 */
export interface AgentDirectAgentReplyPayload extends OperatorChatAuditPayloadHeader {
  kind: "agent_direct_agent_reply";
  agent_id: string;
  session_id: string;
  /** Hash of the agent's response body. */
  response_hash: string;
  sender_role: "agent";
  direction: "agent_to_operator";
}

/**
 * Operator opened a direct-agent chat session. Emitted on synchronous
 * session-open from the click-to-chat path (the click IS the operator's
 * affirmative action; see `principal-policy/loader.ts` enrollment of
 * `direct_agent_session_open` under `tier3_always_allow`). The deprecated
 * inbox-approval path also emits this event and populates
 * `approval_inbox_item_id` with the resolved Tier 1 item id.
 */
export interface OperatorDirectAgentSessionOpenPayload extends OperatorChatAuditPayloadHeader {
  kind: "direct_agent_session_open";
  agent_id: string;
  session_id: string;
  /** Operator-readable label of the agent's current channel-template binding. */
  channel_template_id: string | null;
  /**
   * Tier 1 inbox item id the session was approved through, or null when
   * opened via click-to-chat (no out-of-band approval).
   */
  approval_inbox_item_id: string | null;
  /** ISO8601 timestamp the session expires at (operator-configurable; default 1h). */
  expires_at: string;
}

/**
 * Operator (or the timeout) closed a direct-agent chat session.
 */
export interface OperatorDirectAgentSessionClosePayload extends OperatorChatAuditPayloadHeader {
  kind: "direct_agent_session_close";
  agent_id: string;
  session_id: string;
  /** Reason the session ended: operator click, timeout, fortress lockdown, etc. */
  close_reason:
    | "operator_close"
    | "session_timeout"
    | "fortress_lockdown"
    | "agent_unwrapped";
}

/**
 * Discriminated union of every operator-chat payload shape v1.2 emits.
 */
export type OperatorChatAuditPayload =
  | OperatorConciergeChatPayload
  | OperatorDirectAgentChatPayload
  | AgentDirectAgentReplyPayload
  | OperatorDirectAgentSessionOpenPayload
  | OperatorDirectAgentSessionClosePayload;
