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
 * Discriminated union of every operator-chat payload shape v1.2 emits.
 */
export type OperatorChatAuditPayload = OperatorConciergeChatPayload;
