/**
 * Sanctuary Chat v1.0 — Types
 *
 * Wire shapes for chat messages, presence events, MLS group state,
 * and the chat log persistence layer.
 *
 * WP-MVP-7: Q2 architecture walkthrough decisions.
 */

import type { SignatureScheme } from "../mesh/constants.js";
import type { SignedEvent } from "../mesh/types.js";
import type { PresenceState } from "./constants.js";

// ═══════════════════════════════════════════════════════════════════════
// Chat message payloads
// ═══════════════════════════════════════════════════════════════════════

/**
 * Payload for a chat_message signed event.
 * The actual message content is MLS-encrypted; this payload carries the
 * MLS ciphertext + metadata needed for routing and log persistence.
 */
export interface ChatMessagePayload {
  /** MLS group ID this message belongs to. */
  group_id: string;
  /** MLS epoch at which this message was encrypted. */
  mls_epoch: number;
  /** MLS-encrypted ciphertext (base64url). Decrypts to ChatPlaintext. */
  mls_ciphertext: string;
  /** Sender agent_id or operator principal_id. */
  sender_id: string;
  /** Target: specific agent_id for DM, or "group" for group messages. */
  target: string | "group";
  /** Signature scheme on the outer signed-event envelope. */
  signature_scheme: SignatureScheme;
}

/** Plaintext shape after MLS decryption. Never appears on the wire. */
export interface ChatPlaintext {
  /** UTF-8 message content. */
  content: string;
  /** ISO8601 UTC timestamp from the sender. */
  sent_at: string;
  /** Sender agent_id or operator principal_id. */
  sender_id: string;
  /** Optional thread reference (v1.x; present but unused at v1.0). */
  thread_ref?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// MLS group management payloads
// ═══════════════════════════════════════════════════════════════════════

/** Payload for MLS commit events (add/remove member). */
export interface MLSCommitPayload {
  /** MLS group ID. */
  group_id: string;
  /** "add" or "remove" at v1.0. */
  operation: "add" | "remove";
  /** Agent or principal being added/removed. */
  member_id: string;
  /** MLS KeyPackage for the member (base64url, only for "add"). */
  key_package?: string;
  /** MLS commit message (base64url). */
  mls_commit: string;
  /** New epoch after commit. */
  new_epoch: number;
  /** Signature scheme. */
  signature_scheme: SignatureScheme;
}

/** Payload for cross-fortress MLS group creation invite. */
export interface ChatGroupInvitePayload {
  /** Proposed MLS group ID for the cross-fortress room. */
  group_id: string;
  /** Inviting fortress_id. */
  inviter_fortress_id: string;
  /** Invited fortress_id. */
  invitee_fortress_id: string;
  /** MLS Welcome message for the invitee (base64url). */
  mls_welcome: string;
  /** MLS GroupInfo for the invitee (base64url). */
  mls_group_info: string;
  /** Signature scheme. */
  signature_scheme: SignatureScheme;
}

/** Payload for chat group creation. */
export interface ChatGroupCreatePayload {
  /** MLS group ID. */
  group_id: string;
  /** "intra_fortress" or "cross_fortress". */
  group_type: "intra_fortress" | "cross_fortress";
  /** Fortress IDs participating. Single for intra, two for cross. */
  fortress_ids: string[];
  /** Initial member IDs (agent_ids + operator principal_ids). */
  initial_members: string[];
  /** Signature scheme. */
  signature_scheme: SignatureScheme;
}

// ═══════════════════════════════════════════════════════════════════════
// Presence
// ═══════════════════════════════════════════════════════════════════════

/**
 * Payload for presence heartbeat events.
 * Signed but NOT persisted (ephemeral event).
 * NOT MLS-encrypted (low-sensitivity per spawn prompt).
 */
export interface PresencePayload {
  /** Agent or operator ID publishing presence. */
  member_id: string;
  /** Current presence state. */
  state: PresenceState;
  /** ISO8601 UTC timestamp of this heartbeat. */
  heartbeat_at: string;
  /** Signature scheme on the outer event. */
  signature_scheme: SignatureScheme;
}

/** Tracked presence for a peer. */
export interface PeerPresence {
  member_id: string;
  state: PresenceState;
  last_heartbeat_at: string;
  /** ISO8601 timestamp when presence was last evaluated. */
  evaluated_at: string;
}

// ═══════════════════════════════════════════════════════════════════════
// MLS group state (local, not on wire)
// ═══════════════════════════════════════════════════════════════════════

/** Local state for an MLS group. Held in memory; group secrets never persisted to disk. */
export interface MLSGroupState {
  /** MLS group ID. */
  group_id: string;
  /** "intra_fortress" or "cross_fortress". */
  group_type: "intra_fortress" | "cross_fortress";
  /** Current MLS epoch. */
  epoch: number;
  /** Member IDs currently in the group. */
  members: string[];
  /** Fortress IDs participating. */
  fortress_ids: string[];
  /** ISO8601 timestamp of group creation. */
  created_at: string;
}

// ═══════════════════════════════════════════════════════════════════════
// Chat log persistence
// ═══════════════════════════════════════════════════════════════════════

/** Persisted chat message (fortress-local encrypted state). */
export interface ChatLogEntry {
  /** Unique message ID (from the signed-event envelope event_id). */
  message_id: string;
  /** MLS group ID. */
  group_id: string;
  /** Sender agent_id or operator principal_id. */
  sender_id: string;
  /** Plaintext content (stored encrypted via L1 state store). */
  content: string;
  /** ISO8601 UTC timestamp. */
  sent_at: string;
  /** ISO8601 UTC timestamp when received/stored. */
  stored_at: string;
  /** Target: specific peer or "group". */
  target: string;
  /** Fortress that stored this log entry. */
  fortress_id: string;
}

/** Row shape for the pgvector-indexed chat_messages table. */
export interface ChatMessageRow {
  id: string;
  group_id: string;
  sender_id: string;
  content: string;
  sent_at: string;
  stored_at: string;
  target: string;
  fortress_id: string;
  /** pgvector embedding (float array). */
  embedding: number[];
}

/** Result from a pgvector semantic search. */
export interface ChatSearchResult {
  message: ChatLogEntry;
  /** Cosine similarity score (0-1, higher = more similar). */
  similarity: number;
}

// ═══════════════════════════════════════════════════════════════════════
// Chat service configuration
// ═══════════════════════════════════════════════════════════════════════

/** Configuration for the chat service. */
export interface ChatConfig {
  /** Fortress ID this chat service belongs to. */
  fortress_id: string;
  /** Operator principal_id (fortress primary key holder). */
  operator_principal_id: string;
  /** Postgres connection string for pgvector. Optional; chat works without it. */
  postgres_connection_string?: string;
  /** Embedding function for pgvector indexing. Accepts text, returns vector. */
  embed_fn?: (text: string) => Promise<number[]>;
  /** Presence heartbeat interval override (default 30s). */
  presence_heartbeat_interval_ms?: number;
}

// ═══════════════════════════════════════════════════════════════════════
// Typed signed events for chat
// ═══════════════════════════════════════════════════════════════════════

export type ChatMessageEvent = SignedEvent<ChatMessagePayload>;
export type MLSCommitEvent = SignedEvent<MLSCommitPayload>;
export type ChatGroupCreateEvent = SignedEvent<ChatGroupCreatePayload>;
export type ChatGroupInviteEvent = SignedEvent<ChatGroupInvitePayload>;
export type PresenceEvent = SignedEvent<PresencePayload>;
