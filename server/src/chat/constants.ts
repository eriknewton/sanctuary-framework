/**
 * Sanctuary Chat v1.0 — Constants
 *
 * Topic namespaces, presence timeouts, and chat-specific enumerations.
 * All chat topics live under `sanctuary/chat/v1/` to avoid collision with
 * the federation `sanctuary/fed/v0.1/` namespace (§10 naming discipline).
 *
 * WP-MVP-7: libp2p chat surface per Q2 of the architecture walkthrough.
 */

// ═══════════════════════════════════════════════════════════════════════
// libp2p topic + protocol namespaces
// ═══════════════════════════════════════════════════════════════════════

/** Chat gossipsub topic prefix (distinct from federation prefix). */
const CHAT_TOPIC_PREFIX = "sanctuary/chat/v1";

/**
 * Gossipsub topic for encrypted chat messages within a fortress.
 * One topic per fortress; group membership controls who can decrypt.
 */
export function chatTopic(fortressId: string): string {
  if (!fortressId) throw new Error("chatTopic: fortress_id required");
  return `${CHAT_TOPIC_PREFIX}/messages/${fortressId}`;
}

/**
 * Gossipsub topic for cross-fortress chat messages between two fortresses.
 * Uses a deterministic room ID derived from both fortress IDs (sorted).
 */
export function crossFortressChatTopic(
  fortressIdA: string,
  fortressIdB: string
): string {
  if (!fortressIdA || !fortressIdB) {
    throw new Error("crossFortressChatTopic: both fortress_ids required");
  }
  const sorted = [fortressIdA, fortressIdB].sort();
  return `${CHAT_TOPIC_PREFIX}/cross/${sorted[0]}/${sorted[1]}`;
}

/**
 * Gossipsub topic for presence heartbeats within a fortress.
 * Presence is signed-but-not-persisted (ephemeral events).
 * NOT encrypted: presence is low-sensitivity per spawn prompt.
 */
export function presenceTopic(fortressId: string): string {
  if (!fortressId) throw new Error("presenceTopic: fortress_id required");
  return `${CHAT_TOPIC_PREFIX}/presence/${fortressId}`;
}

/** Direct-stream protocol for group key material exchange (cross-fortress bootstrap). */
export const MLS_KEY_EXCHANGE_PROTOCOL =
  "/sanctuary/chat/v1/mls-key-exchange/1.0.0" as const;

// ═══════════════════════════════════════════════════════════════════════
// Presence state machine
// ═══════════════════════════════════════════════════════════════════════

/**
 * Four-state presence per Q2 of the architecture walkthrough.
 * Transitions are staleness-driven, not explicit state-change messages.
 */
export const PRESENCE_STATES = [
  "active",
  "idle",
  "away",
  "offline",
] as const;

export type PresenceState = (typeof PRESENCE_STATES)[number];

/** Presence heartbeat interval in ms (30s, aligned with mesh heartbeat). */
export const PRESENCE_HEARTBEAT_INTERVAL_MS = 30_000;

/** Staleness thresholds (from last heartbeat). */
export const PRESENCE_STALENESS = {
  /** 60s of no heartbeat: active -> idle */
  IDLE_AFTER_MS: 60_000,
  /** 5min of no heartbeat: idle -> away */
  AWAY_AFTER_MS: 5 * 60_000,
  /** 15min of no heartbeat: away -> offline */
  OFFLINE_AFTER_MS: 15 * 60_000,
} as const;

// ═══════════════════════════════════════════════════════════════════════
// Chat event types (mesh signed-event layer)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Chat event types for the mesh signed-event envelope.
 * These are NOT reserved-prefix (no EXTENSION_, cross_fortress_, multi_master_)
 * and do not collide with V01_EVENT_TYPES.
 */
export const CHAT_EVENT_TYPES = [
  "chat_message",
  "chat_mls_commit",
  "chat_presence",
  "chat_group_create",
  "chat_group_invite",
] as const;

export type ChatEventType = (typeof CHAT_EVENT_TYPES)[number];

// ═══════════════════════════════════════════════════════════════════════
// Group encryption configuration
// ═══════════════════════════════════════════════════════════════════════

/**
 * Cipher suite identifier. v1.0 uses AES-256-GCM with SHA-256 epoch derivation.
 * Retained for wire compatibility; real MLS cipher suite negotiation is a v1.1 item.
 */
export const MLS_CIPHER_SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" as const;

/**
 * Group ID prefix. Groups are named `sanctuary-chat-v1/<fortress_id>`
 * for intra-fortress or `sanctuary-chat-v1/cross/<sorted-ids>` for cross-fortress.
 */
export const MLS_GROUP_ID_PREFIX = "sanctuary-chat-v1" as const;

// ═══════════════════════════════════════════════════════════════════════
// Chat storage
// ═══════════════════════════════════════════════════════════════════════

/**
 * Chat messages are stored under the `outputs` policy slot for retention sweep
 * integration. The storage namespace prefix distinguishes chat from other output data.
 *
 * Decision: reuse `outputs` slot rather than introducing a fifth canonical slot
 * (which would require a spec amendment per Key 10 LOCKED). Chat messages are
 * a form of agent output; the retention sweep already handles `outputs`.
 */
export const CHAT_STORAGE_NAMESPACE_PREFIX = "_chat_messages" as const;

/** Postgres table name for pgvector-indexed chat messages. */
export const CHAT_MESSAGES_TABLE = "chat_messages" as const;

/** Embedding dimension for pgvector. 1536 = OpenAI text-embedding-3-small compatible. */
export const EMBEDDING_DIMENSION = 1536 as const;

// ═══════════════════════════════════════════════════════════════════════
// Coordination peers (policy engine integration)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Policy extension key for agent-initiated chat. An agent's pinned policy
 * may contain `extension.coordination_peers: string[]` naming peer agent IDs
 * the agent is authorized to message. Absence = no chat initiation allowed.
 *
 * This is a policy EXTENSION, not a new slot. The four canonical slots remain
 * locked per Key 10. The extension mechanism is the existing `extension` field
 * on compiled policy artifacts.
 */
export const COORDINATION_PEERS_EXTENSION_KEY = "coordination_peers" as const;

/** Gate reason code for rejected agent chat sends. */
export const CHAT_GATE_REASON_CODES = {
  CHAT_PEER_AUTHORIZED: "chat_peer_authorized",
  CHAT_PEER_NOT_AUTHORIZED: "chat_peer_not_authorized",
  CHAT_NO_COORDINATION_PEERS: "chat_no_coordination_peers",
  CHAT_SENTINEL_DENIED: "chat_sentinel_denied",
} as const;

export type ChatGateReasonCode =
  (typeof CHAT_GATE_REASON_CODES)[keyof typeof CHAT_GATE_REASON_CODES];
