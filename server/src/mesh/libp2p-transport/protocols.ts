/**
 * Sanctuary Federation Protocol v0.1 — libp2p Protocol + Topic Names.
 *
 * Gossipsub topics fan out per federation message class. Direct-stream
 * protocols carry RPC-shape message classes (sync + agent-state-transfer).
 * Both are versioned at the protocol level (v0.1) and at the shape level
 * (1.0.0) so v1.x can introduce new topics / streams without collision.
 *
 * Naming: `sanctuary/fed/v0.1/<class>/<fortress-id>` for topics;
 * `/sanctuary/fed/v0.1/<class>/<version>` for streams. The fortress-id suffix
 * on topics means two different fortresses on the same LAN cannot see each
 * other's gossipsub traffic even with mDNS bringing their peers into view.
 */

/** Gossipsub topic prefix. */
const TOPIC_PREFIX = "sanctuary/fed/v0.1";

/** Direct-stream protocol prefix. */
const STREAM_PREFIX = "/sanctuary/fed/v0.1";

/**
 * Gossipsub topic for broadcast message classes. All v0.1 broadcast events
 * (heartbeat, policy_update, locator_update, audit_broadcast, node_*,
 * master_rotation, dmswitch_triggered) fan out on a single per-fortress topic.
 *
 * Rationale: v0.1 mesh is small (Drew's office, single-operator fortress).
 * Per-class topics would split subscriber sets unnecessarily and complicate
 * late-join replay. v1.x may split this if fan-out costs justify it — the
 * prefix leaves room (`sanctuary/fed/v0.1/<class>/<fortress-id>` when we
 * split; current single-topic shape is equivalent to `<class>=events`).
 */
export function broadcastTopic(fortressId: string): string {
  if (!fortressId) {
    throw new Error("broadcastTopic: fortress_id required");
  }
  return `${TOPIC_PREFIX}/events/${fortressId}`;
}

/**
 * Direct-stream protocol for sync request/response (§3.2).
 *
 * The joining / rejoining node opens a stream of this protocol to the canonical
 * audit node; request is a length-prefixed JSON `SyncRequestPayload`, response
 * is a length-prefixed JSON `SyncResponsePayload`.
 */
export const SYNC_PROTOCOL = `${STREAM_PREFIX}/sync/1.0.0` as const;

/**
 * Direct-stream protocol for Q6 agent-state-transfer (§6.3).
 *
 * Live-migration of an agent's wrapped snapshot from source node to destination.
 * Payload is an HKDF-derived AES-256-GCM ciphertext wrapping the snapshot under
 * info-string `sanctuary-fed-v0.1-lifecycle-agent-state-transfer`.
 */
export const AGENT_STATE_TRANSFER_PROTOCOL = `${STREAM_PREFIX}/agent-state/1.0.0` as const;

/**
 * Direct-stream protocol for generic unicast (audit batches, locator-ack,
 * mesh-internal messages that don't fit the two RPC shapes above).
 *
 * The MeshTransport.unicast(toNodeId, message) contract is "opaque bytes to
 * this node"; dispatch lives at the application layer (MeshNode). The libp2p
 * adapter opens this protocol, writes the single length-prefixed JSON payload,
 * closes.
 */
export const UNICAST_PROTOCOL = `${STREAM_PREFIX}/unicast/1.0.0` as const;

/**
 * All direct-stream protocols the transport registers handlers for.
 */
export const ALL_STREAM_PROTOCOLS = [
  SYNC_PROTOCOL,
  AGENT_STATE_TRANSFER_PROTOCOL,
  UNICAST_PROTOCOL,
] as const;

export type StreamProtocol = (typeof ALL_STREAM_PROTOCOLS)[number];
