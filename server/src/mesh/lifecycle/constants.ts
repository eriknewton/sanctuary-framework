/**
 * Sanctuary Federation Protocol v0.1 — Lifecycle Orchestrator Constants
 *
 * Lifecycle-layer constants. These are additive to the mesh foundation
 * (server/src/mesh/constants.ts) and do NOT overlap with any reserved-v1.x
 * namespace, message class, or capability bit defined there.
 *
 * Spec: Federation_Protocol_V0.1_Spec_2026-04-21.md §3 (node lifecycle).
 */

/**
 * HKDF info-string prefix for deriving the per-node at-rest wrapping key.
 *
 * Q8 (per-node key binding): the per-node Ed25519 private key is wrapped
 * at rest under AES-256-GCM. The wrapping key is HKDF-derived from the
 * fortress-master secret with this info string plus the node_id. At boot,
 * the broker unlock flow surfaces the fortress-master secret; the lifecycle
 * orchestrator re-derives the wrapping key, decrypts, and holds the per-node
 * private key in memory only.
 *
 * This prefix intentionally differs from the two HKDF info strings in the
 * mesh foundation (`sanctuary-fed-v0.1-transport`, `sanctuary-fed-v0.1-audit-chain`)
 * so the wrapping key is independent of transport and audit-chain keys.
 * Recoverable under guardian quorum because it derives from the same master.
 */
export const HKDF_NODE_KEY_WRAP_INFO_PREFIX =
  "sanctuary-fed-v0.1-lifecycle-node-key-wrap";

/**
 * HKDF info-string prefix for deriving an ephemeral agent-state-transfer
 * wrapping key for Q6 state transfer.
 *
 * When the source node ships an agent snapshot to the destination node
 * during migration (§6.3 step 4), the snapshot is encrypted under a key
 * derived from the fortress-master secret with this prefix plus
 * (source_node_id || destination_node_id || agent_id || locator_version).
 * Both nodes can derive the same key without round-trips; a stolen snapshot
 * without the master is useless.
 */
export const HKDF_AGENT_STATE_TRANSFER_INFO_PREFIX =
  "sanctuary-fed-v0.1-lifecycle-agent-state-transfer";

/** MeshNode runtime states. Not serialized on the wire — internal orchestration. */
export type MeshNodeState =
  | "unbooted"
  | "bootstrapping"
  | "joining"
  | "syncing"
  | "active"
  | "draining"
  | "left"
  | "revoked";

/** Per-node presence state (roster-facing). Matches §3.3 heartbeat semantics. */
export type NodePresenceState =
  | "joining"
  | "active"
  | "draining"
  | "unreachable"
  | "left"
  | "revoked"
  | "expired";

/**
 * Discriminator for sync RPC payloads. Q6 state-transfer rides the
 * `sync_request` / `sync_response` pair (already in V01_EVENT_TYPES) with this
 * discriminator — no new v0.1 message class required.
 */
export type SyncKind = "initial_sync" | "delta_sync" | "agent_state_transfer";

/** Default bootstrap-token TTL = 15 minutes (spec §3.1, build-thread pick). */
export const BOOTSTRAP_TOKEN_TTL_MS = 15 * 60 * 1000;
