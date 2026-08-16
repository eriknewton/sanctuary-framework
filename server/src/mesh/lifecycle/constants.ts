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

// ═══════════════════════════════════════════════════════════════════════
// C12-REPLAY / SYNC-APPEND-01 — lifecycle-log growth bounds (rule 8)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Hard cap on the in-memory `NodeLifecycleEventLog`. The log is fed from
 * untrusted sync input, so per rule 8 it carries an explicit ceiling and an
 * eviction rule. 10_000 is generous for a real fortress's join/leave/revoke
 * history over its lifetime while bounding an attacker-appendable relay.
 * Eviction prefers OLDEST NON-REVOKE events; a revoke event is evicted only
 * when no non-revoke event remains, because the roster (not the log) is the
 * authoritative revocation state, so even revoke eviction degrades to "a late
 * joiner learns via a peer with a longer log," never to un-revoking.
 */
export const NODE_LIFECYCLE_LOG_MAX_EVENTS = 10_000;

/**
 * Per-`(fortress, target)` cap on RETAINED accepted-revoke authorizations
 * (SYNC-APPEND-01 §3.3 point 5, re-gate RG3-2). Authorizations are scarce —
 * each costs an M-guardian ceremony or a principal signature — so 8 loses no
 * legitimate revoke/rejoin history for a single target while bounding even a
 * multi-authorization flood. Saturation EVICTS OLDEST and never blocks the
 * newest: the newest authorization carries the ordering witness a late joiner
 * needs, so refusing it would recreate the RG3-1 divergence through the quota.
 */
export const MAX_RETAINED_REVOKE_AUTHORIZATIONS_PER_TARGET = 8;

/**
 * Per-EMITTER cap on retained NON-revoke lifecycle events (rule 8's per-origin
 * quota). The global cap alone lets one in-roster emitter flood non-revoke
 * events and evict every OTHER emitter's history through oldest-first eviction;
 * this bounds any single emitter to 1/16 of the global log, so at least 16
 * emitters' histories can coexist — generous for a v0.1 fortress fleet
 * (single-digit nodes). A full bucket evicts the FLOODING emitter's own oldest
 * event first, never another emitter's. Derivation:
 * floor(NODE_LIFECYCLE_LOG_MAX_EVENTS / 16) = 625.
 */
export const MAX_RETAINED_NON_REVOKE_EVENTS_PER_EMITTER = Math.floor(
  NODE_LIFECYCLE_LOG_MAX_EVENTS / 16
);

// ═══════════════════════════════════════════════════════════════════════
// C12-REPLAY — denial-write ceiling (rule 8, §2.5 + review F-8a/NH-4)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Rolling window over which the revoke-denial audit budgets apply. 3_600_000 =
 * 1 h. Once freshness enforcement exists every replay is a guaranteed denial,
 * so the write amplification is capped in the same change that creates the
 * incentive.
 */
export const REVOKE_DENIAL_AUDIT_WINDOW_MS = 60 * 60 * 1_000;

/**
 * Per-authentic-emitter denial-audit budget per window. `emitter_node` on the
 * denial path is envelope-verified, so buckets cannot be spoofed; this bounds a
 * single emitter's replay-spam audit amplification.
 */
export const REVOKE_DENIAL_AUDIT_PER_EMITTER_MAX = 32;

/**
 * Global per-node denial-audit ceiling ABOVE the per-emitter buckets (review
 * F-8a): a sync response relays events from MANY authentic emitters, so the
 * per-emitter budget totals M*perEmitter with M outside the defender's control.
 * The global ceiling bounds the aggregate. Its saturation is itself audited
 * once, as a sealed summary carrying {suppressed_count, distinct_emitter_count}
 * — attribution granularity degrades, attempt/emitter counts are never lost.
 */
export const REVOKE_DENIAL_AUDIT_GLOBAL_MAX = 256;

// ═══════════════════════════════════════════════════════════════════════
// C12-REPLAY — sync-response request correlation (§3.3 point 7, re-gate NH-3)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Lifetime of an outstanding `sync_request` id. Derived GENEROUSLY against
 * worst-case whole-snapshot transfer: `handleSyncRequest` serves the entire
 * `lifecycle_log.snapshot()` on initial sync and the snapshot grows with
 * fortress age (bounded by NODE_LIFECYCLE_LOG_MAX_EVENTS), so this must dominate
 * a slow-link full-snapshot transfer — minutes, not seconds. 600_000 = 10 min.
 * A too-small value looks like a late joiner on a slow link that never completes
 * initial sync while every live path is healthy (permanent initial-sync
 * starvation); the tell is repeated uncorrelated-`sync_response` audit entries
 * on the joiner. Retry is owned by the INITIATOR with a FRESH id.
 */
export const SYNC_REQUEST_ID_EXPIRY_MS = 10 * 60 * 1_000;

// ═══════════════════════════════════════════════════════════════════════
// C12-SYNC-ORDER-01 — sync-table poison-event audit-governor key (rule 7/8)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Governor key `applySync` uses for a poison policy_update/locator_update
 * drop-audit when no AUTHENTICATED relaying peer is available (an
 * initial-sync `applySync` call outside the `sync_response` receive path,
 * or a direct/test call). NEVER key on the failed event's own claimed
 * `emitter_node` — that field belongs to the event whose verification just
 * FAILED, so it is by definition unauthenticated wire text, not a trust-
 * bearing identity (rule 7). A fixed sentinel collapses every un-relayed
 * poison event into ONE shared bucket, so an attacker rotating the claimed
 * `emitter_node` per event cannot mint unbounded governor buckets (rule 8)
 * the way a per-claimed-identity key would allow.
 */
export const SYNC_TABLE_AUDIT_UNKNOWN_RELAYING_PEER =
  "unknown-relaying-peer" as const;

/**
 * Bound on the outstanding-request set (self-inflicted growth only — ids are
 * minted solely by this node's own `sync_request`s, so an external peer can
 * neither insert nor evict). Evicts oldest when full.
 */
export const MAX_OUTSTANDING_SYNC_REQUESTS = 64;

/** 16 bytes = 128 bits of CSPRNG for a sync-request correlation id. */
export const SYNC_REQUEST_ID_BYTES = 16;

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
