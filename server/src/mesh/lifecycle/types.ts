/**
 * Sanctuary Federation Protocol v0.1 — Lifecycle Orchestrator Types
 *
 * Types that live in the lifecycle layer (runtime state machine, roster,
 * sync RPC payloads, bootstrap tokens). All wire-shape types remain in the
 * mesh foundation (server/src/mesh/types.ts); lifecycle types that flow on
 * the wire do so as the payload body of a v0.1 SignedEvent envelope.
 */

import type { EncryptedPayload } from "../../core/encryption.js";
import type {
  AuditBatch,
  FortressMasterPublicKey,
  LocatorUpdatePayload,
  NodeIdentityCertificate,
  NodeLifecyclePayload,
  PolicyUpdatePayload,
  SignedEvent,
} from "../types.js";
import type { MeshNodeState, NodePresenceState, SyncKind } from "./constants.js";

// ═══════════════════════════════════════════════════════════════════════
// Bootstrap token (§3.1)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Short-lived signed token issued by the console (principal key) for a node
 * to request membership. The token alone does not grant membership — it
 * carries the right to submit a JoinRequest which still requires operator
 * approval via the gate.
 *
 * Spec §3.1.
 */
export interface BootstrapToken {
  /** The pre-assigned node_id this token is good for. */
  intended_node_id: string;
  /** The pre-assigned node_mode. */
  intended_node_mode: "local" | "operator_cloud" | "sovereign_tee";
  /** Fortress issuing this token. */
  fortress_id: string;
  /** Principal that authored this token. */
  issuing_principal: string;
  /** ISO8601 expiry. */
  expires_at: string;
  /** ISO8601 timestamp of issuance (used for TTL validation). */
  issued_at: string;
  /** Opaque nonce to bind this token to a single join attempt. */
  nonce: string;
  /** Ed25519 signature over canonicalize(token minus signature) by issuing principal. */
  signature: string;
}

// ═══════════════════════════════════════════════════════════════════════
// Join flow (§3.1)
// ═══════════════════════════════════════════════════════════════════════

/**
 * JoinRequest — sent by a joining node to the canonical audit node,
 * which forwards to the console for operator approval.
 */
export interface JoinRequest {
  bootstrap_token: BootstrapToken;
  node_pubkey: string;
  node_mode: "local" | "operator_cloud" | "sovereign_tee";
  /** TEE attestation quote if sovereign_tee; null otherwise. v0.1 uses an opaque string. */
  attestation?: string;
  /**
   * Proof the requester was provisioned with the correct master-derived
   * transport key — HMAC over (intended_node_id, node_mode) under the
   * HKDF-derived node_transport_key. Defeats an attacker who steals a
   * bootstrap token but does not hold the master secret.
   */
  hkdf_salt_proof: string;
}

/** Opaque result from the join-approval flow. */
export interface JoinApprovalResult {
  approved: boolean;
  /** Present on approval. */
  certificate?: NodeIdentityCertificate;
  /** Present on denial. Operator-facing string, not the agent-facing one. */
  denial_reason?: string;
}

/**
 * JoinApprover abstraction. Lets the lifecycle orchestrator stay testable
 * without forking or bypassing the principal-policy ApprovalGate.
 *
 * Production wiring (deferred to the console thread, WP-MVP-2): implement
 * this by calling through `ApprovalGate.evaluate("federation_node_join", args)`
 * with `args = { intended_node_id, node_mode, attestation_ok, issuer_principal }`
 * and issuing the NodeIdentityCertificate on approve. Policy-config changes
 * (registering `federation_node_join` at Tier 1) are a policy-loader concern,
 * not an approval-gate change. That keeps the gate API itself untouched.
 *
 * Test wiring: `createAutoApproveJoinApprover()` / `createAutoDenyJoinApprover()`.
 */
export interface JoinApprover {
  requestApproval(request: JoinRequest): Promise<JoinApprovalResult>;
}

// ═══════════════════════════════════════════════════════════════════════
// Roster
// ═══════════════════════════════════════════════════════════════════════

export interface RosterEntry {
  certificate: NodeIdentityCertificate;
  presence: NodePresenceState;
  /** ms-since-epoch of most recent verified heartbeat from this node. 0 on first add. */
  last_heartbeat_at: number;
  /** Most recent advertised policy-version vector from heartbeats. */
  last_policy_versions: Record<string, number>;
  /** Most recent advertised audit_seq from heartbeats. */
  last_audit_seq: number;
  /** ms-since-epoch of revoke / leave / expiry, or undefined if still eligible. */
  ended_at?: number;
}

export interface DropoutEvent {
  node_id: string;
  detected_at: number;
  reason: "missed_heartbeats" | "expired_offline_window";
  last_seen_at: number;
}

// ═══════════════════════════════════════════════════════════════════════
// Monotonic counter store
// ═══════════════════════════════════════════════════════════════════════

export type CounterName =
  | "envelope_monotonic_seq"
  | "heartbeat_seq"
  | "audit_batch_seq"
  | "locator_update_seq";

/**
 * Persistent monotonic counter store.
 *
 * The spec's rollback canary (§8.3) depends on these counters advancing
 * strictly. A counter that resets to a prior value after a restart is
 * indistinguishable from a node rolled back to a prior state — the canonical
 * audit node will reject the resulting events. Persistence is required in
 * production; the `InMemoryCounterStore` is for tests only.
 */
export interface CounterStore {
  next(name: CounterName): number;
  peek(name: CounterName): number;
  set(name: CounterName, value: number): void;
}

// ═══════════════════════════════════════════════════════════════════════
// Node-key storage (Q8 cocoon binding)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Store for a node's at-rest wrapped private key.
 *
 * Q8 pick: per-node cocoon-equivalent. The per-node Ed25519 private key is
 * wrapped via AES-256-GCM under an HKDF-derived key from the fortress-master
 * secret + node_id (see `wrapNodePrivateKey` / `unwrapNodePrivateKey`). The
 * wrapped blob lives here. The master secret is surfaced only transiently
 * at unlock time (through the existing broker flow).
 *
 * No cocoon-schema change: the master cocoon stores the fortress-master
 * secret exactly as today. The per-node wrapped private key is a separate
 * lifecycle-owned artifact that lives alongside the node certificate on the
 * node's local disk in production — in this thread, we ship the in-memory
 * implementation; disk implementation is deferred to a follow-up.
 */
export interface NodeKeyStore {
  save(nodeId: string, wrapped: EncryptedPayload): Promise<void>;
  load(nodeId: string): Promise<EncryptedPayload | null>;
  remove(nodeId: string): Promise<void>;
}

// ═══════════════════════════════════════════════════════════════════════
// Sync RPC payloads (§3.2, Q6)
// ═══════════════════════════════════════════════════════════════════════

export interface SyncRequestPayload {
  kind: SyncKind;
  /** Requester's per-agent policy-version baseline — requester wants anything higher. */
  since_policy_versions?: Record<string, number>;
  /** Requester's locator-version baseline — requester wants anything higher. */
  since_locator_version?: number;
  /** Requester's per-emitter audit-batch-seq baseline. */
  since_audit_seqs?: Record<string, number>;
  /** For agent-state-transfer (Q6): the agent being migrated. */
  agent_id?: string;
  /** For agent-state-transfer (Q6): the locator version that authorized this transfer. */
  authorizing_locator_version?: number;
}

export interface SyncResponsePayload {
  kind: SyncKind;
  /** Missed `node_join` / `node_leave` / `node_revoke` events during offline window. */
  node_lifecycle_events?: SignedEvent<NodeLifecyclePayload>[];
  /** Missed `policy_update` events since `since_policy_versions`. */
  policy_updates?: SignedEvent<PolicyUpdatePayload>[];
  /** Missed `locator_update` events since `since_locator_version`. */
  locator_updates?: SignedEvent<LocatorUpdatePayload>[];
  /** Missed audit batches since `since_audit_seqs[emitter_node]`. */
  audit_batches?: AuditBatch[];
  /**
   * Q6 agent-state-transfer payload. Encrypted under an HKDF-derived key from
   * (fortress_master_secret, source_node_id, destination_node_id, agent_id,
   * authorizing_locator_version). Opaque to the transport layer; the cocoon
   * on the destination side unwraps it using its existing snapshot format.
   */
  agent_state_wrapped?: EncryptedPayload;
}

// ═══════════════════════════════════════════════════════════════════════
// Canonical audit buffer
// ═══════════════════════════════════════════════════════════════════════

export interface FlushedBatch {
  batch_seq: number;
  entry_count: number;
  sealed_at: string;
}

// ═══════════════════════════════════════════════════════════════════════
// MeshNode configuration
// ═══════════════════════════════════════════════════════════════════════

export interface MeshNodeConfig {
  /** Node identity — the 128-bit node_id. */
  node_id: string;
  /** Mode this node is provisioned for. */
  node_mode: "local" | "operator_cloud" | "sovereign_tee";
  /** Fortress this node is a member of. */
  fortress_id: string;
  /** Operator's pinned fortress-master public key (for verifying chain walks). */
  pinned_master_pubkey: FortressMasterPublicKey;
  /** Default-principal id used as `emitter_principal` on system-originated events. */
  system_principal_id?: string;
  /** Is this node the canonical audit node? Operator-designated at bootstrap. */
  is_canonical_audit_node?: boolean;
  /** Heartbeat interval override. */
  heartbeat_interval_ms?: number;
  /** Missed-heartbeat threshold override. */
  heartbeat_missed_threshold?: number;
  /** max_offline_window override. */
  max_offline_window_ms?: number;
  /** Audit batch interval override. */
  audit_batch_interval_ms?: number;
  /** Audit batch max-entries override. */
  audit_batch_max_entries?: number;
}

/**
 * Dependencies injected into a MeshNode.
 *
 * The transport + approver + key stores are injected so tests can wire
 * in-memory implementations and production wires the real broker / persistent
 * stores / libp2p transport.
 */
export interface MeshNodeDeps {
  /** MeshTransport contract (from mesh foundation). */
  transport: import("../in-memory-transport.js").MeshTransport;
  /** Approval gate for operator-decision transitions. */
  approver: JoinApprover;
  /** Per-node key storage (Q8). */
  key_store: NodeKeyStore;
  /** Monotonic counter persistence. */
  counters: CounterStore;
  /**
   * Surface the fortress-master secret to the node at boot-time ONLY for
   * HKDF re-derivation of transport / audit-chain / wrap keys. After boot,
   * the master secret must be zeroed by the caller. For bootstrapFirstNode
   * this is the master just generated; for join this is out-of-band delivered
   * when the node joins a local-mode fortress (production wires the broker
   * unlock flow; tests pass it directly).
   */
  fortress_master_secret: Uint8Array;
}

// ═══════════════════════════════════════════════════════════════════════
// Runtime state snapshot (for tests + operator surfaces)
// ═══════════════════════════════════════════════════════════════════════

/** Read-only snapshot of the MeshNode's internal state. */
export interface MeshNodeSnapshot {
  node_id: string;
  state: MeshNodeState;
  is_canonical_audit: boolean;
  roster_size: number;
  counters: Record<CounterName, number>;
  pending_audit_entries: number;
  cert_present: boolean;
}

/** Minimal shape so tests can assert on received events without reconstructing. */
export interface ReceivedEventLog {
  event_type: string;
  emitter_node: string;
  emitter_principal: string;
  monotonic_seq: number;
  event_id: string;
  at: number;
}
