/**
 * Sanctuary Federation Protocol v0.1 — Types
 *
 * Every wire-shape defined by the spec, plus the internal trust-root types.
 *
 * Cross-thread note: WP-MVP-5 (Policy Engine) consumes this file. Specifically:
 * - FortressMasterPublicKey / PrincipalCertificate / NodeIdentityCertificate
 * - SignedEvent (for policy_update events)
 * - PolicyUpdatePayload
 *
 * Surface changes that affect those shapes MUST come through WP-MVP-3 (this
 * thread), not WP-MVP-5. If WP-MVP-5 surfaces a gap, surface to coordinator
 * for a spec amendment before changing the schema.
 */

import type { NodeMode, SignatureScheme, V01EventType } from "./constants.js";

// ═══════════════════════════════════════════════════════════════════════
// Identity: fortress-master, principal, per-node
// ═══════════════════════════════════════════════════════════════════════

/**
 * Public form of the fortress-master key.
 * Private form is held in the operator's encrypted state store, unlocked by Argon2id passphrase.
 * It is never serialized in any wire protocol message.
 */
export interface FortressMasterPublicKey {
  /** Base64url-encoded Ed25519 public key (32 bytes). */
  public_key: string;
  /** 128-bit fortress-id assigned at bootstrap, stable for the fortress lifetime. */
  fortress_id: string;
  /** ISO8601 timestamp of fortress-master generation. */
  created_at: string;
}

/**
 * Root-signed certificate binding a principal to the fortress.
 * Principals are human (or future-agent) identities: Root, Partner-Alice, etc.
 *
 * The fortress-master signs the principal_pubkey plus metadata. Receivers verify
 * against the pinned fortress-master public key.
 *
 * Spec: §2.1, §2.3, Key 14 multi-principal.
 */
export interface PrincipalCertificate {
  /** Opaque principal identifier — unique within the fortress. */
  principal_id: string;
  /** Base64url-encoded Ed25519 public key. */
  principal_pubkey: string;
  /** Principal role. "root" is the operator; subordinates per Key 14. */
  role: "root" | "partner" | "associate";
  /** Fortress this principal belongs to. */
  fortress_id: string;
  /** ISO8601 timestamp of issuance. */
  issued_at: string;
  /**
   * ISO8601 timestamp of optional expiry. Root principals typically have no expiry;
   * delegated principals may have bounded validity.
   */
  expires_at?: string;
  /**
   * Base64url-encoded Ed25519 signature over canonicalize({principal_id,
   * principal_pubkey, role, fortress_id, issued_at, expires_at}) by the
   * fortress-master private key.
   */
  master_signature: string;
}

/**
 * Per-node certificate issued at join.
 *
 * The operator's principal signs the certificate; the fortress-master MAY also
 * sign (optional at v0.1, REQUIRED at v1.x per §10.4).
 *
 * Spec: §2.2, §10.2, §10.4.
 */
export interface NodeIdentityCertificate {
  /** 128-bit UUID for this node, stable for node lifetime. */
  node_id: string;
  /** Base64url-encoded Ed25519 public key (32 bytes). */
  node_pubkey: string;
  /** Mode this cert binds: local / operator_cloud / sovereign_tee. */
  node_mode: NodeMode;
  /** Fortress this node is a member of. */
  fortress_id: string;
  /** ISO8601 timestamp of join. */
  joined_at: string;
  /**
   * Capability bitmap. Bit 0 is the v0.1 default (standard_fortress_node).
   * Bits 1-2 are v0.1 opt-in. Bits 3-31 are RESERVED for v1.x.
   * v0.1 issuers MUST NOT set bits 3-31; v0.1 verifiers tolerate them.
   */
  capabilities: number;
  /**
   * Chain hint: the principal that signed this cert, and the fortress-master the
   * principal chains to. Verification walks node → principal → fortress-master.
   */
  parent_chain: {
    fortress_master_pubkey: string;
    principal_id: string;
    principal_pubkey: string;
  };
  /** TEE attestation hash for sovereign_tee nodes; null for others at v0.1. */
  tee_attestation_hash?: string;
  /** Signature by the issuing principal's private key over canonicalize(this — signature fields). */
  principal_signature: string;
  /**
   * Optional fortress-master signature over the same canonical body. Present for
   * operators who want extra verification rigor at v0.1. REQUIRED at v1.x for
   * cross-fortress read endpoints.
   */
  master_signature?: string;

  // ── v1.x reservation slots (§10.4) ────────────────────────────────────
  /** RESERVED — delegated grants this node honors (v1.x MSP). Empty at v0.1. */
  delegated_grants?: unknown[];
  /** RESERVED — TCB attestation lineage history (v1.x deeper attestation). Empty at v0.1. */
  attestation_lineage_chain?: unknown[];
}

// ═══════════════════════════════════════════════════════════════════════
// Signed event envelope (§4.2)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Extension envelope — the v1.x forward-compat hinge (§10.1).
 *
 * v0.1 emitters MUST leave this empty. v0.1 receivers MUST ignore unknown keys.
 * Reserved keys are enumerated in constants.RESERVED_EXTENSION_ENVELOPE_KEYS.
 */
export type ExtensionEnvelope = Record<string, unknown>;

/**
 * Signed event. Every federation message — broadcast or unicast, v0.1 or v1.x —
 * uses this envelope.
 *
 * Spec: §4.2.
 */
export interface SignedEvent<Payload = unknown> {
  /** Protocol version. v0.1 emits "0.1"; v0.1 verifier rejects anything else. */
  protocol_version: string;
  /** Event class. v0.1 event types enumerated in constants.V01_EVENT_TYPES. */
  event_type: V01EventType | string;
  /** 128-bit ULID, monotonic-per-emitter. */
  event_id: string;
  /** Node originating this event. */
  emitter_node: string;
  /**
   * Principal attribution — identifies the human/agent principal that authored.
   * "system" is reserved for node-internal events (heartbeat, etc.).
   */
  emitter_principal: string;
  /** Fortress this event is scoped to. Receivers verify chain ends at the fortress-master. */
  fortress_id: string;
  /** Up to three causal predecessor event_ids for ordering. */
  causal_parents: string[];
  /** Opaque event-type-specific bytes. */
  payload: Payload;
  /** SHA-256 of the canonical-JSON-encoded payload. */
  payload_hash: string;
  /** ISO8601 UTC timestamp. */
  emitted_at: string;
  /** Per-emitter monotonic counter. Rollback detector (§8.3). */
  monotonic_seq: number;
  /** Forward-compat slot — empty at v0.1. */
  extension_envelope: ExtensionEnvelope;
  /** Ed25519 signature by the emitting node's per-node key. */
  node_signature: string;
  /** Ed25519 signature by the authoring principal's key. Optional for system events. */
  principal_signature?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// Message-class payloads (§4.3)
// ═══════════════════════════════════════════════════════════════════════

/** heartbeat payload (§3.3). */
export interface HeartbeatPayload {
  node_state: "active" | "draining" | "gated_closed";
  /** Highest-version-pinned vector: agent_id → policy_version. */
  policy_version_vector: Record<string, number>;
  /** Highest contiguous audit-sequence number locally held. */
  audit_seq: number;
  agent_count: number;
  uptime_seconds: number;
}

/** policy_update payload (§5.1). */
export interface PolicyUpdatePayload {
  agent_id: string;
  policy_version: number;
  /** Opaque policy blob — structure is WP-MVP-5's concern. */
  policy_blob: string;
  /** Optional prior version pointer for conflict detection. */
  parent_version?: number;
}

/** locator_update payload (§6.2). */
export interface LocatorUpdatePayload {
  agent_id: string;
  canonical_node: string;
  locator_version: number;
  last_migration_at: string;
  fallback_nodes?: string[];
  hosting_principal: string;
}

/** node_lifecycle payloads — one of several, discriminated by event_type. */
export type NodeLifecyclePayload =
  | NodeJoinPayload
  | NodeLeavePayload
  | NodeRevokePayload
  | NodeAttestationRefreshPayload
  | CanonicalAuditChangePayload
  | MasterRotationPayload;

export interface NodeJoinPayload {
  certificate: NodeIdentityCertificate;
  bootstrap_token_ref: string;
}

export interface NodeLeavePayload {
  node_id: string;
  reason: "graceful" | "operator_directed";
  drain_deadline?: string;
}

export interface NodeRevokePayload {
  node_id: string;
  reason: string;
  effective_at: string;
  /** Present for guardian-initiated revocation (§3.6.1). */
  quorum_signatures?: Array<{ guardian_pubkey: string; signature: string }>;
}

export interface NodeAttestationRefreshPayload {
  node_id: string;
  tee_attestation_hash: string;
  refreshed_at: string;
}

export interface CanonicalAuditChangePayload {
  new_canonical_node: string;
  previous_canonical_node?: string;
}

export interface MasterRotationPayload {
  old_master_pubkey: string;
  new_master_pubkey: FortressMasterPublicKey;
  quorum_signatures: Array<{ guardian_pubkey: string; signature: string }>;
  rotated_at: string;
}

/** receipt_replicate payload (§5.5). */
export interface ReceiptReplicatePayload {
  receipt_id: string;
  originating_agent_id: string;
  /** Opaque signed receipt bytes — Concordia attestation shape, verified independently. */
  receipt_bytes: string;
}

// ═══════════════════════════════════════════════════════════════════════
// Audit batch + entry (§5.2, §5.3)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Audit entry — the atom stored in the canonical audit log.
 *
 * Spec §5.3. Note `signature_scheme` is MANDATORY at v1.0 even though only one
 * value is valid — the crypto-agility hinge for post-quantum migration at v1.x.
 */
export interface AuditEntry {
  entry_id: string;
  emitter_node: string;
  emitter_agent: string;
  emitter_principal: string;
  policy_version: number;
  attestation_state: string;
  signature_scheme: SignatureScheme;
  payload: unknown;
  /** Ed25519 signature over canonicalize(entry minus signature) by emitter_node per-node key. */
  signature: string;
  emitted_at: string;
}

/**
 * Audit batch — sealed every 5 seconds or every 256 entries per §5.2.
 *
 * Two rollback canaries:
 * - `prev_batch_hash` chains batches per-emitter; a break means replay.
 * - `batch_seq` is per-emitter monotonic; non-monotonic means rollback.
 */
export interface AuditBatch {
  batch_id: string;
  emitter_node: string;
  /** Per-emitter monotonic batch counter. */
  batch_seq: number;
  /** SHA-256 of the canonicalize(prev_batch) — empty string for the first batch. */
  prev_batch_hash: string;
  entries: AuditEntry[];
  /**
   * HMAC over canonicalize({batch_id, batch_seq, prev_batch_hash}) using
   * node_audit_chain_key (HKDF-derived from fortress-master per §2.2).
   * Proves the emitter was provisioned with the correct master-derived chain key
   * — a stolen per-node signing key alone cannot forge this proof.
   */
  hkdf_chain_proof: string;
  /** Ed25519 signature over canonicalize(batch minus signature) by per-node key. */
  signature: string;
  /** ISO8601 UTC timestamp of sealing. */
  sealed_at: string;
}

// ═══════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════

export interface FederationConfig {
  heartbeat_interval_ms?: number;
  heartbeat_missed_threshold?: number;
  audit_batch_interval_ms?: number;
  audit_batch_max_entries?: number;
  max_offline_window_ms?: number;
  bootstrap_token_ttl_ms?: number;
}
