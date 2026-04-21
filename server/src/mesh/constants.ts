/**
 * Sanctuary Federation Protocol v0.1 — Constants
 *
 * Protocol version, enumerations, and hard-gate reservations.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md
 * Hard-gate walkthrough: Review/Sanctuary/Federation_V0.1_Hard_Gate_Walkthrough_2026-04-21.md
 *
 * CRITICAL: the reserved constants in this file are the load-bearing forward-compat
 * hinges for the v1.x MSP / Fleet Operator Console extension. Changing any reserved
 * entry without going through a spec amendment breaks acceptance criterion 10.
 */

/**
 * Protocol wire-format version. v0.1 is the only value at v1.0 ship.
 * v1.x implementations MUST accept v0.1 events unchanged.
 */
export const PROTOCOL_VERSION = "0.1" as const;

/**
 * Signature scheme identifier embedded in every AuditEntry and crypto-agility-bearing surface.
 *
 * v1.0: only "ed25519-v1" is valid.
 * v1.x post-quantum migration: "ed25519+ml-dsa-v1" hybrid will be introduced.
 * v1.0 verifiers MUST reject unknown schemes; the field exists so v1.x can add
 * hybrid signing without breaking v1.0 readers. Do not optimize this field away.
 *
 * Spec: §5.3 (Crypto-agility per thesis §3 L1 PQ note).
 */
export type SignatureScheme = "ed25519-v1";
export const SIGNATURE_SCHEME_V1: SignatureScheme = "ed25519-v1";

/**
 * v0.1 node modes — per-node-cert binds a node to exactly one.
 * Spec: §2.2.
 */
export type NodeMode = "local" | "operator_cloud" | "sovereign_tee";

/**
 * v0.1 event types. Adding an event_type requires spec amendment.
 * Reserved namespaces (below) are NOT in this set — they live in the extension space.
 */
export const V01_EVENT_TYPES = [
  // Broadcast (pubsub)
  "heartbeat",
  "policy_update",
  "locator_update",
  "audit_broadcast",
  "node_join",
  "node_leave",
  "node_revoke",
  "node_attestation_refresh",
  "canonical_audit_change",
  "master_rotation",
  "dmswitch_triggered",
  // Unicast (direct streams)
  "audit_batch",
  "receipt_replicate",
  // RPC
  "sync_request",
  "sync_response",
  "rejoin_request",
  "rejoin_response",
  "key_attestation_request",
  "key_attestation_response",
] as const;

export type V01EventType = (typeof V01_EVENT_TYPES)[number];

export function isV01EventType(s: string): s is V01EventType {
  return (V01_EVENT_TYPES as readonly string[]).includes(s);
}

/**
 * Reserved event_type namespaces for v1.x. v0.1 emitters MUST NOT emit these.
 * v0.1 receivers verify signatures and then silently drop at dispatch.
 *
 * Spec: §10.3, hard-gate walkthrough §2.3.
 */
export const RESERVED_EVENT_TYPE_PREFIXES = [
  "EXTENSION_",
  "cross_fortress_",
  "multi_master_",
] as const;

export function isReservedEventType(s: string): boolean {
  return RESERVED_EVENT_TYPE_PREFIXES.some((p) => s.startsWith(p));
}

/**
 * Reserved extension envelope keys for v1.x. v0.1 emitters MUST NOT populate these.
 * v0.1 receivers MUST ignore them (forward-compat).
 *
 * Spec: §10.1, hard-gate walkthrough §2.1.
 */
export const RESERVED_EXTENSION_ENVELOPE_KEYS = [
  "cross_fortress_read_grant",
  "cross_fortress_read_query",
  "cross_fortress_read_response",
  "multi_master_policy_merge",
  "audit_replication_full_n_way",
  "auto_promote_canonical_audit",
  "agent_live_migration",
] as const;

export type ReservedExtensionEnvelopeKey =
  (typeof RESERVED_EXTENSION_ENVELOPE_KEYS)[number];

export function isReservedExtensionKey(
  k: string
): k is ReservedExtensionEnvelopeKey {
  return (RESERVED_EXTENSION_ENVELOPE_KEYS as readonly string[]).includes(k);
}

/**
 * Capability bitmap — bits reserved on NodeIdentityCertificate.capabilities.
 *
 * Bit 0: standard_fortress_node (v0.1 default, set on every v0.1 node).
 * Bit 1: audit_replica_eligible (v0.1 operator opt-in).
 * Bit 2: cold_storage_receipt_replica (v0.1 operator opt-in).
 * Bits 3-31: RESERVED for v1.x. v0.1 issuers MUST NOT set. v0.1 verifiers tolerate.
 *
 * Spec: §10.2, hard-gate walkthrough §2.2.
 */
export const CAP_STANDARD_FORTRESS_NODE = 1 << 0;
export const CAP_AUDIT_REPLICA_ELIGIBLE = 1 << 1;
export const CAP_COLD_STORAGE_RECEIPT_REPLICA = 1 << 2;

/** All v0.1-allowed capability bits OR'd together. Any bit outside this mask is reserved. */
export const V01_ALLOWED_CAPABILITY_MASK =
  CAP_STANDARD_FORTRESS_NODE |
  CAP_AUDIT_REPLICA_ELIGIBLE |
  CAP_COLD_STORAGE_RECEIPT_REPLICA;

export function hasReservedCapabilityBits(caps: number): boolean {
  return (caps & ~V01_ALLOWED_CAPABILITY_MASK) !== 0;
}

/**
 * HKDF info-string prefixes for per-node key derivation.
 *
 * Per-node symmetric keys are HKDF-derived from the fortress-master secret so that
 * guardian recovery can re-derive them. Per-node private asymmetric keys are NOT
 * HKDF-derived — they are generated fresh on the node. See spec §2.2.
 */
export const HKDF_NODE_TRANSPORT_INFO_PREFIX = "sanctuary-fed-v0.1-transport";
export const HKDF_NODE_AUDIT_CHAIN_INFO_PREFIX =
  "sanctuary-fed-v0.1-audit-chain";

/**
 * v0.1 protocol defaults. Build-thread picks (open spec questions §11) captured below.
 * Values here are the defaults chosen for this WP-MVP-3 implementation.
 * They are configurable at runtime via FederationConfig.
 */
export const DEFAULTS = {
  /** §11 Q2 — bootstrap token TTL, ms. 15 minutes. */
  BOOTSTRAP_TOKEN_TTL_MS: 15 * 60 * 1000,
  /** §11 Q3 — heartbeat interval, ms. 30 seconds. */
  HEARTBEAT_INTERVAL_MS: 30_000,
  /** §11 Q3 — missed-heartbeat threshold. 3 missed = 90 seconds. */
  HEARTBEAT_MISSED_THRESHOLD: 3,
  /** §11 Q4 — audit batch interval, ms. 5 seconds. */
  AUDIT_BATCH_INTERVAL_MS: 5_000,
  /** §11 Q4 — audit batch max entries before forced flush. */
  AUDIT_BATCH_MAX_ENTRIES: 256,
  /** §11 Q5 — max-offline-window. 30 days in ms. */
  MAX_OFFLINE_WINDOW_MS: 30 * 24 * 60 * 60 * 1000,
  /** §7.3 — key_attestation challenge interval. */
  KEY_ATTESTATION_CHALLENGE_INTERVAL_MS: 60 * 60 * 1000,
  /** Policy-distribution acceptance deadline per §12 criterion 3. */
  POLICY_DISTRIBUTION_DEADLINE_MS: 5_000,
} as const;
