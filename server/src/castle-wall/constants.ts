/**
 * Castle Wall Phase 1 wire constants.
 *
 * Every value here is a wire-protocol or schema constant that crosses the
 * Sanctuary main / filter daemon boundary. Bumping a value means a wire
 * incompatibility; PR 6 adds the cross-language vector tests that gate any
 * change.
 */

/** Schema version for v1 allowlist rules + manifest + signed envelopes. */
export const CASTLE_WALL_SCHEMA_VERSION_V1 = 1 as const;

/** Audit-log layer for every Castle Wall event. Layer 1 per the Castle Architecture ADR. */
export const CASTLE_WALL_AUDIT_LAYER = "l1" as const;

/**
 * Provenance marker stamped into the `details` of every audit entry the Castle
 * Wall audit consumer writes. It is set AFTER the event's own `details` are
 * spread, so a forged event cannot fake it. Consumers that reason about
 * "actual enforcement" (e.g. the sovereignty posture dashboard's
 * enforcement-evidenced ARMED determination) MUST require this marker so a
 * different L1 producer reusing an operation name like `egress_blocked` can
 * never be mistaken for real Castle Wall extension evidence.
 */
export const CASTLE_WALL_AUDIT_PROVENANCE_KEY = "cw_source" as const;
export const CASTLE_WALL_AUDIT_PROVENANCE_VALUE =
  "castle_wall_audit_consumer" as const;

/**
 * Audit operation name for the periodic Castle Wall daemon LIVENESS heartbeat
 * (observability Slice 2). The daemon appends an `l1` audit entry under this
 * operation on an audit-cadence interval (~30-60s), stamped with the same
 * `cw_source` provenance marker and producer-signature basis that enforcement
 * evidence uses, so the reader can tell an alive-but-idle wall from one that
 * silently died in a quiet window.
 *
 * HONESTY: a heartbeat proves the daemon process is ALIVE, NOT that it
 * adjudicated a real flow. It is deliberately kept OUT of
 * `CASTLE_WALL_ENFORCEMENT_OPERATIONS` so it can NEVER earn the green
 * `armed`/`active` light on its own (green stays gated on
 * `egress_allowed`/`egress_blocked`/`operator_decision`). It only moves the
 * ABSENCE-of-evidence case from `unknown` toward an honest dead-vs-idle split.
 *
 * This is a NEW at-rest audit operation string (documented per the
 * frozen-surface rule); it is not a wire message type and does not alter any
 * existing display string.
 */
export const CASTLE_WALL_HEARTBEAT_OPERATION = "castle_wall_heartbeat" as const;

/** Ed25519 signature scheme tag used in manifest envelopes (matches federation v0.1). */
export const CASTLE_WALL_SIGNATURE_SCHEME_V1 = "ed25519-v1" as const;

/**
 * Domain-separation prefix for the per-event producer signature (Slice L1).
 * MUST byte-match `PRODUCER_SIG_DOMAIN_PREFIX` in the Rust daemon
 * (`castle-wall-daemon/src/lib.rs`). The trailing newline is part of the
 * prefix. Binding the signature to a distinct domain prevents a signature
 * minted for any other purpose (handshake nonce, manifest, transparency
 * checkpoint) from ever validating as an enforcement-event producer signature.
 */
export const CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX =
  "sanctuary.castle-wall.audit-producer.v1\n" as const;

/** Key id stamped on v1 producer signatures. Mirrors `PRODUCER_SIG_KEY_ID_V1`. */
export const CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 = "cw-audit-producer-v1" as const;

/**
 * `details` keys under which the verified producer signature and its key id
 * are persisted into the audit entry, so read-side consumers (Slice R) can
 * re-verify against the pinned producer public key rather than trusting the
 * forgeable `cw_source` marker.
 */
export const CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY = "cw_producer_sig" as const;
export const CASTLE_WALL_PRODUCER_KID_DETAIL_KEY = "cw_producer_kid" as const;

/**
 * `details` keys under which a producer-signed entry persists the EXACT signed
 * inputs, so a read-side consumer (Slice R) can reconstruct the signed message
 * and re-verify the signature against the pinned producer key — closing the
 * in-process forgery hole at READ time, not merely trusting the persisted
 * marker or basis string.
 *
 * `cw_producer_signed_canonical` is the verbatim `eventCanonicalJson` the daemon
 * signed (stored as-is; never re-canonicalized — re-encoding would drift the
 * bytes and break verification). `cw_producer_captured_at_ms` is the capture
 * timestamp the signature is bound to (the seq is already persisted as the
 * entry's `details.seq`). Together with `cw_producer_sig` + `cw_producer_kid`,
 * these are the full `ProducerSignatureInput` the reader needs.
 *
 * Only the producer-signed branch carries these; the channel-unsigned branch
 * must NOT (there is no producer signature to reconstruct, and persisting a
 * forged canonical/timestamp must never let a forged entry masquerade as
 * verifiable).
 */
export const CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY =
  "cw_producer_signed_canonical" as const;
export const CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY =
  "cw_producer_captured_at_ms" as const;

/**
 * `details` key recording the authenticity basis the consumer established for
 * this entry. `producer_signed` means a producer signature was verified
 * against the pinned key (the in-process forgery hole is closed for this
 * entry). `channel_authenticated_unsigned` means the entry was accepted on the
 * legacy basis (mutually-pinned IPC channel + tamper-evident chain) because no
 * pinned producer key was configured — honest about NOT being per-producer
 * authenticated. Slice R reads this to render the green light's true basis.
 */
export const CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY = "cw_evidence_basis" as const;
export const CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED = "producer_signed" as const;
export const CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED =
  "channel_authenticated_unsigned" as const;

/** IPC framing header per scope-lock section 5 (LSP-style). */
export const CASTLE_WALL_IPC_CONTENT_LENGTH_HEADER = "Content-Length" as const;

/** Prompt coalescing default: at most this many prompts per window per agent. */
export const CASTLE_WALL_DEFAULT_PROMPT_FLOOD_CAP = 5 as const;

/** Prompt coalescing window in seconds for the default cap. */
export const CASTLE_WALL_DEFAULT_PROMPT_FLOOD_WINDOW_SECONDS = 30 as const;

/** Default operator-decision timeout for an open prompt, in seconds. */
export const CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS = 30 as const;

/** Default duration for the emergency `--no-wall` recovery mode, in seconds (1 hour). */
export const CASTLE_WALL_DEFAULT_NO_WALL_DURATION_SECONDS = 3600 as const;

/** Default WAL retention TTL on the filter-daemon side, in seconds (24 hours). */
export const CASTLE_WALL_DEFAULT_WAL_TTL_SECONDS = 86400 as const;

/** Default WAL size cap on the filter-daemon side, in bytes (100 MB). */
export const CASTLE_WALL_DEFAULT_WAL_SIZE_CAP_BYTES = 104857600 as const;

/** Fixed length of an IPC request_id nonce in bytes (16 bytes hex-encoded = 32 chars). */
export const CASTLE_WALL_REQUEST_ID_NONCE_BYTES = 16 as const;

/** JSON-RPC method namespace for IPC messages. Subsequent PRs add concrete methods. */
export const CASTLE_WALL_IPC_NAMESPACE = "castle-wall" as const;
