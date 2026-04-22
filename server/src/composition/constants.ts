/**
 * Sanctuary Composition v1.0 -- Constants
 *
 * Composition event types, default fortress-config values, JSON-RPC method names,
 * and sidecar configuration. All composition events use the composition_* prefix.
 *
 * Reserved namespace: composition_* (per spawn prompt hard rule; do not reuse
 * policy_*, chat_*, mesh_*, recovery_*, fortress_*, attestation_*, or identity_*).
 *
 * Scope lock: Review/Sanctuary/Sanctuary_MVP_Scope_Lock_2026-04-21.md WP-MVP-10
 * Architecture walkthrough: Q4 (Concordia intra-mesh composition)
 */

import { SIGNATURE_SCHEME_V1, type SignatureScheme } from "../mesh/constants.js";

// Re-export for composition module consumers
export { SIGNATURE_SCHEME_V1 };
export type { SignatureScheme };

// -----------------------------------------------------------------------
// Composition event-type prefix and event types
// -----------------------------------------------------------------------

export const COMPOSITION_EVENT_TYPE_PREFIX = "composition_" as const;

/**
 * Composition event types. These events are emitted by the composition
 * subsystem only when composition is enabled.
 */
export const COMPOSITION_EVENT_TYPES = [
  "composition_receipt_packed",
  "composition_receipt_verified",
  "composition_mandate_verified",
  "composition_verascore_published",
  "composition_sidecar_spawned",
  "composition_sidecar_crashed",
  "composition_sidecar_recovered",
  "composition_degraded",
  "composition_recovered",
] as const;

export type CompositionEventType = (typeof COMPOSITION_EVENT_TYPES)[number];

export function isCompositionEventType(s: string): s is CompositionEventType {
  return (COMPOSITION_EVENT_TYPES as readonly string[]).includes(s);
}

// -----------------------------------------------------------------------
// Default fortress-config values for composition
// -----------------------------------------------------------------------

/**
 * Default composition config. Composition is OFF by default.
 * The structural moat invariant: framework alone = fully operational.
 */
export const COMPOSITION_DEFAULTS = {
  /** Master toggle. false = zero composition code paths reachable. */
  ENABLED: false,
  /** Verascore scope default. "private" = operator-private only. */
  VERASCORE_SCOPE: "private" as const,
  /** Sidecar spawn timeout in ms. */
  SIDECAR_SPAWN_TIMEOUT_MS: 10_000,
  /** Sidecar RPC call timeout in ms. */
  SIDECAR_RPC_TIMEOUT_MS: 5_000,
  /** Sidecar initial restart delay in ms. */
  SIDECAR_RESTART_INITIAL_DELAY_MS: 1_000,
  /** Sidecar max restart delay in ms (exponential backoff cap). */
  SIDECAR_RESTART_MAX_DELAY_MS: 60_000,
  /** Sidecar restart backoff multiplier. */
  SIDECAR_RESTART_BACKOFF_MULTIPLIER: 2,
  /** Maximum consecutive sidecar crashes before settling into steady degraded state. */
  SIDECAR_MAX_CONSECUTIVE_CRASHES: 5,
  /** Maximum replay queue depth (commitment events queued while sidecar is down). */
  REPLAY_QUEUE_MAX_DEPTH: 1000,
  /** Maximum mandate delegation chain depth. */
  MAX_MANDATE_DELEGATION_DEPTH: 5,
} as const;

// -----------------------------------------------------------------------
// Verascore scope values
// -----------------------------------------------------------------------

export const VERASCORE_SCOPES = ["private", "public"] as const;
export type VerascoreScope = (typeof VERASCORE_SCOPES)[number];

// -----------------------------------------------------------------------
// JSON-RPC method names (sidecar protocol)
// -----------------------------------------------------------------------

/**
 * JSON-RPC methods supported by the Concordia Python sidecar.
 * The sidecar is a long-lived child process communicating over stdio.
 */
export const SIDECAR_RPC_METHODS = {
  /** Health check. Returns { ok: true, version: "0.4.0" }. */
  PING: "ping",
  /** Returns sidecar version info. */
  VERSION: "version",
  /** Pack a Concordia receipt from a Sanctuary commitment event. */
  PACK_RECEIPT: "pack_receipt",
  /** Verify a Concordia receipt. */
  VERIFY_RECEIPT: "verify_receipt",
  /** Verify a Concordia mandate (delegation chain validation). */
  VERIFY_MANDATE: "verify_mandate",
  /** Graceful shutdown. */
  SHUTDOWN: "shutdown",
} as const;

// -----------------------------------------------------------------------
// Sidecar signature scheme
// -----------------------------------------------------------------------

/**
 * The signature scheme emitted by composition-produced signed envelopes.
 * v1.0: ed25519-v1 only. This field is MANDATORY on every composition-emitted
 * signed envelope. The sidecar must NOT strip or default this field on re-wrap.
 */
export const SIDECAR_SIGNATURE_SCHEME: SignatureScheme = SIGNATURE_SCHEME_V1;

// -----------------------------------------------------------------------
// Concordia schema URNs
// -----------------------------------------------------------------------

export const CONCORDIA_MANDATE_SCHEMA_URN = "urn:concordia:schema:mandate:v1";
export const CONCORDIA_RECEIPT_SCHEMA_URN = "urn:concordia:schema:receipt:v1";

// -----------------------------------------------------------------------
// Composition config persistence
// -----------------------------------------------------------------------

/** Reserved namespace for composition config. Underscore-prefixed = internal. */
export const COMPOSITION_CONFIG_NAMESPACE = "_composition" as const;

/** Key within the namespace for the composition config document. */
export const COMPOSITION_CONFIG_KEY = "config" as const;

/** HKDF domain separation for composition encryption. */
export const HKDF_COMPOSITION_INFO = "sanctuary-composition-v1" as const;

// -----------------------------------------------------------------------
// Sidecar JSON-RPC per-message size cap
// -----------------------------------------------------------------------

/**
 * Maximum accepted size of a single JSON-RPC frame received from the sidecar,
 * in bytes. A frame whose accumulated length exceeds this before the
 * newline-terminated boundary is rejected. The sidecar process is killed and
 * an audit entry is written. The fortress continues operating (composition
 * degrades, fortress does not halt).
 *
 * 10 MiB is chosen to comfortably accommodate a large mandate delegation
 * chain (up to MAX_MANDATE_DELEGATION_DEPTH = 5 nested mandates plus
 * receipt references) while cutting off OOM vectors from a buggy or
 * compromised sidecar that tries to emit a multi-GB response.
 */
export const MAX_SIDECAR_MESSAGE_BYTES = 10 * 1024 * 1024;

// -----------------------------------------------------------------------
// HKDF info-string for sidecar signing key derivation
// -----------------------------------------------------------------------

/**
 * HKDF info-string for deriving the composition sidecar's Ed25519 signing
 * keypair from the fortress-master secret. The salt is the fortress_id.
 *
 * Decision A default (WP-MVP-10 Follow-up #1):
 *   composition-scoped, admits patron-scope subkey templating at v1.x
 *   (e.g. "sanctuary-composition-v1.0-{principal_id}-sidecar-signing-key")
 *   without breaking the v1.0 derivation.
 *
 * The spec §10.3 `composition_*` event-type namespace allocation is the
 * matching wire-level reservation; this HKDF prefix is the key-material
 * reservation on the same boundary.
 *
 * Recovery cascade alignment: on fortress-master rotation, the derived
 * sidecar key changes deterministically. Composition events signed under
 * the old key remain verifiable via the preserved historical-master pubkey
 * (spec §9.5 audit-continuity).
 */
export const HKDF_COMPOSITION_SIDECAR_SIGNING_INFO =
  "sanctuary-composition-v1.0-sidecar-signing-key" as const;
