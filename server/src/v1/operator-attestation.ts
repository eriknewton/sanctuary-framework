/**
 * Durable Ed25519 operator attestation for the /v1 session ceremony (PR-A3).
 *
 * PR-A1 shipped a TEMPORARY `local_operator` attestation: a network caller
 * proved possession of the dashboard bearer token (a shared secret) to open a
 * /v1 session. PR-A3 REPLACES that validator with this durable attestation —
 * the operator signs, with their persistent Ed25519 identity key, a statement
 * binding the caller's ephemeral session client key. The daemon verifies that
 * signature against the operator identity public key it already uses to gate
 * OPERATOR_SIGNED writes (PR-A2 agents protect/unprotect). One operator key
 * now backs both opening a session AND authorizing a write.
 *
 * Why this is not a downgrade of the bearer token: the bearer token is a
 * bearer secret — anyone who exfiltrates it (env, config, a log) can open a
 * session. A durable attestation requires a live signature from the operator's
 * Ed25519 private key, which never leaves the operator's custody and is bound
 * to one specific ephemeral client key, so a captured attestation is useless
 * without the matching (transient, zeroed-after-use) client private key.
 *
 * Binding: the operator signs over a domain-separated, length-prefixed,
 * injective encoding of (operator_pubkey || client_pubkey || issued_at). The
 * client_pubkey binding stops an attestation minted for one session from being
 * replayed to authorize a different client key; the issued_at + freshness
 * window bounds the replay horizon even further.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { timingSafeEqual } from "node:crypto";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";

/** Domain separator for durable operator attestations (versioned under v1). */
export const V1_OPERATOR_ATTESTATION_DOMAIN = "sanctuary.v1.operator-attestation";

/**
 * Default freshness window for an attestation's `issued_at`. The operator
 * signs immediately before the ceremony; the operator-signer and the daemon
 * are the operator's own co-located machines, so a generous five-minute window
 * tolerates clock skew without meaningfully widening the replay horizon (the
 * client-key binding is the primary anti-replay control).
 */
export const V1_OPERATOR_ATTESTATION_MAX_AGE_MS = 5 * 60_000;
/** Tolerance for an `issued_at` slightly in the future (clock skew). */
export const V1_OPERATOR_ATTESTATION_FUTURE_SKEW_MS = 60_000;

/** Wire shape of a durable operator attestation in a session-init body. */
export interface OperatorEd25519Attestation {
  type: "operator_ed25519";
  /** base64url, 32 bytes — the operator identity public key that signed. */
  operator_pubkey: string;
  /** UNIX milliseconds at which the operator produced the signature. */
  issued_at: number;
  /** base64url, 64 bytes — Ed25519 over the binding message below. */
  signature: string;
}

function lengthPrefixed(field: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer).setUint32(0, field.length, false);
  out.set(field, 4);
  return out;
}

/**
 * Build the exact byte string the operator signs (and the daemon verifies)
 * for a durable operator attestation. Injective length-prefixed encoding under
 * a domain separator: no two distinct (operator_pubkey, client_pubkey,
 * issued_at) triples collide, so neither field can be spliced from another
 * attestation.
 */
export function buildOperatorAttestationMessage(
  operatorPubkey: Uint8Array,
  clientPubkey: Uint8Array,
  issuedAtMs: number,
): Uint8Array {
  const encoder = new TextEncoder();
  const issuedAt = new Uint8Array(8);
  // 53-bit-safe big-endian split (Number → two 32-bit halves).
  new DataView(issuedAt.buffer).setUint32(0, Math.floor(issuedAtMs / 0x100000000), false);
  new DataView(issuedAt.buffer).setUint32(4, issuedAtMs >>> 0, false);
  const parts = [
    encoder.encode(V1_OPERATOR_ATTESTATION_DOMAIN),
    lengthPrefixed(operatorPubkey),
    lengthPrefixed(clientPubkey),
    issuedAt,
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  return message;
}

/**
 * Verify a durable operator attestation. Never throws: ANY malformed input
 * (missing fields, bad base64url, wrong key/signature length, stale or future
 * `issued_at`, operator-key mismatch, bad signature) returns false so the
 * caller maps it to one generic denial — no oracle for WHICH check failed.
 *
 * `resolvedOperatorPubkey` is the daemon's operator identity public key (the
 * same key the OPERATOR_SIGNED write path resolves); null means no operator
 * identity is configured, which always fails closed here.
 */
export function verifyOperatorAttestation(input: {
  attestation: unknown;
  clientPubkey: Uint8Array;
  resolvedOperatorPubkey: Uint8Array | null;
  now: number;
  maxAgeMs?: number;
  futureSkewMs?: number;
}): boolean {
  const resolved = input.resolvedOperatorPubkey;
  if (!resolved || resolved.length !== ED25519_PUBLIC_KEY_BYTES) return false;

  const att = input.attestation;
  if (typeof att !== "object" || att === null) return false;
  const { type, operator_pubkey, issued_at, signature } = att as {
    type?: unknown;
    operator_pubkey?: unknown;
    issued_at?: unknown;
    signature?: unknown;
  };
  if (type !== "operator_ed25519") return false;
  if (typeof operator_pubkey !== "string") return false;
  if (typeof issued_at !== "number" || !Number.isFinite(issued_at)) return false;
  if (typeof signature !== "string") return false;

  let operatorKey: Uint8Array;
  let sig: Uint8Array;
  try {
    operatorKey = fromBase64url(operator_pubkey);
    sig = fromBase64url(signature);
  } catch {
    return false;
  }
  if (operatorKey.length !== ED25519_PUBLIC_KEY_BYTES || sig.length !== ED25519_SIGNATURE_BYTES) return false;

  // The presented operator key MUST be THE configured operator identity —
  // constant-time over fixed 32-byte keys (no key-content timing oracle).
  if (!timingSafeEqual(operatorKey, resolved)) return false;

  // Freshness: bound the replay horizon. Equal-length comparison, no oracle.
  const maxAgeMs = input.maxAgeMs ?? V1_OPERATOR_ATTESTATION_MAX_AGE_MS;
  const futureSkewMs = input.futureSkewMs ?? V1_OPERATOR_ATTESTATION_FUTURE_SKEW_MS;
  if (issued_at < input.now - maxAgeMs) return false;
  if (issued_at > input.now + futureSkewMs) return false;

  const message = buildOperatorAttestationMessage(
    operatorKey,
    input.clientPubkey,
    issued_at,
  );
  return verify(message, sig, operatorKey);
}

/**
 * Produce a durable operator attestation with a raw (already-decrypted,
 * transient) operator Ed25519 private key. The caller owns zeroing the key
 * after use. Used by the CLI/host-app session-open path and by tests; never
 * logs or returns private key material.
 */
export function signOperatorAttestation(params: {
  operatorPublicKey: Uint8Array;
  operatorPrivateKey: Uint8Array;
  clientPubkey: Uint8Array;
  issuedAtMs: number;
}): OperatorEd25519Attestation {
  const message = buildOperatorAttestationMessage(
    params.operatorPublicKey,
    params.clientPubkey,
    params.issuedAtMs,
  );
  const signature = ed25519.sign(message, params.operatorPrivateKey);
  return {
    type: "operator_ed25519",
    operator_pubkey: toBase64url(params.operatorPublicKey),
    issued_at: params.issuedAtMs,
    signature: toBase64url(signature),
  };
}
