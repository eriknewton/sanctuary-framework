/**
 * Per-event producer-signature verification (Slice L1, consumer side).
 *
 * The Linux daemon signs every drained enforcement event with a key the
 * in-process TS server cannot reach (see
 * `castle-wall-daemon/src/ipc/producer_sig.rs`). This module verifies that
 * signature against the daemon's TOFU-pinned producer public key BEFORE the
 * audit consumer accepts the event as enforcement evidence.
 *
 * # Why this closes the in-process forgery hole
 *
 * Before Slice L1, an in-process TS module already holding the `AuditLog`
 * reference could append an `l1 egress_blocked` entry stamped with the
 * `cw_source` provenance marker, and it would hash-chain cleanly and render
 * the dashboard green — without the wall having done anything. The marker is a
 * plain string; nothing stops a co-located module from writing it.
 *
 * A producer signature cannot be forged that way: the signing key lives only
 * in the daemon process / a root-owned file. The in-process server holds only
 * the *public* key, which can verify but never sign. So a forged entry lacking
 * a valid producer signature fails verification here and is rejected as
 * enforcement evidence (fail closed).
 *
 * # Byte-exact cross-language contract
 *
 * `producerSigningBytes()` MUST be byte-identical to `producer_signing_bytes`
 * in the Rust daemon. The signed message is:
 *
 * ```text
 * DOMAIN_PREFIX                 (ends in '\n')
 * eventCanonicalJson '\n'
 * capturedAtUnixMs (decimal ASCII) '\n'
 * seq (decimal ASCII)
 * ```
 *
 * `eventCanonicalJson` is the exact canonical-JSON string the daemon committed
 * to its WAL and signed. The consumer verifies over that **same string** (not
 * a re-canonicalized object), so there is no re-encoding drift: the producer
 * and consumer hash identical bytes.
 */

import { readFile } from "node:fs/promises";

import { ed25519 } from "@noble/curves/ed25519";

import {
  CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../constants.js";

const ENCODER = new TextEncoder();

/** Encode bytes as unpadded base64url. */
export function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Load the daemon's published audit-producer public key from disk and return
 * it as base64url-no-pad. The file holds 32 raw Ed25519 verifying-key bytes
 * (the daemon writes it world-readable at `<policy_dir>/audit-producer.pub`).
 * Throws if the file is missing or not exactly 32 bytes — a caller that wants
 * L1 enforcement MUST get a valid key or fail, never silently degrade.
 */
export async function loadPinnedProducerKeyB64url(
  pubKeyPath: string
): Promise<string> {
  const bytes = new Uint8Array(await readFile(pubKeyPath));
  if (bytes.length !== 32) {
    throw new Error(
      `audit-producer public key at ${pubKeyPath} is ${bytes.length} bytes, expected 32`
    );
  }
  return toBase64url(bytes);
}

/** Decode an unpadded base64url string to bytes. Throws on malformed input. */
export function fromBase64url(s: string): Uint8Array {
  const normalized = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const pad = (4 - (normalized.length % 4)) % 4;
  const std = (normalized + "=".repeat(pad)).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Compute the exact bytes the daemon signed for one enforcement event.
 * Mirror of the Rust `producer_signing_bytes`.
 */
export function producerSigningBytes(
  eventCanonicalJson: string,
  capturedAtUnixMs: number,
  seq: number
): Uint8Array {
  return ENCODER.encode(
    `${CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX}${eventCanonicalJson}\n${capturedAtUnixMs}\n${seq}`
  );
}

/** The signed-tuple + signature the consumer needs to verify one event. */
export interface ProducerSignatureInput {
  /** The exact canonical-JSON string the daemon signed (the WAL bytes). */
  eventCanonicalJson: string;
  /** Capture timestamp the signature is bound to (anti-replay). */
  capturedAtUnixMs: number;
  /** Monotonic WAL sequence the signature is bound to (anti-replay). */
  seq: number;
  /** base64url-no-pad of the 64-byte Ed25519 signature. */
  signatureB64url: string | null | undefined;
  /** Key id selecting the pinned producer public key. */
  keyId: string | null | undefined;
}

/** Result of a verification attempt. Verdicts are explicit; never "best effort". */
export type ProducerSignatureVerdict =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Verify a producer signature against a pinned producer public key.
 *
 * FAIL CLOSED: any missing field, length mismatch, key-id mismatch, malformed
 * encoding, or signature-verification failure returns `{ ok: false }`. A
 * thrown exception inside `@noble` is caught and converted to a failure — it
 * is never allowed to surface as an accept.
 *
 * @param pinnedProducerKeyB64url the TOFU-pinned producer public key
 *   (base64url-no-pad, 32 raw verifying-key bytes).
 */
export function verifyProducerSignature(
  input: ProducerSignatureInput,
  pinnedProducerKeyB64url: string,
  expectedKeyId: string = CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1
): ProducerSignatureVerdict {
  if (
    typeof input.signatureB64url !== "string" ||
    input.signatureB64url.length === 0
  ) {
    return { ok: false, reason: "producer_signature_missing" };
  }
  if (input.keyId !== expectedKeyId) {
    return {
      ok: false,
      reason: `producer_key_id_mismatch: ${String(input.keyId)}`,
    };
  }
  if (
    !Number.isSafeInteger(input.seq) ||
    !Number.isSafeInteger(input.capturedAtUnixMs)
  ) {
    return { ok: false, reason: "producer_signature_bad_binding_fields" };
  }
  try {
    const key = fromBase64url(pinnedProducerKeyB64url);
    if (key.length !== 32) {
      return { ok: false, reason: "pinned_producer_key_wrong_length" };
    }
    const sig = fromBase64url(input.signatureB64url);
    if (sig.length !== 64) {
      return { ok: false, reason: "producer_signature_wrong_length" };
    }
    const message = producerSigningBytes(
      input.eventCanonicalJson,
      input.capturedAtUnixMs,
      input.seq
    );
    if (!ed25519.verify(sig, message, key)) {
      return { ok: false, reason: "producer_signature_verification_failed" };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      reason: `producer_signature_verify_error: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
}
