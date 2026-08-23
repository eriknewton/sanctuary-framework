/**
 * Sanctuary MCP Server — AES-256-GCM Encryption
 *
 * All state encryption in Sanctuary uses AES-256-GCM (authenticated encryption).
 * This provides both confidentiality and integrity — a modified ciphertext will
 * fail authentication, detecting tampering.
 *
 * Security invariants:
 * - Every encryption uses a unique 12-byte IV (NIST SP 800-38D)
 * - The 16-byte authentication tag is always verified on decryption
 * - Keys are 256 bits (32 bytes)
 */

import { gcm } from "@noble/ciphers/aes.js";
import { generateIV } from "./random.js";
import { toBase64url, fromBase64url } from "./encoding.js";
// an `EncryptedPayload` is `JSON.parse`d off disk before it is decrypted, so
// its header fields are attacker-influenced and go through the untrusted-
// diagnostic chokepoint (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../errors/index.js";

/**
 * CONTRACT PIN (coordinator gate G-B, 2026-08-22): the exact payload
 * version and algorithm `decrypt()` below explicitly checks, plus the IV
 * byte length `encrypt()` below always emits (N3, coordinator gate,
 * 2026-08-22: decrypt()'s cipher does NOT itself require this length -
 * @noble/ciphers' `gcm()` accepts other nonce sizes - this is the one
 * length a legitimate export ever produces, pinned so a caller can treat
 * any other length as malformed). Exported so a caller validating an
 * EncryptedPayload BEFORE calling decrypt() (server/src/exit/verifier.ts
 * `isWellFormedExitStateEntryElement`) can pin to these SAME values,
 * rather than checking only that a field has the right TYPE - a
 * well-typed WRONG value (`alg: "aes-128-gcm"`) passed that check and
 * only failed later, post-staging, misread as a signature failure. Must
 * match `decrypt()`'s own checks below if either changes.
 */
export const SUPPORTED_PAYLOAD_VERSION = 1;
export const SUPPORTED_PAYLOAD_ALG = "aes-256-gcm" as const;
/** Exact IV byte length `generateIV()` (core/random.ts) always produces; decrypt()'s cipher itself accepts other lengths, this pins to the one an export actually emits. */
export const PAYLOAD_IV_BYTE_LENGTH = 12;

/** Encrypted payload structure stored on disk */
export interface EncryptedPayload {
  /** Format version */
  v: number;
  /** Algorithm identifier */
  alg: "aes-256-gcm";
  /** Initialization vector (base64url) */
  iv: string;
  /** Ciphertext (base64url) */
  ct: string;
  /** Authentication tag (base64url) — included in ciphertext by @noble/ciphers */
  /** Timestamp. Plain envelope metadata only; never use for security decisions. */
  ts: string;
}

/**
 * Encrypt plaintext bytes with AES-256-GCM.
 *
 * @param plaintext - Data to encrypt
 * @param key - 256-bit encryption key
 * @param aad - Optional additional authenticated data (authenticated but not encrypted)
 * @returns EncryptedPayload ready for JSON serialization
 */
export function encrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad?: Uint8Array
): EncryptedPayload {
  // 32 = the AES-256 key size (256 bits / 8). NOT an Ed25519 key length, which
  // is also 32 bytes: `ED25519_PUBLIC_KEY_BYTES` must never be substituted here.
  if (key.length !== 32) {
    throw new Error("Key must be exactly 32 bytes (256 bits)");
  }

  const iv = generateIV();
  // AAD binds caller-owned context without storing it in the envelope. Custody
  // wraps and store codecs rely on this so a ciphertext moved to a different
  // type, id, or domain fails authentication instead of decrypting as valid.
  const cipher = gcm(key, iv, aad);
  // @noble/ciphers gcm.encrypt appends the 16-byte auth tag to the ciphertext
  const ciphertext = cipher.encrypt(plaintext);

  return {
    v: SUPPORTED_PAYLOAD_VERSION,
    alg: SUPPORTED_PAYLOAD_ALG,
    iv: toBase64url(iv),
    ct: toBase64url(ciphertext),
    ts: new Date().toISOString(),
  };
}

/**
 * Decrypt an AES-256-GCM encrypted payload.
 *
 * @param payload - EncryptedPayload from encrypt()
 * @param key - 256-bit encryption key (must match the encryption key)
 * @param aad - Optional additional authenticated data (must match encryption AAD)
 * @returns Decrypted plaintext bytes
 * @throws If authentication tag verification fails (tampered data)
 */
export function decrypt(
  payload: EncryptedPayload,
  key: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  // 32 = the AES-256 key size (256 bits / 8); must match the check in `encrypt`
  // above. Not an asymmetric key length.
  if (key.length !== 32) {
    throw new Error("Key must be exactly 32 bytes (256 bits)");
  }
  if (payload.v !== SUPPORTED_PAYLOAD_VERSION) {
    throw new Error(`Unsupported payload version: ${describeUntrusted(payload.v)}`);
  }
  if (payload.alg !== SUPPORTED_PAYLOAD_ALG) {
    throw new Error(`Unsupported algorithm: ${describeUntrusted(payload.alg)}`);
  }

  const iv = fromBase64url(payload.iv);
  const ciphertext = fromBase64url(payload.ct);
  // The same AAD must be supplied on decrypt. The GCM tag is the swap detector,
  // so callers do not need a parallel "expected type" field inside ciphertext.
  const cipher = gcm(key, iv, aad);

  // gcm.decrypt verifies the auth tag and throws if tampered
  return cipher.decrypt(ciphertext);
}

/**
 * Re-encrypt data with a new key (for key rotation or export).
 * Decrypts with old key, re-encrypts with new key.
 */
export function reEncrypt(
  payload: EncryptedPayload,
  oldKey: Uint8Array,
  newKey: Uint8Array,
  aad?: Uint8Array
): EncryptedPayload {
  const plaintext = decrypt(payload, oldKey, aad);
  return encrypt(plaintext, newKey, aad);
}
