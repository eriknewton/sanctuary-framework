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
  if (key.length !== 32) {
    throw new Error("Key must be exactly 32 bytes (256 bits)");
  }

  const iv = generateIV();
  const cipher = gcm(key, iv, aad);
  // @noble/ciphers gcm.encrypt appends the 16-byte auth tag to the ciphertext
  const ciphertext = cipher.encrypt(plaintext);

  return {
    v: 1,
    alg: "aes-256-gcm",
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
  if (key.length !== 32) {
    throw new Error("Key must be exactly 32 bytes (256 bits)");
  }
  if (payload.v !== 1) {
    throw new Error(`Unsupported payload version: ${payload.v}`);
  }
  if (payload.alg !== "aes-256-gcm") {
    throw new Error(`Unsupported algorithm: ${payload.alg}`);
  }

  const iv = fromBase64url(payload.iv);
  const ciphertext = fromBase64url(payload.ct);
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
