/**
 * Sanctuary MCP Server — Secure Random Generation
 *
 * All randomness in Sanctuary flows through this module.
 * Uses crypto.getRandomValues (Web Crypto API) for CSPRNG.
 */

import { randomBytes as nodeRandomBytes } from "node:crypto";

/**
 * Generate cryptographically secure random bytes.
 * Uses Node.js crypto module (backed by OpenSSL CSPRNG).
 */
export function randomBytes(length: number): Uint8Array {
  if (length <= 0) {
    throw new RangeError("Length must be positive");
  }
  const buf = nodeRandomBytes(length);
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/**
 * Generate a random IV for AES-256-GCM (12 bytes per NIST SP 800-38D).
 */
export function generateIV(): Uint8Array {
  return randomBytes(12);
}

/**
 * Generate a random salt for key derivation (32 bytes).
 */
export function generateSalt(): Uint8Array {
  return randomBytes(32);
}

/**
 * Generate a random 256-bit key (for recovery key generation).
 */
export function generateRandomKey(): Uint8Array {
  return randomBytes(32);
}
