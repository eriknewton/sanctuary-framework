// fail-before-exempt: deterministic replacement for a probabilistic ciphertext-absence check; behavior unchanged
import { expect } from "vitest";
import {
  decrypt,
  PAYLOAD_IV_BYTE_LENGTH,
  SUPPORTED_PAYLOAD_ALG,
  SUPPORTED_PAYLOAD_VERSION,
  type EncryptedPayload,
} from "../../src/core/encryption.js";
import { bytesToString, fromBase64url, toBase64url } from "../../src/core/encoding.js";

/** Check public envelope fields and authenticate the JSON record with the actual store key. */
export function assertEncryptedJsonPrivacy(
  serialized: string,
  needle: string,
  key: Uint8Array,
  aad?: Uint8Array,
): Record<string, unknown> {
  const envelope = JSON.parse(serialized) as EncryptedPayload;
  expect(Object.keys(envelope).sort()).toEqual(["alg", "ct", "iv", "ts", "v"]);
  const { ct, iv, ...metadata } = envelope;
  // IV and ciphertext are authenticated random bytes; searching either spelling can flake.
  expect(JSON.stringify({ fields: Object.keys(envelope), metadata })).not.toContain(needle);
  expect(envelope.v).toBe(SUPPORTED_PAYLOAD_VERSION);
  expect(envelope.alg).toBe(SUPPORTED_PAYLOAD_ALG);
  expect(new Date(envelope.ts).toISOString()).toBe(envelope.ts);
  for (const encoded of [iv, ct]) {
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(toBase64url(fromBase64url(encoded))).toBe(encoded);
  }
  expect(fromBase64url(iv)).toHaveLength(PAYLOAD_IV_BYTE_LENGTH);
  const tagBytes = 128 / 8; // AES-GCM's 128-bit authentication tag.
  expect(fromBase64url(ct).length).toBeGreaterThan(tagBytes);
  const record: unknown = JSON.parse(bytesToString(decrypt(envelope, key, aad)));
  expect(record).toBeTypeOf("object");
  expect(record).not.toBeNull();
  expect(Array.isArray(record)).toBe(false);
  const wrongKey = key.slice();
  wrongKey[0] = wrongKey[0]! ^ 1; // Flip one bit to guarantee a different AES key.
  expect(() => decrypt(envelope, wrongKey, aad)).toThrow();
  return record as Record<string, unknown>;
}
