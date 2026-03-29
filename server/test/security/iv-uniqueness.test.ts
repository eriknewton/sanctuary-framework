/**
 * Security Test: IV Uniqueness
 *
 * Verifies that no two encryptions ever share the same IV.
 * IV reuse in AES-GCM is catastrophic — it breaks both
 * confidentiality and authenticity.
 */

import { describe, it, expect } from "vitest";
import { encrypt } from "../../src/core/encryption.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes } from "../../src/core/encoding.js";

describe("IV Uniqueness", () => {
  it("should never produce duplicate IVs across 10,000 encryptions", () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes("test-value");
    const ivSet = new Set<string>();

    for (let i = 0; i < 10_000; i++) {
      const result = encrypt(plaintext, key);
      expect(ivSet.has(result.iv)).toBe(false);
      ivSet.add(result.iv);
    }

    expect(ivSet.size).toBe(10_000);
  });

  it("should produce unique IVs even with identical plaintexts and keys", () => {
    const key = generateRandomKey();
    const plaintext = stringToBytes("identical-value");

    const result1 = encrypt(plaintext, key);
    const result2 = encrypt(plaintext, key);

    expect(result1.iv).not.toBe(result2.iv);
    // Ciphertexts should also differ (different IV = different ciphertext)
    expect(result1.ct).not.toBe(result2.ct);
  });
});
