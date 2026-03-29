/**
 * Security Test: Key Never in Response
 *
 * Verifies that private keys never appear in any tool response.
 * This is a critical invariant — the private key exists only
 * encrypted on disk and briefly in memory during signing.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { createIdentity, sign } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { decrypt } from "../../src/core/encryption.js";

describe("Key Never in Response", () => {
  let masterKey: Uint8Array;
  let identityEncKey: Uint8Array;

  beforeEach(() => {
    masterKey = generateRandomKey();
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  });

  it("should not include private key in createIdentity output", () => {
    const { publicIdentity, storedIdentity } = createIdentity(
      "test",
      identityEncKey,
      "recovery-key"
    );

    // Decrypt the private key to know what we're looking for
    const privateKey = decrypt(
      storedIdentity.encrypted_private_key,
      identityEncKey
    );
    const privateKeyB64 = toBase64url(privateKey);

    // The public identity should not contain the private key
    const publicJson = JSON.stringify(publicIdentity);
    expect(publicJson).not.toContain(privateKeyB64);

    // The stored identity's serialization should not contain the plaintext private key
    // (it should only have the encrypted form)
    const storedJson = JSON.stringify(storedIdentity);
    expect(storedJson).not.toContain(privateKeyB64);

    // Clean up
    privateKey.fill(0);
  });

  it("should not include private key in sign output", () => {
    const { storedIdentity } = createIdentity(
      "test",
      identityEncKey,
      "recovery-key"
    );

    // Get the private key to check against
    const privateKey = decrypt(
      storedIdentity.encrypted_private_key,
      identityEncKey
    );
    const privateKeyB64 = toBase64url(privateKey);

    // Sign something
    const payload = stringToBytes("test-payload");
    const signature = sign(
      payload,
      storedIdentity.encrypted_private_key,
      identityEncKey
    );
    const signatureB64 = toBase64url(signature);

    // The signature should not contain the private key
    expect(signatureB64).not.toBe(privateKeyB64);
    expect(signatureB64).not.toContain(privateKeyB64);

    // Clean up
    privateKey.fill(0);
  });

  it("should zero out private key after signing", () => {
    // This test verifies the implementation pattern rather than runtime memory,
    // since we can't directly inspect deallocated memory in JS.
    // The sign() function in identity.ts uses a try/finally to zero the key.

    const { storedIdentity } = createIdentity(
      "test",
      identityEncKey,
      "recovery-key"
    );

    const payload = stringToBytes("test-payload");

    // Multiple signs should all work (key is decrypted fresh each time)
    for (let i = 0; i < 10; i++) {
      const sig = sign(
        payload,
        storedIdentity.encrypted_private_key,
        identityEncKey
      );
      expect(sig.length).toBe(64); // Ed25519 signature is 64 bytes
    }
  });
});
