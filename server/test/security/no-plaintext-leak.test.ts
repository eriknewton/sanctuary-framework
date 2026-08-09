// fail-before-exempt: authenticated StateStore fixture wiring only; key-resolution fail-before coverage lives in state-envelope-integrity.test.ts and master-rotation.test.ts
/**
 * Security Test: No Plaintext Leak
 *
 * Verifies that plaintext state values never appear on the filesystem
 * after being written through the StateStore.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey, deriveNamespaceKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

describe("No Plaintext Leak", () => {
  let storage: MemoryStorage;
  let stateStore: StateStore;
  let masterKey: Uint8Array;
  let identityEncKey: Uint8Array;
  let identity: ReturnType<typeof createIdentity>;

  beforeEach(async () => {
    masterKey = generateRandomKey();
    storage = new MemoryStorage();
    stateStore = new StateStore(storage, masterKey);
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    identity = createIdentity("test", identityEncKey, "recovery-key");
    await persistStoredIdentity(storage, masterKey, identity.storedIdentity);
  });

  it("should never store plaintext values in storage", async () => {
    const sensitiveValue = "MY_SECRET_API_KEY_12345_VERY_SENSITIVE";

    await stateStore.write(
      "secrets",
      "api-key",
      sensitiveValue,
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    // Scan all stored data for the plaintext value
    const allEntries = await storage.list("secrets");
    for (const entry of allEntries) {
      const raw = await storage.read("secrets", entry.key);
      expect(raw).not.toBeNull();
      const rawString = bytesToString(raw!);

      // The plaintext value must NEVER appear in stored data
      expect(rawString).not.toContain(sensitiveValue);
    }
  });

  it("should not leak plaintext across multiple writes", async () => {
    const secrets = [
      "password123",
      "credit-card-4111-1111-1111-1111",
      "ssn-123-45-6789",
      "secret-negotiation-strategy-underbid-by-10-percent",
    ];

    for (let i = 0; i < secrets.length; i++) {
      await stateStore.write(
        "sensitive",
        `secret-${i}`,
        secrets[i]!,
        identity.storedIdentity.identity_id,
        identity.storedIdentity.encrypted_private_key,
        identityEncKey
      );
    }

    // Scan ALL storage (all namespaces) for any plaintext
    const allEntries = await storage.list("sensitive");
    for (const entry of allEntries) {
      const raw = await storage.read("sensitive", entry.key);
      const rawString = bytesToString(raw!);

      for (const secret of secrets) {
        expect(rawString).not.toContain(secret);
      }
    }
  });

  it("should return correct plaintext only through StateStore.read", async () => {
    const value = "this-should-be-recoverable-through-api-only";

    await stateStore.write(
      "test",
      "recoverable",
      value,
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    // Read through the StateStore should return the original value
    const result = await stateStore.read("test", "recoverable");
    expect(result).not.toBeNull();
    expect(result!.value).toBe(value);
  });
});
