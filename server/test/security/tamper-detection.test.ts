// fail-before-exempt: authenticated StateStore fixture wiring only; key-resolution fail-before coverage lives in state-envelope-integrity.test.ts and master-rotation.test.ts
/**
 * Security Test: Tamper Detection
 *
 * Verifies that modifying any byte of an encrypted state file
 * causes the read to fail (GCM authentication tag verification).
 */

import { describe, it, expect, beforeEach } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

describe("Tamper Detection", () => {
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

    // Write a known value
    await stateStore.write(
      "test",
      "tamper-target",
      "original-value",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );
  });

  it("should detect modification of ciphertext", async () => {
    // Read the raw stored data
    const raw = await storage.read("test", "tamper-target");
    expect(raw).not.toBeNull();

    // Parse and modify the ciphertext
    const entry = JSON.parse(bytesToString(raw!));
    const ctBytes = Buffer.from(entry.payload.ct, "base64");

    // Flip one bit in the ciphertext
    ctBytes[0] = ctBytes[0]! ^ 0x01;
    entry.payload.ct = ctBytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    // Write the tampered data back
    await storage.write("test", "tamper-target", stringToBytes(JSON.stringify(entry)));

    // Create a fresh StateStore (to clear caches)
    const freshStore = new StateStore(storage, masterKey);

    // Read should fail due to GCM auth tag mismatch
    await expect(
      freshStore.read("test", "tamper-target")
    ).rejects.toThrow();
  });

  it("should detect modification of IV", async () => {
    const raw = await storage.read("test", "tamper-target");
    const entry = JSON.parse(bytesToString(raw!));

    // Modify the IV
    const ivBytes = Buffer.from(entry.payload.iv, "base64");
    ivBytes[0] = ivBytes[0]! ^ 0xff;
    entry.payload.iv = ivBytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    await storage.write("test", "tamper-target", stringToBytes(JSON.stringify(entry)));

    const freshStore = new StateStore(storage, masterKey);
    await expect(
      freshStore.read("test", "tamper-target")
    ).rejects.toThrow();
  });

  it("should detect version number rollback", async () => {
    // Write a second version
    await stateStore.write(
      "test",
      "tamper-target",
      "updated-value",
      identity.storedIdentity.identity_id,
      identity.storedIdentity.encrypted_private_key,
      identityEncKey
    );

    // Verify version is 2
    const result = await stateStore.read("test", "tamper-target");
    expect(result!.version).toBe(2);

    // Now tamper: replace with version 1 data
    const raw = await storage.read("test", "tamper-target");
    const entry = JSON.parse(bytesToString(raw!));
    entry.ver = 1; // Rollback version number
    await storage.write("test", "tamper-target", stringToBytes(JSON.stringify(entry)));

    // The StateStore's version cache should detect the rollback
    await expect(
      stateStore.read("test", "tamper-target")
    ).rejects.toThrow(/rollback/i);
  });
});
