/**
 * Crypto-hygiene: derived namespace keys are zeroed on cache eviction / clear.
 *
 * StateStore caches HKDF-derived namespace keys (15-min TTL, LRU-128). On LRU
 * eviction and in invalidateKeyCache() the cached key bytes are now .fill(0)'d
 * before the entry is dropped, consistent with the rest of the codebase
 * (identity.ts, master-custody.ts, master-rotation.ts). These tests pin the
 * observable contract: zeroing must not corrupt the cache's correctness —
 * invalidateKeyCache() still empties the cache and a subsequent read
 * re-derives the key and decrypts correctly.
 */
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { generateRandomKey } from "../../src/core/random.js";
import { deriveNamespaceKey, derivePurposeKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import type { StoredIdentity } from "../../src/core/identity.js";

const KID = "agent-cache-1";

async function buildStore(): Promise<{ store: StateStore; master: Uint8Array; identity: StoredIdentity; idKey: Uint8Array }> {
  const storage = new MemoryStorage();
  const master = generateRandomKey();

  const seed = generateRandomKey();
  const publicKey = ed25519.getPublicKey(seed);
  const idKey = derivePurposeKey(master, "identity-encryption");
  const identity: StoredIdentity = {
    identity_id: KID,
    label: "cache test agent",
    public_key: toBase64url(publicKey),
    did: "did:key:test",
    created_at: new Date().toISOString(),
    key_type: "ed25519",
    key_protection: "passphrase",
    encrypted_private_key: encrypt(seed, idKey),
    rotation_history: [],
  };
  await storage.write(
    "_identities",
    KID,
    stringToBytes(
      JSON.stringify(encrypt(stringToBytes(JSON.stringify(identity)), idKey))
    )
  );

  const store = new StateStore(storage, master);
  return { store, master, identity, idKey };
}

describe("namespace key cache zeroing (crypto hygiene)", () => {
  it("invalidateKeyCache() still re-derives a correct key for a subsequent read", async () => {
    const { store, identity, idKey } = await buildStore();

    await store.write("notes", "k1", "hello sovereign world", KID, identity.encrypted_private_key, idKey);

    // Populate the cache, then clear it (which zeros the cached key bytes).
    const before = await store.read("notes", "k1");
    expect(before?.value).toBe("hello sovereign world");

    store.invalidateKeyCache();

    // After clearing the (zeroed) cache, a read must re-derive the namespace
    // key and decrypt correctly — zeroing must not have corrupted anything.
    const after = await store.read("notes", "k1");
    expect(after?.value).toBe("hello sovereign world");
  });

  it("deriveNamespaceKey is deterministic, so a re-derived key matches the original", () => {
    const master = generateRandomKey();
    const k1 = deriveNamespaceKey(master, "notes");
    const k2 = deriveNamespaceKey(master, "notes");
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
  });
});
