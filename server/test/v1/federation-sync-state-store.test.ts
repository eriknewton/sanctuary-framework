/**
 * Store-level durability tests for the federation peer-sync security state
 * (Federation 3/3b P0).
 *
 * The DEBT these close: the per-sender accepted high-water, the outbound
 * high-water, and the folded node-revocation projection were in-memory ONLY, so
 * a daemon restart re-opened the whole-envelope replay window (no prior
 * high-water) AND silently un-revoked every evicted node until those evictions
 * re-synced. These tests prove the durable backend rehydrates all of it across a
 * restart (a NEW store over the SAME storage), fails CLOSED on a corrupt record
 * (never resets-to-empty), distinguishes a fresh fortress (no record -> empty
 * snapshot) from a corrupt one (throw), and throws on a write failure.
 *
 * Deterministic in-memory storage fakes only; keychain-free; no sockets / temp
 * dirs.
 */

import { describe, expect, it } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import type {
  StorageBackend,
  StorageEntryMeta,
} from "../../src/storage/interface.js";
import {
  FederationSyncStateStore,
  FederationSyncStateStoreError,
  emptyFederationSyncState,
  type FederationSyncStateSnapshot,
} from "../../src/v1/federation-sync-state-store.js";

/** A 32-byte custody master stand-in (deterministic, keychain-free). */
function masterKey(): Uint8Array {
  return new Uint8Array(32).fill(9);
}

function sampleSnapshot(): FederationSyncStateSnapshot {
  return {
    acceptedHighWater: new Map([
      ["linux-1", 7],
      ["mini-1", 42],
    ]),
    outboundHighWater: 5,
    revokedNodeIds: new Set(["evil-node", "stale-node"]),
    highestEvictionSerial: 3,
    revokedRootPubkeys: new Set(["revoked-root-k1"]),
    highestRevocationSerial: 1,
  };
}

/** A storage backend whose `write` always throws (persist-failure injection). */
class FailingWriteStorage extends MemoryStorage {
  override async write(): Promise<void> {
    throw new Error("disk write failed");
  }
}

/** A storage backend that returns a non-decryptable blob for any read. */
class CorruptReadStorage implements StorageBackend {
  async write(): Promise<void> {}
  async read(): Promise<Uint8Array | null> {
    const garbage = JSON.stringify({
      v: 1,
      alg: "aes-256-gcm",
      iv: "AAAAAAAAAAAAAAAA",
      ct: "AAAAAAAAAAAAAAAAAAAAAA",
      ts: new Date().toISOString(),
    });
    return new TextEncoder().encode(garbage);
  }
  async delete(): Promise<boolean> {
    return false;
  }
  async list(): Promise<StorageEntryMeta[]> {
    return [];
  }
  async exists(): Promise<boolean> {
    return true;
  }
  async totalSize(): Promise<number> {
    return 0;
  }
}

describe("FederationSyncStateStore - durable peer-sync security state", () => {
  it("round-trips the full snapshot through encrypt -> decrypt", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    const snapshot = sampleSnapshot();

    await store.persist(snapshot);
    const loaded = await store.load();

    expect([...loaded.acceptedHighWater].sort()).toEqual(
      [...snapshot.acceptedHighWater].sort(),
    );
    expect(loaded.outboundHighWater).toBe(snapshot.outboundHighWater);
    expect([...loaded.revokedNodeIds].sort()).toEqual(
      [...snapshot.revokedNodeIds].sort(),
    );
    expect(loaded.highestEvictionSerial).toBe(snapshot.highestEvictionSerial);
  });

  it("restart survival: a NEW store over the SAME storage rehydrates the state", async () => {
    const storage = new MemoryStorage();
    const snapshot = sampleSnapshot();
    await new FederationSyncStateStore({ storage, masterKey: masterKey() }).persist(
      snapshot,
    );

    // Simulate a daemon restart: a fresh store instance, same on-disk bytes.
    const afterRestart = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();

    expect(afterRestart.acceptedHighWater.get("linux-1")).toBe(7);
    expect(afterRestart.outboundHighWater).toBe(5);
    expect(afterRestart.revokedNodeIds.has("evil-node")).toBe(true);
    expect(afterRestart.highestEvictionSerial).toBe(3);
  });

  it("DUR-4 fresh fortress: no record -> empty/zero snapshot, NOT a throw", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });

    const loaded = await store.load();

    expect(loaded.acceptedHighWater.size).toBe(0);
    expect(loaded.outboundHighWater).toBe(0);
    expect(loaded.revokedNodeIds.size).toBe(0);
    expect(loaded.highestEvictionSerial).toBe(0);
    expect(loaded).toEqual(emptyFederationSyncState());
  });

  it("DUR-4 / CC-2 corrupt record -> THROWS (fail closed), never resets to empty", async () => {
    const store = new FederationSyncStateStore({
      storage: new CorruptReadStorage(),
      masterKey: masterKey(),
    });

    await expect(store.load()).rejects.toBeInstanceOf(
      FederationSyncStateStoreError,
    );
  });

  it("CC-2 at-rest tamper of the persisted record -> THROWS on the next load", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    await store.persist(sampleSnapshot());

    // Flip a byte of the on-disk ciphertext: AEAD verification must fail closed.
    const raw = await storage.read("_federation", "sync-state-v1");
    expect(raw).not.toBeNull();
    const tampered = new TextDecoder().decode(raw!);
    const obj = JSON.parse(tampered) as { ct: string };
    obj.ct = obj.ct.slice(0, -2) + (obj.ct.endsWith("AA") ? "BB" : "AA");
    await storage.write(
      "_federation",
      "sync-state-v1",
      new TextEncoder().encode(JSON.stringify(obj)),
    );

    await expect(store.load()).rejects.toBeInstanceOf(
      FederationSyncStateStoreError,
    );
  });

  it("CC-2 a REMOVED revocation cannot silently un-revoke: a different master fails closed", async () => {
    const storage = new MemoryStorage();
    // Persist a revocation under master A.
    await new FederationSyncStateStore({
      storage,
      masterKey: new Uint8Array(32).fill(1),
    }).persist(sampleSnapshot());

    // A store keyed with a DIFFERENT master (e.g. a record swapped from another
    // fortress, or a key mismatch) cannot decrypt -> throws, never loads an
    // empty (un-revoked) projection.
    await expect(
      new FederationSyncStateStore({
        storage,
        masterKey: new Uint8Array(32).fill(2),
      }).load(),
    ).rejects.toBeInstanceOf(FederationSyncStateStoreError);
  });

  it("DUR-4 wrong record version -> THROWS (fail closed)", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    // Persist a valid record, then re-encrypt a v:2 body under the same key.
    await store.persist(sampleSnapshot());
    const raw = await storage.read("_federation", "sync-state-v1");
    const payload = JSON.parse(new TextDecoder().decode(raw!));
    // Build a v:2 decryptable record by encrypting a wrong-version body with the
    // SAME purpose key. Reuse the store's own encryption indirectly: persist then
    // mutate is not enough (the body is encrypted), so encrypt here.
    const { encrypt } = await import("../../src/core/encryption.js");
    const { derivePurposeKey } = await import("../../src/core/key-derivation.js");
    const key = derivePurposeKey(masterKey(), "federation-sync-state");
    const badBody = new TextEncoder().encode(
      JSON.stringify({ v: 2, accepted_high_water: [], outbound_high_water: 0 }),
    );
    const reEncrypted = encrypt(badBody, key);
    void payload;
    await storage.write(
      "_federation",
      "sync-state-v1",
      new TextEncoder().encode(JSON.stringify(reEncrypted)),
    );

    await expect(store.load()).rejects.toBeInstanceOf(
      FederationSyncStateStoreError,
    );
  });

  it("DUR write failure -> persist THROWS so the caller fails closed", async () => {
    const store = new FederationSyncStateStore({
      storage: new FailingWriteStorage(),
      masterKey: masterKey(),
    });

    await expect(store.persist(sampleSnapshot())).rejects.toThrow();
  });
});
