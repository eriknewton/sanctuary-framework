/**
 * `KnownSignersStore` (Exit V2 drill F2, `server/src/reputation/known-signers-store.ts`).
 *
 * Independent gate on #1303 (2026-08-23), item 4: a per-import bound alone
 * is not a store-wide bound - a sequence of individually quota-respecting
 * imports, each carrying fresh signer DIDs, could otherwise grow
 * `_known_signers` without limit. `persistIfAbsent` now enforces an
 * explicit, atomic, store-wide cap computed from NET-NEW keys, refusing the
 * WHOLE batch (nothing written) when it would be exceeded.
 */

import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { ed25519 } from "@noble/curves/ed25519";
import {
  KnownSignersStore,
  KnownSignersQuotaError,
  KNOWN_SIGNERS_NAMESPACE,
  MEMORY_PROVENANCE_SIGNER_PREFIX,
} from "../../src/reputation/known-signers-store.js";

/** A fresh, syntactically valid Ed25519 keypair, for constructing distinct DIDs cheaply. */
function freshEntry(label: string): { did: string; publicKey: Uint8Array } {
  const seed = generateRandomKey();
  const publicKey = ed25519.getPublicKey(seed);
  // The store never validates that `did` derives from `publicKey` - that
  // invariant is enforced one layer up, by exit/verifier.ts
  // `resolveKnownSigners` before a caller ever reaches persistIfAbsent. A
  // synthetic label-based did is sufficient here to test the STORE's own
  // quota bookkeeping in isolation.
  return { did: `did:key:test-${label}`, publicKey };
}

describe("KnownSignersStore quota (independent gate item 4)", () => {
  it("repeated batches of fresh DIDs are admitted up to the cap, then the WHOLE next batch is refused with nothing written", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new KnownSignersStore(storage, masterKey, {
      maxKnownSigners: 5,
    });

    // Fill to exactly the cap, three DIDs at a time (batches do not align
    // with the cap boundary, proving the check is store-wide, not
    // batch-local).
    await store.persistIfAbsent(
      [freshEntry("a1"), freshEntry("a2"), freshEntry("a3")],
      "import-1"
    );
    expect((await storage.list(KNOWN_SIGNERS_NAMESPACE)).length).toBe(3);

    await store.persistIfAbsent(
      [freshEntry("b1"), freshEntry("b2")],
      "import-2"
    );
    expect((await storage.list(KNOWN_SIGNERS_NAMESPACE)).length).toBe(5);

    // The store is now exactly AT the cap. One more fresh DID must be
    // refused wholesale - a repeated-overwrite-with-fresh-DIDs attempt
    // (each batch names DIDs never seen before) does not get partial
    // credit.
    const beforeSnapshot = (await storage.list(KNOWN_SIGNERS_NAMESPACE))
      .map((e) => e.key)
      .sort();
    await expect(
      store.persistIfAbsent([freshEntry("c1")], "import-3")
    ).rejects.toThrow(KnownSignersQuotaError);
    const afterSnapshot = (await storage.list(KNOWN_SIGNERS_NAMESPACE))
      .map((e) => e.key)
      .sort();
    expect(afterSnapshot).toEqual(beforeSnapshot);
    expect(afterSnapshot.length).toBe(5);
  });

  it("a batch that would cross the cap is refused ENTIRELY, including the entries that would themselves have fit", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new KnownSignersStore(storage, masterKey, {
      maxKnownSigners: 5,
    });
    await store.persistIfAbsent(
      [freshEntry("a1"), freshEntry("a2"), freshEntry("a3")],
      "import-1"
    );
    expect((await storage.list(KNOWN_SIGNERS_NAMESPACE)).length).toBe(3);

    // 3 more net-new DIDs against 2 remaining headroom: the batch as a
    // whole exceeds the cap, so NONE of the 3 land - not even the 2 that
    // would have fit alone.
    await expect(
      store.persistIfAbsent(
        [freshEntry("d1"), freshEntry("d2"), freshEntry("d3")],
        "import-2"
      )
    ).rejects.toThrow(KnownSignersQuotaError);
    expect((await storage.list(KNOWN_SIGNERS_NAMESPACE)).length).toBe(3);
  });

  it("re-persisting the SAME DIDs (already recorded) never counts against the cap", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new KnownSignersStore(storage, masterKey, {
      maxKnownSigners: 2,
    });
    const entries = [freshEntry("x1"), freshEntry("x2")];
    await store.persistIfAbsent(entries, "import-1");
    expect((await storage.list(KNOWN_SIGNERS_NAMESPACE)).length).toBe(2);

    // The store is at its (tiny) cap, but re-persisting the SAME entries is
    // a no-op (net-new count is 0), so it must NOT throw.
    await expect(
      store.persistIfAbsent(entries, "import-2")
    ).resolves.toBeUndefined();
    expect((await storage.list(KNOWN_SIGNERS_NAMESPACE)).length).toBe(2);

    // The persisted record keeps its ORIGINAL first_seen_import_id - a
    // later re-assertion is not treated as a fresh write.
    const first = await store.lookup(entries[0]!.did);
    expect(first?.first_seen_import_id).toBe("import-1");
  });
});

describe("KnownSignersStore partition isolation (C4)", () => {
  it("keeps reputation and memory-provenance headroom independent", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const reputation = new KnownSignersStore(storage, masterKey, {
      maxKnownSigners: 2,
      partition: "reputation",
    });
    const memory = new KnownSignersStore(storage, masterKey, {
      maxKnownSigners: 2,
      partition: "memory_provenance",
    });
    await reputation.persistIfAbsent([freshEntry("r1"), freshEntry("r2")], "rep-import");
    expect((await memory.wouldExceedCapacity([freshEntry("m1")])).exceeds).toBe(false);
    await memory.persistIfAbsent([freshEntry("m1"), freshEntry("m2")], "memory-import");
    expect((await reputation.wouldExceedCapacity([freshEntry("r3")])).exceeds).toBe(true);
    expect((await memory.wouldExceedCapacity([freshEntry("m3")])).exceeds).toBe(true);
    const keys = (await storage.list(KNOWN_SIGNERS_NAMESPACE)).map((entry) => entry.key);
    expect(keys.filter((key) => key.startsWith(MEMORY_PROVENANCE_SIGNER_PREFIX))).toHaveLength(2);
    expect(keys.filter((key) => !key.startsWith(MEMORY_PROVENANCE_SIGNER_PREFIX))).toHaveLength(2);

    const reverseStorage = new MemoryStorage();
    const reverseMemory = new KnownSignersStore(reverseStorage, masterKey, {
      maxKnownSigners: 2, partition: "memory_provenance",
    });
    const reverseReputation = new KnownSignersStore(reverseStorage, masterKey, {
      maxKnownSigners: 2, partition: "reputation",
    });
    await reverseMemory.persistIfAbsent([freshEntry("mx1"), freshEntry("mx2")], "memory-full");
    expect((await reverseReputation.wouldExceedCapacity([freshEntry("rx1")])).exceeds).toBe(false);
    await reverseReputation.persistIfAbsent([freshEntry("rx1")], "rep-after-memory-full");
    expect((await reverseStorage.list(KNOWN_SIGNERS_NAMESPACE)).length).toBe(3);
  });
});
