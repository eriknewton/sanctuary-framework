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

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type {
  StorageBackend,
  StorageEntryMeta,
} from "../../src/storage/interface.js";
import {
  FederationSyncStateStore,
  FederationSyncStateStoreError,
  emptyFederationSyncState,
  FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
  type FederationSyncStateSnapshot,
} from "../../src/v1/federation-sync-state-store.js";
import { FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY } from "../../src/v1/federation-sync-state-store.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";

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

describe("FederationSyncStateStore - cross-process lost-update close (monotonic merge)", () => {
  /**
   * The race this fix closes: the `rotate-root --compromised` CLI loads fresh,
   * folds the compromised root into `revokedRootPubkeys` + lifts
   * `highestRevocationSerial`, and persists to the single blob. The LIVE daemon's
   * in-memory state never learns of that write, so the daemon's next persist (a
   * high-water advance built from its STALE in-memory snapshot) would, with a
   * blind whole-blob overwrite, CLOBBER the revoked root + the new serial. On the
   * next restart the clobbered blob hydrates -> a cert chaining to the compromised
   * root is accepted again.
   *
   * Each `FederationSyncStateStore` instance over the SAME storage stands in for a
   * distinct process (CLI vs daemon); the daemon instance's snapshot is built from
   * state that predates the CLI write (it never saw it). With the read-modify-write
   * merge in `writeNow`, the daemon's overwrite UNIONs the at-rest revocation back
   * in instead of dropping it.
   */
  it("daemon high-water overwrite after a CLI root-revocation does NOT un-revoke the root", async () => {
    const storage = new MemoryStorage();
    const compromisedRoot = "compromised-root-K1";

    // --- t0: daemon boots, snapshots its in-memory state (no revoked root yet).
    // Capture it NOW; this is what a later daemon persist would write blindly.
    const daemonStore = new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    });
    const daemonStaleSnapshot: FederationSyncStateSnapshot = {
      acceptedHighWater: new Map([["peer-a", 3]]),
      outboundHighWater: 2,
      revokedNodeIds: new Set(),
      highestEvictionSerial: 0,
      revokedRootPubkeys: new Set(), // <- never learned of the CLI revocation
      highestRevocationSerial: 0,
    };

    // --- t1: the CLI (a SEPARATE process) loads fresh, revokes the root, persists.
    const cliStore = new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    });
    const cliSnapshot = await cliStore.load();
    cliSnapshot.revokedRootPubkeys.add(compromisedRoot);
    cliSnapshot.highestRevocationSerial = Math.max(
      cliSnapshot.highestRevocationSerial,
      9,
    );
    await cliStore.persist(cliSnapshot);

    // --- t2: the daemon persists a high-water advance from its STALE snapshot.
    // Pre-fix this whole-blob overwrite drops the revoked root + the serial floor.
    const advanced: FederationSyncStateSnapshot = {
      ...daemonStaleSnapshot,
      acceptedHighWater: new Map([["peer-a", 4]]), // an advance
    };
    await daemonStore.persist(advanced);

    // --- t3: a fresh restart hydrates the on-disk blob.
    const afterRestart = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();

    // The compromised root MUST still be revoked, and the serial floor preserved.
    expect(afterRestart.revokedRootPubkeys.has(compromisedRoot)).toBe(true);
    expect(afterRestart.highestRevocationSerial).toBe(9);
    // The daemon's legitimate high-water advance is ALSO preserved (monotonic max).
    expect(afterRestart.acceptedHighWater.get("peer-a")).toBe(4);
    expect(afterRestart.outboundHighWater).toBe(2);
  });

  it("merge is strictly monotonic: a stale daemon write never lowers a serial or drops a revoked node", async () => {
    const storage = new MemoryStorage();

    // Seed the blob with a high floor + revocations (as if a prior CLI/eviction wrote it).
    await new FederationSyncStateStore({ storage, masterKey: masterKey() }).persist({
      acceptedHighWater: new Map([["peer-a", 10]]),
      outboundHighWater: 7,
      revokedNodeIds: new Set(["evicted-1"]),
      highestEvictionSerial: 5,
      revokedRootPubkeys: new Set(["root-old"]),
      highestRevocationSerial: 4,
    });

    // A daemon persists a STALE snapshot with LOWER floors + missing revocations.
    await new FederationSyncStateStore({ storage, masterKey: masterKey() }).persist({
      acceptedHighWater: new Map([["peer-a", 2], ["peer-b", 1]]),
      outboundHighWater: 1,
      revokedNodeIds: new Set(),
      highestEvictionSerial: 1,
      revokedRootPubkeys: new Set(),
      highestRevocationSerial: 1,
    });

    const loaded = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();

    // Floors are MAX (never lowered); the new sender is added; revocations survive.
    expect(loaded.acceptedHighWater.get("peer-a")).toBe(10);
    expect(loaded.acceptedHighWater.get("peer-b")).toBe(1);
    expect(loaded.outboundHighWater).toBe(7);
    expect(loaded.highestEvictionSerial).toBe(5);
    expect(loaded.highestRevocationSerial).toBe(4);
    expect(loaded.revokedNodeIds.has("evicted-1")).toBe(true);
    expect(loaded.revokedRootPubkeys.has("root-old")).toBe(true);
  });

  it("union grows both directions: each writer's distinct revocation survives the other's overwrite", async () => {
    const storage = new MemoryStorage();

    // Writer 1 commits root-A.
    const s1 = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();
    s1.revokedRootPubkeys.add("root-A");
    s1.highestRevocationSerial = 3;
    await new FederationSyncStateStore({ storage, masterKey: masterKey() }).persist(s1);

    // Writer 2 started from the EMPTY pre-A state and commits root-B (it never saw A).
    const s2: FederationSyncStateSnapshot = {
      acceptedHighWater: new Map(),
      outboundHighWater: 0,
      revokedNodeIds: new Set(),
      highestEvictionSerial: 0,
      revokedRootPubkeys: new Set(["root-B"]),
      highestRevocationSerial: 6,
    };
    await new FederationSyncStateStore({ storage, masterKey: masterKey() }).persist(s2);

    const loaded = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();

    expect(loaded.revokedRootPubkeys.has("root-A")).toBe(true);
    expect(loaded.revokedRootPubkeys.has("root-B")).toBe(true);
    expect(loaded.highestRevocationSerial).toBe(6);
  });
});

/**
 * The write-OVERLAP race (the residual the cross-process lock closes). The
 * sequential-completion case above is closed by the read-modify-write alone: the
 * second writer's persist starts AFTER the first's persist resolved, so its
 * merge-read sees the committed revocation. This block proves the genuine OVERLAP
 * case: two SEPARATE processes (separate store instances over the SAME on-disk
 * storage) BOTH begin their read-modify-write before either has written. Without
 * a lock spanning the whole read-modify-write, the daemon's read would precede the
 * CLI's write, so its later overwrite would drop the CLI-committed revocation. The
 * cross-process file lock in `writeNow` serializes the two read-modify-writes, so
 * the second one reads the first's committed state and unions it.
 *
 * Uses a REAL FilesystemStorage over a temp dir so the lock engages (it degrades
 * to a no-op on non-filesystem backends, which have no cross-process surface). An
 * injected per-instance write delay forces the two persists to be in-flight at the
 * same wall-clock window; the lock makes their critical sections non-overlapping
 * anyway.
 */
describe("FederationSyncStateStore - write-OVERLAP close (cross-process lock)", () => {
  let fortressPath: string;

  beforeEach(async () => {
    fortressPath = await mkdtemp(join(tmpdir(), "fed-sync-overlap-"));
  });

  afterEach(async () => {
    await rm(fortressPath, { recursive: true, force: true });
  });

  /**
   * A FilesystemStorage whose `write` is artificially slowed so two concurrent
   * persists are genuinely in-flight together. The lock must still serialize their
   * read-modify-writes (the loser blocks on the lockfile, then reads the winner's
   * committed state). Records the order of `read`/`write` calls so the test can
   * assert the critical sections did NOT interleave.
   */
  class SlowWriteFilesystemStorage extends FilesystemStorage {
    public readonly ops: string[] = [];
    constructor(
      basePath: string,
      private readonly writeDelayMs: number,
    ) {
      super(basePath);
    }
    override async read(
      namespace: string,
      key: string,
    ): Promise<Uint8Array | null> {
      if (key === "sync-state-v1") this.ops.push(`read:${namespace}/${key}`);
      return super.read(namespace, key);
    }
    override async write(
      namespace: string,
      key: string,
      data: Uint8Array,
    ): Promise<void> {
      if (key === "sync-state-v1") {
        await new Promise((r) => setTimeout(r, this.writeDelayMs));
        this.ops.push(`write:${namespace}/${key}`);
      }
      return super.write(namespace, key, data);
    }
  }

  it("two overlapping cross-process writers BOTH persist; the revoked root SURVIVES and the floor holds", async () => {
    const storage = new SlowWriteFilesystemStorage(
      join(fortressPath, "state"),
      40,
    );
    const compromisedRoot = "compromised-root-K1";

    // Distinct store instances == distinct processes over the same on-disk blob.
    const cliStore = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    const daemonStore = new FederationSyncStateStore({ storage, masterKey: masterKey() });

    // The CLI revokes the compromised root + lifts the serial.
    const cliSnapshot: FederationSyncStateSnapshot = {
      acceptedHighWater: new Map(),
      outboundHighWater: 0,
      revokedNodeIds: new Set(),
      highestEvictionSerial: 0,
      revokedRootPubkeys: new Set([compromisedRoot]),
      highestRevocationSerial: 9,
    };
    // The daemon, from a STALE in-memory snapshot, only advances a high-water and
    // KNOWS NOTHING of the CLI's revocation.
    const daemonSnapshot: FederationSyncStateSnapshot = {
      acceptedHighWater: new Map([["peer-a", 4]]),
      outboundHighWater: 2,
      revokedNodeIds: new Set(),
      highestEvictionSerial: 0,
      revokedRootPubkeys: new Set(),
      highestRevocationSerial: 0,
    };

    // Fire BOTH persists so their critical sections want to overlap (the slow
    // write keeps the first in-flight while the second tries to acquire the lock).
    await Promise.all([
      cliStore.persist(cliSnapshot),
      daemonStore.persist(daemonSnapshot),
    ]);
    // Snapshot the op-trace of the two persists BEFORE the restart load adds its
    // own hydrate read.
    const persistOps = [...storage.ops];

    // A fresh restart hydrates the on-disk blob.
    const afterRestart = await new FederationSyncStateStore({
      storage,
      masterKey: masterKey(),
    }).load();

    // The compromised root MUST still be revoked and the serial floor preserved,
    // regardless of which writer won the lock first.
    expect(afterRestart.revokedRootPubkeys.has(compromisedRoot)).toBe(true);
    expect(afterRestart.highestRevocationSerial).toBe(9);
    // The daemon's legitimate high-water advance is also preserved (monotonic max).
    expect(afterRestart.acceptedHighWater.get("peer-a")).toBe(4);
    expect(afterRestart.outboundHighWater).toBe(2);

    // PROOF the lock (not just the merge) closed the window: the two persist
    // critical sections did NOT interleave. With a per-blob read/write op trace,
    // the loser's merge-READ must come AFTER the winner's WRITE (no read,read,
    // write,write). Each persist does exactly one merge-read + one write.
    const reads = persistOps
      .map((op, i) => ({ op, i }))
      .filter((e) => e.op.startsWith("read:"));
    const writes = persistOps
      .map((op, i) => ({ op, i }))
      .filter((e) => e.op.startsWith("write:"));
    expect(reads.length).toBe(2);
    expect(writes.length).toBe(2);
    // The second read happens after the first write: serialized, not overlapping.
    expect(reads[1]!.i).toBeGreaterThan(writes[0]!.i);
  });
});

/**
 * F1 re-gate (§1 + Finding #6): the EXTERNAL anti-rollback anchor + the
 * tamper-evident tri-state established sentinel. These operate at the STORE
 * level, capturing/restoring RAW on-disk bytes (never handing the attacker the
 * master), which is exactly the keyless filesystem attacker the fix defends
 * against. The dashboard-level composition (§8 audit floor, the latch) is
 * covered in federation-guardian-disable-gate.test.ts.
 */
describe("FederationSyncStateStore - §1 external anti-rollback anchor", () => {
  function snapshotWithFloors(floors: {
    generation: number;
    disableNonce: number;
    loweredHighWater: number;
  }): FederationSyncStateSnapshot {
    return {
      ...emptyFederationSyncState(),
      guardianRevocationRequirementGeneration: floors.generation,
      guardianDisableNonce: floors.disableNonce,
      guardianLoweredHighWater: floors.loweredHighWater,
    };
  }

  it("persist writes a valid anchor at the merged floors; read authenticates it", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    await store.persist(
      snapshotWithFloors({ generation: 4, disableNonce: 3, loweredHighWater: 2 }),
    );
    const anchor = await store.readGuardianAntiRollbackAnchor();
    expect(anchor.status).toBe("valid");
    if (anchor.status !== "valid") throw new Error("unreachable");
    expect(anchor.data.requirement_generation).toBe(4);
    expect(anchor.data.disable_nonce).toBe(3);
    expect(anchor.data.lowered_high_water).toBe(2);
  });

  it("the anchor is NON-DECREASING: a lower persist never lowers an anchored floor", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    await store.persist(
      snapshotWithFloors({ generation: 9, disableNonce: 7, loweredHighWater: 5 }),
    );
    // A subsequent persist carrying LOWER floors (a stale writer) must not lower
    // the anchor.
    await store.writeGuardianAntiRollbackAnchor({
      loweredHighWater: 0,
      disableNonce: 0,
      requirementGeneration: 0,
    });
    const anchor = await store.readGuardianAntiRollbackAnchor();
    expect(anchor.status).toBe("valid");
    if (anchor.status !== "valid") throw new Error("unreachable");
    expect(anchor.data.requirement_generation).toBe(9);
    expect(anchor.data.disable_nonce).toBe(7);
    expect(anchor.data.lowered_high_water).toBe(5);
  });

  it("absent anchor reads as absent (neutral); tampered anchor reads as invalid (latch signal)", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    expect((await store.readGuardianAntiRollbackAnchor()).status).toBe("absent");

    await store.persist(
      snapshotWithFloors({ generation: 2, disableNonce: 1, loweredHighWater: 0 }),
    );
    // Corrupt the anchor's MAC on disk (a keyless attacker mangling the record).
    const raw = await storage.read("_meta", FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(bytesToString(raw!)) as { mac: string };
    parsed.mac = "AAAA" + parsed.mac.slice(4);
    await storage.write(
      "_meta",
      FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
      stringToBytes(JSON.stringify(parsed)),
    );
    expect((await store.readGuardianAntiRollbackAnchor()).status).toBe("invalid");
  });

  it("a keyless attacker who cannot re-MAC the anchor cannot forge a higher floor", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    await store.persist(
      snapshotWithFloors({ generation: 2, disableNonce: 2, loweredHighWater: 2 }),
    );
    // The attacker rewrites the anchor's data floors UP without the master key
    // (leaving the old MAC): the read must reject it (invalid), never accept a
    // forged higher floor.
    const raw = await storage.read("_meta", FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY);
    const parsed = JSON.parse(bytesToString(raw!)) as {
      data: { requirement_generation: number };
      mac: string;
    };
    parsed.data.requirement_generation = 999;
    await storage.write(
      "_meta",
      FEDERATION_GUARDIAN_ANTIROLLBACK_ANCHOR_KEY,
      stringToBytes(JSON.stringify(parsed)),
    );
    expect((await store.readGuardianAntiRollbackAnchor()).status).toBe("invalid");
  });
});

describe("FederationSyncStateStore - Finding #6 tamper-evident established sentinel (tri-state)", () => {
  it("absent -> {status: absent}; established -> {status: established}", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    expect((await store.guardianRequirementEstablished()).status).toBe("absent");
    await store.markGuardianRequirementEstablished();
    expect((await store.guardianRequirementEstablished()).status).toBe("established");
  });

  it("present-but-bad-MAC -> {status: invalid} (was the old false 'absent')", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    await store.markGuardianRequirementEstablished();
    // Corrupt the MAC (a keyless attacker cannot recompute it under the master).
    await storage.write(
      "_meta",
      FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
      stringToBytes(JSON.stringify({ v: 1, mac: "not-the-real-mac" })),
    );
    expect((await store.guardianRequirementEstablished()).status).toBe("invalid");
  });

  it("present-but-unparseable -> {status: invalid}", async () => {
    const storage = new MemoryStorage();
    const store = new FederationSyncStateStore({ storage, masterKey: masterKey() });
    await store.markGuardianRequirementEstablished();
    await storage.write(
      "_meta",
      FEDERATION_GUARDIAN_REQUIREMENT_ESTABLISHED_KEY,
      stringToBytes("{ this is not json"),
    );
    expect((await store.guardianRequirementEstablished()).status).toBe("invalid");
  });
});
