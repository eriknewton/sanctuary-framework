import { describe, expect, it } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { TestSdwMemoryBackendAdapter, testMemoryProvenanceDependencies } from "./test-memory-backend.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import {
  SdwMemoryProvenanceMigration,
  SDW_MEMORY_PROVENANCE_MIGRATION_ID,
} from "../../src/sdw/memory-provenance-migration.js";
import {
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_REPLAY_ANCHOR_KEY,
} from "../../src/sdw/records.js";
import { ROTATION_JOURNAL_KEY } from "../../src/core/master-custody.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE } from "../../src/storage/exit-import-journal.js";
import {
  prepareSdwBackendWrite,
  type Persistable,
} from "../../src/sdw/write-gate.js";
import type { SdwRecord } from "../../src/sdw/records.js";
import { readReplayAnchor, writeReplayAnchor } from "../../src/sdw/replay-anchor.js";
import {
  documentProvenanceKey,
  documentProvenanceStatusKey,
  documentChunkKey,
  SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
  SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY,
  SDW_MEMORY_PROVENANCE_COMPLETION_KEY,
} from "../../src/sdw/grammar.js";

const MASTER_KEY = new Uint8Array(32).fill(73);
const NOW = "2026-08-24T18:00:00.000Z";
const OWNER = "fleet-self";
const FORTRESS = "fortress:c3-test";

function fixture(options: {
  readonly pageSize?: number;
  readonly candidateCap?: number;
  readonly fault?: ConstructorParameters<typeof SdwMemoryProvenanceMigration>[0]["__fault"];
  readonly storage?: MemoryStorage;
} = {}) {
  const storage = options.storage ?? new MemoryStorage();
  const deps = testMemoryProvenanceDependencies(MASTER_KEY);
  const migration = new SdwMemoryProvenanceMigration({
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS,
    ownerRef: OWNER,
    ...deps,
    now: () => NOW,
    pageSize: options.pageSize,
    candidateCap: options.candidateCap,
    __fault: options.fault,
  });
  const adapter = new TestSdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS,
    ownerRef: OWNER,
    now: () => NOW,
    resolveMemoryIntegrityState: () => migration.getState(),
  });
  return { storage, migration, adapter };
}

class FailOnceDeleteStorage extends MemoryStorage {
  failKey: string | null = null;

  override async delete(namespace: string, key: string, secure?: boolean): Promise<boolean> {
    if (key === this.failKey) {
      this.failKey = null;
      throw new Error(`injected delete failure: ${key}`);
    }
    return super.delete(namespace, key, secure);
  }
}

class FailOnceWriteStorage extends MemoryStorage {
  failKey: string | null = null;

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (key === this.failKey) {
      this.failKey = null;
      throw new Error(`injected write failure: ${key}`);
    }
    return super.write(namespace, key, data);
  }
}

class TransactionalMemoryStorage implements StorageBackend {
  private readonly base = new MemoryStorage();

  write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    return this.base.write(namespace, key, data);
  }
  read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.base.read(namespace, key);
  }
  delete(namespace: string, key: string, secure?: boolean): Promise<boolean> {
    return this.base.delete(namespace, key, secure);
  }
  list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.base.list(namespace, prefix);
  }
  exists(namespace: string, key: string): Promise<boolean> {
    return this.base.exists(namespace, key);
  }
  totalSize(): Promise<number> { return this.base.totalSize(); }

  async sdwTransaction<T>(fn: (txn: {
    write(namespace: string, key: string, data: Uint8Array): Promise<void>;
    writePersistable<R extends SdwRecord>(
      persistable: Persistable<R>, encryptionKey: Uint8Array, fortressId: string,
    ): Promise<void>;
    read(namespace: string, key: string): Promise<Uint8Array | null>;
    delete(namespace: string, key: string): Promise<boolean>;
  }) => Promise<T>): Promise<T> {
    const overlay = new Map<string, { namespace: string; key: string; data: Uint8Array | null }>();
    const composite = (namespace: string, key: string) => `${namespace}\0${key}`;
    const result = await fn({
      write: async (namespace, key, data) => {
        overlay.set(composite(namespace, key), {
          namespace, key, data,
        });
      },
      writePersistable: async (persistable, encryptionKey, fortressId) => {
        const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId);
        overlay.set(composite(prepared.namespace, prepared.storageKey), {
          namespace: prepared.namespace, key: prepared.storageKey, data: prepared.data,
        });
      },
      read: async (namespace, key) => {
        const staged = overlay.get(composite(namespace, key));
        return staged === undefined ? this.base.read(namespace, key) : staged.data;
      },
      delete: async (namespace, key) => {
        overlay.set(composite(namespace, key), { namespace, key, data: null });
        return true;
      },
    });
    for (const staged of overlay.values()) {
      if (staged.data === null) await this.base.delete(staged.namespace, staged.key);
      else await this.base.write(staged.namespace, staged.key, staged.data);
    }
    return result;
  }
}

function input(passageId: string, text = `legacy-${passageId}`) {
  return {
    passage_id: passageId,
    text,
    provenanceContext: memoryInsertIngress(() => "caller:test", "user_content"),
  } as const;
}

async function makeUnsigned(
  subject: ReturnType<typeof fixture>,
  passageId: string,
): Promise<void> {
  await subject.adapter.insertPassage(input(passageId), "user_content");
  await subject.storage.delete(
    SDW_DOCUMENT_CORPUS_NAMESPACE,
    documentProvenanceKey(`mem.${OWNER}.${passageId}`),
  );
}

describe("Memory Integrity C3 provenance migration", () => {
  it("migrates a mixed store into honest legacy provenance and completes only after the final pass", async () => {
    const subject = fixture();
    await makeUnsigned(subject, "p1");
    await subject.adapter.insertPassage(input("p2"), "user_content");
    const p2RawBefore = await subject.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(`mem.${OWNER}.p2`),
    );

    const result = await subject.migration.migratePage();
    expect(result).toMatchObject({
      state: "state_COMPLETE",
      completed: true,
      migrated: 1,
      verified: 2,
      quarantined: 0,
      unsigned: 0,
    });
    const provenance = await subject.adapter.getPassageProvenance("p1");
    expect(provenance).toMatchObject({
      status: "verified",
      companion: {
        origin: { body: {
          author_agent_id: "unknown_legacy",
          ingress_channel: "legacy_migration",
          source_class: "legacy_unattested",
          recorded_at: NOW,
        } },
        admission: { body: {
          admission_channel: "legacy_migration",
          origin_trust_tier: "legacy_unattested",
          verification_basis: "legacy_local_observation",
        } },
      },
    });
    expect((provenance as { companion?: { origin?: { body?: { created_at?: unknown } } } }).companion?.origin?.body)
      .not.toHaveProperty("created_at");
    expect(await subject.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(`mem.${OWNER}.p2`),
    )).toEqual(p2RawBefore);
    const markerRaw = await subject.storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY);
    expect(Buffer.from(markerRaw!).toString("utf8")).not.toContain(SDW_MEMORY_PROVENANCE_MIGRATION_ID);
    await expect(subject.adapter.getPassage("p1")).resolves.toMatchObject({ provenance_status: "verified" });
  });

  it("preserves every pre-existing replay-anchor component while adding one completion counter", async () => {
    const subject = fixture();
    await writeReplayAnchor(subject.storage, MASTER_KEY, {
      catalog: 7,
      chain_head: [{ id: "query", seq: 4 }],
      manifests: [{ id: "manifest", seq: 3 }],
      tombstones: [{ id: "tombstone", seq: 2 }],
      export_state: 9,
    });
    await makeUnsigned(subject, "p1");
    await expect(subject.migration.migratePage()).resolves.toMatchObject({ state: "state_COMPLETE" });
    const anchor = await readReplayAnchor(subject.storage, MASTER_KEY);
    expect(anchor).toEqual({
      status: "valid",
      data: {
        catalog: 7,
        chain_head: [{ id: "query", seq: 4 }],
        manifests: [{ id: "manifest", seq: 3 }],
        tombstones: [{ id: "tombstone", seq: 2 }],
        export_state: 9,
        memory_provenance_completion: [{ id: "memory-provenance-v1", seq: 1 }],
      },
    });
  });

  it("processes one bounded page and revalidates every skipped companion before resuming", async () => {
    const subject = fixture({ pageSize: 1 });
    await makeUnsigned(subject, "p1");
    await makeUnsigned(subject, "p2");
    await expect(subject.migration.migratePage()).resolves.toMatchObject({
      state: "state_MIGRATING", scanned: 1, migrated: 1,
    });
    const key = documentProvenanceKey(`mem.${OWNER}.p1`);
    const bytes = (await subject.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key))!;
    bytes[bytes.length - 1] ^= 1;
    // Raw test corruption simulates an interrupted-store conflict; MemoryStorage
    // correctly refuses an unauthorised normal write, so use its own prior raw
    // entry through the test-only map-independent delete/restore sequence.
    await subject.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, key);
    const { restoreRawSdwBackendWrite } = await import("../../src/sdw/write-gate.js");
    await restoreRawSdwBackendWrite(subject.storage, SDW_DOCUMENT_CORPUS_NAMESPACE, key, bytes);
    await expect(subject.migration.migratePage()).resolves.toMatchObject({
      state: "state_MIGRATING", scanned: 1, quarantined: 1,
    });
    expect(await subject.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceStatusKey(`mem.${OWNER}.p1`),
    )).not.toBeNull();
    expect(await subject.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(`mem.${OWNER}.p2`),
    )).toBeNull();
    await expect(subject.migration.migratePage()).resolves.toMatchObject({
      state: "state_MIGRATING", scanned: 1, quarantined: 1,
    });
  });

  it("restores exact pre-images when a page write is interrupted, then resumes idempotently", async () => {
    for (const interruptedBoundary of ["after_provenance_write", "after_journal_write"] as const) {
      let fail = true;
      const subject = fixture({
        fault: (boundary) => {
          if (boundary === interruptedBoundary && fail) {
            fail = false;
            throw new Error(`injected interruption: ${interruptedBoundary}`);
          }
        },
      });
      await makeUnsigned(subject, "p1");
      const key = documentProvenanceKey(`mem.${OWNER}.p1`);
      expect(await subject.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key)).toBeNull();
      await expect(subject.migration.migratePage()).rejects.toThrow(`injected interruption: ${interruptedBoundary}`);
      expect(await subject.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key)).toBeNull();
      await expect(subject.migration.migratePage()).resolves.toMatchObject({ state: "state_COMPLETE" });
    }
  });

  it("resumes a run interrupted immediately after durable active-pointer publication", async () => {
    let fail = true;
    const subject = fixture({
      fault: (boundary) => {
        if (boundary === "after_active_write" && fail) {
          fail = false;
          throw new Error("start interrupted");
        }
      },
    });
    await makeUnsigned(subject, "p1");
    await expect(subject.migration.migratePage()).rejects.toThrow("start interrupted");
    await expect(subject.migration.getState()).resolves.toBe("state_MIGRATING");
    for (const key of [
      SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY,
      SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY,
    ]) {
      const raw = await subject.storage.read(SDW_META_NAMESPACE, key);
      expect(Buffer.from(raw!).toString("utf8")).not.toContain(SDW_MEMORY_PROVENANCE_MIGRATION_ID);
      expect(Buffer.from(raw!).toString("utf8")).not.toContain(NOW);
    }
    await expect(subject.migration.migratePage()).resolves.toMatchObject({ state: "state_COMPLETE" });
  });

  it("restores the prior journal when active-pointer publication fails", async () => {
    const storage = new FailOnceWriteStorage();
    const subject = fixture({ storage });
    await makeUnsigned(subject, "p1");
    storage.failKey = SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY;
    await expect(subject.migration.migratePage()).rejects.toThrow("injected write failure");
    expect(await storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY)).toBeNull();
    expect(await storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY)).toBeNull();
    await expect(subject.migration.getState()).resolves.toBe("state_PRE_MIGRATION");
    await expect(subject.migration.migratePage()).resolves.toMatchObject({ state: "state_COMPLETE" });
  });

  it("atomically discards the complete transactional overlay on an interrupted page", async () => {
    const storage = new TransactionalMemoryStorage();
    const deps = testMemoryProvenanceDependencies(MASTER_KEY);
    let fail = true;
    const migration = new SdwMemoryProvenanceMigration({
      storage, masterKey: MASTER_KEY, fortressId: FORTRESS, ownerRef: OWNER, ...deps, now: () => NOW,
      __fault: (boundary) => {
        if (boundary === "after_provenance_write" && fail) {
          fail = false;
          throw new Error("transaction interruption");
        }
      },
    });
    const adapter = new TestSdwMemoryBackendAdapter({
      storage, masterKey: MASTER_KEY, fortressId: FORTRESS, ownerRef: OWNER, now: () => NOW,
    });
    await adapter.insertPassage(input("p1"), "user_content");
    await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(`mem.${OWNER}.p1`));
    await expect(migration.migratePage()).rejects.toThrow("transaction interruption");
    expect(await storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(`mem.${OWNER}.p1`),
    )).toBeNull();
    expect(await storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY)).toBeNull();
    await expect(migration.getState()).resolves.toBe("state_PRE_MIGRATION");
    await expect(migration.migratePage()).resolves.toMatchObject({ state: "state_COMPLETE" });
  });

  it("reports partial_scope when interruption rollback cannot be verified", async () => {
    const subject = fixture({
      fault: (boundary) => {
        if (boundary === "after_provenance_write") throw new Error("commit failure");
        if (boundary === "before_rollback_restore") throw new Error("restore failure");
      },
    });
    await makeUnsigned(subject, "p1");
    await expect(subject.migration.migratePage()).rejects.toMatchObject({ category: "partial_scope" });
    await expect(subject.migration.abortMigration()).rejects.toMatchObject({ category: "partial_scope" });
    await expect(subject.migration.migratePage()).rejects.toMatchObject({ category: "partial_scope" });
  });

  it("quarantines conflicting provenance and never writes the completion marker", async () => {
    let fail = true;
    const subject = fixture({
      fault: (boundary) => {
        if (boundary === "after_status_write" && fail) {
          fail = false;
          throw new Error("injected status interruption");
        }
      },
    });
    await subject.adapter.insertPassage(input("p1"), "user_content");
    const key = documentProvenanceKey(`mem.${OWNER}.p1`);
    const bytes = (await subject.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key))!;
    bytes[0] ^= 1;
    await subject.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, key);
    const { restoreRawSdwBackendWrite } = await import("../../src/sdw/write-gate.js");
    await restoreRawSdwBackendWrite(subject.storage, SDW_DOCUMENT_CORPUS_NAMESPACE, key, bytes);
    const conflictBytes = await subject.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key);

    await expect(subject.migration.migratePage()).rejects.toThrow("injected status interruption");
    expect(await subject.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceStatusKey(`mem.${OWNER}.p1`),
    )).toBeNull();
    expect(await subject.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key)).toEqual(conflictBytes);
    await expect(subject.migration.migratePage()).resolves.toMatchObject({
      state: "state_MIGRATING", completed: false, quarantined: 1,
    });
    expect(await subject.storage.exists(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceStatusKey(`mem.${OWNER}.p1`),
    )).toBe(true);
    expect(await subject.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key)).toEqual(conflictBytes);
    expect(await subject.storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY)).toBeNull();
  });

  it("never overwrites a validly encoded companion from an unresolvable signer", async () => {
    const storage = new MemoryStorage();
    const migrationDeps = testMemoryProvenanceDependencies(MASTER_KEY);
    const otherSigner = testMemoryProvenanceDependencies(new Uint8Array(32).fill(92));
    const writer = new SdwMemoryBackendAdapter({
      storage, masterKey: MASTER_KEY, fortressId: FORTRESS, ownerRef: OWNER,
      ...otherSigner,
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
    });
    await writer.insertPassage(input("p1"), "user_content");
    const key = documentProvenanceKey(`mem.${OWNER}.p1`);
    const before = await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key);
    const migration = new SdwMemoryProvenanceMigration({
      storage, masterKey: MASTER_KEY, fortressId: FORTRESS, ownerRef: OWNER,
      ...migrationDeps, now: () => NOW,
    });
    await expect(migration.migratePage()).resolves.toMatchObject({
      state: "state_MIGRATING", completed: false, quarantined: 1,
    });
    expect(await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, key)).toEqual(before);
    expect(await storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceStatusKey(`mem.${OWNER}.p1`),
    )).not.toBeNull();
  });

  it("quarantines a legacy document whose chunk set cannot be fully verified", async () => {
    const subject = fixture();
    await makeUnsigned(subject, "p1");
    await subject.storage.delete(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentChunkKey(`mem.${OWNER}.p1`, "000000", "c000000"),
    );
    await expect(subject.migration.migratePage()).resolves.toMatchObject({
      state: "state_MIGRATING", completed: false, quarantined: 1,
    });
    await expect(subject.adapter.getPassageProvenance("p1")).resolves.toMatchObject({
      status: "quarantined",
      reason: "content_hash_mismatch",
    });
  });

  it("abandons only a recoverable active run and returns to PRE_MIGRATION", async () => {
    const subject = fixture({ pageSize: 1 });
    await makeUnsigned(subject, "p1");
    await makeUnsigned(subject, "p2");
    await subject.migration.migratePage();
    await expect(subject.migration.abortMigration()).resolves.toMatchObject({
      state: "state_PRE_MIGRATION", completed: false,
    });
    await expect(subject.adapter.getPassage("p2")).resolves.toMatchObject({ provenance_status: "unsigned" });
  });

  it("enters MARKER_ABSENT_POST_COMPLETE and fails every provenance-dependent read closed", async () => {
    const subject = fixture();
    await makeUnsigned(subject, "p1");
    await subject.migration.migratePage();
    await subject.storage.delete(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY);
    await expect(subject.migration.getState()).resolves.toBe("state_MARKER_ABSENT_POST_COMPLETE");
    await expect(subject.adapter.getPassage("p1")).rejects.toMatchObject({ category: "auth_failed" });
    await expect(subject.adapter.getPassageProvenance("p1")).rejects.toMatchObject({ category: "auth_failed" });
    await subject.storage.delete(SDW_META_NAMESPACE, SDW_REPLAY_ANCHOR_KEY);
    await expect(subject.migration.getState()).resolves.toBe("state_MARKER_ABSENT_POST_COMPLETE");
    await expect(subject.adapter.getPassage("p1")).rejects.toMatchObject({ category: "auth_failed" });
  });

  it("refuses a marker-loss transition between the initial and final provenance state reads", async () => {
    const storage = new MemoryStorage();
    let reads = 0;
    const adapter = new TestSdwMemoryBackendAdapter({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS,
      ownerRef: OWNER,
      now: () => NOW,
      resolveMemoryIntegrityState: async () =>
        ++reads === 1 ? "state_COMPLETE" : "state_MARKER_ABSENT_POST_COMPLETE",
    });
    await adapter.insertPassage(input("p1"), "user_content");
    await expect(adapter.getPassageProvenance("p1")).rejects.toMatchObject({ category: "auth_failed" });
  });

  it("repairs only the anchored prior epoch after a successful full verification pass", async () => {
    const subject = fixture();
    await makeUnsigned(subject, "p1");
    await subject.migration.migratePage();
    await subject.storage.delete(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY);
    await expect(subject.migration.repairCompletionMarker()).resolves.toMatchObject({
      state: "state_COMPLETE", completed: true,
    });
    await expect(subject.adapter.getPassage("p1")).resolves.toMatchObject({ provenance_status: "verified" });
  });

  it("fails closed when authenticated marker and replay-anchor epochs disagree", async () => {
    const subject = fixture();
    await makeUnsigned(subject, "p1");
    await subject.migration.migratePage();
    const anchor = await readReplayAnchor(subject.storage, MASTER_KEY);
    if (anchor.status !== "valid") throw new Error("expected replay anchor");
    await writeReplayAnchor(subject.storage, MASTER_KEY, {
      ...anchor.data,
      memory_provenance_completion: [{ id: "memory-provenance-v1", seq: 2 }],
    });
    await expect(subject.migration.getState()).rejects.toMatchObject({ category: "auth_failed" });
  });

  it("leaves MARKER_ABSENT_POST_COMPLETE when marker repair finds an unsigned candidate", async () => {
    const subject = fixture();
    await makeUnsigned(subject, "p1");
    await subject.migration.migratePage();
    await subject.storage.delete(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY);
    await subject.storage.delete(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(`mem.${OWNER}.p1`),
    );
    await expect(subject.migration.repairCompletionMarker()).rejects.toMatchObject({ category: "auth_failed" });
    await expect(subject.migration.getState()).resolves.toBe("state_MARKER_ABSENT_POST_COMPLETE");
  });

  it("restores the marker-absent state exactly when repair publication fails", async () => {
    let fail = false;
    const subject = fixture({
      fault: (boundary) => {
        if (boundary === "after_repair_marker_write" && fail) {
          fail = false;
          throw new Error("repair publication failed");
        }
      },
    });
    await makeUnsigned(subject, "p1");
    await subject.migration.migratePage();
    await subject.storage.delete(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY);
    fail = true;
    await expect(subject.migration.repairCompletionMarker()).rejects.toThrow("repair publication failed");
    expect(await subject.storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY)).toBeNull();
    await expect(subject.migration.getState()).resolves.toBe("state_MARKER_ABSENT_POST_COMPLETE");
  });

  it("refuses an unsigned downgrade after completion even when the marker remains present", async () => {
    const subject = fixture();
    await makeUnsigned(subject, "p1");
    await subject.migration.migratePage();
    await subject.storage.delete(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(`mem.${OWNER}.p1`),
    );
    await expect(subject.adapter.getPassage("p1")).rejects.toMatchObject({ category: "auth_failed" });
    await expect(subject.adapter.searchPassages({ text: "legacy" })).rejects.toMatchObject({ category: "auth_failed" });
    await expect(subject.adapter.listPassages()).rejects.toMatchObject({ category: "auth_failed" });
  });

  it("checks the corpus-wide cap before publishing an active run and accepts exactly the cap", async () => {
    const atCap = fixture({ candidateCap: 2 });
    await makeUnsigned(atCap, "p1");
    await makeUnsigned(atCap, "p2");
    await expect(atCap.migration.migratePage()).resolves.toMatchObject({ state: "state_COMPLETE" });

    const overCap = fixture({ candidateCap: 2 });
    await makeUnsigned(overCap, "p1");
    await makeUnsigned(overCap, "p2");
    await makeUnsigned(overCap, "p3");
    await expect(overCap.migration.migratePage()).rejects.toMatchObject({ category: "candidate_cap" });
    await expect(overCap.migration.getState()).resolves.toBe("state_PRE_MIGRATION");
    expect(await overCap.storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY)).toBeNull();
  });

  it("does not silently exclude a doc.mem candidate outside the configured owner", async () => {
    const subject = fixture();
    const foreign = new TestSdwMemoryBackendAdapter({
      storage: subject.storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS,
      ownerRef: "unexpected-owner",
      now: () => NOW,
    });
    await foreign.insertPassage({ passage_id: "p1", text: "foreign owner" }, "user_content");
    await expect(subject.migration.migratePage()).resolves.toMatchObject({
      state: "state_MIGRATING",
      completed: false,
      quarantined: 1,
    });
    expect(await subject.storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceStatusKey("mem.unexpected-owner.p1"),
    )).not.toBeNull();
  });

  it("fails closed if the primary identity changes before the page commit", async () => {
    const storage = new MemoryStorage();
    const first = testMemoryProvenanceDependencies(MASTER_KEY);
    const second = testMemoryProvenanceDependencies(new Uint8Array(32).fill(91));
    let resolutions = 0;
    const migration = new SdwMemoryProvenanceMigration({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS,
      ownerRef: OWNER,
      resolvePrimarySigningHandle: () => ++resolutions < 3 ? first.handle : second.handle,
      resolveSignerPublicKey: first.resolveSignerPublicKey,
      now: () => NOW,
    });
    const adapter = new TestSdwMemoryBackendAdapter({
      storage, masterKey: MASTER_KEY, fortressId: FORTRESS, ownerRef: OWNER, now: () => NOW,
    });
    await adapter.insertPassage(input("p1"), "user_content");
    await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(`mem.${OWNER}.p1`));
    await expect(migration.migratePage()).rejects.toMatchObject({ category: "auth_failed" });
    expect(await storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentProvenanceKey(`mem.${OWNER}.p1`),
    )).toBeNull();
  });

  it.each(["after_completion_anchor_write", "after_completion_marker_write"] as const)(
    "restores anchor, marker, journal, and active pointer after %s",
    async (boundary) => {
      let fail = true;
      const subject = fixture({
        fault: (observed) => {
          if (observed === boundary && fail) {
            fail = false;
            throw new Error(`injected ${boundary}`);
          }
        },
      });
      await makeUnsigned(subject, "p1");
      await expect(subject.migration.migratePage()).rejects.toThrow(`injected ${boundary}`);
      await expect(subject.migration.getState()).resolves.toBe("state_MIGRATING");
      expect(await subject.storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_COMPLETION_KEY)).toBeNull();
      expect(await subject.storage.read(SDW_META_NAMESPACE, SDW_REPLAY_ANCHOR_KEY)).toBeNull();
      await expect(subject.migration.migratePage()).resolves.toMatchObject({ state: "state_COMPLETE" });
    },
  );

  it("restores the active pointer and journal exactly when recoverable abort cleanup fails", async () => {
    const storage = new FailOnceDeleteStorage();
    const deps = testMemoryProvenanceDependencies(MASTER_KEY);
    const migration = new SdwMemoryProvenanceMigration({
      storage, masterKey: MASTER_KEY, fortressId: FORTRESS, ownerRef: OWNER,
      ...deps, now: () => NOW, pageSize: 1,
    });
    const adapter = new TestSdwMemoryBackendAdapter({
      storage, masterKey: MASTER_KEY, fortressId: FORTRESS, ownerRef: OWNER, now: () => NOW,
    });
    await adapter.insertPassage(input("p1"), "user_content");
    await adapter.insertPassage(input("p2"), "user_content");
    await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(`mem.${OWNER}.p1`));
    await storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, documentProvenanceKey(`mem.${OWNER}.p2`));
    await migration.migratePage();
    const activeBefore = await storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY);
    const journalBefore = await storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY);
    storage.failKey = SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY;
    await expect(migration.abortMigration()).rejects.toThrow("injected delete failure");
    expect(await storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_ACTIVE_KEY)).toEqual(activeBefore);
    expect(await storage.read(SDW_META_NAMESPACE, SDW_MEMORY_PROVENANCE_MIGRATION_JOURNAL_KEY)).toEqual(journalBefore);
    await expect(migration.getState()).resolves.toBe("state_MIGRATING");
  });

  it("refuses while an Exit import or master-rotation journal exists", async () => {
    const exitBlocked = fixture();
    await exitBlocked.storage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "active", new Uint8Array([1]));
    await expect(exitBlocked.migration.migratePage()).rejects.toThrow("Exit import journal");

    const rotationBlocked = fixture();
    await rotationBlocked.storage.write("_meta", ROTATION_JOURNAL_KEY, new Uint8Array([1]));
    await expect(rotationBlocked.migration.migratePage()).rejects.toThrow("master-rotation journal");
  });

  it("freezes the migration identifier", () => {
    expect(SDW_MEMORY_PROVENANCE_MIGRATION_ID).toBe("MI_C_SDW_MEMORY_PROVENANCE_V1");
  });
});
