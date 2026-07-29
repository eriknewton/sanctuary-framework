import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { bytesToString, stringToBytes } from "../../src/core/encoding.js";
import { LmdbStorageBackend } from "../../src/sdw/lmdb-backend.js";
import {
  SDW_CATALOG_HKDF_INFO,
  SDW_CATALOG_NAMESPACE,
  SDW_META_NAMESPACE,
  SDW_WORKING_STATE_HKDF_INFO,
  defaultSdwStoreDescriptors,
  type SdwCatalogRecord,
  type SdwWorkingStateRecord,
} from "../../src/sdw/records.js";
import {
  catalogKey,
  deriveSourceRefId,
  documentChunkKey,
  documentKey,
  isSdwIdentifier,
  queryKey,
  sdwAadDebugString,
  stateKey,
  vectorKey,
  vectorMapKey,
  vectorSegmentKey,
} from "../../src/sdw/grammar.js";
import {
  assertSdwRawWriteAuthorized,
  encryptedEnvelopeContains,
  mintPersistable,
  sdwBackendWrite,
  type Taint,
} from "../../src/sdw/write-gate.js";
import { SdwCatalogStore } from "../../src/sdw/catalog-store.js";
import {
  emptyReplayAnchorData,
  readReplayAnchor,
  writeReplayAnchor,
} from "../../src/sdw/replay-anchor.js";
import { SdwCatalogError, SdwReplayAnchorError, SdwValidationError, UnsupportedRecordVersion } from "../../src/sdw/errors.js";

const FORTRESS_ID = "fortress:test";
const MASTER_KEY = new Uint8Array(32).fill(7);

describe("SDW Phase 1 write gate", () => {
  it("rejects forbidden and missing taints before persistence", () => {
    const record = workingStateRecord("state1", "safe note");
    const forbidden: readonly (Taint | undefined)[] = [
      "policy",
      "secret",
      "identity_key",
      "unknown",
      undefined,
    ];
    for (const taint of forbidden) {
      expect(() =>
        mintPersistable(
          { value: record, taint },
          "_sdw_working_state",
          stateKey("task", record.state_id),
          FORTRESS_ID,
        ),
      ).toThrow(SdwValidationError);
    }
  });

  it("rejects policy and key-like text without echoing matched material", () => {
    const fixtures = [
      "principal_policy:\n  deny: everything",
      "-----BEGIN ED25519 PRIVATE KEY-----\nabc\n-----END ED25519 PRIVATE KEY-----",
      "SANCTUARY_RECOVERY_KEY=abcd",
    ];
    for (const fixture of fixtures) {
      const record = workingStateRecord("state1", fixture);
      try {
        mintPersistable(
          { value: record, taint: "user_content" },
          "_sdw_working_state",
          stateKey("task", record.state_id),
          FORTRESS_ID,
        );
        throw new Error("expected classifier rejection");
      } catch (error) {
        expect(error).toBeInstanceOf(SdwValidationError);
        expect((error as Error).message).not.toContain(fixture);
      }
    }
  });

  it("writes only encrypted envelope bytes through the gate", async () => {
    const storage = new MemoryStorage();
    const record = workingStateRecord("state1", "plain operator note");
    const persistable = mintPersistable(
      { value: record, taint: "user_content" },
      "_sdw_working_state",
      stateKey("task", record.state_id),
      FORTRESS_ID,
    );
    await sdwBackendWrite(
      storage,
      persistable,
      derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
      FORTRESS_ID,
    );
    const raw = await storage.read("_sdw_working_state", stateKey("task", record.state_id));
    expect(raw).not.toBeNull();
    expect(encryptedEnvelopeContains(raw!, "plain operator note")).toBe(false);
  });

  it("revalidates forged persistables at the write boundary", async () => {
    const storage = new MemoryStorage();
    const safeRecord = workingStateRecord("state1", "safe note");
    const persistable = mintPersistable(
      { value: safeRecord, taint: "user_content" },
      "_sdw_working_state",
      stateKey("task", safeRecord.state_id),
      FORTRESS_ID,
    );
    const forgedSecret = {
      ...persistable,
      record: workingStateRecord("state2", "SANCTUARY_RECOVERY_KEY=abcd"),
      storageKey: stateKey("task", "state2"),
    } as any;
    await expect(
      sdwBackendWrite(
        storage,
        forgedSecret,
        derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
        FORTRESS_ID,
      ),
    ).rejects.toMatchObject({ category: "classifier_reject" });

    const forgedTaint = { ...persistable, taint: "secret" } as any;
    await expect(
      sdwBackendWrite(
        storage,
        forgedTaint,
        derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
        FORTRESS_ID,
      ),
    ).rejects.toMatchObject({ category: "forbidden_taint" });
  });
});

describe("SDW grammar and AAD vectors", () => {
  it("produces grammar-conforming keys and length-prefixed AAD for every Phase 1 key family", () => {
    const keys = [
      catalogKey(),
      stateKey("task", "state-ABC123"),
      queryKey("00000000000000000001", "query-ABC123"),
      documentKey("doc-ABC123"),
      documentChunkKey("doc-ABC123", "000001", "chunk-ABC123"),
      vectorKey("vec-ABC123"),
      vectorMapKey("segment-ABC123", 42),
      vectorSegmentKey("segment-ABC123", 3),
    ];
    for (const key of keys) {
      expect(isSdwIdentifier(key)).toBe(true);
      expect(sdwAadDebugString(FORTRESS_ID, "_sdw_catalog", catalogKey())).toBe(
        "13:fortress:test12:_sdw_catalog19:catalog.environment",
      );
    }
  });

  it("keeps hostile source.uri out of keys and AAD", () => {
    const hostileUri = "https://example.test/a/b?x=%2f#principal_policy";
    const sourceRef = deriveSourceRefId({
      kind: "url",
      uri: hostileUri,
      title: "hostile",
    });
    const key = documentKey(sourceRef);
    const aad = sdwAadDebugString(FORTRESS_ID, "_sdw_document_corpus", key);
    expect(isSdwIdentifier(sourceRef)).toBe(true);
    expect(key).not.toContain(hostileUri);
    expect(aad).not.toContain(hostileUri);
  });
});

describe("SDW catalog and replay anchor", () => {
  it("initializes and opens a catalog only for the matching fortress", async () => {
    const storage = new MemoryStorage();
    const store = new SdwCatalogStore({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
    });
    await store.initialize("env-1", "2026-06-08T00:00:00.000Z");
    await expect(store.openExisting()).resolves.toMatchObject({
      fortress_id: FORTRESS_ID,
      environment_id: "env-1",
    });
    const wrongFortress = new SdwCatalogStore({
      storage,
      masterKey: MASTER_KEY,
      fortressId: "fortress:other",
    });
    await expect(wrongFortress.openExisting()).rejects.toBeInstanceOf(SdwCatalogError);
  });

  it("fails closed on a missing catalog in a non-empty environment", async () => {
    const storage = new MemoryStorage();
    await writeReplayAnchor(storage, MASTER_KEY, emptyReplayAnchorData());
    const store = new SdwCatalogStore({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
    });
    await expect(store.openExisting()).rejects.toMatchObject({
      category: "missing_catalog",
    });
  });

  it("detects invalid replay-anchor edits and fails closed when an established catalog loses its anchor", async () => {
    const storage = new MemoryStorage();
    await writeReplayAnchor(storage, MASTER_KEY, { ...emptyReplayAnchorData(), catalog: 2 });
    await expect(readReplayAnchor(storage, MASTER_KEY)).resolves.toMatchObject({
      status: "valid",
    });
    const raw = await storage.read(SDW_META_NAMESPACE, "sdw-replay-anchors-v1");
    storage.rawWriteForTest(
      SDW_META_NAMESPACE,
      "sdw-replay-anchors-v1",
      stringToBytes(bytesToString(raw!).replace('"catalog":2', '"catalog":0')),
    );
    await expect(readReplayAnchor(storage, MASTER_KEY)).rejects.toBeInstanceOf(
      SdwReplayAnchorError,
    );
    storage.rawWriteForTest(SDW_META_NAMESPACE, "sdw-replay-anchors-v1", stringToBytes("{}"));
    await expect(readReplayAnchor(storage, MASTER_KEY)).resolves.toEqual({
      status: "stripped",
    });

    const established = new MemoryStorage();
    const store = new SdwCatalogStore({
      storage: established,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
    });
    await store.initialize("env-1", "2026-06-08T00:00:00.000Z");
    established.rawWriteForTest(SDW_META_NAMESPACE, "sdw-replay-anchors-v1", stringToBytes("{}"));
    await expect(store.openExisting()).rejects.toMatchObject({
      category: "replay_anchor_invalid",
    });

    const emptyStore = new SdwCatalogStore({
      storage: new MemoryStorage(),
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
    });
    await expect(emptyStore.openExisting()).rejects.toMatchObject({
      category: "empty_environment",
    });
  });

  it("surfaces catalog authentication failures separately from benign list skips", async () => {
    const storage = new MemoryStorage();
    const store = new SdwCatalogStore({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
    });
    await store.initialize("env-1", "2026-06-08T00:00:00.000Z");
    tamperCatalogCiphertext(storage, catalogKey());

    await expect(store.loadCatalogList()).resolves.toMatchObject({
      records: [],
      accounting: {
        loaded: 0,
        auth_failed: 1,
        auth_failed_keys: [catalogKey()],
        unsupported_version: 0,
        skipped: [],
      },
    });
  });

  it("throws UnsupportedRecordVersion on direct read and skips it during list rehydration", async () => {
    const storage = new MemoryStorage();
    const store = new SdwCatalogStore({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
    });
    await store.initialize("env-1", "2026-06-08T00:00:00.000Z");
    await overwriteCatalogVersion(storage, 2);
    await expect(store.openExisting()).rejects.toBeInstanceOf(UnsupportedRecordVersion);
    await expect(store.loadCatalogList()).resolves.toMatchObject({
      records: [],
      accounting: {
        loaded: 0,
        unsupported_version: 1,
        skipped: [catalogKey()],
      },
    });
  });

  it("uses the listed catalog key when accounting unsupported versions", async () => {
    const storage = new MemoryStorage();
    const store = new SdwCatalogStore({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
    });
    await store.initialize("env-1", "2026-06-08T00:00:00.000Z");
    await overwriteCatalogVersion(storage, 2, "catalog.future");
    await expect(store.loadCatalogList()).resolves.toMatchObject({
      records: [
        {
          kind: "catalog",
          version: 1,
          environment_id: "env-1",
        },
      ],
      accounting: {
        loaded: 1,
        unsupported_version: 1,
        skipped: ["catalog.future"],
      },
    });
  });
});

describe("LmdbStorageBackend", () => {
  it.skipIf(!lmdbNativeOpenAvailable())(
    "stores raw bytes, lists by namespace prefix, and deletes logically",
    async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-sdw-lmdb-"));
    const backend = await LmdbStorageBackend.open({ path: dir });
    try {
      await backend.write("ordinary", "catalog.environment", new Uint8Array([1, 2, 3]));
      await backend.write("ordinary", "catalog.other", new Uint8Array([4]));
      await backend.write("other", "sdw-replay-anchors-v1", new Uint8Array([9]));
      await expect(backend.read("ordinary", "catalog.environment")).resolves.toEqual(
        new Uint8Array([1, 2, 3]),
      );
      await expect(backend.list("ordinary", "catalog.")).resolves.toHaveLength(2);
      await expect(backend.exists("other", "sdw-replay-anchors-v1")).resolves.toBe(true);
      await expect(backend.delete("ordinary", "catalog.other", true)).resolves.toBe(true);
      await expect(backend.exists("ordinary", "catalog.other")).resolves.toBe(false);
      await expect(
        backend.write("_sdw_catalog", "catalog.raw", new Uint8Array([5])),
      ).rejects.toBeInstanceOf(SdwValidationError);
      await backend.sdwTransaction(async (txn) => {
        await expect(
          txn.write("_sdw_catalog", "catalog.txn.raw", new Uint8Array([5])),
        ).rejects.toBeInstanceOf(SdwValidationError);
        const record = workingStateRecord("state-txn", "transactional note");
        const persistable = mintPersistable(
          { value: record, taint: "user_content" },
          "_sdw_working_state",
          stateKey("task", record.state_id),
          FORTRESS_ID,
        );
        await txn.writePersistable(
          persistable,
          derivePurposeKey(MASTER_KEY, SDW_WORKING_STATE_HKDF_INFO),
          FORTRESS_ID,
        );
      });
      const raw = await backend.read("_sdw_working_state", stateKey("task", "state-txn"));
      expect(raw).not.toBeNull();
      expect(encryptedEnvelopeContains(raw!, "transactional note")).toBe(false);
    } finally {
      await backend.close();
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  },
  );
});

function lmdbNativeOpenAvailable(): boolean {
  const script = `
    import('lmdb').then(async lmdb => {
      const fs = await import('node:fs/promises');
      const os = await import('node:os');
      const path = await import('node:path');
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'lmdb-smoke-'));
      const db = lmdb.open({ path: dir, encoding: 'binary', compression: false, mapSize: 1024 * 1024 });
      await db.close();
      await fs.rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  return result.status === 0;
}

function workingStateRecord(stateId: string, summary: string): SdwWorkingStateRecord {
  return {
    kind: "working_state",
    version: 1,
    state_id: stateId,
    scope: "task",
    owner_ref: "owner-1",
    status: "active",
    created_at: "2026-06-08T00:00:00.000Z",
    updated_at: "2026-06-08T00:00:00.000Z",
    content_type: "application/json",
    state: {
      kind: "task_checkpoint",
      task_ref: "task-1",
      summary,
    },
  };
}

async function overwriteCatalogVersion(
  storage: StorageBackend,
  version: number,
  storageKey = catalogKey(),
): Promise<void> {
  const key = derivePurposeKey(MASTER_KEY, SDW_CATALOG_HKDF_INFO);
  const record = {
    kind: "catalog",
    version,
    fortress_id: FORTRESS_ID,
    environment_id: "env-1",
    created_at: "2026-06-08T00:00:00.000Z",
    replay_anchor_seq: 1,
    stores: defaultSdwStoreDescriptors(),
  } satisfies Omit<SdwCatalogRecord, "version"> & { readonly version: number };
  const envelope = encrypt(
    stringToBytes(JSON.stringify(record)),
    key,
    stringToBytes(sdwAadDebugString(FORTRESS_ID, SDW_CATALOG_NAMESPACE, storageKey)),
  );
  if (storage instanceof MemoryStorage) {
    storage.rawWriteForTest(SDW_CATALOG_NAMESPACE, storageKey, stringToBytes(JSON.stringify(envelope)));
    return;
  }
  await storage.write(SDW_CATALOG_NAMESPACE, storageKey, stringToBytes(JSON.stringify(envelope)));
}

function tamperCatalogCiphertext(storage: MemoryStorage, storageKey: string): void {
  const composite = storage.readSync(SDW_CATALOG_NAMESPACE, storageKey);
  const envelope = JSON.parse(bytesToString(composite!)) as { ct: string };
  const replacement = envelope.ct.endsWith("A") ? "B" : "A";
  envelope.ct = `${envelope.ct.slice(0, -1)}${replacement}`;
  storage.rawWriteForTest(SDW_CATALOG_NAMESPACE, storageKey, stringToBytes(JSON.stringify(envelope)));
}

class MemoryStorage implements StorageBackend {
  private readonly data = new Map<string, Uint8Array>();

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.rawWriteForTest(namespace, key, assertSdwRawWriteAuthorized(namespace, key, data));
  }

  rawWriteForTest(namespace: string, key: string, data: Uint8Array): void {
    this.data.set(this.composite(namespace, key), new Uint8Array(data));
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.data.get(this.composite(namespace, key)) ?? null;
  }

  readSync(namespace: string, key: string): Uint8Array | null {
    return this.data.get(this.composite(namespace, key)) ?? null;
  }

  async delete(namespace: string, key: string): Promise<boolean> {
    return this.data.delete(this.composite(namespace, key));
  }

  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    for (const [composite, value] of this.data) {
      const [entryNamespace, entryKey] = composite.split("\0", 2) as [string, string];
      if (entryNamespace !== namespace || !entryKey.startsWith(prefix)) continue;
      entries.push({
        namespace,
        key: entryKey,
        size_bytes: value.byteLength,
        modified_at: "2026-06-08T00:00:00.000Z",
      });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.data.has(this.composite(namespace, key));
  }

  async totalSize(): Promise<number> {
    let total = 0;
    for (const value of this.data.values()) total += value.byteLength;
    return total;
  }

  private composite(namespace: string, key: string): string {
    return `${namespace}\0${key}`;
  }
}
