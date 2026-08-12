import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import {
  chunkText,
  passageContentHash,
  SdwMemoryBackendAdapter,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import type { MemoryBackendAdapter } from "../../src/sdw/adapters/memory-backend.js";
import { documentChunkKey, documentKey } from "../../src/sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import {
  assertSdwRawWriteAuthorized,
  encryptedEnvelopeContains,
} from "../../src/sdw/write-gate.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { CrossProcessLockError } from "../../src/storage/cross-process-lock.js";

const FORTRESS_ID = "fortress:test";
const MASTER_KEY = new Uint8Array(32).fill(7);
const NOW = "2026-06-11T00:00:00.000Z";
const EXPECTED_BATCH_LOCK_TIMEOUT_MS = 30_000;

class MemoryStorage implements StorageBackend {
  readonly data = new Map<string, Uint8Array>();
  readonly secureDeletes: string[] = [];

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    const checked = assertSdwRawWriteAuthorized(namespace, key, data);
    this.data.set(`${namespace}\0${key}`, new Uint8Array(checked));
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.data.get(`${namespace}\0${key}`) ?? null;
  }

  async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    if (secureOverwrite === true) this.secureDeletes.push(`${namespace}\0${key}`);
    return this.data.delete(`${namespace}\0${key}`);
  }

  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    for (const [composite, data] of this.data) {
      const separator = composite.indexOf("\0");
      const entryNamespace = composite.slice(0, separator);
      const key = composite.slice(separator + 1);
      if (entryNamespace !== namespace || !key.startsWith(prefix)) continue;
      entries.push({ namespace, key, size_bytes: data.byteLength, modified_at: NOW });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.data.has(`${namespace}\0${key}`);
  }

  async totalSize(): Promise<number> {
    let total = 0;
    for (const value of this.data.values()) total += value.byteLength;
    return total;
  }
}

class RollbackFailureStorage extends MemoryStorage {
  readonly deleteCalls: string[] = [];

  constructor(
    private readonly writeFailureKey: string,
    private readonly deleteFailureKey: string,
  ) {
    super();
  }

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (key === this.writeFailureKey) {
      throw new Error("simulated document write failure");
    }
    await super.write(namespace, key, data);
  }

  override async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    this.deleteCalls.push(key);
    if (key === this.deleteFailureKey) {
      throw new Error("simulated rollback delete failure");
    }
    return super.delete(namespace, key, secureOverwrite);
  }
}

class ConfigurableWriteFailureStorage extends MemoryStorage {
  writeFailureKey: string | null = null;
  writeFailureMessage = "simulated document write failure";

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (key === this.writeFailureKey) {
      this.writeFailureKey = null;
      throw new Error(this.writeFailureMessage);
    }
    await super.write(namespace, key, data);
  }
}

class NoopDeleteAfterWriteFailureStorage extends ConfigurableWriteFailureStorage {
  readonly deleteCalls: string[] = [];

  constructor(private readonly noopDeleteKey: string) {
    super();
  }

  override async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    this.deleteCalls.push(key);
    if (key === this.noopDeleteKey) {
      if (secureOverwrite === true) this.secureDeletes.push(`${namespace}\0${key}`);
      return true;
    }
    return super.delete(namespace, key, secureOverwrite);
  }
}

class FailVerificationListStorage extends ConfigurableWriteFailureStorage {
  private listCalls = 0;

  constructor(private readonly failAfterListCalls: number) {
    super();
  }

  override async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    this.listCalls += 1;
    if (this.listCalls > this.failAfterListCalls) {
      throw new Error("injected list failure");
    }
    return super.list(namespace, prefix);
  }
}

class LockTrackingStorage extends MemoryStorage {
  readonly lockNamespaces: string[] = [];

  constructor(private readonly lockRoot: string) {
    super();
  }

  namespacePath(namespace: string): string {
    this.lockNamespaces.push(namespace);
    return join(this.lockRoot, namespace);
  }

  async writeDurable(namespace: string, key: string, data: Uint8Array): Promise<void> {
    await this.write(namespace, key, data);
  }
}

function makeAdapter(
  storage: MemoryStorage,
  overrides: {
    ownerRef?: string;
    maxChunkChars?: number;
    corpusScanCap?: number;
    listMaxLimit?: number;
  } = {},
): MemoryBackendAdapter {
  return new SdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: overrides.ownerRef ?? "letta-archive-1",
    maxChunkChars: overrides.maxChunkChars,
    corpusScanCap: overrides.corpusScanCap,
    listMaxLimit: overrides.listMaxLimit,
    now: () => NOW,
  });
}

async function ownerScopeCorpusKeys(
  storage: MemoryStorage,
  ownerRef = "letta-archive-1",
): Promise<readonly string[]> {
  const entries = [
    ...(await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${ownerRef}.`)),
    ...(await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `chunk.mem.${ownerRef}.`)),
  ];
  return [...new Set(entries.map((entry) => entry.key))].sort();
}

/**
 * Counts every storage.read() call so a test can prove decrypt work stayed
 * bounded (LD4 SDW-SEARCH-DOS-01) instead of scaling with corpus size.
 */
class ReadCountingStorage extends MemoryStorage {
  readCount = 0;
  override async read(namespace: string, key: string): Promise<Uint8Array | null> {
    this.readCount++;
    return super.read(namespace, key);
  }
}

describe("SDW memory-backend adapter: insert + get", () => {
  it("roundtrips a passage with tags and metadata, encrypted at rest", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage);
    const inserted = await adapter.insertPassage(
      {
        passage_id: "p-1",
        text: "The operator prefers concise weekly summaries.",
        tags: ["preference"],
        metadata: [{ key: "session", value: "s-42" }],
      },
      "user_content",
    );
    expect(inserted.passage_id).toBe("p-1");
    expect(inserted.owner_ref).toBe("letta-archive-1");
    expect(inserted.chunk_count).toBe(1);
    expect(inserted.content_hash).toBe(passageContentHash(inserted.text));

    const fetched = await adapter.getPassage("p-1");
    expect(fetched).not.toBeNull();
    expect(fetched!.text).toBe("The operator prefers concise weekly summaries.");
    expect(fetched!.tags).toEqual(["preference"]);
    expect(fetched!.metadata).toEqual([{ key: "session", value: "s-42" }]);
    expect(fetched!.created_at).toBe(NOW);

    // Custody invariant: ciphertext only in the document-corpus namespace.
    const docRaw = await storage.read(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentKey("mem.letta-archive-1.p-1"),
    );
    expect(docRaw).not.toBeNull();
    for (const raw of storage.data.values()) {
      expect(encryptedEnvelopeContains(raw, "concise weekly summaries")).toBe(false);
    }
  });

  it("generates a valid passage id when none is supplied", async () => {
    const adapter = makeAdapter(new MemoryStorage());
    const inserted = await adapter.insertPassage({ text: "auto id" }, "agent_derived_clean");
    expect(inserted.passage_id).toMatch(/^[A-Za-z0-9_-]{20}$/);
    await expect(adapter.getPassage(inserted.passage_id)).resolves.toMatchObject({
      text: "auto id",
    });
  });

  it("chunks long passages and reassembles them exactly", async () => {
    const adapter = makeAdapter(new MemoryStorage(), { maxChunkChars: 5 });
    const text = "abcdefghijklmnopqrstuvwxyz0123456789";
    const inserted = await adapter.insertPassage({ passage_id: "long-1", text }, "user_content");
    expect(inserted.chunk_count).toBe(Math.ceil(text.length / 5));
    const fetched = await adapter.getPassage("long-1");
    expect(fetched!.text).toBe(text);
  });

  it("roundtrips an astral character split across the default chunk boundary", async () => {
    const adapter = makeAdapter(new MemoryStorage());
    const text = `${"a".repeat(8191)}😀tail`;
    const inserted = await adapter.insertPassage(
      { passage_id: "emoji-boundary", text },
      "user_content",
    );
    expect(inserted.chunk_count).toBe(2);
    await expect(adapter.getPassage("emoji-boundary")).resolves.toMatchObject({ text });
  });

  it("stores empty text as a single empty chunk", async () => {
    const adapter = makeAdapter(new MemoryStorage());
    const inserted = await adapter.insertPassage({ passage_id: "empty-1", text: "" }, "user_content");
    expect(inserted.chunk_count).toBe(1);
    await expect(adapter.getPassage("empty-1")).resolves.toMatchObject({ text: "" });
  });

  it("rejects duplicate passage ids and invalid identifiers", async () => {
    const adapter = makeAdapter(new MemoryStorage());
    await adapter.insertPassage({ passage_id: "dup-1", text: "first" }, "user_content");
    await expect(
      adapter.insertPassage({ passage_id: "dup-1", text: "second" }, "user_content"),
    ).rejects.toMatchObject({ category: "duplicate_passage" });
    await expect(
      adapter.insertPassage({ passage_id: "bad id with spaces", text: "x" }, "user_content"),
    ).rejects.toBeInstanceOf(SdwValidationError);
    await expect(adapter.getPassage("bad id with spaces")).rejects.toBeInstanceOf(
      SdwValidationError,
    );
  });
});

describe("SDW memory-backend adapter: write-gate enforcement", () => {
  it("rejects forbidden taints before anything is written", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage);
    await expect(
      adapter.insertPassage(
        { passage_id: "t-1", text: "policy-shaped content" },
        "policy" as never,
      ),
    ).rejects.toMatchObject({ category: "forbidden_taint" });
    expect(storage.data.size).toBe(0);
  });

  it("fails closed when the classifier flags secret-shaped text", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage);
    await expect(
      adapter.insertPassage(
        {
          passage_id: "s-1",
          text: "remember this: -----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2Vw",
        },
        "user_content",
      ),
    ).rejects.toMatchObject({ category: "classifier_reject" });
    expect(storage.data.size).toBe(0);
  });

  it("does not combine a prose keyword with a generated record identifier", () => {
    const adapter = makeAdapter(new MemoryStorage());
    const screen = adapter.screenPassage(
      {
        passage_id: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE",
        text: "Never paste a secret into an operator memory file.",
      },
      "user_content",
    );
    expect(screen).toEqual({ ok: true });
  });

  it("keeps metadata key/value pairs in one entropy-classifier context", () => {
    const adapter = makeAdapter(new MemoryStorage());
    const screen = adapter.screenPassage(
      {
        passage_id: "metadata-secret",
        text: "ordinary note",
        metadata: [{
          key: "credential",
          value: "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE",
        }],
      },
      "user_content",
    );
    expect(screen).toMatchObject({ ok: false, category: "classifier_reject" });
  });

  it("rejects unpaired surrogates before writing", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage);
    await expect(
      adapter.insertPassage({ passage_id: "bad-surrogate", text: "bad \uD800 text" }, "user_content"),
    ).rejects.toMatchObject({ category: "invalid_text" });
    expect(storage.data.size).toBe(0);
  });

  it("signals partial_scope when insert rollback leaves a written key behind", async () => {
    const documentId = "mem.letta-archive-1.rollback-1";
    const docKey = documentKey(documentId);
    const chunk0 = documentChunkKey(documentId, "000000", "c000000");
    const chunk1 = documentChunkKey(documentId, "000001", "c000001");
    const chunk2 = documentChunkKey(documentId, "000002", "c000002");
    const storage = new RollbackFailureStorage(docKey, chunk1);
    const adapter = makeAdapter(storage, { maxChunkChars: 2 });

    await expect(
      adapter.insertPassage({ passage_id: "rollback-1", text: "abcdef" }, "user_content"),
    ).rejects.toMatchObject({ category: "partial_scope" });

    expect(storage.deleteCalls).toEqual([chunk2, chunk1, chunk0, docKey]);
    expect(storage.data.has(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${chunk0}`)).toBe(false);
    expect(storage.data.has(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${chunk1}`)).toBe(true);
    expect(storage.data.has(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${chunk2}`)).toBe(false);
  });

  it("signals partial_scope when batch rollback cannot verify raw owner-scope keys", async () => {
    const documentId = "mem.letta-archive-1.batch-2";
    const docKey = documentKey(documentId);
    const chunk0 = documentChunkKey(documentId, "000000", "c000000");
    const storage = new RollbackFailureStorage(docKey, chunk0);
    const adapter = makeAdapter(storage, { maxChunkChars: 2 });

    await expect(
      adapter.putPassages(
        [
          { passage_id: "batch-1", text: "ok" },
          { passage_id: "batch-2", text: "abcd" },
        ],
        "user_content",
      ),
    ).rejects.toMatchObject({ category: "partial_scope" });

    expect(storage.data.has(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${chunk0}`)).toBe(true);
  });

  it("signals partial_scope when rollback deletes report success but verification finds a leftover key", async () => {
    const documentId = "mem.letta-archive-1.batch-verify";
    const docKey = documentKey(documentId);
    const chunk0 = documentChunkKey(documentId, "000000", "c000000");
    const storage = new NoopDeleteAfterWriteFailureStorage(chunk0);
    storage.writeFailureKey = docKey;
    const adapter = makeAdapter(storage, { maxChunkChars: 2 });

    let caught: unknown;
    try {
      await adapter.putPassages(
        [
          { passage_id: "batch-ok", text: "ok" },
          { passage_id: "batch-verify", text: "abcd" },
        ],
        "user_content",
      );
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(SdwValidationError);
    expect(caught).toMatchObject({ category: "partial_scope" });
    expect((caught as Error).cause).toBeInstanceOf(Error);
    expect(((caught as Error).cause as Error).message).toContain(
      "owner-scope key listing mismatch",
    );
    expect(storage.deleteCalls).toContain(chunk0);
    expect(storage.data.has(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${chunk0}`)).toBe(true);
  });

  it("restores raw keys and decrypted text when failed re-ingest grows or shrinks chunk count", async () => {
    for (const row of [
      { passageId: "reingest-grow", before: "aa", after: "aabbcc" },
      { passageId: "reingest-shrink", before: "aabbcc", after: "zz" },
    ]) {
      const documentId = `mem.letta-archive-1.${row.passageId}`;
      const storage = new ConfigurableWriteFailureStorage();
      const adapter = makeAdapter(storage, { maxChunkChars: 2 });
      await adapter.putPassages(
        [{ passage_id: row.passageId, text: row.before }],
        "user_content",
      );
      const beforeKeys = await ownerScopeCorpusKeys(storage);

      storage.writeFailureKey = documentKey(documentId);
      await expect(
        adapter.putPassages(
          [{ passage_id: row.passageId, text: row.after }],
          "user_content",
        ),
      ).rejects.toThrow("simulated document write failure");

      expect(await ownerScopeCorpusKeys(storage)).toEqual(beforeKeys);
      await expect(adapter.getPassage(row.passageId)).resolves.toMatchObject({
        text: row.before,
      });
    }
  });

  it("maps verification read failures to partial_scope with the original cause", async () => {
    const documentId = "mem.letta-archive-1.batch-list-fail";
    const docKey = documentKey(documentId);
    const storage = new FailVerificationListStorage(2);
    storage.writeFailureKey = docKey;
    const adapter = makeAdapter(storage, { maxChunkChars: 2 });

    let caught: unknown;
    try {
      await adapter.putPassages(
        [
          { passage_id: "batch-ok", text: "ok" },
          { passage_id: "batch-list-fail", text: "abcd" },
        ],
        "user_content",
      );
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(SdwValidationError);
    expect(caught).toMatchObject({ category: "partial_scope" });
    expect((caught as Error).cause).toBeInstanceOf(Error);
    expect(((caught as Error).cause as Error).message).toBe("injected list failure");
  });

  it("takes the filesystem-style owner-scope lock around non-transactional batch replacement", async () => {
    const lockRoot = await mkdtemp(join(tmpdir(), "sdw-memory-lock-"));
    try {
      const storage = new LockTrackingStorage(lockRoot);
      const adapter = makeAdapter(storage);

      await adapter.putPassages([{ passage_id: "locked-batch", text: "ok" }], "user_content");

      expect(storage.lockNamespaces).toEqual(["sdw_memory_locks"]);
      await expect(adapter.getPassage("locked-batch")).resolves.toMatchObject({ text: "ok" });
    } finally {
      await rm(lockRoot, { recursive: true, force: true });
    }
  });

  it("uses the measured 30 s timeout for filesystem-style owner-scope batch locks", async () => {
    const lockRoot = await mkdtemp(join(tmpdir(), "sdw-memory-lock-timeout-"));
    try {
      const storage = new LockTrackingStorage(lockRoot);
      const adapter = makeAdapter(storage);
      const lockDir = join(lockRoot, "sdw_memory_locks");
      await mkdir(lockDir, { recursive: true, mode: 0o700 });
      await writeFile(
        join(lockDir, "mem.letta-archive-1.batch-replace.lock"),
        JSON.stringify({ pid: process.pid, acquired_at: NOW }),
      );

      const nowSpy = vi.spyOn(Date, "now");
      nowSpy.mockReturnValue(EXPECTED_BATCH_LOCK_TIMEOUT_MS);
      nowSpy.mockReturnValueOnce(0);
      try {
        let caught: unknown;
        try {
          await adapter.putPassages(
            [{ passage_id: "lock-timeout", text: "blocked" }],
            "user_content",
          );
        } catch (error) {
          caught = error;
        }
        expect(caught).toBeInstanceOf(CrossProcessLockError);
        expect(caught).toMatchObject({
          name: "CrossProcessLockError",
          message: expect.stringContaining("held >30000ms"),
        });
      } finally {
        nowSpy.mockRestore();
      }
    } finally {
      await rm(lockRoot, { recursive: true, force: true });
    }
  });
});

describe("SDW memory-backend adapter: search", () => {
  it("matches case-insensitively, ranks by occurrences, honors limit and tag filter", async () => {
    const adapter = makeAdapter(new MemoryStorage());
    await adapter.insertPassage(
      { passage_id: "a", text: "Sanctuary keeps memory sovereign. Memory stays local.", tags: ["infra"] },
      "user_content",
    );
    await adapter.insertPassage(
      { passage_id: "b", text: "memory appears once here", tags: ["infra"] },
      "user_content",
    );
    await adapter.insertPassage(
      { passage_id: "c", text: "nothing relevant", tags: ["other"] },
      "user_content",
    );

    const results = await adapter.searchPassages({ text: "MEMORY" });
    expect(results.map((result) => result.passage.passage_id)).toEqual(["a", "b"]);
    expect(results[0]!.match_count).toBe(2);

    const limited = await adapter.searchPassages({ text: "memory", limit: 1 });
    expect(limited).toHaveLength(1);
    expect(limited[0]!.passage.passage_id).toBe("a");

    const tagged = await adapter.searchPassages({ text: "relevant", tag: "infra" });
    expect(tagged).toHaveLength(0);

    const empty = await adapter.searchPassages({ text: "" });
    expect(empty).toHaveLength(0);
  });

  it("finds matches that span chunk boundaries", async () => {
    const adapter = makeAdapter(new MemoryStorage(), { maxChunkChars: 4 });
    await adapter.insertPassage({ passage_id: "span-1", text: "abcNEEDLExyz" }, "user_content");
    const results = await adapter.searchPassages({ text: "needle" });
    expect(results).toHaveLength(1);
    expect(results[0]!.passage.passage_id).toBe("span-1");
  });
});

describe("SDW memory-backend adapter: per-call scan/decrypt bound (LD4 SDW-SEARCH-DOS-01)", () => {
  it("fails closed with a typed bound instead of ranking a silently partial corpus scan", async () => {
    const storage = new MemoryStorage();
    // corpusScanCap=2 with 3 passages in the owner scope: a full-fidelity
    // ranked search cannot honestly answer from a 2-of-3 scan, so it must
    // refuse rather than return results from an arbitrary slice of the
    // vault as if they were the true top matches.
    const adapter = makeAdapter(storage, { corpusScanCap: 2, listMaxLimit: 2 });
    for (const id of ["p1", "p2", "p3"]) {
      await adapter.insertPassage({ passage_id: id, text: `needle appears in ${id}` }, "user_content");
    }

    await expect(adapter.searchPassages({ text: "needle" })).rejects.toMatchObject({
      category: "search_scan_bound",
    });
  });

  it("never decrypts a passage body when the corpus exceeds the scan cap, only bounded metadata", async () => {
    const storage = new ReadCountingStorage();
    // corpusScanCap=2 with 5 multi-chunk passages: a pre-fix implementation
    // would decrypt every document's metadata AND its full chunked body
    // (readPassageText) unconditionally, so read count would scale with the
    // whole 5-passage corpus. The fix must refuse before any body decrypt,
    // so read count stays pinned to (roughly) the metadata scan window,
    // never reaching the chunk reads at all.
    const adapter = makeAdapter(storage, { corpusScanCap: 2, listMaxLimit: 2, maxChunkChars: 4 });
    for (const id of ["r1", "r2", "r3", "r4", "r5"]) {
      await adapter.insertPassage(
        { passage_id: id, text: `sovereign-memory-passage-${id}-with-several-chunks` },
        "user_content",
      );
    }

    storage.readCount = 0;
    await expect(adapter.searchPassages({ text: "sovereign" })).rejects.toMatchObject({
      category: "search_scan_bound",
    });
    // Each multi-chunk passage's body alone costs several chunk reads on top
    // of its one document-metadata read; 5 passages worth of full bodies is
    // comfortably double digits. A bounded implementation only reads
    // document metadata for the capped scan window (corpusScanCap=2) before
    // refusing, so the count stays in the single digits regardless of how
    // large the real corpus is.
    expect(storage.readCount).toBeLessThan(10);
  });

  it("clamps a caller-supplied limit to the configured ceiling instead of decrypting an unbounded result set", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage, { corpusScanCap: 5, listMaxLimit: 2 });
    for (const id of ["c1", "c2", "c3"]) {
      await adapter.insertPassage({ passage_id: id, text: `text ${id}` }, "user_content");
    }

    // Number.MAX_SAFE_INTEGER mirrors the pre-fix listPassages default
    // (options.limit ?? Number.MAX_SAFE_INTEGER); it must clamp to
    // listMaxLimit=2, not decrypt and return all 3.
    const listed = await adapter.listPassages({ limit: Number.MAX_SAFE_INTEGER });
    expect(listed).toHaveLength(2);

    const searched = await adapter.searchPassages({ text: "text", limit: Number.MAX_SAFE_INTEGER });
    expect(searched.length).toBeLessThanOrEqual(2);
  });

  it("pages a corpus larger than the scan cap correctly via the after cursor, never claiming a short page is complete when it might not be", async () => {
    const storage = new MemoryStorage();
    // corpusScanCap === listMaxLimit === 2: every page is exactly at the cap,
    // so this proves cursor pagination still reaches every passage even
    // though no single call ever scans more than 2 documents.
    const adapter = makeAdapter(storage, { corpusScanCap: 2, listMaxLimit: 2 });
    for (const id of ["p1", "p2", "p3", "p4", "p5"]) {
      await adapter.insertPassage({ passage_id: id, text: `text ${id}` }, "user_content");
    }

    const collected: string[] = [];
    let after: string | undefined;
    for (let page = 0; page < 10; page++) {
      const batch = await adapter.listPassages({ after });
      if (batch.length === 0) break;
      collected.push(...batch.map((p) => p.passage_id));
      after = batch[batch.length - 1]!.passage_id;
    }

    expect(collected).toEqual(["p1", "p2", "p3", "p4", "p5"]);
  });

  it("pages a mixed-charset corpus without dropping or duplicating any passage across pages (LD4 fix-round-2 cursor-order mismatch)", async () => {
    // Regression for a fix-round-2 gate finding: the `after` cursor was
    // compared with code-unit `>` while storage.list() (both shipping
    // backends) sorts with `localeCompare`. Those orderings diverge across
    // the passage_id charset (SDW_IDENTIFIER_PATTERN allows
    // [A-Za-z0-9._:@+-]), e.g. under localeCompare "_" sorts before "A" and
    // "Z", but under code-unit "_" (0x5f) sorts after every uppercase
    // letter (0x41-0x5a). A code-unit cursor walking a localeCompare-sorted
    // list re-admits already-seen keys and skips over ones it jumped past,
    // which is exactly the drop/duplicate pattern asserted below.
    const storage = new MemoryStorage();
    const ids = [
      "A", "Z", "Ab", "M9", "a", "z", "_", "_x", "9", "-", "-x", "1", "0", "ZZ",
    ];
    // corpusScanCap === listMaxLimit === 3: forces at least 5 pages over 14
    // passages, so the cursor is exercised across every divergent boundary
    // in the charset, not just a single split point.
    const adapter = makeAdapter(storage, { corpusScanCap: 3, listMaxLimit: 3 });
    for (const id of ids) {
      await adapter.insertPassage({ passage_id: id, text: `text ${id}` }, "user_content");
    }

    const collected: string[] = [];
    let after: string | undefined;
    for (let page = 0; page < 20; page++) {
      const batch = await adapter.listPassages({ after });
      if (batch.length === 0) break;
      collected.push(...batch.map((p) => p.passage_id));
      after = batch[batch.length - 1]!.passage_id;
    }

    // Every passage appears EXACTLY once; storage.list()'s localeCompare
    // order is the ground truth for "the" correct order, so compare against
    // that rather than insertion order.
    const expectedOrder = [...ids].sort((x, y) => x.localeCompare(y));
    expect(collected).toEqual(expectedOrder);
    expect(new Set(collected).size).toBe(ids.length);
  });

  it("rejects corpusScanCap/listMaxLimit overrides that would raise the module ceiling", () => {
    expect(() =>
      makeAdapter(new MemoryStorage(), { corpusScanCap: 2001 }),
    ).toThrow(SdwValidationError);
    expect(() =>
      makeAdapter(new MemoryStorage(), { listMaxLimit: 501 }),
    ).toThrow(SdwValidationError);
    expect(() =>
      makeAdapter(new MemoryStorage(), { corpusScanCap: 1, listMaxLimit: 2 }),
    ).toThrow(SdwValidationError);
  });
});

describe("SDW memory-backend adapter: list, count, isolation", () => {
  it("lists in stable order with cursor pagination and counts per owner", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage);
    for (const id of ["p1", "p2", "p3"]) {
      await adapter.insertPassage({ passage_id: id, text: `text ${id}` }, "user_content");
    }
    const all = await adapter.listPassages();
    expect(all.map((passage) => passage.passage_id)).toEqual(["p1", "p2", "p3"]);

    const page = await adapter.listPassages({ limit: 1, after: "p1" });
    expect(page.map((passage) => passage.passage_id)).toEqual(["p2"]);

    await expect(adapter.countPassages()).resolves.toBe(3);
  });

  it("isolates owners sharing one fortress and storage backend", async () => {
    const storage = new MemoryStorage();
    const first = makeAdapter(storage, { ownerRef: "engine-a" });
    const second = makeAdapter(storage, { ownerRef: "engine-b" });
    await first.insertPassage({ passage_id: "only-a", text: "alpha memory" }, "user_content");
    await second.insertPassage({ passage_id: "only-b", text: "beta memory" }, "user_content");

    await expect(first.countPassages()).resolves.toBe(1);
    await expect(first.getPassage("only-b")).resolves.toBeNull();
    const found = await second.searchPassages({ text: "memory" });
    expect(found.map((result) => result.passage.passage_id)).toEqual(["only-b"]);
  });

  it("rejects an owner_ref that could collide across the document id grammar", () => {
    expect(() => makeAdapter(new MemoryStorage(), { ownerRef: "a.b" })).toThrow(
      SdwValidationError,
    );
    expect(() => makeAdapter(new MemoryStorage(), { maxChunkChars: 0 })).toThrow(
      SdwValidationError,
    );
  });
});

describe("SDW memory-backend adapter: delete + integrity", () => {
  it("securely deletes the document and every chunk", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage, { maxChunkChars: 4 });
    await adapter.insertPassage({ passage_id: "d-1", text: "0123456789" }, "user_content");
    expect(storage.data.size).toBe(4);

    await expect(adapter.deletePassage("d-1")).resolves.toBe(true);
    expect(storage.data.size).toBe(0);
    expect(storage.secureDeletes).toHaveLength(4);
    await expect(adapter.getPassage("d-1")).resolves.toBeNull();
    await expect(adapter.deletePassage("d-1")).resolves.toBe(false);
  });

  it("fails closed when a chunk is missing or text is tampered", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage, { maxChunkChars: 4 });
    await adapter.insertPassage({ passage_id: "i-1", text: "0123456789" }, "user_content");
    const missingChunkKey = documentChunkKey("mem.letta-archive-1.i-1", "000001", "c000001");
    expect(storage.data.has(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${missingChunkKey}`)).toBe(true);
    storage.data.delete(`${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${missingChunkKey}`);
    await expect(adapter.getPassage("i-1")).rejects.toMatchObject({
      category: "passage_incomplete",
    });
  });

  it("propagates decode failures instead of skipping records silently", async () => {
    const storage = new MemoryStorage();
    const adapter = makeAdapter(storage);
    await adapter.insertPassage({ passage_id: "x-1", text: "intact" }, "user_content");
    const docComposite = `${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${documentKey("mem.letta-archive-1.x-1")}`;
    const raw = storage.data.get(docComposite)!;
    const envelope = JSON.parse(new TextDecoder().decode(raw)) as { ct: string };
    const flipped = (envelope.ct[0] === "A" ? "B" : "A") + envelope.ct.slice(1);
    storage.data.set(
      docComposite,
      new TextEncoder().encode(JSON.stringify({ ...envelope, ct: flipped })),
    );
    await expect(adapter.getPassage("x-1")).rejects.toBeInstanceOf(SdwValidationError);
    await expect(adapter.listPassages()).rejects.toBeInstanceOf(SdwValidationError);
  });
});

describe("SDW memory-backend adapter: chunking helpers", () => {
  it("chunkText covers empty, exact, and overflow cases", () => {
    expect(chunkText("", 4)).toEqual([""]);
    expect(chunkText("abcd", 4)).toEqual(["abcd"]);
    expect(chunkText("abcde", 4)).toEqual(["abcd", "e"]);
  });

  it("passageContentHash is deterministic and domain-separated", () => {
    expect(passageContentHash("a")).toBe(passageContentHash("a"));
    expect(passageContentHash("a")).not.toBe(passageContentHash("b"));
    expect(passageContentHash("a")).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});
