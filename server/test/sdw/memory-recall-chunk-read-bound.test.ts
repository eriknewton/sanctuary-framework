// Recall refuses a stored chunk record longer than the read-side maximum derived from the configured chunk size,
// before its bytes are read into memory or decoded, on the in-memory store and on the shipped file store. The
// oversized records here are really stored, written by an adapter configured with a larger chunk size.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { HermesRecallBudget, RECALL_MAX_PASSAGE_SCAN_UNITS } from "../../src/hermes-memory-bridge/recall.js";
import { DEFAULT_MAX_CHUNK_CHARS, recallChunkRecordMaxBytes } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { StorageReadBoundError, type StorageBackend } from "../../src/storage/interface.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";

const MASTER = new Uint8Array(32).fill(53);
const FORTRESS = "chunk-read-bound";
const CREATED = "2026-11-01T00:00:00.000Z";
const WRITER_CHUNK_CHARS = 100_000; // The largest chunk size an adapter accepts, so one chunk holds the whole text.
// Sixty thousand one-byte units: past the default record maximum (about 50 000 such units), inside one passage's
// scan cap, so the passage would be scanned and scored whole if its record were read.
const OVERSIZED_UNITS = 60_000;
const OVERSIZED_TEXT = `board meeting ${"a".repeat(OVERSIZED_UNITS)}`;
const dirs: string[] = [];
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

/** Records the key of every call to the store's unbounded read, so a test can see which records recall read whole. */
function countUnboundedReads(storage: StorageBackend): string[] {
  const keys: string[] = [];
  const read = storage.read.bind(storage);
  storage.read = async (namespace, key) => { keys.push(key); return read(namespace, key); };
  return keys;
}

const stores = {
  memory: async () => new MemoryStorage(),
  filesystem: async () => {
    const dir = await mkdtemp(join(tmpdir(), "chunk-read-bound-"));
    dirs.push(dir);
    return new FilesystemStorage(dir);
  },
};

describe.each(Object.keys(stores) as (keyof typeof stores)[])("on the %s store", name => {
  async function corpus() {
    const storage = await stores[name]();
    const writer = new TestSdwMemoryBackendAdapter({ storage, masterKey: MASTER, fortressId: FORTRESS, ownerRef: "agent",
      now: () => CREATED, maxChunkChars: WRITER_CHUNK_CHARS });
    await writer.insertPassage({ passage_id: "big", text: OVERSIZED_TEXT }, "user_content");
    await writer.insertPassage({ passage_id: "small", text: "board meeting notes" }, "user_content");
    const reader = new TestSdwMemoryBackendAdapter({ storage, masterKey: MASTER, fortressId: FORTRESS, ownerRef: "agent", now: () => CREATED });
    return { storage, reader };
  }

  it("refuses the oversized stored record as an unreadable chunk, and never reads it whole", async () => {
    const { storage, reader } = await corpus();
    const bigChunk = (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, "chunk.mem.agent.big")).at(0)!;
    // The precondition: the stored record really is past the reader's maximum, and the passage within its scan cap.
    expect(bigChunk.size_bytes).toBeGreaterThan(recallChunkRecordMaxBytes(DEFAULT_MAX_CHUNK_CHARS));
    expect(OVERSIZED_TEXT.length).toBeLessThan(RECALL_MAX_PASSAGE_SCAN_UNITS);
    const unbounded = countUnboundedReads(storage);
    // The property: a verified passage with an unreadable chunk refuses the recall under the existing refusal table.
    await expect(reader.recallPassages(new HermesRecallBudget("board meeting", () => 0, new AbortController().signal)))
      .rejects.toBeInstanceOf(StorageReadBoundError);
    expect(unbounded).not.toContain(bigChunk.key);
  });

  it("reads a record at the configured chunk size, so the maximum refuses only what that writer cannot produce", async () => {
    const storage = await stores[name]();
    const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: MASTER, fortressId: FORTRESS, ownerRef: "agent", now: () => CREATED });
    // Quote marks are the heaviest unit the write gate accepts in passage text: two JSON bytes each.
    const text = `board meeting ${'"'.repeat(DEFAULT_MAX_CHUNK_CHARS * 2)}`;
    await adapter.insertPassage({ passage_id: "full", text }, "user_content");
    const result = await adapter.recallPassages(new HermesRecallBudget("board meeting", () => 0, new AbortController().signal));
    expect(result.passages.map(passage => passage.passage_id)).toHaveLength(1);
  });

  it("readBounded returns the bytes within the bound, null when absent, and refuses past it", async () => {
    const { storage } = await corpus();
    const bigChunk = (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, "chunk.mem.agent.big")).at(0)!;
    const whole = await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, bigChunk.key);
    expect(await storage.readBounded!(SDW_DOCUMENT_CORPUS_NAMESPACE, bigChunk.key, bigChunk.size_bytes)).toEqual(whole);
    await expect(storage.readBounded!(SDW_DOCUMENT_CORPUS_NAMESPACE, bigChunk.key, bigChunk.size_bytes - 1))
      .rejects.toBeInstanceOf(StorageReadBoundError);
    expect(await storage.readBounded!(SDW_DOCUMENT_CORPUS_NAMESPACE, "chunk.mem.agent.absent", 1)).toBeNull();
  });
});
