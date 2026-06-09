import { describe, expect, it } from "vitest";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import {
  documentChunkKey,
  documentKey,
  sdwAad,
  sdwAadDebugString,
  stateKey,
} from "../../src/sdw/grammar.js";
import type { SdwTxn, SdwTransactional } from "../../src/sdw/lmdb-backend.js";
import {
  chainHeadKey,
  queryStorageKey,
  SdwDocumentCorpusStore,
  SdwQueryHistoryStore,
  SdwWorkingStateStore,
} from "../../src/sdw/index.js";
import {
  SDW_META_NAMESPACE,
  SDW_DOCUMENT_CORPUS_HKDF_INFO,
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_QUERY_HISTORY_HKDF_INFO,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_REPLAY_ANCHOR_KEY,
  SDW_WORKING_STATE_HKDF_INFO,
  SDW_WORKING_STATE_NAMESPACE,
  type SdwDocumentChunkRecord,
  type SdwDocumentRecord,
  type SdwQueryHistoryRecord,
  type SdwWorkingStateRecord,
} from "../../src/sdw/records.js";
import { assertSdwRawWriteAuthorized, encryptedEnvelopeContains } from "../../src/sdw/write-gate.js";
import { readReplayAnchor } from "../../src/sdw/replay-anchor.js";
import { SdwReplayAnchorError, SdwValidationError, UnsupportedRecordVersion } from "../../src/sdw/errors.js";

const FORTRESS_ID = "fortress:test";
const MASTER_KEY = new Uint8Array(32).fill(8);
const NOW = "2026-06-08T00:00:00.000Z";

describe("SDW Phase 2 working-state store", () => {
  it("writes closed payload variants through the gate and rejects taint, oversize, unknown variant, and identity mismatch", async () => {
    const storage = new TxMemoryStorage();
    const store = new SdwWorkingStateStore({ storage, masterKey: MASTER_KEY, fortressId: FORTRESS_ID });
    const record = workingStateRecord("state-1", "persistable note");

    await store.put(record, "agent_derived_clean");
    const raw = await storage.read(SDW_WORKING_STATE_NAMESPACE, stateKey("task", "state-1"));
    expect(raw).not.toBeNull();
    expect(encryptedEnvelopeContains(raw!, "persistable note")).toBe(false);
    await expect(store.get("task", "state-1")).resolves.toMatchObject({ state_id: "state-1" });

    await expect(store.put(record, "policy")).rejects.toBeInstanceOf(SdwValidationError);
    await expect(store.put({ ...record, state: { kind: "raw_json", value: {} } } as any, "user_content")).rejects.toBeInstanceOf(SdwValidationError);
    await expect(store.put({ ...record, state_id: "state-2", state: { kind: "task_checkpoint", task_ref: "task-1", summary: "x".repeat(1024 * 1024) } }, "user_content")).rejects.toMatchObject({ category: "record_too_large" });

    await storage.rawEncryptedWrite(
      SDW_WORKING_STATE_NAMESPACE,
      stateKey("task", "state-bad"),
      { ...record, state_id: "different" },
      SDW_WORKING_STATE_HKDF_INFO,
    );
    await expect(store.get("task", "state-bad")).rejects.toMatchObject({ category: "identity_mismatch" });
  });
});

describe("SDW Phase 2 query-history store", () => {
  it("materializes audit events transactionally with a monotonic hash chain and reconciles missing cache entries from audit", async () => {
    const storage = new TxMemoryStorage();
    const store = new SdwQueryHistoryStore({ storage, masterKey: MASTER_KEY, fortressId: FORTRESS_ID });
    const first = auditEvent("audit-1", "query-1", "2026-06-08T00:00:00.000Z");
    const second = auditEvent("audit-2", "query-2", "2026-06-08T00:00:01.000Z");

    const firstRecord = await store.appendFromAudit(first);
    const secondRecord = await store.appendFromAudit(second);
    expect(firstRecord.sequence).toBe(1);
    expect(secondRecord.sequence).toBe(2);
    expect(secondRecord.previous_record_hash).toBe(firstRecord.record_hash);
    expect(secondRecord.previous_query_key).toBe(queryStorageKey(first.occurred_at, first.query_id));
    await expect(store.readChainHead()).resolves.toMatchObject({
      latest_sequence: 2,
      latest_query_key: queryStorageKey(second.occurred_at, second.query_id),
    });
    await expect(readReplayAnchor(storage, MASTER_KEY)).resolves.toMatchObject({
      status: "valid",
      data: {
        chain_head: [{ id: FORTRESS_ID, seq: 2 }],
      },
    });

    const rebuiltStorage = new TxMemoryStorage();
    const rebuiltStore = new SdwQueryHistoryStore({ storage: rebuiltStorage, masterKey: MASTER_KEY, fortressId: FORTRESS_ID });
    await expect(rebuiltStore.reconcileFromAudit([first, second])).resolves.toEqual({
      rebuilt: 2,
      tampered: [],
    });
    await expect(rebuiltStore.verifyChain()).resolves.toMatchObject({ tampered: [] });
  });

  it("detects hash-chain tampering and fails closed on unsupported direct-read versions", async () => {
    const storage = new TxMemoryStorage();
    const store = new SdwQueryHistoryStore({ storage, masterKey: MASTER_KEY, fortressId: FORTRESS_ID });
    const first = auditEvent("audit-1", "query-1", "2026-06-08T00:00:00.000Z");
    const second = auditEvent("audit-2", "query-2", "2026-06-08T00:00:01.000Z");
    await store.appendFromAudit(first);
    await store.appendFromAudit(second);

    await storage.rawEncryptedWrite(
      SDW_QUERY_HISTORY_NAMESPACE,
      queryStorageKey(first.occurred_at, first.query_id),
      { ...queryRecordFixture(first), sequence: 9, record_hash: "bad-hash" },
      SDW_QUERY_HISTORY_HKDF_INFO,
    );
    await expect(store.verifyChain()).resolves.toMatchObject({
      tampered: [queryStorageKey(first.occurred_at, first.query_id)],
    });
    await expect(store.reconcileFromAudit([first, second])).resolves.toEqual({
      rebuilt: 2,
      tampered: [queryStorageKey(first.occurred_at, first.query_id)],
    });
    await expect(store.verifyChain()).resolves.toMatchObject({ tampered: [] });

    const unsupported = { ...queryRecordFixture(auditEvent("audit-3", "query-3", "2026-06-08T00:00:02.000Z")), version: 2 };
    await storage.rawEncryptedWrite(
      SDW_QUERY_HISTORY_NAMESPACE,
      queryStorageKey("2026-06-08T00:00:02.000Z", "query-3"),
      unsupported,
      SDW_QUERY_HISTORY_HKDF_INFO,
    );
    await expect(store.getByKey(queryStorageKey("2026-06-08T00:00:02.000Z", "query-3"))).rejects.toBeInstanceOf(UnsupportedRecordVersion);
    expect(await storage.exists(SDW_QUERY_HISTORY_NAMESPACE, chainHeadKey(FORTRESS_ID))).toBe(true);
  });

  it("fails closed when a replayed chain head regresses below the meta replay floor", async () => {
    const storage = new TxMemoryStorage();
    const store = new SdwQueryHistoryStore({ storage, masterKey: MASTER_KEY, fortressId: FORTRESS_ID });
    const events = Array.from({ length: 7 }, (_, index) =>
      auditEvent(
        `audit-${index + 1}`,
        `query-${index + 1}`,
        `2026-06-08T00:00:0${index}.000Z`,
      ),
    );

    for (const event of events.slice(0, 5)) await store.appendFromAudit(event);
    const capturedHead = await storage.read(SDW_QUERY_HISTORY_NAMESPACE, chainHeadKey(FORTRESS_ID));
    expect(capturedHead).not.toBeNull();
    await store.appendFromAudit(events[5]!);
    await store.appendFromAudit(events[6]!);
    storage.rawWriteForTest(SDW_QUERY_HISTORY_NAMESPACE, chainHeadKey(FORTRESS_ID), capturedHead!);
    await storage.delete(SDW_QUERY_HISTORY_NAMESPACE, queryStorageKey(events[5]!.occurred_at, events[5]!.query_id));
    await storage.delete(SDW_QUERY_HISTORY_NAMESPACE, queryStorageKey(events[6]!.occurred_at, events[6]!.query_id));

    await expect(store.readChainHead()).rejects.toMatchObject({
      category: "replay_detected",
    });
    await expect(store.verifyChain()).rejects.toBeInstanceOf(SdwReplayAnchorError);
  });

  it("fails closed when an established query-history chain loses its meta anchor", async () => {
    const storage = new TxMemoryStorage();
    const store = new SdwQueryHistoryStore({ storage, masterKey: MASTER_KEY, fortressId: FORTRESS_ID });
    await store.appendFromAudit(auditEvent("audit-1", "query-1", "2026-06-08T00:00:00.000Z"));

    storage.rawWriteForTest(SDW_META_NAMESPACE, SDW_REPLAY_ANCHOR_KEY, stringToBytes("{}"));

    await expect(store.readChainHead()).rejects.toMatchObject({
      category: "replay_anchor_invalid",
    });
  });
});

describe("SDW Phase 2 document-corpus store", () => {
  it("stores document metadata and chunks encrypted, keeps source.uri out of key/AAD, and adds no fetch path", async () => {
    const storage = new TxMemoryStorage();
    const store = new SdwDocumentCorpusStore({ storage, masterKey: MASTER_KEY, fortressId: FORTRESS_ID });
    const hostileUri = "https://example.test/a/b?x=%2f&y=1#frag";
    const document = documentRecord("doc-1", hostileUri);
    const chunk = chunkRecord("doc-1", "chunk-1", "chunk text");

    await store.putDocument(document, "user_content");
    await store.putChunk(chunk, "user_content");
    const docKey = documentKey("doc-1");
    const chunkKey = documentChunkKey("doc-1", "000000", "chunk-1");
    expect(docKey).not.toContain(hostileUri);
    expect(sdwAadDebugString(FORTRESS_ID, SDW_DOCUMENT_CORPUS_NAMESPACE, docKey)).not.toContain(hostileUri);
    expect(await store.getDocument("doc-1")).toMatchObject({ source: { uri: hostileUri } });
    expect(encryptedEnvelopeContains((await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, docKey))!, hostileUri)).toBe(false);
    expect(encryptedEnvelopeContains((await storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, chunkKey))!, "chunk text")).toBe(false);
    expect(typeof (store as any).fetchUrl).toBe("undefined");
    expect(typeof (store as any).ingestUrl).toBe("undefined");

    await expect(store.putDocument(document, "secret")).rejects.toBeInstanceOf(SdwValidationError);
    await storage.rawEncryptedWrite(
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      documentKey("doc-mismatch"),
      { ...document, document_id: "different" },
      SDW_DOCUMENT_CORPUS_HKDF_INFO,
    );
    await expect(store.getDocument("doc-mismatch")).rejects.toMatchObject({ category: "identity_mismatch" });
  });
});

function workingStateRecord(stateId: string, summary: string): SdwWorkingStateRecord {
  return {
    kind: "working_state",
    version: 1,
    state_id: stateId,
    scope: "task",
    owner_ref: "owner-1",
    status: "active",
    created_at: NOW,
    updated_at: NOW,
    content_type: "application/json",
    state: { kind: "task_checkpoint", task_ref: "task-1", summary },
  };
}

function documentRecord(documentId: string, uri: string): SdwDocumentRecord {
  return {
    kind: "document",
    version: 1,
    document_id: documentId,
    source: { kind: "url", uri, title: "Example", media_type: "text/plain" },
    content_hash: "hash-1",
    chunk_count: 1,
    byte_length: 10,
    created_at: NOW,
    updated_at: NOW,
    tags: ["tag-1"],
    metadata: [{ key: "source-ref", value: "local only" }],
  };
}

function chunkRecord(documentId: string, chunkId: string, text: string): SdwDocumentChunkRecord {
  return {
    kind: "document_chunk",
    version: 1,
    chunk_id: chunkId,
    document_id: documentId,
    chunk_ordinal: 0,
    text,
    content_hash: "hash-2",
    char_start: 0,
    char_end: text.length,
    token_count: 2,
    vector_refs: ["vec-1"],
    created_at: NOW,
  };
}

function auditEvent(auditEventId: string, queryId: string, occurredAt: string) {
  return {
    audit_event_id: auditEventId,
    occurred_at: occurredAt,
    actor: { kind: "agent" as const, agent_ref: "agent-1" },
    channel: "mcp" as const,
    operation: "search",
    prompt_or_query: `question ${queryId}`,
    query_id: queryId,
    normalized_query: `question ${queryId}`,
    result_summary: "ok",
    result_refs: [{ kind: "audit_event" as const, ref: auditEventId }],
  };
}

function queryRecordFixture(event: ReturnType<typeof auditEvent>): SdwQueryHistoryRecord {
  return {
    kind: "query_history",
    version: 1,
    query_id: event.query_id,
    sequence: 1,
    previous_record_hash: null,
    previous_query_key: null,
    record_hash: "hash-1",
    audit_event_id: event.audit_event_id,
    occurred_at: event.occurred_at,
    actor: event.actor,
    channel: event.channel,
    operation: event.operation,
    prompt_or_query: event.prompt_or_query,
    normalized_query: event.normalized_query,
    result_summary: event.result_summary,
    result_refs: event.result_refs,
    policy_visibility: "not_included",
    created_at: event.occurred_at,
  };
}

class TxMemoryStorage implements StorageBackend, SdwTransactional {
  private readonly data = new Map<string, Uint8Array>();

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.rawWriteForTest(namespace, key, assertSdwRawWriteAuthorized(namespace, key, data));
  }

  async sdwTransaction<T>(fn: (txn: SdwTxn) => Promise<T>): Promise<T> {
    const txn: SdwTxn = {
      write: async (namespace, key, data) => this.write(namespace, key, data),
      writePersistable: async (persistable, encryptionKey, fortressId) => {
        const { prepareSdwBackendWrite } = await import("../../src/sdw/write-gate.js");
        const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId);
        await this.write(prepared.namespace, prepared.storageKey, prepared.data);
      },
      read: async (namespace, key) => this.read(namespace, key),
      delete: async (namespace, key) => this.delete(namespace, key),
    };
    return fn(txn);
  }

  async rawEncryptedWrite(namespace: string, key: string, record: unknown, hkdfInfo: string): Promise<void> {
    const envelope = encrypt(
      stringToBytes(JSON.stringify(record)),
      derivePurposeKey(MASTER_KEY, hkdfInfo),
      sdwAad(FORTRESS_ID, namespace, key),
    );
    this.rawWriteForTest(namespace, key, stringToBytes(JSON.stringify(envelope)));
  }

  rawWriteForTest(namespace: string, key: string, data: Uint8Array): void {
    this.data.set(`${namespace}\0${key}`, new Uint8Array(data));
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.data.get(`${namespace}\0${key}`) ?? null;
  }

  async delete(namespace: string, key: string): Promise<boolean> {
    return this.data.delete(`${namespace}\0${key}`);
  }

  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    for (const [composite, data] of this.data) {
      const [entryNamespace, key] = composite.split("\0", 2) as [string, string];
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
