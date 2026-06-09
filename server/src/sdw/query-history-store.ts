import type { StorageBackend } from "../storage/interface.js";
import { hashToString } from "../core/hashing.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes } from "../core/encoding.js";
import { padQuerySequence, queryKey } from "./grammar.js";
import type { SdwTransactional } from "./lmdb-backend.js";
import {
  SDW_QUERY_HISTORY_HKDF_INFO,
  SDW_QUERY_HISTORY_NAMESPACE,
  type SdwQueryHistoryChainHeadRecord,
  type SdwQueryHistoryRecord,
} from "./records.js";
import { mintPersistable, type Taint } from "./write-gate.js";
import { canonicalJson, decodeSdwRecord } from "./store-codec.js";
import { SdwReplayAnchorError, SdwValidationError } from "./errors.js";
import {
  assertReplayAnchorPresentForEstablishedStore,
  emptyReplayAnchorData,
  prepareReplayAnchorWrite,
  readReplayAnchor,
  replayAnchorCounterSeq,
  upsertReplayAnchorCounter,
} from "./replay-anchor.js";

export interface SdwQueryHistoryAuditEvent {
  readonly audit_event_id: string;
  readonly occurred_at: string;
  readonly actor: SdwQueryHistoryRecord["actor"];
  readonly channel: SdwQueryHistoryRecord["channel"];
  readonly operation: string;
  readonly prompt_or_query: string;
  readonly query_id: string;
  readonly normalized_query?: string;
  readonly result_summary?: string;
  readonly result_refs?: SdwQueryHistoryRecord["result_refs"];
}

export interface SdwQueryHistoryStoreOptions {
  readonly storage: StorageBackend;
  readonly masterKey: Uint8Array;
  readonly fortressId: string;
}

export interface SdwQueryHistoryReconcileResult {
  readonly rebuilt: number;
  readonly tampered: readonly string[];
}

export class SdwQueryHistoryStore {
  private readonly storage: StorageBackend;
  private readonly masterKey: Uint8Array;
  private readonly encryptionKey: Uint8Array;
  private readonly fortressId: string;

  constructor(options: SdwQueryHistoryStoreOptions) {
    this.storage = options.storage;
    this.masterKey = options.masterKey;
    this.encryptionKey = derivePurposeKey(options.masterKey, SDW_QUERY_HISTORY_HKDF_INFO);
    this.fortressId = options.fortressId;
  }

  async appendFromAudit(event: SdwQueryHistoryAuditEvent, taint: Taint = "agent_derived_clean"): Promise<SdwQueryHistoryRecord> {
    const transactional = asTransactional(this.storage);
    if (transactional === null) {
      throw new SdwValidationError("transaction_required", "Query history requires SdwTransactional storage");
    }
    let written: SdwQueryHistoryRecord | undefined;
    await transactional.sdwTransaction(async (txn) => {
      const head = await this.readChainHeadFromTxn(txn);
      const sequence = head.latest_sequence + 1;
      const storageKey = queryStorageKey(sequence, event.query_id);
      const withoutHash: Omit<SdwQueryHistoryRecord, "record_hash"> = {
        kind: "query_history",
        version: 1,
        query_id: event.query_id,
        sequence,
        previous_record_hash: head.latest_record_hash,
        previous_query_key: head.latest_query_key,
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
      const record: SdwQueryHistoryRecord = {
        ...withoutHash,
        record_hash: queryRecordHash(withoutHash),
      };
      const nextHead: SdwQueryHistoryChainHeadRecord = {
        kind: "query_history_chain_head",
        version: 1,
        fortress_id: this.fortressId,
        latest_sequence: sequence,
        latest_record_hash: record.record_hash,
        latest_query_key: storageKey,
        replay_anchor_seq: sequence,
        updated_at: event.occurred_at,
      };
      await txn.writePersistable(
        mintPersistable({ value: record, taint }, SDW_QUERY_HISTORY_NAMESPACE, storageKey, this.fortressId),
        this.encryptionKey,
        this.fortressId,
      );
      await txn.writePersistable(
        mintPersistable(
          { value: nextHead, taint: "system_generated" },
          SDW_QUERY_HISTORY_NAMESPACE,
          chainHeadKey(this.fortressId),
          this.fortressId,
        ),
        this.encryptionKey,
        this.fortressId,
      );
      await this.writeChainHeadAnchor(txn, sequence);
      written = record;
    });
    return written!;
  }

  async reconcileFromAudit(events: readonly SdwQueryHistoryAuditEvent[]): Promise<SdwQueryHistoryReconcileResult> {
    const verified = await this.verifyChain();
    if (verified.tampered.length > 0) {
      await this.rebuildFromAudit(events);
      return {
        rebuilt: events.length,
        tampered: verified.tampered,
      };
    }
    for (const event of events) {
      if (verified.auditEventIds.has(event.audit_event_id)) continue;
      await this.appendFromAudit(event, "agent_derived_clean");
    }
    return {
      rebuilt: events.filter((event) => !verified.auditEventIds.has(event.audit_event_id)).length,
      tampered: verified.tampered,
    };
  }

  async getByKey(storageKey: string): Promise<SdwQueryHistoryRecord | null> {
    const raw = await this.storage.read(SDW_QUERY_HISTORY_NAMESPACE, storageKey);
    if (raw === null) return null;
    return this.decodeQuery(raw, storageKey);
  }

  async readChainHead(): Promise<SdwQueryHistoryChainHeadRecord> {
    const raw = await this.storage.read(SDW_QUERY_HISTORY_NAMESPACE, chainHeadKey(this.fortressId));
    if (raw === null) return emptyChainHead(this.fortressId);
    const head = this.decodeChainHead(raw);
    const anchor = await readReplayAnchor(this.storage, this.masterKey);
    assertReplayAnchorPresentForEstablishedStore(anchor, true, "query-history chain");
    if (anchor.status !== "valid") {
      throw new SdwReplayAnchorError("replay_anchor_invalid", "SDW replay anchor missing");
    }
    this.assertChainHeadNotRolledBack(head, anchor.data);
    return head;
  }

  async verifyChain(): Promise<{ readonly auditEventIds: ReadonlySet<string>; readonly tampered: readonly string[] }> {
    const head = await this.readChainHead();
    const auditEventIds = new Set<string>();
    const tampered: string[] = [];
    let expectedKey = head.latest_query_key;
    let expectedHash = head.latest_record_hash;
    let expectedSequence = head.latest_sequence;
    while (expectedKey !== null) {
      const raw = await this.storage.read(SDW_QUERY_HISTORY_NAMESPACE, expectedKey);
      if (raw === null) {
        tampered.push(expectedKey);
        break;
      }
      try {
        const record = this.decodeQuery(raw, expectedKey);
        if (
          record.sequence !== expectedSequence ||
          record.record_hash !== expectedHash ||
          record.record_hash !== queryRecordHash(omitRecordHash(record))
        ) {
          tampered.push(expectedKey);
          break;
        }
        auditEventIds.add(record.audit_event_id);
        expectedKey = record.previous_query_key;
        expectedHash = record.previous_record_hash;
        expectedSequence -= 1;
      } catch {
        if (expectedKey !== null) tampered.push(expectedKey);
        break;
      }
    }
    return { auditEventIds, tampered };
  }

  private async readChainHeadFromTxn(txn: { read(namespace: string, key: string): Promise<Uint8Array | null> }): Promise<SdwQueryHistoryChainHeadRecord> {
    const raw = await txn.read(SDW_QUERY_HISTORY_NAMESPACE, chainHeadKey(this.fortressId));
    if (raw === null) return emptyChainHead(this.fortressId);
    const head = this.decodeChainHead(raw);
    const anchor = await readReplayAnchor(txn, this.masterKey);
    assertReplayAnchorPresentForEstablishedStore(anchor, true, "query-history chain");
    if (anchor.status !== "valid") {
      throw new SdwReplayAnchorError("replay_anchor_invalid", "SDW replay anchor missing");
    }
    this.assertChainHeadNotRolledBack(head, anchor.data);
    return head;
  }

  private async rebuildFromAudit(events: readonly SdwQueryHistoryAuditEvent[]): Promise<void> {
    const transactional = asTransactional(this.storage);
    if (transactional === null) {
      throw new SdwValidationError("transaction_required", "Query history requires SdwTransactional storage");
    }
    await transactional.sdwTransaction(async (txn) => {
      let latestRecordHash: string | null = null;
      let latestQueryKey: string | null = null;
      let latestSequence = 0;
      for (const event of events) {
        latestSequence += 1;
        const storageKey = queryStorageKey(latestSequence, event.query_id);
        const withoutHash: Omit<SdwQueryHistoryRecord, "record_hash"> = {
          kind: "query_history",
          version: 1,
          query_id: event.query_id,
          sequence: latestSequence,
          previous_record_hash: latestRecordHash,
          previous_query_key: latestQueryKey,
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
        const record: SdwQueryHistoryRecord = {
          ...withoutHash,
          record_hash: queryRecordHash(withoutHash),
        };
        await txn.writePersistable(
          mintPersistable(
            { value: record, taint: "agent_derived_clean" },
            SDW_QUERY_HISTORY_NAMESPACE,
            storageKey,
            this.fortressId,
          ),
          this.encryptionKey,
          this.fortressId,
        );
        latestRecordHash = record.record_hash;
        latestQueryKey = storageKey;
      }
      const nextHead: SdwQueryHistoryChainHeadRecord = {
        kind: "query_history_chain_head",
        version: 1,
        fortress_id: this.fortressId,
        latest_sequence: latestSequence,
        latest_record_hash: latestRecordHash,
        latest_query_key: latestQueryKey,
        replay_anchor_seq: latestSequence,
        updated_at: events.at(-1)?.occurred_at ?? new Date(0).toISOString(),
      };
      await txn.writePersistable(
        mintPersistable(
          { value: nextHead, taint: "system_generated" },
          SDW_QUERY_HISTORY_NAMESPACE,
          chainHeadKey(this.fortressId),
          this.fortressId,
        ),
        this.encryptionKey,
        this.fortressId,
      );
      await this.writeChainHeadAnchor(txn, latestSequence);
    });
  }

  private assertChainHeadNotRolledBack(
    head: SdwQueryHistoryChainHeadRecord,
    anchorData: { readonly chain_head: readonly { readonly id: string; readonly seq: number }[] },
  ): void {
    const floor = replayAnchorCounterSeq(anchorData.chain_head, this.fortressId);
    if (head.latest_sequence < floor) {
      throw new SdwReplayAnchorError(
        "replay_detected",
        "SDW query-history chain-head rollback detected",
      );
    }
  }

  private async writeChainHeadAnchor(
    txn: { read(namespace: string, key: string): Promise<Uint8Array | null>; write(namespace: string, key: string, data: Uint8Array): Promise<void> },
    sequence: number,
  ): Promise<void> {
    const anchor = await readReplayAnchor(txn, this.masterKey);
    const base = anchor.status === "valid" ? anchor.data : emptyReplayAnchorData();
    const prepared = prepareReplayAnchorWrite(this.masterKey, {
      ...base,
      chain_head: upsertReplayAnchorCounter(base.chain_head, this.fortressId, sequence),
    });
    await txn.write(prepared.namespace, prepared.storageKey, prepared.data);
  }

  private decodeQuery(raw: Uint8Array, storageKey: string): SdwQueryHistoryRecord {
    return decodeSdwRecord<SdwQueryHistoryRecord>(raw, {
      namespace: SDW_QUERY_HISTORY_NAMESPACE,
      storageKey,
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: "query_history",
      verifyIdentity: (record) => storageKey === queryStorageKey(record.sequence, record.query_id),
    });
  }

  private decodeChainHead(raw: Uint8Array): SdwQueryHistoryChainHeadRecord {
    return decodeSdwRecord<SdwQueryHistoryChainHeadRecord>(raw, {
      namespace: SDW_QUERY_HISTORY_NAMESPACE,
      storageKey: chainHeadKey(this.fortressId),
      fortressId: this.fortressId,
      encryptionKey: this.encryptionKey,
      expectedKind: "query_history_chain_head",
      verifyIdentity: (record) => record.fortress_id === this.fortressId,
    });
  }
}

export function chainHeadKey(fortressId: string): string {
  return `chain-head.${fortressId}`;
}

export function queryStorageKey(sequence: number, queryId: string): string {
  return queryKey(padQuerySequence(sequence), queryId);
}

export function queryRecordHash(record: Omit<SdwQueryHistoryRecord, "record_hash">): string {
  return hashToString(stringToBytes(canonicalJson(record)));
}

function omitRecordHash(record: SdwQueryHistoryRecord): Omit<SdwQueryHistoryRecord, "record_hash"> {
  const { record_hash: _recordHash, ...rest } = record;
  return rest;
}

function emptyChainHead(fortressId: string): SdwQueryHistoryChainHeadRecord {
  return {
    kind: "query_history_chain_head",
    version: 1,
    fortress_id: fortressId,
    latest_sequence: 0,
    latest_record_hash: null,
    latest_query_key: null,
    replay_anchor_seq: 0,
    updated_at: "1970-01-01T00:00:00.000Z",
  };
}

function asTransactional(storage: StorageBackend): (StorageBackend & SdwTransactional) | null {
  if ("sdwTransaction" in storage && typeof storage.sdwTransaction === "function") {
    return storage as StorageBackend & SdwTransactional;
  }
  return null;
}
