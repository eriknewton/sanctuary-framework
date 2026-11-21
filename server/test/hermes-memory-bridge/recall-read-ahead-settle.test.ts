// Every read-ahead slot settles whatever another slot does: an authenticated chunk record with a malformed text field
// is that slot's refusal, held to its passage's turn, and the drain waits for every other slot's reads before the
// bridge sees the call return and releases its admission record.
import { describe, expect, it } from "vitest";
import { stringToBytes } from "../../src/core/encoding.js";
import { encrypt } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { HERMES_MAX_CALL_RECORDS } from "../../src/hermes-memory-bridge/constants.js";
import { RECALL_READ_AHEAD_PASSAGES, RECALL_READS_PER_SLOT } from "../../src/hermes-memory-bridge/recall.js";
import { RecallReadAheadRing } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SdwDocumentCorpusStore, padChunkOrdinal } from "../../src/sdw/document-corpus-store.js";
import { documentChunkKey, sdwAad } from "../../src/sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_HKDF_INFO, SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { BRIDGE_FORTRESS, BRIDGE_MASTER_KEY, nextTurn, quiesce, recallBridge, turnsUntil, type ScheduledStorage } from "./recall-read-ahead-harness.js";

const PRODUCT_BOUND = RECALL_READ_AHEAD_PASSAGES * RECALL_READS_PER_SLOT * HERMES_MAX_CALL_RECORDS;
const passages = (count: number) => Array.from({ length: count }, (_, n) => ({ id: `p${String(n).padStart(2, "0")}`, text: `board meeting ${n}` }));
/** The passages in the first read-ahead window after p00, whose two first reads park. */
const PARKED = Array.from({ length: RECALL_READ_AHEAD_PASSAGES - 1 }, (_, n) => `p${String(n + 1).padStart(2, "0")}`);
const parksFirstReads = (key: string) => PARKED.some(id => key === `doc.mem.agent.${id}` || key === `prov.mem.agent.${id}`);

/** Serve p00's first chunk as a corpus-key-authenticated record whose text field is null. */
async function plantMalformedFirstChunk(storage: ScheduledStorage): Promise<void> {
  const documentId = "mem.agent.p00";
  const corpus = new SdwDocumentCorpusStore({ storage, masterKey: BRIDGE_MASTER_KEY, fortressId: BRIDGE_FORTRESS });
  const chunk = (await corpus.getChunk(documentId, 0, `c${padChunkOrdinal(0)}`))!;
  const storageKey = documentChunkKey(documentId, padChunkOrdinal(0), chunk.chunk_id);
  storage.planted.set(storageKey, stringToBytes(JSON.stringify(encrypt(
    stringToBytes(JSON.stringify({ ...chunk, text: null })), derivePurposeKey(BRIDGE_MASTER_KEY, SDW_DOCUMENT_CORPUS_HKDF_INFO),
    sdwAad(BRIDGE_FORTRESS, SDW_DOCUMENT_CORPUS_NAMESPACE, storageKey)))));
  storage.resetCounts();
}

describe("a malformed chunk record in the first passage", () => {
  it("is that passage's refusal, and the call returns only after the other slots' parked reads settle", async () => {
    const h = await recallBridge(passages(6));
    try {
      await plantMalformedFirstChunk(h.storage);
      h.storage.rule = key => parksFirstReads(key) ? "park" : undefined;
      h.accept("c1"); h.call("c1", "r1");
      await turnsUntil(() => h.storage.parked.length === PARKED.length * RECALL_READS_PER_SLOT);
      await quiesce();
      // The property: p00's refusal is decided, but the call is held while the other slots' reads are pending.
      expect(h.responses("r1")).toEqual([]);
      expect(h.recordCount()).toBe(1);
      h.storage.release();
      await turnsUntil(() => h.recordCount() === 0);
      expect(h.storage.inFlight).toBe(0);
      expect(h.storage.settled).toBe(h.storage.issued);
      expect(h.body("r1")).toMatchObject({ outcome: "unavailable" });
      expect(h.recallAudits()).toEqual([]);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });

  it("returns reads in flight to zero after every call of repeated waves, within the product-wide bound", async () => {
    // A call that left its parked reads behind would pass the product-wide bound after this many calls.
    const calls = Math.floor(PRODUCT_BOUND / (PARKED.length * RECALL_READS_PER_SLOT)) + 1;
    const h = await recallBridge(passages(6));
    const afterEachCall: number[] = [];
    try {
      await plantMalformedFirstChunk(h.storage);
      h.storage.rule = key => parksFirstReads(key) ? "park" : undefined;
      h.accept("c1");
      for (let n = 0; n < calls; n++) {
        h.storage.tag = n;
        h.call("c1", `wave-${n}`);
        // Release only this call's parked reads, and only while the call is still held on them, so a read one
        // call leaves behind is never released by a later call and stays counted.
        for (let turn = 0; turn < 5000 && h.responses(`wave-${n}`).length === 0; turn++) {
          await quiesce(5);
          if (h.responses(`wave-${n}`).length === 0 && h.storage.parked.some(read => read.tag === n)) h.storage.release(n);
        }
        await turnsUntil(() => h.recordCount() === 0);
        afterEachCall.push(h.storage.inFlight);
      }
      expect(afterEachCall).toEqual(Array.from({ length: calls }, () => 0));
      expect(h.storage.peakInFlight).toBeLessThanOrEqual(PRODUCT_BOUND);
      expect(h.storage.writes).toBe(0);
    } finally { h.storage.release(); h.core.relayEof(); }
  });
});

describe("the read-ahead ring", () => {
  it("drains every held slot, and take() returns the failure, when one slot's read function rejects", async () => {
    const releases: (() => void)[] = [];
    const ring = new RecallReadAheadRing(RECALL_READ_AHEAD_PASSAGES, ordinal => ordinal === 0
      ? Promise.reject(new Error("slot failure"))
      : new Promise<void>(release => releases.push(release)));
    ring.fill(0, RECALL_READ_AHEAD_PASSAGES, () => true);
    let drained = false;
    const drain = ring.drain().then(() => { drained = true; });
    for (let turn = 0; turn < 25; turn++) await nextTurn();
    // The property: the drain is still waiting on the parked slots, whatever the rejected slot did.
    expect(drained).toBe(false);
    for (const release of releases) release();
    await drain;
    expect(drained).toBe(true);
    const taken = await ring.take(0);
    expect(taken?.failed).toMatchObject({ ok: false, error: { message: "slot failure" } });
  });
});
