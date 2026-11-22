// fail-before-exempt: new results-store module, no base behaviour.
import { afterEach, describe, expect, it } from "vitest";
import { LocalOplog } from "../../src/local-recompile/oplog.js";
import {
  INDETERMINATE_TTL_MS,
  LocalResultsStore,
  PENDING_GRACE_MS,
  RESULTS_MAX_OBJECTS,
  RESULTS_MAX_TOTAL_BYTES,
  RESULT_BODY_MAX_BYTES,
  RESULT_OBJECT_MAX_BYTES,
  RESULT_TTL_MS,
  objectKey,
  type ResultsStoreOptions,
} from "../../src/local-recompile/results-store.js";
import { deriveLocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { LOCAL_RESULTS_NAMESPACE, openRecord, sealedRecordMaxBytes } from "../../src/local-recompile/store-record.js";
import { FIXTURE_SEAT, StrictMemoryStorage, fixtureRequestId, fixtureStoreKeys } from "./__fixtures__/strict-memory-storage.js";

const START = Date.UTC(2026, 0, 1);
const MINUTE = 60_000;
const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

async function openStores(options: ResultsStoreOptions = {}) {
  const storage = new StrictMemoryStorage();
  const keys = fixtureStoreKeys();
  const clock = { now: START };
  const now = () => clock.now;
  const oplog = new LocalOplog(storage, keys.oplogKey, { now });
  const results = new LocalResultsStore(storage, keys.resultsKey, oplog, { now, ...options });
  cleanups.push(() => {
    results.close();
    oplog.close();
    keys.oplogKey.fill(0);
    keys.resultsKey.fill(0);
  });
  await oplog.ensure();
  await results.ensure();
  return { storage, keys, clock, oplog, results };
}

function pending(n: number, deadline = START + MINUTE) {
  return { request_id: fixtureRequestId(n), seat: FIXTURE_SEAT, kind: "summarize" as const, deadline };
}

async function oplogKinds(oplog: LocalOplog): Promise<string[]> {
  const status = await oplog.status();
  return (await oplog.readRows(status.base_seq, status.rows)).map((row) => row.kind);
}

describe("results store bounds", () => {
  it("pins the production result constants", () => {
    const KIB = 1024;
    expect(RESULTS_MAX_OBJECTS).toBe(200);
    expect(RESULT_BODY_MAX_BYTES).toBe(32 * KIB);
    expect(RESULT_OBJECT_MAX_BYTES).toBe(36 * KIB);
    expect(RESULTS_MAX_TOTAL_BYTES).toBe(8 * KIB * KIB);
    expect(RESULTS_MAX_OBJECTS * RESULT_OBJECT_MAX_BYTES).toBeLessThan(RESULTS_MAX_TOTAL_BYTES);
    expect(RESULT_TTL_MS).toBe(30 * 24 * 60 * MINUTE);
    expect(PENDING_GRACE_MS).toBe(10 * MINUTE);
    expect(INDETERMINATE_TTL_MS).toBe(24 * 60 * MINUTE);
  });

  it("ten thousand putPending calls keep at most 200 objects and 8 MiB", async () => {
    const PUTS = 10_000;
    const { storage, results } = await openStores();
    for (let n = 0; n < PUTS; n += 1) await results.putPending(pending(n));
    const live = await results.list({ includeUncommitted: true });
    expect(live).toHaveLength(RESULTS_MAX_OBJECTS);
    // The survivors are the newest puts: eviction removed the oldest first.
    expect(live.map((object) => object.request_id)).toEqual(
      Array.from({ length: RESULTS_MAX_OBJECTS }, (_, index) => fixtureRequestId(PUTS - RESULTS_MAX_OBJECTS + index)),
    );
    const stored = await storage.listKeys(LOCAL_RESULTS_NAMESPACE);
    expect(stored.filter((key) => key.startsWith("obj/"))).toHaveLength(RESULTS_MAX_OBJECTS);
    let bytes = 0;
    for (const key of stored) bytes += (await storage.read(LOCAL_RESULTS_NAMESPACE, key))!.length;
    expect(bytes).toBeLessThanOrEqual(RESULTS_MAX_TOTAL_BYTES);
  }, 300_000);

  it("committed bodies past the byte cap evict the oldest objects to stay under it", async () => {
    // Room for about three full bodies.
    const maxTotalBytes = 3 * RESULT_OBJECT_MAX_BYTES;
    const { results } = await openStores({ caps: { maxTotalBytes } });
    const big = { summary: "x".repeat(RESULT_BODY_MAX_BYTES - 64) };
    for (let n = 0; n < 6; n += 1) {
      await results.putPending(pending(n));
      await results.markCommitted(fixtureRequestId(n), big);
    }
    const live = await results.list();
    expect(live.length).toBeLessThanOrEqual(3);
    expect(live.map((object) => object.request_id)).toContain(fixtureRequestId(5));
    expect(live.map((object) => object.request_id)).not.toContain(fixtureRequestId(0));
  });

  it("eviction removes pending and indeterminate before committed, oldest first", async () => {
    const { clock, oplog, results } = await openStores({ caps: { maxObjects: 4 } });
    const advance = () => { clock.now += 1; };
    await results.putPending(pending(1)); advance();
    await results.markCommitted(fixtureRequestId(1), { summary: "one" }); advance();
    await results.putPending(pending(2)); advance();
    await results.putPending(pending(3)); advance();
    await results.markIndeterminate(fixtureRequestId(3)); advance();
    await results.putPending(pending(4)); advance();
    await results.putPending(pending(5)); advance();
    await results.putPending(pending(6)); advance();
    await results.putPending(pending(7)); advance();
    const ids = (await results.list({ includeUncommitted: true })).map((object) => object.request_id);
    // 2 then 3 (uncommitted, oldest first) went before 4; committed 1 outlived every uncommitted one.
    expect(ids.sort()).toEqual([1, 5, 6, 7].map(fixtureRequestId).sort());
    const evicted = (await oplog.readRows(0, 100)).filter((row) => row.kind === "result_evicted").map((row) => row.body);
    expect(evicted).toEqual([2, 3, 4].map((n) => ({ request_id: fixtureRequestId(n) })));
    await results.putPending(pending(8));
    const after = (await results.list({ includeUncommitted: true })).map((object) => object.request_id);
    expect(after).toContain(fixtureRequestId(1));
    expect(after).not.toContain(fixtureRequestId(5));
  });

  it("an over-cap body is refused and nothing is written", async () => {
    const { storage, results } = await openStores();
    await results.putPending(pending(1));
    const before = storage.calls.filter((call) => call.op !== "read").length;
    await expect(
      results.markCommitted(fixtureRequestId(1), { summary: "x".repeat(RESULT_BODY_MAX_BYTES + 1) }),
    ).rejects.toMatchObject({ kind: "capacity" });
    expect(storage.calls.filter((call) => call.op !== "read").length).toBe(before);
    expect(await results.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({ state: "pending" });
  });

  it("a body that is not flat text is refused", async () => {
    const { results } = await openStores();
    await results.putPending(pending(1));
    await expect(results.markCommitted(fixtureRequestId(1), { nested: { deep: "x" } } as never)).rejects.toMatchObject({
      kind: "invalid_record",
    });
  });

  it("a duplicate request id is refused", async () => {
    const { results } = await openStores();
    await results.putPending(pending(1));
    await expect(results.putPending(pending(1))).rejects.toMatchObject({ kind: "exists" });
  });
});

describe("results store reads and transitions", () => {
  it("default reads return committed objects only", async () => {
    const { results } = await openStores();
    await results.putPending(pending(1));
    await results.putPending(pending(2));
    await results.markCommitted(fixtureRequestId(2), { summary: "done" });
    expect(await results.get(fixtureRequestId(1))).toBeNull();
    expect(await results.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({ state: "pending" });
    expect((await results.list()).map((object) => object.request_id)).toEqual([fixtureRequestId(2)]);
    expect(await results.list({ includeUncommitted: true })).toHaveLength(2);
  });

  it("a completion that arrives after the object became indeterminate is discarded", async () => {
    const { results } = await openStores();
    await results.putPending(pending(1));
    await results.markIndeterminate(fixtureRequestId(1));
    await expect(results.markCommitted(fixtureRequestId(1), { summary: "late" })).rejects.toMatchObject({ kind: "conflict" });
    expect(await results.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({
      state: "indeterminate",
      body: null,
    });
  });

  it("delete writes its operator-log row before the delete", async () => {
    const { storage, oplog, results } = await openStores();
    await results.putPending(pending(1));
    const before = storage.calls.length;
    expect(await results.delete(fixtureRequestId(1))).toBe(true);
    const calls = storage.calls.slice(before);
    const logRow = calls.findIndex((call) => call.op === "create" && call.key?.startsWith("row/"));
    const objectDelete = calls.findIndex((call) => call.op === "delete" && call.key === objectKey(fixtureRequestId(1)));
    expect(logRow).toBeGreaterThan(-1);
    expect(logRow).toBeLessThan(objectDelete);
    expect((await oplogKinds(oplog)).slice(-1)).toEqual(["result_deleted"]);
    expect(await results.delete(fixtureRequestId(1))).toBe(false);
  });

  it("every mutation takes the results lock, then the operator-log lock inside it", async () => {
    const { storage, results } = await openStores();
    const before = storage.calls.length;
    await results.putPending(pending(1));
    const locks = storage.calls.slice(before).filter((call) => call.op === "lock" || call.op === "unlock");
    expect(locks.map((call) => `${call.op}:${call.namespace}`)).toEqual([
      "lock:_local_results",
      "lock:_local_oplog",
      "unlock:_local_oplog",
      "unlock:_local_results",
    ]);
  });

  it("sweep expires committed objects, marks overdue pending objects indeterminate and deletes stale indeterminate ones", async () => {
    const { clock, oplog, results } = await openStores();
    await results.putPending(pending(1, START + MINUTE));
    await results.markCommitted(fixtureRequestId(1), { summary: "kept a while" });
    await results.putPending(pending(2, START + MINUTE));

    // Before any threshold nothing moves.
    expect(await results.sweep(START + MINUTE)).toEqual({ expired: 0, indeterminate: 0, repaired: 0 });

    const overdue = START + MINUTE + PENDING_GRACE_MS;
    clock.now = overdue;
    expect(await results.sweep(overdue)).toEqual({ expired: 0, indeterminate: 1, repaired: 0 });
    expect(await results.get(fixtureRequestId(2), { includeUncommitted: true })).toMatchObject({ state: "indeterminate" });

    const staleIndeterminate = overdue + INDETERMINATE_TTL_MS;
    expect(await results.sweep(staleIndeterminate)).toEqual({ expired: 1, indeterminate: 0, repaired: 0 });
    expect(await results.get(fixtureRequestId(2), { includeUncommitted: true })).toBeNull();

    const committedExpiry = START + RESULT_TTL_MS;
    expect(await results.sweep(committedExpiry)).toEqual({ expired: 1, indeterminate: 0, repaired: 0 });
    expect(await results.list({ includeUncommitted: true })).toEqual([]);

    const kinds = await oplogKinds(oplog);
    expect(kinds.filter((kind) => kind === "result_indeterminate")).toHaveLength(1);
    expect(kinds.filter((kind) => kind === "result_expired")).toHaveLength(2);
  });

  it("sweep drops an index entry whose object is gone", async () => {
    const { storage, results } = await openStores();
    await results.putPending(pending(1));
    await storage.delete(LOCAL_RESULTS_NAMESPACE, objectKey(fixtureRequestId(1)));
    expect(await results.sweep(START)).toEqual({ expired: 0, indeterminate: 0, repaired: 1 });
    expect(await results.list({ includeUncommitted: true })).toEqual([]);
  });
});

describe("results store keys", () => {
  it("each store decrypts only with its own purpose key", async () => {
    const MASTER_KEY_BYTES = 32;
    const master = crypto.getRandomValues(new Uint8Array(MASTER_KEY_BYTES));
    const keys = deriveLocalStoreKeys(master);
    master.fill(0);
    expect(Buffer.from(keys.oplogKey).equals(Buffer.from(keys.resultsKey))).toBe(false);
    const storage = new StrictMemoryStorage();
    const oplog = new LocalOplog(storage, keys.oplogKey);
    const results = new LocalResultsStore(storage, keys.resultsKey, oplog);
    cleanups.push(() => { results.close(); oplog.close(); });
    await oplog.ensure();
    await results.ensure();
    await results.putPending(pending(1, Date.now() + MINUTE));
    const bounds = { plaintextMaxBytes: RESULT_OBJECT_MAX_BYTES, sealedMaxBytes: sealedRecordMaxBytes(RESULT_OBJECT_MAX_BYTES) };
    const sealed = (await storage.read(LOCAL_RESULTS_NAMESPACE, objectKey(fixtureRequestId(1))))!;
    expect(openRecord(sealed, keys.resultsKey, objectKey(fixtureRequestId(1)), bounds)).toMatchObject({ state: "pending" });
    expect(() => openRecord(sealed, keys.oplogKey, objectKey(fixtureRequestId(1)), bounds)).toThrow(/authentication/);
    const swappedResults = new LocalResultsStore(storage, keys.oplogKey, oplog);
    cleanups.push(() => swappedResults.close());
    await expect(swappedResults.list({ includeUncommitted: true })).rejects.toMatchObject({ kind: "authentication" });
  });

  it("an object moved to another request id fails authentication", async () => {
    const { storage, results } = await openStores();
    await results.putPending(pending(1));
    await results.putPending(pending(2));
    const first = (await storage.read(LOCAL_RESULTS_NAMESPACE, objectKey(fixtureRequestId(1))))!;
    await storage.write(LOCAL_RESULTS_NAMESPACE, objectKey(fixtureRequestId(2)), first);
    await expect(results.get(fixtureRequestId(2), { includeUncommitted: true })).rejects.toMatchObject({
      kind: "authentication",
    });
  });
});
