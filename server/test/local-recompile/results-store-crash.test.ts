// fail-before-exempt: new results-store module, no base behaviour.
import { afterEach, describe, expect, it } from "vitest";
import { LocalOplog } from "../../src/local-recompile/oplog.js";
import {
  LocalResultsStore,
  PENDING_GRACE_MS,
  RESULT_OBJECT_MAX_BYTES,
  RESULTS_MAX_OBJECTS,
  type LocalResultObject,
} from "../../src/local-recompile/results-store.js";
import {
  LOCAL_RESULTS_NAMESPACE,
  canonicalBytes,
  openRecord,
  sealedRecordMaxBytes,
} from "../../src/local-recompile/store-record.js";
import { FIXTURE_SEAT, StrictMemoryStorage, fixtureRequestId, fixtureStoreKeys } from "./__fixtures__/strict-memory-storage.js";

const START = Date.UTC(2026, 0, 1);
const MINUTE = 60_000;
// One committed body of this many characters fills most of the fixture byte cap below.
const BODY_CHARS = 1_000;
// Room for one committed object plus one pending object, but not two committed objects.
const FIXTURE_MAX_TOTAL_BYTES = 2_000;
// Far above any fixture index or object; the reader only needs to open what the store sealed.
const READ_BOUNDS = {
  plaintextMaxBytes: RESULTS_MAX_OBJECTS * RESULT_OBJECT_MAX_BYTES,
  sealedMaxBytes: sealedRecordMaxBytes(RESULTS_MAX_OBJECTS * RESULT_OBJECT_MAX_BYTES),
};

class FixtureCrash extends Error {}

const cleanups: Array<() => void> = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

function open(storage: StrictMemoryStorage, keys: { oplogKey: Uint8Array; resultsKey: Uint8Array }, clock: { now: number }) {
  const now = () => clock.now;
  const oplog = new LocalOplog(storage, keys.oplogKey, { now });
  const results = new LocalResultsStore(storage, keys.resultsKey, oplog, { now, caps: { maxTotalBytes: FIXTURE_MAX_TOTAL_BYTES } });
  cleanups.push(() => {
    results.close();
    oplog.close();
  });
  return { oplog, results };
}

interface RawEntry { request_id: string; state: string; bytes: number }

/** Read the store's records directly, independent of the store's own read path. */
async function raw(storage: StrictMemoryStorage, resultsKey: Uint8Array) {
  const indexBytes = await storage.read(LOCAL_RESULTS_NAMESPACE, "index");
  const index = (openRecord(indexBytes!, resultsKey, "index", READ_BOUNDS) as { entries: RawEntry[] }).entries;
  const objects = new Map<string, LocalResultObject>();
  for (const key of await storage.listKeys(LOCAL_RESULTS_NAMESPACE, "obj/")) {
    const sealed = await storage.read(LOCAL_RESULTS_NAMESPACE, key);
    objects.set(key.slice("obj/".length), openRecord(sealed!, resultsKey, key, READ_BOUNDS) as LocalResultObject);
  }
  return { index, objects };
}

/** Reachability and size under a crash: every object has an entry, and no entry undercounts its object. */
async function expectCrashConsistent(storage: StrictMemoryStorage, resultsKey: Uint8Array, label: string) {
  const { index, objects } = await raw(storage, resultsKey);
  for (const [id, object] of objects) {
    const entry = index.find((candidate) => candidate.request_id === id);
    expect(entry, `${label}: object ${id} is reachable from the index`).toBeDefined();
    expect(entry!.bytes, `${label}: entry ${id} never undercounts its object`).toBeGreaterThanOrEqual(
      canonicalBytes(object, RESULT_OBJECT_MAX_BYTES).length,
    );
  }
  expect(index.reduce((sum, entry) => sum + entry.bytes, 0), `${label}: index total within the cap`).toBeLessThanOrEqual(FIXTURE_MAX_TOTAL_BYTES);
}

/** After recovery housekeeping the index agrees with every object exactly. */
async function expectAgreement(storage: StrictMemoryStorage, resultsKey: Uint8Array, label: string) {
  const { index, objects } = await raw(storage, resultsKey);
  expect(index.map((entry) => entry.request_id).sort(), label).toEqual([...objects.keys()].sort());
  for (const entry of index) {
    const object = objects.get(entry.request_id)!;
    expect({ state: entry.state, bytes: entry.bytes }, `${label}: ${entry.request_id}`).toEqual({
      state: object.state,
      bytes: canonicalBytes(object, RESULT_OBJECT_MAX_BYTES).length,
    });
  }
}

/** Run `operation` with a crash injected before mutation number `crashAt`; true when it finished first. */
async function withCrashAt(storage: StrictMemoryStorage, crashAt: number, operation: () => Promise<unknown>): Promise<boolean> {
  let count = 0;
  storage.beforeMutation = () => {
    if (count++ === crashAt) throw new FixtureCrash("fixture crash");
  };
  try {
    await operation();
    return true;
  } catch {
    return false;
  } finally {
    storage.beforeMutation = () => undefined;
  }
}

describe("results store crash consistency", () => {
  it("a commit that evicts keeps the index and the object in agreement under a crash at any write", async () => {
    let crashPoints = 0;
    for (let crashAt = 0; ; crashAt += 1) {
      const storage = new StrictMemoryStorage();
      const keys = fixtureStoreKeys();
      const clock = { now: START };
      const first = open(storage, keys, clock);
      await first.oplog.ensure();
      await first.results.ensure();
      // An older committed object B, then a pending A whose commit needs B's room.
      await first.results.putPending({ request_id: fixtureRequestId(2), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
      await first.results.markCommitted(fixtureRequestId(2), { summary: "b".repeat(BODY_CHARS) });
      clock.now += 1;
      await first.results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
      const finished = await withCrashAt(storage, crashAt, () =>
        first.results.markCommitted(fixtureRequestId(1), { summary: "a".repeat(BODY_CHARS) }),
      );
      await expectCrashConsistent(storage, keys.resultsKey, `crash before write ${crashAt}`);
      // A restarted store's housekeeping brings the index into exact agreement with the objects.
      const restarted = open(storage, keys, clock);
      await restarted.results.sweep();
      await expectAgreement(storage, keys.resultsKey, `recovered after write ${crashAt}`);
      if (finished) {
        expect(await restarted.results.get(fixtureRequestId(1))).toMatchObject({ state: "committed" });
        expect(await restarted.results.get(fixtureRequestId(2), { includeUncommitted: true })).toBeNull();
        break;
      }
      crashPoints += 1;
    }
    // The commit evicts, logs and writes several records, so several crash points were exercised.
    expect(crashPoints).toBeGreaterThan(3);
  });

  it("a pending object that becomes indeterminate stays consistent under a crash at any write", async () => {
    for (let crashAt = 0; ; crashAt += 1) {
      const storage = new StrictMemoryStorage();
      const keys = fixtureStoreKeys();
      const clock = { now: START };
      const first = open(storage, keys, clock);
      await first.oplog.ensure();
      await first.results.ensure();
      await first.results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
      clock.now = START + MINUTE + PENDING_GRACE_MS;
      const finished = await withCrashAt(storage, crashAt, () => first.results.sweep());
      await expectCrashConsistent(storage, keys.resultsKey, `crash before write ${crashAt}`);
      const restarted = open(storage, keys, clock);
      await restarted.results.sweep();
      await expectAgreement(storage, keys.resultsKey, `recovered after write ${crashAt}`);
      // Whatever the crash point, the object ends indeterminate and a late completion is refused.
      expect(await restarted.results.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({ state: "indeterminate" });
      await expect(restarted.results.markCommitted(fixtureRequestId(1), { summary: "late" })).rejects.toMatchObject({ kind: "conflict" });
      if (finished) break;
    }
  });
});

describe("results store commit refusals", () => {
  it("a completion past the deadline plus grace is refused even before a sweep runs", async () => {
    const storage = new StrictMemoryStorage();
    const keys = fixtureStoreKeys();
    const clock = { now: START };
    const { oplog, results } = open(storage, keys, clock);
    await oplog.ensure();
    await results.ensure();
    await results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
    clock.now = START + MINUTE + PENDING_GRACE_MS;
    await expect(results.markCommitted(fixtureRequestId(1), { summary: "late" })).rejects.toMatchObject({ kind: "conflict" });
    expect(await results.get(fixtureRequestId(1))).toBeNull();
  });

  it("a body with an own __proto__ field is refused", async () => {
    const storage = new StrictMemoryStorage();
    const keys = fixtureStoreKeys();
    const clock = { now: START };
    const { oplog, results } = open(storage, keys, clock);
    await oplog.ensure();
    await results.ensure();
    await results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
    // JSON.parse creates an own enumerable "__proto__" property, the shape a job reply would carry;
    // the commit's re-validation of the copied body refuses it.
    const body = JSON.parse('{"summary":"text","__proto__":["a"]}') as Record<string, string | string[]>;
    expect(Object.keys(body)).toContain("__proto__");
    await expect(results.markCommitted(fixtureRequestId(1), body)).rejects.toMatchObject({ kind: "invalid_record" });
  });

  it("a body with an own string-valued __proto__ field is refused, not committed without it", async () => {
    const storage = new StrictMemoryStorage();
    const keys = fixtureStoreKeys();
    const clock = { now: START };
    const { oplog, results } = open(storage, keys, clock);
    await oplog.ensure();
    await results.ensure();
    await results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
    // A string assigned through the prototype setter is ignored, so a copied body would silently lose the field.
    const body = JSON.parse('{"summary":"text","__proto__":"field"}') as Record<string, string>;
    expect(Object.keys(body)).toContain("__proto__");
    await expect(results.markCommitted(fixtureRequestId(1), body)).rejects.toMatchObject({ kind: "invalid_record" });
    expect(await results.get(fixtureRequestId(1))).toBeNull();
  });
});
