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
// Far more mutations than any one fixture operation makes; a loop that reaches it fails instead of hanging.
const MAX_CRASH_POINTS = 64;
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

function open(
  storage: StrictMemoryStorage,
  keys: { oplogKey: Uint8Array; resultsKey: Uint8Array },
  clock: { now: number },
  maxTotalBytes = FIXTURE_MAX_TOTAL_BYTES,
) {
  const now = () => clock.now;
  const oplog = new LocalOplog(storage, keys.oplogKey, { now });
  const results = new LocalResultsStore(storage, keys.resultsKey, oplog, { now, caps: { maxTotalBytes } });
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
async function expectCrashConsistent(storage: StrictMemoryStorage, resultsKey: Uint8Array, label: string, cap = FIXTURE_MAX_TOTAL_BYTES) {
  const { index, objects } = await raw(storage, resultsKey);
  for (const [id, object] of objects) {
    const entry = index.find((candidate) => candidate.request_id === id);
    expect(entry, `${label}: object ${id} is reachable from the index`).toBeDefined();
    expect(entry!.bytes, `${label}: entry ${id} never undercounts its object`).toBeGreaterThanOrEqual(
      canonicalBytes(object, RESULT_OBJECT_MAX_BYTES).length,
    );
  }
  expect(indexTotal(index), `${label}: index total within the cap`).toBeLessThanOrEqual(cap);
}

function indexTotal(index: RawEntry[]): number {
  return index.reduce((sum, entry) => sum + entry.bytes, 0);
}

/** The store's own list agrees with the objects' states, whatever an entry's copy says. */
async function expectListFollowsObjects(storage: StrictMemoryStorage, results: LocalResultsStore, resultsKey: Uint8Array, label: string) {
  const { objects } = await raw(storage, resultsKey);
  const committed = [...objects.values()].filter((object) => object.state === "committed").map((object) => object.request_id);
  expect((await results.list()).map((object) => object.request_id).sort(), label).toEqual(committed.sort());
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

/**
 * Run `operation` with a crash injected before mutation number `crashAt`; true when it finished first.
 * Only a failure that follows the injected crash counts as the crash (the store maps the storage error
 * to its own kind); any other failure is rethrown, so a regression fails the test.
 */
async function withCrashAt(storage: StrictMemoryStorage, crashAt: number, operation: () => Promise<unknown>): Promise<boolean> {
  let count = 0;
  let crashed = false;
  storage.beforeMutation = () => {
    if (count++ === crashAt) {
      crashed = true;
      throw new FixtureCrash("fixture crash");
    }
  };
  let finished = false;
  try {
    await operation();
    finished = true;
  } catch (error) {
    if (!crashed) throw error;
  } finally {
    storage.beforeMutation = () => undefined;
  }
  // Outside the try, so this check can fail: an operation that finished must not have swallowed the crash.
  if (finished) expect(crashed, "an operation that finished never saw the crash").toBe(false);
  return finished;
}

/** One pending object A and one committed object B; returns the index total, so a store can be opened exactly full. */
async function pendingBesideCommitted(storage: StrictMemoryStorage, keys: { oplogKey: Uint8Array; resultsKey: Uint8Array }, clock: { now: number }) {
  const setup = open(storage, keys, clock);
  await setup.oplog.ensure();
  await setup.results.ensure();
  await setup.results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
  clock.now += 1;
  await setup.results.putPending({ request_id: fixtureRequestId(2), seat: FIXTURE_SEAT, kind: "summarize", deadline: START + MINUTE });
  await setup.results.markCommitted(fixtureRequestId(2), { summary: "b".repeat(BODY_CHARS) });
  return indexTotal((await raw(storage, keys.resultsKey)).index);
}

describe("results store crash consistency", () => {
  it("a commit that evicts keeps the index and the object in agreement under a crash at any write", async () => {
    let crashPoints = 0;
    let finishedAt = -1;
    for (let crashAt = 0; crashAt < MAX_CRASH_POINTS && finishedAt < 0; crashAt += 1) {
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
      // Before any repair, the crashed store's own list already follows the objects.
      await expectListFollowsObjects(storage, first.results, keys.resultsKey, `list after crash before write ${crashAt}`);
      // A restarted store's boot brings the index into exact agreement with the objects, before any sweep.
      const restarted = open(storage, keys, clock);
      await restarted.oplog.ensure();
      await restarted.results.ensure();
      await expectAgreement(storage, keys.resultsKey, `booted after write ${crashAt}`);
      await restarted.results.sweep();
      await expectAgreement(storage, keys.resultsKey, `swept after write ${crashAt}`);
      if (finished) {
        expect(await restarted.results.get(fixtureRequestId(1))).toMatchObject({ state: "committed" });
        expect(await restarted.results.get(fixtureRequestId(2), { includeUncommitted: true })).toBeNull();
        finishedAt = crashAt;
      } else {
        crashPoints += 1;
      }
    }
    expect(finishedAt, "the commit finished within the crash-point bound").toBeGreaterThanOrEqual(0);
    // The commit evicts, logs and writes several records, so several crash points were exercised.
    expect(crashPoints).toBeGreaterThan(3);
  });

  it("a pending object that becomes indeterminate stays consistent under a crash at any write", async () => {
    let finishedAt = -1;
    for (let crashAt = 0; crashAt < MAX_CRASH_POINTS && finishedAt < 0; crashAt += 1) {
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
      await restarted.oplog.ensure();
      await restarted.results.ensure();
      await expectAgreement(storage, keys.resultsKey, `booted after write ${crashAt}`);
      await restarted.results.sweep();
      await expectAgreement(storage, keys.resultsKey, `recovered after write ${crashAt}`);
      // Whatever the crash point, the object ends indeterminate and a late completion is refused.
      expect(await restarted.results.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({ state: "indeterminate" });
      await expect(restarted.results.markCommitted(fixtureRequestId(1), { summary: "late" })).rejects.toMatchObject({ kind: "conflict" });
      if (finished) finishedAt = crashAt;
    }
    expect(finishedAt, "the sweep finished within the crash-point bound").toBeGreaterThanOrEqual(0);
  });

  it("an indeterminate transition in a full store makes room and stays consistent under a crash at any write", async () => {
    let finishedAt = -1;
    for (let crashAt = 0; crashAt < MAX_CRASH_POINTS && finishedAt < 0; crashAt += 1) {
      const storage = new StrictMemoryStorage();
      const keys = fixtureStoreKeys();
      const clock = { now: START };
      const cap = await pendingBesideCommitted(storage, keys, clock);
      const full = open(storage, keys, clock, cap);
      clock.now = START + MINUTE + PENDING_GRACE_MS;
      const finished = await withCrashAt(storage, crashAt, () => full.results.sweep());
      await expectCrashConsistent(storage, keys.resultsKey, `crash before write ${crashAt}`, cap);
      const restarted = open(storage, keys, clock, cap);
      await restarted.oplog.ensure();
      await restarted.results.ensure();
      await restarted.results.sweep();
      await expectAgreement(storage, keys.resultsKey, `recovered after write ${crashAt}`);
      expect(indexTotal((await raw(storage, keys.resultsKey)).index)).toBeLessThanOrEqual(cap);
      expect(await restarted.results.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({ state: "indeterminate" });
      if (finished) finishedAt = crashAt;
    }
    expect(finishedAt, "the sweep finished within the crash-point bound").toBeGreaterThanOrEqual(0);
  });
});

describe("results store crash harness", () => {
  it("fails when an operation finishes after swallowing the injected crash", async () => {
    const storage = new StrictMemoryStorage();
    const swallowing = async () => {
      await storage.delete(LOCAL_RESULTS_NAMESPACE, "fixture").catch(() => undefined);
    };
    await expect(withCrashAt(storage, 0, swallowing)).rejects.toThrow("never saw the crash");
  });
});

describe("results store byte cap", () => {
  it("a pending object that becomes indeterminate in an exactly full store keeps the index within the cap", async () => {
    const storage = new StrictMemoryStorage();
    const keys = fixtureStoreKeys();
    const clock = { now: START };
    const cap = await pendingBesideCommitted(storage, keys, clock);
    const { results } = open(storage, keys, clock, cap);
    clock.now = START + MINUTE + PENDING_GRACE_MS;
    await results.sweep();
    const { index } = await raw(storage, keys.resultsKey);
    expect(indexTotal(index)).toBeLessThanOrEqual(cap);
    expect(await results.get(fixtureRequestId(1), { includeUncommitted: true })).toMatchObject({ state: "indeterminate" });
    // The committed object was the only other entry, so it made the room.
    expect(await results.get(fixtureRequestId(2), { includeUncommitted: true })).toBeNull();
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
