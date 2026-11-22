// fail-before-exempt: new store bootstrap module, no base behaviour.
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { ensureLocalStores } from "../../src/local-recompile/ensure-stores.js";
import { LocalOplog } from "../../src/local-recompile/oplog.js";
import { LocalResultsStore } from "../../src/local-recompile/results-store.js";
import { LOCAL_OPLOG_NAMESPACE, type LocalStoreBackend } from "../../src/local-recompile/store-record.js";
import { SHORT_SOCKET_TMP_PARENT } from "../helpers/short-socket-tmp-parent.js";
import { FIXTURE_SEAT, StrictMemoryStorage, fixtureRequestId, fixtureStoreKeys } from "./__fixtures__/strict-memory-storage.js";

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describe("ensureLocalStores", () => {
  it("creates both stores once and verifies them on the second call", async () => {
    const storage = new StrictMemoryStorage();
    const keys = fixtureStoreKeys();
    expect(await ensureLocalStores(storage, keys)).toEqual({ ok: true, oplog: "created", results: "created" });
    const writes = storage.calls.filter((call) => call.op === "write" || call.op === "create").length;
    expect(await ensureLocalStores(storage, keys)).toEqual({ ok: true, oplog: "verified", results: "verified" });
    expect(storage.calls.filter((call) => call.op === "write" || call.op === "create").length).toBe(writes);
  });

  it("refuses a head that does not decrypt", async () => {
    const storage = new StrictMemoryStorage();
    const keys = fixtureStoreKeys();
    await ensureLocalStores(storage, keys);
    const other = fixtureStoreKeys();
    expect(await ensureLocalStores(storage, { oplogKey: other.oplogKey, resultsKey: keys.resultsKey })).toEqual({
      ok: false,
      reason: "authentication",
    });
  });

  it("refuses a log that has an anchor but no head, rather than re-initializing it", async () => {
    const storage = new StrictMemoryStorage();
    const keys = fixtureStoreKeys();
    await ensureLocalStores(storage, keys);
    await storage.delete(LOCAL_OPLOG_NAMESPACE, "head");
    expect(await ensureLocalStores(storage, keys)).toEqual({ ok: false, reason: "invalid_record" });
  });

  it("refuses a backend without the strict lock and writes", async () => {
    const keys = fixtureStoreKeys();
    expect(await ensureLocalStores(new MemoryStorage() as unknown as LocalStoreBackend, keys)).toEqual({
      ok: false,
      reason: "capability",
    });
  });

  it("creates and uses both stores on a filesystem fortress", async () => {
    const base = await realpath(await mkdtemp(join(SHORT_SOCKET_TMP_PARENT, "lre-")));
    cleanups.push(() => rm(base, { recursive: true, force: true }));
    const runtimeRoot = await realpath(await mkdtemp(join(base, "r")));
    const storage = new FilesystemStorage(join(base, "state"));
    const keys = fixtureStoreKeys();
    expect(await ensureLocalStores(storage, keys, { oplog: { runtimeRoot }, results: { runtimeRoot } })).toEqual({
      ok: true,
      oplog: "created",
      results: "created",
    });
    const oplog = new LocalOplog(storage, keys.oplogKey, { runtimeRoot });
    const results = new LocalResultsStore(storage, keys.resultsKey, oplog, { runtimeRoot });
    cleanups.push(() => { results.close(); oplog.close(); });
    const deadline = Date.now() + 60_000;
    await results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline });
    await results.markCommitted(fixtureRequestId(1), { summary: "on disk" });
    expect(await results.get(fixtureRequestId(1))).toMatchObject({ state: "committed", body: { summary: "on disk" } });
    expect(await oplog.verifyChain()).toEqual({ ok: true, base_seq: 0, head_seq: 2 });
    expect(await storage.listKeys("_local_results")).toEqual(expect.arrayContaining(["index", `obj/${fixtureRequestId(1)}`]));
  });
});
