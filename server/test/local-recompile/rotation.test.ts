// fail-before-exempt: new local stores; this file imports branch modules, so on base it fails by import.
// The base witness for the two rotation recipes is rotation-recipe-witness.test.ts, which fails on base by assertion.
import { afterEach, describe, expect, it } from "vitest";
import { establishMaster } from "../../src/core/master-custody.js";
import { rotateMaster } from "../../src/core/master-rotation.js";
import { LocalOplog } from "../../src/local-recompile/oplog.js";
import { LocalResultsStore } from "../../src/local-recompile/results-store.js";
import { deriveLocalStoreKeys, type LocalStoreKeys } from "../../src/local-recompile/store-keys.js";
import { createCustodySessionTracker } from "../helpers/custody-sessions.js";
import { FIXTURE_SEAT, StrictMemoryStorage, fixtureRequestId } from "./__fixtures__/strict-memory-storage.js";

const PASSPHRASE = "local-store-rotation-passphrase";
const FORTRESS_ID = "fortress-local-store-rotation";
const custodySessions = createCustodySessionTracker();
const opened: Array<{ close(): void }> = [];
afterEach(() => {
  for (const store of opened.splice(0).reverse()) store.close();
  custodySessions.release();
});

function openStores(storage: StrictMemoryStorage, keys: LocalStoreKeys) {
  const oplog = new LocalOplog(storage, keys.oplogKey);
  const results = new LocalResultsStore(storage, keys.resultsKey, oplog);
  opened.push(oplog, results);
  return { oplog, results };
}

async function fortressWithLocalStores() {
  const storage = new StrictMemoryStorage();
  const established = custodySessions.track(
    await establishMaster({ storage, passphrase: PASSPHRASE, firstRun: { installMode: "interactive", mintRecoveryKey: true } }),
  );
  const keys = deriveLocalStoreKeys(established.masterKey);
  const { oplog, results } = openStores(storage, keys);
  await oplog.ensure();
  await results.ensure();
  await oplog.append("worker_spawned", { pid: 4242 });
  await results.putPending({ request_id: fixtureRequestId(1), seat: FIXTURE_SEAT, kind: "summarize", deadline: Date.now() + 60_000 });
  await results.markCommitted(fixtureRequestId(1), { summary: "survives rotation" });
  return { storage, oldKeys: keys };
}

async function rotate(storage: StrictMemoryStorage) {
  return rotateMaster({
    storage,
    fortressId: FORTRESS_ID,
    passphrase: PASSPHRASE,
    approve: async () => true,
    captureRecoveryKey: async (recoveryKey, verify) => verify(recoveryKey),
  });
}

describe("master rotation over the local stores", () => {
  it("rotation preflight accepts a fortress holding the local stores", async () => {
    const { storage } = await fortressWithLocalStores();
    await expect(rotate(storage)).resolves.toMatchObject({ converted_entries: expect.any(Number) });
  });

  it("master rotation re-encrypts both stores and the chain still verifies", async () => {
    const { storage, oldKeys } = await fortressWithLocalStores();
    await rotate(storage);
    const established = custodySessions.track(await establishMaster({ storage, passphrase: PASSPHRASE }));
    const newKeys = deriveLocalStoreKeys(established.masterKey);
    expect(Buffer.from(newKeys.oplogKey).equals(Buffer.from(oldKeys.oplogKey))).toBe(false);

    const rotated = openStores(storage, newKeys);
    expect(await rotated.oplog.verifyChain()).toMatchObject({ ok: true, base_seq: 0 });
    expect(await rotated.results.get(fixtureRequestId(1))).toMatchObject({ body: { summary: "survives rotation" } });
    await rotated.oplog.append("operator_render", { request_id: fixtureRequestId(1) });
    expect(await rotated.oplog.verifyChain()).toMatchObject({ ok: true });

    const stale = openStores(storage, oldKeys);
    await expect(stale.oplog.verifyChain()).rejects.toMatchObject({ kind: "authentication" });
    await expect(stale.results.list()).rejects.toMatchObject({ kind: "authentication" });
  });
});
