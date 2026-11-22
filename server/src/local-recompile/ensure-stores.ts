/**
 * Boot-time creation and verification of both local stores. 1b calls this at
 * boot and keeps the local job tools disarmed on any refusal.
 */
import { LocalOplog, type OplogOptions } from "./oplog.js";
import { LocalResultsStore, type ResultsStoreOptions } from "./results-store.js";
import { toLocalStoreError, type LocalStoreBackend, type LocalStoreFailure } from "./store-record.js";

export interface LocalStoreKeyPair {
  oplogKey: Uint8Array;
  resultsKey: Uint8Array;
}

export type EnsureLocalStoresResult =
  | { ok: true; oplog: "created" | "verified"; results: "created" | "verified" }
  | { ok: false; reason: LocalStoreFailure };

/** Create each store when absent and verify it when present; refusals carry only a closed kind. */
export async function ensureLocalStores(
  storage: LocalStoreBackend,
  keys: LocalStoreKeyPair,
  options: { oplog?: OplogOptions; results?: ResultsStoreOptions } = {},
): Promise<EnsureLocalStoresResult> {
  let oplog: LocalOplog | undefined;
  let results: LocalResultsStore | undefined;
  try {
    oplog = new LocalOplog(storage, keys.oplogKey, options.oplog);
    results = new LocalResultsStore(storage, keys.resultsKey, oplog, options.results);
    const oplogState = await oplog.ensure();
    const resultsState = await results.ensure();
    return { ok: true, oplog: oplogState, results: resultsState };
  } catch (error) {
    return { ok: false, reason: toLocalStoreError(error).kind };
  } finally {
    results?.close();
    oplog?.close();
  }
}
