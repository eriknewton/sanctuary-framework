/**
 * Purpose keys for the operator log and the results store.
 *
 * Only the master-key holder (the server and the operator CLI) imports this
 * file; the job worker receives the two derived keys and never reaches it.
 */
import { derivePurposeKey } from "../core/key-derivation.js";

// Must match the `_local_oplog` purpose-encrypted recipe in core/master-rotation.ts.
export const LOCAL_OPLOG_PURPOSE = "local-oplog-v1";
// Must match the `_local_results` purpose-encrypted recipe in core/master-rotation.ts.
export const LOCAL_RESULTS_PURPOSE = "local-results-v1";

export interface LocalStoreKeys {
  oplogKey: Uint8Array;
  resultsKey: Uint8Array;
}

/** Derive both store keys from the master key; the caller zeroes them when done. */
export function deriveLocalStoreKeys(masterKey: Uint8Array): LocalStoreKeys {
  return {
    oplogKey: derivePurposeKey(masterKey, LOCAL_OPLOG_PURPOSE),
    resultsKey: derivePurposeKey(masterKey, LOCAL_RESULTS_PURPOSE),
  };
}
