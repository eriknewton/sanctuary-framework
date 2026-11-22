// Base witness for the two local-store rotation recipes: this file imports only modules that exist on the
// base branch and seals records in the local stores' format by hand, so on base it fails by assertion
// (rotation preflight refuses the two namespaces as having no recipe), not by a missing import.
import { afterEach, describe, expect, it } from "vitest";
import { decrypt, encrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { rotateMaster } from "../../src/core/master-rotation.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createCustodySessionTracker } from "../helpers/custody-sessions.js";

const PASSPHRASE = "local-store-recipe-witness-passphrase";
const FORTRESS_ID = "fortress-local-store-recipe-witness";
// Literal namespace and purpose labels, written out here so this file needs no module from the branch.
// Must match LOCAL_OPLOG_PURPOSE and LOCAL_RESULTS_PURPOSE in src/local-recompile/store-keys.ts and the
// `_local_oplog` and `_local_results` recipes in src/core/master-rotation.ts.
const STORES = [
  { namespace: "_local_oplog", purpose: "local-oplog-v1", recordKey: "row/1" },
  { namespace: "_local_results", purpose: "local-results-v1", recordKey: "index" },
] as const;

const encoder = new TextEncoder();
const custodySessions = createCustodySessionTracker();
afterEach(() => custodySessions.release());

/** Seal the way the local stores do: AES-GCM under the purpose key, the record key as AAD, JSON envelope bytes. */
function seal(plaintext: string, key: Uint8Array, recordKey: string): Uint8Array {
  return encoder.encode(JSON.stringify(encrypt(encoder.encode(plaintext), key, encoder.encode(recordKey))));
}

function open(sealed: Uint8Array, key: Uint8Array, recordKey: string): string {
  const envelope = JSON.parse(new TextDecoder().decode(sealed)) as EncryptedPayload;
  return new TextDecoder().decode(decrypt(envelope, key, encoder.encode(recordKey)));
}

describe("master rotation recipes for the local stores", () => {
  it("rotation accepts records in both local stores and re-encrypts them under the new master", async () => {
    const storage = new MemoryStorage();
    const established = custodySessions.track(
      await establishMaster({ storage, passphrase: PASSPHRASE, firstRun: { installMode: "interactive", mintRecoveryKey: true } }),
    );
    for (const store of STORES) {
      const key = derivePurposeKey(established.masterKey, store.purpose);
      await storage.write(store.namespace, store.recordKey, seal(`record in ${store.namespace}`, key, store.recordKey));
    }

    await expect(
      rotateMaster({
        storage,
        fortressId: FORTRESS_ID,
        passphrase: PASSPHRASE,
        approve: async () => true,
        captureRecoveryKey: async (recoveryKey, verify) => verify(recoveryKey),
      }),
    ).resolves.toMatchObject({ converted_entries: expect.any(Number) });

    const rotated = custodySessions.track(await establishMaster({ storage, passphrase: PASSPHRASE }));
    for (const store of STORES) {
      const sealed = (await storage.read(store.namespace, store.recordKey))!;
      expect(open(sealed, derivePurposeKey(rotated.masterKey, store.purpose), store.recordKey)).toBe(`record in ${store.namespace}`);
      expect(() => open(sealed, derivePurposeKey(established.masterKey, store.purpose), store.recordKey)).toThrow();
    }
  });
});
