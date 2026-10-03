/**
 * Checkpoint reconstruction requires the verified writer's resident signing key.
 * LEGACY-BUG-001
 */
import { describe, expect, it } from "vitest";
import { StateStore } from "../../src/cognitive/state-store.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { persistStoredIdentity } from "../util/persist-stored-identity.js";

describe("checkpoint import writer binding", () => {
  for (const condition of ["missing", "replaced"] as const) {
    it(`refuses ${condition} resident writer material without rewriting state or floors`, async () => {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const encKey = derivePurposeKey(masterKey, "identity-encryption");
      const { storedIdentity: identity } = createIdentity("writer", encKey, "recovery-key");
      const state = new StateStore(storage, masterKey);
      const write = (value: string) => state.write(
        "notes", "key", value, identity.identity_id, identity.encrypted_private_key, encKey,
      );
      await write("checkpoint");
      const { bundle } = await state.export("notes");
      await write("current");
      if (condition === "replaced") {
        const { storedIdentity: replacement } = createIdentity("replacement", encKey, "recovery-key");
        await persistStoredIdentity(storage, masterKey, {
          ...identity, encrypted_private_key: replacement.encrypted_private_key,
        });
      }
      const before = await storage.read("notes", "key");
      const metadata = await storage.list("_meta");
      const floors = await Promise.all(metadata.map(({ key }) => storage.read("_meta", key)));
      await expect(new StateStore(storage, masterKey).import(
        bundle, "overwrite", () => fromBase64url(identity.public_key), { restoreAsNewVersions: true },
      )).rejects.toMatchObject({ classification: "writer_unverified" });
      expect(await storage.read("notes", "key")).toEqual(before);
      expect(await Promise.all(metadata.map(({ key }) => storage.read("_meta", key)))).toEqual(floors);
    });
  }
});
