import { afterEach, describe, expect, it, vi } from "vitest";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";

async function fixture() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("sole", encryptionKey, "passphrase");
  encryptionKey.fill(0);
  await new IdentityManager(storage, masterKey).save(storedIdentity);
  return { storage, masterKey, id: storedIdentity.identity_id, manager: new IdentityManager(storage, masterKey) };
}

afterEach(() => vi.restoreAllMocks());

describe("identity load evidence", () => {
  it.each(["null read", "duplicate id", "key mismatch"])("counts a %s before sole proof", async (scenario) => {
    const { storage, masterKey, id, manager } = await fixture();
    try {
      if (scenario === "null read") {
        const read = storage.read.bind(storage);
        vi.spyOn(storage, "read").mockImplementation((ns, key) => ns === "_identities" ? Promise.resolve(null) : read(ns, key));
      } else {
        await storage.write("_identities", "another-key", (await storage.read("_identities", id))!);
        if (scenario === "key mismatch") await storage.delete("_identities", id);
      }
      const evidence = await manager.load();
      expect(evidence.skipped_null_reads).toBe(scenario === "null read" ? 1 : 0);
      expect(evidence.duplicate_ids).toBe(scenario === "duplicate id" ? 1 : 0);
      expect(evidence.key_mismatches).toBe(scenario === "null read" ? 0 : 1);
      expect(evidence.decrypted_keys).toEqual(scenario === "null read" ? [] : scenario === "duplicate id" ? [id, "another-key"].sort() : ["another-key"]);
    } finally { masterKey.fill(0); }
  });

  it("records every validated storage key and keeps load totals", async () => {
    const { masterKey, id, manager } = await fixture();
    try {
      expect(await manager.load()).toEqual({ total: 1, loaded: 1, failed: 0, skipped_null_reads: 0, duplicate_ids: 0, key_mismatches: 0, decrypted_keys: [id] });
    } finally { masterKey.fill(0); }
  });
});
