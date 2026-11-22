// fail-before-exempt: sole proof is a new module; identity-load-evidence.test.ts witnesses the additive counters against base.
import { afterEach, describe, expect, it, vi } from "vitest";
import { collectSoleProofInputs, proveSoleIdentity } from "../../src/agent-native/session-binding.js";
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

describe("sole identity proof", () => {
  it.each(["null read", "duplicate id", "key mismatch", "unstable relist", "dropped candidate"])(
    "a null read, a duplicate id, a key mismatch, an unstable relist, or a candidate dropped by `load()`'s own listing each prevent sole proof",
    async (scenario) => {
      const { storage, masterKey, id, manager } = await fixture();
      try {
        if (scenario === "null read") {
          const read = storage.read.bind(storage);
          vi.spyOn(storage, "read").mockImplementation((ns, key) => ns === "_identities" ? Promise.resolve(null) : read(ns, key));
        } else if (scenario === "duplicate id" || scenario === "key mismatch") {
          await storage.write("_identities", "another-key", (await storage.read("_identities", id))!);
          if (scenario === "key mismatch") await storage.delete("_identities", id);
        } else if (scenario === "unstable relist") {
          vi.spyOn(storage, "listKeys").mockResolvedValueOnce([id]).mockResolvedValueOnce([id, "another-key"]);
        } else {
          vi.spyOn(storage, "listKeys").mockResolvedValue([id, "dropped"]);
        }
        expect(proveSoleIdentity(await collectSoleProofInputs(storage, manager)).proven).toBe(false);
      } finally { masterKey.fill(0); }
    },
  );

  it("a single decrypted record that is not the enumerated key is unproven", async () => {
    const { storage, manager, masterKey, id } = await fixture();
    try {
      // Both enumerations agree on one key; the one record that decrypts is a different key, so only element equality refuses.
      vi.spyOn(storage, "listKeys").mockResolvedValue(["enumerated-elsewhere"]);
      const inputs = await collectSoleProofInputs(storage, manager);
      expect(inputs.evidence).toMatchObject({ total: 1, loaded: 1, key_mismatches: 0, decrypted_keys: [id] });
      expect(proveSoleIdentity(inputs)).toMatchObject({ proven: false, state: "state_UNBOUND_UNPROVEN" });
    } finally { masterKey.fill(0); }
  });

  it("a backend without listKeys cannot prove sole", async () => {
    const { manager, masterKey } = await fixture();
    try {
      const load = vi.spyOn(manager, "load");
      expect(proveSoleIdentity(await collectSoleProofInputs({}, manager))).toMatchObject({ proven: false, state: "state_UNBOUND_UNPROVEN" });
      expect(load).toHaveBeenCalledOnce();
    } finally { masterKey.fill(0); }
  });

  it("exactly one clean record is proven", async () => {
    const { storage, manager, masterKey, id } = await fixture();
    try {
      expect(proveSoleIdentity(await collectSoleProofInputs(storage, manager))).toEqual({ proven: true, identity_id: id });
    } finally { masterKey.fill(0); }
  });

  it.each(["before", "after"])("an enumeration failure %s loading remains unproven", async (stage) => {
    const { storage, manager, masterKey, id } = await fixture();
    try {
      const list = vi.spyOn(storage, "listKeys");
      if (stage === "after") list.mockResolvedValueOnce([id]);
      list.mockRejectedValueOnce(new Error("enumeration unavailable"));
      expect(proveSoleIdentity(await collectSoleProofInputs(storage, manager))).toMatchObject({ proven: false, state: "state_UNBOUND_UNPROVEN" });
    } finally { masterKey.fill(0); }
  });

  it("a load failure propagates to the caller", async () => {
    const failure = new Error("load failed");
    await expect(collectSoleProofInputs({}, { load: async () => { throw failure; } })).rejects.toBe(failure);
  });

  it("a comparison failure remains unproven", async () => {
    const { storage, manager, masterKey } = await fixture();
    try {
      const inputs = await collectSoleProofInputs(storage, manager);
      Object.defineProperty(inputs.evidence, "decrypted_keys", { get() { throw new Error("unreadable evidence"); } });
      expect(proveSoleIdentity(inputs)).toMatchObject({ proven: false, state: "state_UNBOUND_UNPROVEN" });
    } finally { masterKey.fill(0); }
  });

  it.each(["empty", "several", "invalid record"])("classifies an %s identity set", async (scenario) => {
    const { storage, manager, masterKey, id } = await fixture();
    try {
      if (scenario === "empty") await storage.delete("_identities", id);
      else await storage.write("_identities", scenario === "several" ? "another-key" : id, new TextEncoder().encode("invalid"));
      expect(proveSoleIdentity(await collectSoleProofInputs(storage, manager))).toMatchObject({ proven: false, state: scenario === "empty" ? "state_UNBOUND_NO_IDENTITY" : scenario === "several" ? "state_UNBOUND_SEVERAL_IDENTITIES" : "state_UNBOUND_UNPROVEN" });
    } finally { masterKey.fill(0); }
  });
});
