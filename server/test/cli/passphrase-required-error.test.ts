/**
 * v1.2.1 (Finding FFF): verify the error message says "passphrase required"
 * instead of "corrupted or incomplete installation" when key-params exist
 * but SANCTUARY_PASSPHRASE is unset.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { stringToBytes } from "../../src/core/encoding.js";
import { createSanctuaryServer } from "../../src/index.js";

describe("passphrase-required error (Finding FFF)", () => {
  let originalPassphrase: string | undefined;
  let originalRecoveryKey: string | undefined;

  beforeEach(() => {
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    originalRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
  });

  afterEach(() => {
    if (originalPassphrase !== undefined)
      process.env.SANCTUARY_PASSPHRASE = originalPassphrase;
    else delete process.env.SANCTUARY_PASSPHRASE;
    if (originalRecoveryKey !== undefined)
      process.env.SANCTUARY_RECOVERY_KEY = originalRecoveryKey;
    else delete process.env.SANCTUARY_RECOVERY_KEY;
  });

  it("says 'passphrase required' not 'corrupted'", async () => {
    const storage = new MemoryStorage();
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(
        JSON.stringify({ alg: "argon2id", salt: "abc", m: 65536, t: 3, p: 4, l: 32 }),
      ),
    );

    await expect(createSanctuaryServer({ storage })).rejects.toThrow(
      /passphrase required/i,
    );
    await expect(createSanctuaryServer({ storage })).rejects.not.toThrow(
      /corrupted/i,
    );
  });
});
