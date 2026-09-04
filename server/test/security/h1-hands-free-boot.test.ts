/**
 * H1 (wired-consumer): the headline "hands-free memory reads after restart" only
 * holds if the MCP server, given NO credential env, resolves the EXACT-fortress
 * stored credential (OS keyring / custody key) read-only at boot and unlocks the
 * existing fortress. Before this build the boot path supplied only
 * SANCTUARY_PASSPHRASE / SANCTUARY_RECOVERY_KEY, so a host whose passphrase was
 * already stored by `protect` could not boot hands-free — the claim had no
 * production call site.
 *
 * This test constructs the real boot object graph (createSanctuaryServer) with
 * ONLY a stored keyring credential (an in-memory keychain fake injected at the
 * exact read-only seam the CLI verbs use) and asserts it comes up and reads a
 * memory item with no credential env. A planted divergence proves that removing
 * the stored credential (nothing resolvable) fails the boot CLOSED rather than
 * minting a fresh master over the existing state.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  stringToBytes,
  bytesToString,
  constantTimeEqual,
} from "../../src/core/encoding.js";
import { encrypt, decrypt } from "../../src/core/encryption.js";
import { deriveNamespaceKey } from "../../src/core/key-derivation.js";
import { createSanctuaryServer } from "../../src/index.js";
import type { readStoredPassphrase } from "../../src/wrap/passphrase.js";
import { createTempHome } from "../helpers/temp-fortress.js";

let saved: { pass?: string; rec?: string };
let fortressHome: Awaited<ReturnType<typeof createTempHome>>;

beforeEach(async () => {
  saved = {
    pass: process.env.SANCTUARY_PASSPHRASE,
    rec: process.env.SANCTUARY_RECOVERY_KEY,
  };
  delete process.env.SANCTUARY_PASSPHRASE;
  delete process.env.SANCTUARY_RECOVERY_KEY;
  fortressHome = await createTempHome("sanctuary-h1");
});

afterEach(async () => {
  if (saved.pass !== undefined) process.env.SANCTUARY_PASSPHRASE = saved.pass;
  else delete process.env.SANCTUARY_PASSPHRASE;
  if (saved.rec !== undefined) process.env.SANCTUARY_RECOVERY_KEY = saved.rec;
  else delete process.env.SANCTUARY_RECOVERY_KEY;
  await fortressHome.cleanup();
});

/** In-memory keychain fake at the readStoredPassphrase seam. */
function storedPassphraseFake(value: string | null): typeof readStoredPassphrase {
  return (async () =>
    value === null
      ? null
      : { value, source: "keychain" as const, location: "test-keychain" }) as
    typeof readStoredPassphrase;
}

describe("H1: hands-free MCP boot via the exact-fortress stored credential", () => {
  it("boots and reads a memory item with ONLY a stored keyring credential (no env)", async () => {
    const storage = new MemoryStorage();
    const PASSPHRASE = "h1-hands-free-fortress-passphrase";

    // Run 1: create the fortress WITH the passphrase (as `protect`/first run
    // would), then write a memory item encrypted under the fortress master.
    const run1 = await createSanctuaryServer({ storage, passphrase: PASSPHRASE });
    const nsKey1 = deriveNamespaceKey(run1.masterKey, "memory-ns");
    const payload = encrypt(stringToBytes("remembered-after-restart"), nsKey1);
    await storage.write(
      "memory-ns",
      "note-1",
      stringToBytes(JSON.stringify(payload)),
    );

    // Run 2 (RESTART): no passphrase option, no credential env — only the stored
    // keyring credential, delivered through the read-only boot seam H1 added.
    const run2 = await createSanctuaryServer({
      storage,
      __testReadStoredPassphrase: storedPassphraseFake(PASSPHRASE),
    });

    // Same master recovered hands-free.
    expect(constantTimeEqual(run1.masterKey, run2.masterKey)).toBe(true);

    // The memory item reads back with the hands-free-recovered master.
    const nsKey2 = deriveNamespaceKey(run2.masterKey, "memory-ns");
    const raw = await storage.read("memory-ns", "note-1");
    expect(raw).not.toBeNull();
    const decrypted = decrypt(JSON.parse(bytesToString(raw!)), nsKey2);
    expect(bytesToString(decrypted)).toBe("remembered-after-restart");
  });

  it("PLANTED DIVERGENCE: no resolvable stored credential fails the boot CLOSED (never mints over data)", async () => {
    const storage = new MemoryStorage();
    const PASSPHRASE = "h1-hands-free-fortress-passphrase-2";

    // Existing fortress with an envelope.
    await createSanctuaryServer({ storage, passphrase: PASSPHRASE });

    // Restart with the stored-credential fake returning NOTHING and no env. H1
    // must refuse rather than mint a new master over the existing envelope.
    await expect(
      createSanctuaryServer({
        storage,
        __testReadStoredPassphrase: storedPassphraseFake(null),
      }),
    ).rejects.toThrow(/hands-free|no credential|Refusing/i);
  });
});
