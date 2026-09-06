/**
 * L1 (Grok re-gate residual): `createSanctuaryServer` reads an OS-keyring custody
 * key at hands-free boot and passes it to `establishMaster` as `keychainKey`.
 * The `bootKeychainKey.fill(0)` that wipes that factor ran only AFTER a
 * successful `establishMaster`; when establishment THREW (wrong keychain factor,
 * rotation-in-progress, orphaned state) the factor stayed live in process memory
 * on the rejected path. The fix zeroes it in a `finally`, so it is wiped on both
 * the success and the throw path (MUST-NEVER 6 — no key material lingers past the
 * operation that needed it).
 *
 * This test injects a keychain custody factor at the exact boot seam, forces
 * establishment to reject (the fortress envelope has no keychain wrap, so the
 * injected key cannot unlock it), and asserts the injected buffer was zeroed.
 * Against the pre-fix source the buffer keeps its bytes after the rejection.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";

import { MemoryStorage } from "../../src/storage/memory.js";
import { createSanctuaryServer } from "../../src/index.js";
import type { readStoredPassphrase } from "../../src/wrap/passphrase.js";
import type { readKeychainCustodyKeyStatus } from "../../src/wrap/keychain-custody.js";
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
  fortressHome = await createTempHome("sanctuary-l1-keychain-zeroize");
});

afterEach(async () => {
  if (saved.pass !== undefined) process.env.SANCTUARY_PASSPHRASE = saved.pass;
  else delete process.env.SANCTUARY_PASSPHRASE;
  if (saved.rec !== undefined) process.env.SANCTUARY_RECOVERY_KEY = saved.rec;
  else delete process.env.SANCTUARY_RECOVERY_KEY;
  await fortressHome.cleanup();
});

/** In-memory keyring fake at the readStoredPassphrase seam. */
function storedPassphraseFake(value: string | null): typeof readStoredPassphrase {
  return (async () =>
    value === null
      ? null
      : { value, source: "keychain" as const, location: "test-keychain" }) as
    typeof readStoredPassphrase;
}

/** Keychain custody-key fake that reports a stored factor at boot. */
function keychainCustodyFake(
  key: Uint8Array,
): typeof readKeychainCustodyKeyStatus {
  return (async () => ({
    status: "found" as const,
    key,
    service: "test-custody-service",
  })) as typeof readKeychainCustodyKeyStatus;
}

describe("L1: the boot keychain custody factor is zeroed on the establishMaster throw path", () => {
  it("wipes the injected keychain factor even when establishment REJECTS", async () => {
    const storage = new MemoryStorage();
    const PASSPHRASE = "l1-keychain-zeroization-fortress-passphrase";

    // Create a fortress whose envelope has a passphrase wrap (and a minted
    // recovery wrap) but NO keychain wrap.
    await createSanctuaryServer({ storage, passphrase: PASSPHRASE });

    // A keychain custody factor that does NOT unlock this envelope. Non-zero
    // sentinel bytes so "was it wiped?" is unambiguous.
    const factor = new Uint8Array(32).fill(0xab);

    // Boot hands-free: passphrase seam returns nothing, keychain seam returns the
    // factor. establishMaster gets keychainKey=factor, finds no keychain wrap, and
    // REJECTS with CustodyUnlockError.
    await expect(
      createSanctuaryServer({
        storage,
        __testReadStoredPassphrase: storedPassphraseFake(null),
        __testReadKeychainCustody: keychainCustodyFake(factor),
      }),
    ).rejects.toBeInstanceOf(Error);

    // The finally wiped the factor on the rejected path (the fix). Against the
    // pre-fix source these bytes are still 0xab.
    expect(Array.from(factor).every((b) => b === 0)).toBe(true);
  });
});
