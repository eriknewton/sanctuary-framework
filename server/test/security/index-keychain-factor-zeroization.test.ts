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
 *
 * SECOND BOUNDARY (2026-09-08), the standalone dashboard. The same wipe there
 * covered establishment only, while the boot performs TWO fortress reads
 * between the moment the resolver hands the factor over and that `try`: the
 * first-run probe and the park-eligibility envelope read. A read that faults in
 * that window (a transient I/O error, a fortress on a network volume that drops)
 * left the factor live, and the test above cannot see it because it rejects the
 * factor INSIDE the resolver, before any of that window exists. The second
 * describe below drives that window with the same observation technique: inject
 * the factor at the boot seam, fail a read after the hand-over, assert the
 * buffer is zeroed.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { createSanctuaryServer } from "../../src/index.js";
import { startStandaloneDashboard } from "../../src/dashboard-standalone.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { getOrCreateKeychainCustodyKey } from "../../src/wrap/keychain-custody.js";
import type { readStoredPassphrase } from "../../src/wrap/passphrase.js";
import type { readKeychainCustodyKeyStatus } from "../../src/wrap/keychain-custody.js";
import { createTempHome } from "../helpers/temp-fortress.js";

/** `server/src`, resolved from this file so the pin assertions below are
 *  independent of the vitest working directory. */
const SERVER_SRC = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

/**
 * Join a comment's continuation lines so a pin sentence can be asserted as
 * EXACT text rather than as a regex with a tolerance window. Strips the leading
 * `//` or ` *` of each wrapped line and collapses runs of whitespace; it does
 * not otherwise alter the source.
 *
 * FAILURE MODE, from the outside: reformatting a pinned comment (prettier
 * rewrapping it, a rename widening a line) fails the assertion with "expected 1
 * to be 0" and looks like a deleted pin. Re-read the sentence at the site
 * before concluding the contract was dropped.
 */
function flattenCommentProse(source: string): string {
  return source
    .replace(/\n[ \t]*(?:\/\/|\*)[ \t]?/g, " ")
    .replace(/[ \t]+/g, " ");
}

/** Count non-overlapping occurrences of an exact substring. */
function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

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

  it("both boot paths carry the cross-file pin naming the other's zeroization", () => {
    // AGENTS.md prose hygiene: a cross-file contract is pinned on BOTH sides,
    // so an editor who relaxes one zeroization is warned at the site they are
    // editing. The dashboard side named `createSanctuaryServer` while the
    // index side named nothing, which is exactly the one-sided pin the rule
    // exists to prevent: a reader of index.ts had no way to know a second
    // boot path wipes the same factor.
    //
    // WHY THE ASSERTION IS AN EXACT SENTENCE AND NOT A TOLERANT REGEX: both
    // files carry SEVERAL `MUST MATCH` pins about each other (the two test
    // seams, the refusal text, the passphrase-source union). A gap-tolerant
    // pattern was satisfied by any of them, so deleting the ZEROIZATION pin
    // left this test green — a pin assertion that cannot fail when its pin is
    // gone is not a pin assertion. Each side is matched by the one sentence
    // that names the other's wipe, and it must appear EXACTLY once.
    const index = readFileSync(
      join(SERVER_SRC, "index.ts"),
      "utf-8",
    );
    const dashboard = readFileSync(
      join(SERVER_SRC, "dashboard-standalone.ts"),
      "utf-8",
    );
    const indexPin =
      "MUST MATCH the same zeroization in `startStandaloneDashboard` " +
      "(src/dashboard-standalone.ts)";
    const dashboardPin =
      "MUST MATCH the same zeroization in `createSanctuaryServer` " +
      "(src/index.ts)";
    expect(occurrences(flattenCommentProse(index), indexPin)).toBe(1);
    expect(occurrences(flattenCommentProse(dashboard), dashboardPin)).toBe(1);
  });
});

describe("the dashboard boot keychain custody factor is zeroed across its WHOLE owned lifetime", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("wipes the injected keychain factor when a fortress read faults after the hand-over", async () => {
    // The window this test exists for: the resolver has already verified the
    // factor and handed the bytes to the dashboard, and the boot then reads the
    // fortress twice more (the first-run probe, the park-eligibility envelope
    // read) BEFORE the establishment `try`. Those reads can fault for reasons
    // that have nothing to do with the credential.
    //
    // FAILS BEFORE THE FIX: the wipe sat in the establishment `try`'s `finally`,
    // which this throw never enters, so 32 bytes of live key material outlived
    // the refused boot (MUST-NEVER 6).
    const fortress = fortressHome.defaultFortressPath;
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });

    // The fortress `init` leaves behind: an envelope with an OS-keyring custody
    // wrap, so the factor below VERIFIES and the boot really does take
    // ownership of it. A factor the resolver rejects would never reach the
    // window under test.
    const enrolled = await getOrCreateKeychainCustodyKey(fortress);
    if (!enrolled) throw new Error("test keyring did not yield a custody key");
    const storage = new FilesystemStorage(join(fortress, "state"));
    const established = await establishMaster({
      storage,
      keychainKey: enrolled,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
      storagePathHint: fortress,
    });
    await established.masterWriteBarrier?.release().catch(() => undefined);
    established.masterKey.fill(0);

    // The buffer whose fate this test is about: the same bytes, handed to the
    // boot through its own seam so the test holds the object the dashboard
    // takes ownership of (the observation technique of the test above).
    const factor = Uint8Array.from(enrolled);
    enrolled.fill(0);
    expect(factor.some((b) => b !== 0)).toBe(true);

    // Arm the fault at the hand-over. The boot announces the hand-over on its
    // operator channel immediately after taking the bytes, which is exactly the
    // instant the guarded region must already have opened; every fortress read
    // after it belongs to the window.
    let armed = false;
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      if (args.map(String).join(" ").includes("Custody: opened with the")) {
        armed = true;
      }
    });
    const realRead = FilesystemStorage.prototype.read;
    vi.spyOn(FilesystemStorage.prototype, "read").mockImplementation(
      async function (
        this: FilesystemStorage,
        namespace: string,
        key: string,
      ): Promise<Uint8Array | null> {
        if (armed) {
          throw new Error("EIO: simulated transient fortress read fault");
        }
        return realRead.call(this, namespace, key);
      },
    );

    await expect(
      startStandaloneDashboard({
        storagePath: fortress,
        // The boot's own custody seam, so the bytes it takes ownership of are
        // the buffer this test holds.
        __testReadKeychainCustody: keychainCustodyFake(factor),
        discoveryOptions: { home: fortressHome.home, root: fortress },
        host: "127.0.0.1",
        authToken: "dashboard-zeroization-token-not-a-secret",
        distressPort: 0,
        // Port 0 is never bound on this path: the read faults long before the
        // HTTP server is created, so no listener can leak out of this test.
        port: 0,
      }),
    ).rejects.toThrow();

    expect(armed, "the boot never reached the keychain-factor hand-over").toBe(
      true,
    );
    expect(Array.from(factor).every((b) => b === 0)).toBe(true);
  }, 120_000);
});
