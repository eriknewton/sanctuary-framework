/**
 * The MCP server's boot credential path and `protect` resolve through the SAME
 * chain (`wrap/custody-credential.ts`), so a fortress `protect` can open is a
 * fortress the server it launches can open.
 *
 * Capability under test: `createSanctuaryServer` boots hands-free on a fortress
 * whose custody factor was enrolled by `init`, EVEN WHEN a stale
 * `sanctuary-passphrase-<id>` item for the same fortress is also present on the
 * host (the leftover of an earlier failed mint). Register:
 * defect.a73-install-emitted-protect-fails-custody-establishment.
 *
 * Why the stale item matters: the boot path used to run its own chain that read
 * that item FIRST, with no check that it opens this fortress and no
 * fall-through when it does not, and handed it to custody establishment. The
 * first test below proves that credential fails the boot CLOSED, which is
 * exactly what the old order produced: `protect` succeeds through the enrolled
 * factor, and the server it just launched refuses to start.
 *
 * Every keyring read and write here goes through the wrap keychain chokepoint,
 * which the suite serves from the in-memory store (test/setup/keychain-fake.ts):
 * no `security` / `secret-tool` subprocess runs, and the operator's login
 * keychain and real `~/.sanctuary` are never touched.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createSanctuaryServer } from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { getOrCreateKeychainCustodyKey } from "../../src/wrap/keychain-custody.js";
import { persistUserProvidedPassphrase } from "../../src/wrap/passphrase.js";
import { constantTimeEqual, toBase64url } from "../../src/core/encoding.js";
import { createTempHome } from "../helpers/temp-fortress.js";

/**
 * A passphrase stored for THIS fortress that does not open it: the shape an
 * interrupted `protect` left behind before the fix (mint, store, fail to
 * unlock).
 */
const STALE_PASSPHRASE = "a-stale-item-from-a-failed-mint-not-a-real-secret";

let fortressHome: Awaited<ReturnType<typeof createTempHome>>;

describe("MCP boot resolves its credential through the shared custody resolver", () => {
  let fortress: string;
  let storage: MemoryStorage;
  let enrolledFactor: Uint8Array;
  let establishedMaster: Uint8Array;
  /** Everything the boot wrote to an operator-facing channel. */
  let emitted: string[];

  beforeEach(async () => {
    fortressHome = await createTempHome("sanctuary-a73-boot");
    fortress = fortressHome.defaultFortressPath;
    storage = new MemoryStorage();

    // The fortress `init` leaves behind: an OS-keyring custody factor and no
    // passphrase wrap.
    const factor = await getOrCreateKeychainCustodyKey(fortress);
    if (!factor) throw new Error("test keyring did not yield a custody key");
    enrolledFactor = factor;
    const established = await establishMaster({
      storage,
      keychainKey: enrolledFactor,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
      storagePathHint: fortress,
    });
    establishedMaster = established.masterKey;

    // The stale item, stored for this exact fortress path.
    await persistUserProvidedPassphrase(STALE_PASSPHRASE, {
      storagePath: fortress,
    });

    emitted = [];
    const record = (...args: unknown[]): void => {
      emitted.push(args.map((a) => String(a)).join(" "));
    };
    vi.spyOn(console, "error").mockImplementation(record);
    vi.spyOn(console, "warn").mockImplementation(record);
    vi.spyOn(console, "info").mockImplementation(record);
    vi.spyOn(console, "log").mockImplementation(record);
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string) => {
      emitted.push(String(chunk));
      return true;
    }) as typeof process.stderr.write);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await fortressHome.cleanup();
  });

  it("PLANTED DIVERGENCE: the stale stored passphrase the old order preferred fails the boot CLOSED", async () => {
    // The old boot chain read this item first and passed it straight to custody
    // establishment. Supplying it explicitly reproduces that hand-off: the
    // credential does not open the fortress, so the server refuses to start on
    // a fortress `protect` had just opened.
    await expect(
      createSanctuaryServer({ storage, passphrase: STALE_PASSPHRASE }),
    ).rejects.toThrow(/does not unlock|credential/i);
  });

  it("boots on the enrolled custody factor with the stale item still present", async () => {
    const server = await createSanctuaryServer({ storage });
    try {
      // The same master `init` established: the boot used the enrolled factor,
      // not the stale item and not a fresh mint.
      expect(constantTimeEqual(server.masterKey, establishedMaster)).toBe(true);
    } finally {
      await server.cleanup();
    }
  });

  /**
   * The GUI-launcher shape: a wrapper that exports the credential variables
   * unconditionally leaves them EMPTY when the operator supplied nothing (a
   * LaunchAgent plist with an empty `EnvironmentVariables` entry, `env
   * SANCTUARY_PASSPHRASE= sanctuary ...`, a shell that exports an unset var).
   *
   * FAILS BEFORE THE FIX: this boot gated the host-local lookup on
   * `passphrase === undefined && envRecoveryKey === undefined`, so an empty
   * string read as "the operator named a credential". The resolver was never
   * consulted, and `establishMaster` then received nothing at all (the spread
   * is truthiness-gated), so the boot refused. The standalone dashboard tested
   * truthiness and opened the very same fortress: one host state, two answers.
   */
  it("treats an EMPTY SANCTUARY_PASSPHRASE as unset and still boots on the enrolled factor", async () => {
    process.env.SANCTUARY_PASSPHRASE = "";
    try {
      const server = await createSanctuaryServer({ storage });
      try {
        expect(constantTimeEqual(server.masterKey, establishedMaster)).toBe(
          true,
        );
      } finally {
        await server.cleanup();
      }
    } finally {
      delete process.env.SANCTUARY_PASSPHRASE;
    }
  });

  /**
   * Same predicate, the other variable and the option form. An empty explicit
   * `--passphrase` must fall THROUGH to the next source rather than settle the
   * question, which is what the shared resolver's operator-source loop does.
   *
   * FAILS BEFORE THE FIX: `options?.passphrase ?? process.env.SANCTUARY_PASSPHRASE`
   * kept the empty option (`??` only falls through on null/undefined), and an
   * empty `SANCTUARY_RECOVERY_KEY` likewise suppressed the lookup.
   */
  it("treats an EMPTY explicit passphrase and an EMPTY recovery key as unset", async () => {
    process.env.SANCTUARY_RECOVERY_KEY = "";
    try {
      const server = await createSanctuaryServer({ storage, passphrase: "" });
      try {
        expect(constantTimeEqual(server.masterKey, establishedMaster)).toBe(
          true,
        );
      } finally {
        await server.cleanup();
      }
    } finally {
      delete process.env.SANCTUARY_RECOVERY_KEY;
    }
  });

  it("emits no credential value on either the refused or the successful boot", async () => {
    await expect(
      createSanctuaryServer({ storage, passphrase: STALE_PASSPHRASE }),
    ).rejects.toThrow();
    const server = await createSanctuaryServer({ storage });
    await server.cleanup();

    const output = emitted.join("\n");
    expect(output).not.toContain(STALE_PASSPHRASE);
    expect(output).not.toContain(toBase64url(enrolledFactor));
    expect(output).not.toContain(toBase64url(establishedMaster));
  });
});
