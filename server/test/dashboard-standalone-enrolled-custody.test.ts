/**
 * Capability under test: the standalone dashboard boot opens a fortress with
 * the OS-keyring custody factor `sanctuary init` enrols, and when nothing
 * opens it, refuses with ONE listing of the accepted credential sources plus
 * the actionable enrolled-factor diagnostic. It resolves that credential
 * through the shared custody-credential chain in the wrap layer, the same
 * chain `protect`, `export-passphrase`, the install planner and the MCP stdio
 * boot run, so the two boot paths agree by construction.
 *
 * Register: defect.dashboard-boot-ignores-enrolled-keyring-custody-factor.
 *
 * Every keyring read and write here goes through the wrap keychain chokepoint,
 * which the suite serves from the in-memory store (test/setup/keychain-fake.ts):
 * no `security` / `secret-tool` subprocess runs, and the operator's login
 * keychain and real `~/.sanctuary` are never touched. The fortress itself is a
 * per-test temporary directory.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { startStandaloneDashboard } from "../src/dashboard-standalone.js";
import type { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import {
  establishMaster,
  verifyRecoveryWrapByReentry,
} from "../src/core/master-custody.js";
import { getOrCreateKeychainCustodyKeyTransactional } from "../src/wrap/keychain-custody.js";
import { IdentityManager } from "../src/cognitive/tools.js";
import { setKeychainExec } from "../src/wrap/keychain-exec.js";
import { installInMemoryKeychainStore } from "./setup/keychain-fake.js";
import { toBase64url } from "../src/core/encoding.js";
import { createTempHome } from "./helpers/temp-fortress.js";
import { bindWithRetry, randomTestPort } from "./util/port-collision-retry.js";

const DASHBOARD_TOKEN = "enrolled-custody-dashboard-token-not-a-secret";

/**
 * Replace the in-memory credential store with one that answers every lookup
 * the same way, so a fortress whose envelope DOES carry an enrolled OS-keyring
 * factor can be booted against a keyring that no longer yields it.
 *
 * Portable across both backends on purpose: `classifyDarwinFailure` reads the
 * exit code / stderr marker and `classifyLinuxFailure` reads stderr emptiness,
 * so `not-found` is (code 44, empty stderr) and `unreachable` is (code 36,
 * "interaction is not allowed") on either platform. A stub that only spoke
 * macOS would classify as `not-found` on the Linux CI runner and quietly test
 * the wrong branch.
 *
 * FAILURE MODE, from the outside: the store is process-global, so a test that
 * installs this and does not restore it in `afterEach` leaves every later test
 * in the worker unable to read any credential, and the damage looks like
 * unrelated custody flakes.
 */
function installKeyringAnswering(kind: "not-found" | "unreachable"): void {
  const answer =
    kind === "not-found"
      ? { stdout: "", stderr: "", code: 44 }
      : { stdout: "", stderr: "interaction is not allowed", code: 36 };
  setKeychainExec(async () => answer);
}

/**
 * Retry-safe wrapper around `startStandaloneDashboard`. The channel embeds the
 * port in its self-origin and session URLs, so the port has to be known before
 * bind (the `bindWithRetry` contract in test/util/port-collision-retry.ts).
 */
async function startWithRetry(
  options: Parameters<typeof startStandaloneDashboard>[0],
): Promise<{ dashboard: DashboardApprovalChannel; port: number }> {
  return bindWithRetry(async () => {
    const port = randomTestPort();
    const dashboard = await startStandaloneDashboard({
      distressPort: 0,
      host: "127.0.0.1",
      authToken: DASHBOARD_TOKEN,
      ...options,
      port,
    });
    return { dashboard, port };
  });
}

describe("standalone dashboard boots on the enrolled custody factor", () => {
  let fortressHome: Awaited<ReturnType<typeof createTempHome>>;
  let fortress: string;
  let dashboard: DashboardApprovalChannel | null = null;
  /** Everything the boot wrote to an operator-facing channel. */
  let emitted: string[];

  beforeEach(async () => {
    fortressHome = await createTempHome("sanctuary-dashboard-custody");
    fortress = fortressHome.defaultFortressPath;
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    emitted = [];
    const record = (...args: unknown[]): void => {
      emitted.push(args.map((a) => String(a)).join(" "));
    };
    vi.spyOn(console, "error").mockImplementation(record);
    vi.spyOn(console, "warn").mockImplementation(record);
    vi.spyOn(console, "info").mockImplementation(record);
    vi.spyOn(console, "log").mockImplementation(record);
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop().catch(() => undefined);
      dashboard = null;
    }
    // Restore the shared in-memory store BEFORE anything else: a bespoke stub
    // installed by a test is process-global and would outlive a failing test.
    installInMemoryKeychainStore();
    vi.restoreAllMocks();
    await fortressHome.cleanup();
  });

  /**
   * The fortress `sanctuary init` leaves behind on the documented interactive
   * path: an OS-keyring custody factor wrapping the master, and NO stored
   * passphrase.
   */
  async function enrolCustodyFactorAndCreateEnvelope(): Promise<Uint8Array> {
    const mutation =
      await getOrCreateKeychainCustodyKeyTransactional(fortress);
    if (!mutation) throw new Error("test keyring did not yield a custody key");
    mutation.commit();
    const factor = mutation.value;
    const storage = new FilesystemStorage(join(fortress, "state"));
    const established = await establishMaster({
      storage,
      keychainKey: factor,
      firstRun: { installMode: "interactive", mintRecoveryKey: true },
      storagePathHint: fortress,
    });
    // The recovery wrap is minted UNVERIFIED and the interactive `init` flow
    // promotes it by re-entry. Do the same here: the custody floor refuses to
    // persist trust-bearing state on an interactive-install fortress with
    // fewer than two verified factor types, so skipping this step would fail
    // the test for a reason that has nothing to do with credential resolution.
    await verifyRecoveryWrapByReentry(
      storage,
      established.envelope!,
      established.mintedRecoveryKey!,
    );
    await established.masterWriteBarrier?.release().catch(() => undefined);
    established.masterKey.fill(0);
    return factor;
  }

  /**
   * What the MCP stdio boot would persist as `key_protection` for THIS
   * fortress, plus the master it opened with (copied, so the caller can read
   * the identity the dashboard writes later without contending for a second
   * master-write barrier while the dashboard holds one).
   *
   * This is `establishMaster` itself, not a restatement of it: the parity the
   * test asserts is only worth anything if the expected value comes from the
   * function `createSanctuaryServer` reads (`custody.keyProtection`).
   *
   * FAILURE MODE, from the outside: call this while a dashboard is running and
   * the barrier acquisition blocks until the suite's timeout, which reads as an
   * unrelated hang rather than a lock conflict. Call it BEFORE the boot.
   */
  async function mcpBootKeyProtection(
    factor: Uint8Array,
  ): Promise<{ keyProtection: string; masterKey: Uint8Array }> {
    const storage = new FilesystemStorage(join(fortress, "state"));
    const established = await establishMaster({
      storage,
      keychainKey: Uint8Array.from(factor),
      storagePathHint: fortress,
    });
    const masterKey = Uint8Array.from(established.masterKey);
    const keyProtection = established.keyProtection;
    await established.masterWriteBarrier?.release().catch(() => undefined);
    established.masterKey.fill(0);
    return { keyProtection, masterKey };
  }

  it("opens with no passphrase option and no credential environment", async () => {
    const factor = await enrolCustodyFactorAndCreateEnvelope();
    // `createTempHome` already cleared SANCTUARY_PASSPHRASE and
    // SANCTUARY_RECOVERY_KEY; assert it so the test cannot silently pass on an
    // ambient credential the way the pre-fix path would have needed.
    expect(process.env.SANCTUARY_PASSPHRASE).toBeUndefined();
    expect(process.env.SANCTUARY_RECOVERY_KEY).toBeUndefined();

    // Read BEFORE the boot: the dashboard holds the master-write barrier for
    // its whole lifetime, so a second establishment while it runs would block.
    const mcpBoot = await mcpBootKeyProtection(factor);

    // Before the fix this threw "cannot unlock this fortress ... with the
    // available factors", naming only the sanctuary-passphrase service: the
    // boot never consulted the enrolled factor at all.
    const started = await startWithRetry({
      storagePath: fortress,
      discoveryOptions: { home: fortressHome.home, root: fortress },
    });
    dashboard = started.dashboard;

    // Genuinely unlocked, not parked: a protected route answers, which needs
    // the master-key-derived dependencies to have been wired.
    const res = await fetch(`http://127.0.0.1:${started.port}/api/status`, {
      headers: { Authorization: `Bearer ${DASHBOARD_TOKEN}` },
    });
    expect(res.status).toBe(200);

    // The identity this boot created carries the label the MCP boot would
    // persist for the SAME fortress. `establishMaster` maps a keychain-key
    // unwrap to "passphrase", so an enrolled-factor boot that decided the
    // label from "was a passphrase string in scope" wrote "recovery-key" and
    // the two boot paths disagreed about the same custody.
    //
    // FAILS BEFORE THE FIX: the dashboard passed
    // `passphrase ? "passphrase" : "recovery-key"` and no passphrase exists on
    // this path, so `key_protection` read "recovery-key" here.
    const identityReader = new IdentityManager(
      new FilesystemStorage(join(fortress, "state")),
      mcpBoot.masterKey,
    );
    const loaded = await identityReader.load();
    expect(loaded.loaded).toBe(1);
    const persisted = identityReader.getDefault();
    expect(persisted).toBeDefined();
    expect(persisted!.key_protection).toBe(mcpBoot.keyProtection);
    expect(persisted!.key_protection).toBe("passphrase");
    mcpBoot.masterKey.fill(0);

    // No credential value reached an operator-facing channel.
    expect(emitted.join("\n")).not.toContain(toBase64url(factor));
    factor.fill(0);
  }, 120_000);

  it("names the enrolled keyring factor, not the recovery key, when identity files do not decrypt", async () => {
    const factor = await enrolCustodyFactorAndCreateEnvelope();
    factor.fill(0);

    // One encrypted identity record this fortress's master cannot open: valid
    // JSON so the load path reaches `decrypt`, garbage so decryption fails.
    // That is the exact state the warning below exists for (a sub-tenant's
    // identity files under a different master).
    const storage = new FilesystemStorage(join(fortress, "state"));
    const identityDir = storage.namespacePath("_identities");
    await mkdir(identityDir, { recursive: true, mode: 0o700 });
    await writeFile(
      join(identityDir, "foreign-tenant-identity.enc"),
      JSON.stringify({ ciphertext: "not-this-fortresses-identity" }),
      { mode: 0o600 },
    );

    const started = await startWithRetry({
      storagePath: fortress,
      discoveryOptions: { home: fortressHome.home, root: fortress },
    });
    dashboard = started.dashboard;

    const warning = emitted.find((line) =>
      line.includes("Encrypted identities found but NONE loaded"),
    );
    expect(warning, "the identity-decrypt warning did not fire").toBeDefined();

    // FAILS BEFORE THE FIX: the keychain-key branch never set
    // `passphraseSource`, so the label chain fell through to its default and
    // this same warning said "the master key derived from the recovery key"
    // and told the operator to set SANCTUARY_PASSPHRASE. Neither credential
    // took part in this boot.
    expect(warning!).toContain("OS keyring custody factor");
    expect(warning!).not.toContain("recovery key");
    expect(warning!).not.toContain("SANCTUARY_PASSPHRASE");
  }, 120_000);

  /**
   * Attempt the boot and return the refusal. Written as a helper because both
   * refusal tests below need the SAME thrown message and neither may leave a
   * started dashboard behind if the boot unexpectedly succeeds.
   */
  async function bootAndCaptureRefusal(): Promise<Error> {
    let threw: Error | null = null;
    try {
      const started = await startWithRetry({
        storagePath: fortress,
        discoveryOptions: { home: fortressHome.home, root: fortress },
      });
      dashboard = started.dashboard;
    } catch (err) {
      threw = err as Error;
    }
    if (threw === null) throw new Error("the boot was expected to refuse");
    return threw;
  }

  it("refuses with BOTH the enrolled-factor diagnostic naming the OS keyring and the accepted-sources listing", async () => {
    // The fortress `init` leaves behind, with the enrolled OS-keyring custody
    // factor genuinely recorded in the envelope, and then a keyring that no
    // longer holds the item (deleted, or a different login keychain). The
    // factor IS enrolled and CANNOT unlock: the earlier version of this test
    // used a passphrase-only fortress with no keychain factor at all, so its
    // regex matched the accepted-sources LIST ITEM rather than the enrolled-
    // factors diagnostic, and it would have passed with the diagnostic absent.
    const factor = await enrolCustodyFactorAndCreateEnvelope();
    factor.fill(0);
    installKeyringAnswering("not-found");

    const threw = await bootAndCaptureRefusal();

    // 1. The actionable diagnostic, which comes from the ENVELOPE's factor
    //    inventory and so exists only because a keychain wrap is enrolled.
    expect(threw.message).toMatch(/cannot unlock this fortress/);
    expect(threw.message).toMatch(
      /Enrolled recovery factors on this fortress:[^\n]*OS keyring/,
    );
    // 2. Keyring reachability, derived from the RESOLVER's single read rather
    //    than a second probe of the same item.
    expect(threw.message).toContain("its item is MISSING from the keyring");
    // 3. The shared accepted-sources listing, asserted as the exact sentence
    //    (a regex over the list items alone cannot tell the two blocks apart).
    expect(threw.message).toContain(
      "Accepted credentials, in the order they are tried:",
    );
    // 4. The two blocks AGREE about that same item: "MISSING from the keyring"
    //    above and "none of them present" here are one observation, not two.
    expect(threw.message).toContain("Present on this host: none of them.");
    expect(threw.message).toContain(fortress);
    expect(threw.message).toContain("SANCTUARY_RECOVERY_KEY=");
    expect(threw.message).toMatch(/keychain-schema\.md/);
  }, 120_000);

  it("reports a LOCKED keyring as locked, with the classifier and the guidance agreeing", async () => {
    const factor = await enrolCustodyFactorAndCreateEnvelope();
    factor.fill(0);
    // A damaged encrypted fallback credential alongside the locked keyring.
    // This is the state where the two stored-passphrase observers disagree:
    // the native `observeStoredPassphrase` answers `fallback-unreadable`
    // (naming the file) while the `readStoredPassphrase` adapter answers
    // `absent + keyringUnreachable` (naming the keyring).
    //
    // FAILS BEFORE THE FIX: `resolveHostLocalBootCredential` selected the
    // adapter only when a test seam was injected, so the MCP boot (which
    // injects one) and this dashboard boot (which does not) printed DIFFERENT
    // stored-passphrase lines for identical host state. Both now take the
    // adapter, so this asserts the adapter's line from the dashboard.
    await writeFile(
      join(fortress, "passphrase.enc"),
      "not a valid sanctuary fallback credential",
      { mode: 0o600 },
    );
    installKeyringAnswering("unreachable");

    const threw = await bootAndCaptureRefusal();

    // The resolver's own classifier marker, through the accepted-sources block.
    expect(threw.message).toMatch(/locked or unreachable/);
    // The actionable block's guidance for the same condition.
    expect(threw.message).toContain("LOCKED or unreachable");
    expect(threw.message).toContain(
      "Accepted credentials, in the order they are tried:",
    );
    // The stored-passphrase line is the ADAPTER's, identical to the one the
    // MCP stdio boot prints for this host state.
    expect(threw.message).toContain(
      "the fallback credential is also unreadable, so keyring contents remain unknown",
    );
    // Never a value, and never the on-disk location of a credential.
    expect(threw.message).not.toContain("passphrase.enc");
  }, 120_000);
});
