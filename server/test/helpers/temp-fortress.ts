/**
 * Per-test fortress isolation.
 *
 * The suite must be hermetic: no test may read from or write to the
 * operator's own `~/.sanctuary`. Reaching it is a defect in both directions.
 * It writes into real state (the backup directory grew on essentially every
 * run, to thousands of files), and it reads real custody, so the same test
 * behaves differently on a developer machine that has a fortress, a machine
 * that does not, and a fresh CI runner.
 *
 * `assertHermeticStoragePath` in `src/paths.ts` now fails such a resolution
 * closed under Vitest. This helper is the supported way to satisfy it.
 *
 * Why BOTH `HOME` and `SANCTUARY_STORAGE_PATH` are overridden:
 *
 *  - `SANCTUARY_STORAGE_PATH` is the highest-precedence input to
 *    `resolveStoragePath`, so it redirects every code path that resolves
 *    ambiently.
 *  - `HOME` is what `os.homedir()` reads on POSIX, and it is the input to the
 *    `~/.sanctuary` fallback plus every sibling artifact a wrap touches
 *    (agent config files under `~/.hermes`, `~/.config`, and friends).
 *
 * Setting only `SANCTUARY_STORAGE_PATH`, and in particular setting it once
 * globally for the whole suite, is NOT equivalent and is actively harmful:
 * several suites already isolate per test by overriding `HOME` alone, and a
 * global storage-path override outranks that, silently collapsing every test
 * in the file onto a single shared fortress. Custody is established on the
 * first test's passphrase, so every later test fails to unlock it. Isolation
 * has to be per test, and it has to move `HOME` with it.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * A fixed, obviously-not-real passphrase for tests that need custody to
 * unlock but are not testing custody itself.
 */
export const TEST_PASSPHRASE = "test-fortress-passphrase-not-a-real-secret";

/**
 * Pin `SANCTUARY_PASSPHRASE` for the duration of a test; returns the restore.
 *
 * Without this, a CLI verb that needs a master key falls through to
 * `getOrCreatePassphrase`, which talks to the real OS keyring. Against a
 * temporary fortress the derived service name is new every run, so the keyring
 * is genuinely empty and the resolver GENERATES a passphrase and WRITES it:
 * one new login-keychain entry per test, per run, forever. That is the same
 * class of defect as the fortress backup directory growing on every run, just
 * in a different store, so isolating the fortress without also pinning the
 * passphrase would move the pollution rather than fix it.
 *
 * Use in any suite that drives a CLI verb which derives a fortress master key.
 */
export function useTestPassphrase(value: string = TEST_PASSPHRASE): () => void {
  const original = process.env.SANCTUARY_PASSPHRASE;
  process.env.SANCTUARY_PASSPHRASE = value;
  return () => {
    if (original === undefined) delete process.env.SANCTUARY_PASSPHRASE;
    else process.env.SANCTUARY_PASSPHRASE = original;
  };
}

/**
 * Redirect `HOME` to a fresh temporary directory, without setting
 * `SANCTUARY_STORAGE_PATH`.
 *
 * For the narrow case of a test that must exercise the DEFAULT fortress
 * resolution -- "no storage path configured, so fall back to `~/.sanctuary`".
 * Setting `SANCTUARY_STORAGE_PATH` would defeat the very branch under test,
 * while leaving `HOME` alone points that branch at the operator's own
 * fortress. Moving `HOME` keeps the branch exercised and the run hermetic:
 * `os.homedir()` reads `$HOME` on POSIX, so the default resolves to
 * `<tempHome>/.sanctuary`.
 *
 * Returns the temp home plus the fortress path the default now resolves to,
 * so assertions can name it without recomputing the join.
 */
export async function createTempHome(prefix = "sanctuary-test-home"): Promise<{
  home: string;
  defaultFortressPath: string;
  cleanup: () => Promise<void>;
}> {
  // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
  const home = await mkdtemp(join(tmpdir(), `${prefix}-`));
  const originalHome = process.env.HOME;
  process.env.HOME = home;
  // The operator's machine is not a fixture: moving HOME alone still leaves an
  // ambient SANCTUARY_STORAGE_PATH / SANCTUARY_FORTRESS_PATH pointing at the
  // real fortress, and an ambient passphrase or recovery key able to unlock
  // it. Clear every path and credential variable for the life of the temp
  // home (the default-resolution branch this helper exists for still resolves
  // to `<tempHome>/.sanctuary`), and restore them on cleanup.
  const AMBIENT_FORTRESS_ENV = [
    "SANCTUARY_STORAGE_PATH",
    "SANCTUARY_FORTRESS_PATH",
    "SANCTUARY_PASSPHRASE",
    "SANCTUARY_RECOVERY_KEY",
  ] as const;
  const originalAmbient = new Map<string, string | undefined>();
  for (const key of AMBIENT_FORTRESS_ENV) {
    originalAmbient.set(key, process.env[key]);
    delete process.env[key];
  }

  let cleanedUp = false;
  const cleanup = async (): Promise<void> => {
    if (cleanedUp) return;
    cleanedUp = true;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    for (const [key, value] of originalAmbient) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    try {
      await rm(home, { recursive: true, force: true });
    } catch {
      // A leftover temp dir is not worth failing a test over; the OS reaps it.
    }
  };

  return { home, defaultFortressPath: join(home, ".sanctuary"), cleanup };
}

export interface TempFortress {
  /** The temporary home directory. */
  home: string;
  /** The fortress path inside it: `<home>/.sanctuary`. */
  storagePath: string;
  /** Restore the previous environment and remove the directory. */
  cleanup: () => Promise<void>;
}

/**
 * Create a fresh temporary fortress and point this process at it.
 *
 * Call in `beforeEach` and `await`-`cleanup()` in `afterEach` so each test
 * gets its own custody state. Reusing one fortress across tests reintroduces
 * the cross-test coupling described above.
 *
 * @param prefix Short label for the temp directory, to make stray directories
 *               attributable to the suite that leaked them.
 */
export async function createTempFortress(
  prefix = "sanctuary-test",
): Promise<TempFortress> {
  // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
  const home = await mkdtemp(join(tmpdir(), `${prefix}-`));
  const storagePath = join(home, ".sanctuary");

  const originalHome = process.env.HOME;
  const originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
  process.env.HOME = home;
  process.env.SANCTUARY_STORAGE_PATH = storagePath;
  const restorePassphrase = useTestPassphrase();

  let cleanedUp = false;
  const cleanup = async (): Promise<void> => {
    // Idempotent: an afterEach that also runs on a failed test must not
    // restore a second time and clobber the outer environment.
    if (cleanedUp) return;
    cleanedUp = true;
    restorePassphrase();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    }
    try {
      await rm(home, { recursive: true, force: true });
    } catch {
      // A leftover temp dir is not worth failing a test over; the OS reaps it.
    }
  };

  return { home, storagePath, cleanup };
}
