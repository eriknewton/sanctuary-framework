/**
 * Sanctuary MCP Server — Shared path resolution
 *
 * Resolves per-tenant storage paths and network ports from environment
 * variables, with sensible defaults for single-tenant installations.
 *
 * Multi-tenancy contract: every Sanctuary artifact that used to live under a
 * hardcoded `~/.sanctuary/*` location must now route through one of these
 * helpers so two instances on the same host can pick distinct locations.
 */

import { access, constants, stat } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";

/** Default top-level storage directory when no env override is set. */
export const DEFAULT_STORAGE_DIR = ".sanctuary";

/** Default dashboard port — matched by config.ts default. */
export const DEFAULT_DASHBOARD_PORT = 3501;

export type FortressPathWritableResult =
  | { ok: true }
  | { ok: false; path: string; reason: string };

const ACCESS_FAILURE_CODES = new Set(["EACCES", "EROFS", "ENOENT"]);

/**
 * Check only the filesystem location that `mkdir -p <fortressPath>` needs.
 *
 * If the fortress path exists, check that exact path. If it does not exist,
 * check the nearest existing ancestor. Unknown filesystem states are allowed
 * to continue so this preflight never becomes stricter than the later write.
 */
export async function preflightFortressPathWritable(
  fortressPath: string,
): Promise<FortressPathWritableResult> {
  const targetPath = resolve(fortressPath);
  let currentPath = targetPath;

  while (true) {
    try {
      await stat(currentPath);
      return checkWritable(currentPath);
    } catch (error) {
      const code = errorCode(error);
      if (code !== "ENOENT") {
        const accessResult = await checkWritable(currentPath);
        return accessResult.ok ? { ok: true } : accessResult;
      }

      const parentPath = dirname(currentPath);
      if (parentPath === currentPath) {
        return { ok: false, path: currentPath, reason: "ENOENT" };
      }
      currentPath = parentPath;
    }
  }
}

export function formatFortressPathWritableError(
  fortressPath: string,
  result: Exclude<FortressPathWritableResult, { ok: true }>,
): string {
  return `Sanctuary cannot create its secure storage at ${fortressPath}: ${result.reason}. Make sure you can write to ${result.path}, or pass --fortress <writable-path> to choose a different location.`;
}

async function checkWritable(path: string): Promise<FortressPathWritableResult> {
  try {
    await access(path, constants.W_OK);
    return { ok: true };
  } catch (error) {
    const reason = errorCode(error);
    if (reason && ACCESS_FAILURE_CODES.has(reason)) {
      return { ok: false, path, reason };
    }
    return { ok: true };
  }
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error
    ? String((error as NodeJS.ErrnoException).code)
    : undefined;
}

/**
 * Thrown when a test run resolves storage to the operator's own fortress.
 *
 * See {@link assertHermeticStoragePath} for why this fails closed.
 */
export class NonHermeticStoragePathError extends Error {
  constructor(public readonly resolvedPath: string) {
    super(
      `Sanctuary test isolation: a test resolved its storage path to the operator's own fortress at ${resolvedPath}.\n` +
        `Tests must never read from or write to the real fortress: doing so pollutes it (the backup directory grows on every run),\n` +
        `and it makes the suite non-hermetic, so the same test can pass on a developer machine that has a fortress and fail on a\n` +
        `fresh CI runner that does not.\n` +
        `Fix the test by giving it its own fortress: use createTempFortress() from test/helpers/temp-fortress.ts, or pass an\n` +
        `explicit storage path to the function under test. Do not set SANCTUARY_STORAGE_PATH globally for the whole suite: several suites\n` +
        `already isolate per test by overriding HOME, and a global override silently defeats that and collapses them onto one fortress.\n` +
        `If a test genuinely needs to observe the default home resolution, pass an explicit fake home argument instead.`,
    );
    this.name = "NonHermeticStoragePathError";
  }
}

/**
 * The operator's real home directory, captured once at module load.
 *
 * `os.userInfo().homedir` reads the account record (passwd on POSIX,
 * USERPROFILE on Windows) and so is immune to a test reassigning
 * `process.env.HOME` -- which is exactly how several suites isolate
 * themselves. `os.homedir()` honours `$HOME` on POSIX and therefore cannot
 * answer this question once a test has moved it.
 *
 * `userInfo()` can throw when the uid has no passwd entry (some containers).
 * "Could not look" is representable: fall back to the `HOME` observed at
 * module load, which under Vitest is still the pristine operator value
 * because test files mutate it in `beforeEach`, after their imports resolve.
 * Both candidates are treated as the operator fortress so the guard stays
 * conservative when the two disagree.
 */
const OPERATOR_HOME_CANDIDATES: readonly string[] = (() => {
  const candidates = new Set<string>();
  try {
    candidates.add(userInfo().homedir);
  } catch {
    // No passwd entry for this uid; the HOME fallback below is all we have.
  }
  const envHome = process.env.HOME ?? process.env.USERPROFILE;
  if (envHome && envHome.length > 0) candidates.add(envHome);
  return [...candidates].filter((h) => h.length > 0);
})();

/**
 * Fail closed when a Vitest run resolves storage to the operator's own fortress.
 *
 * The suite must be hermetic: every test runs against a fortress it provisioned
 * itself. Reaching the operator's `~/.sanctuary` is always a defect, in both
 * directions -- it writes into real state (the recurring backup-directory
 * growth), and it reads real custody, so results differ between a machine with
 * a fortress and a fresh CI runner.
 *
 * Only active under Vitest (`VITEST` is set in every worker). Production
 * resolution is untouched: `~/.sanctuary` is the correct answer for a
 * single-tenant install.
 *
 * `SANCTUARY_ALLOW_OPERATOR_FORTRESS=1` is the deliberate escape hatch for a
 * test that must exercise the real default. It is opt-in per process and never
 * set by the suite.
 */
export function assertHermeticStoragePath(resolvedPath: string): void {
  if (!process.env.VITEST) return;
  if (process.env.SANCTUARY_ALLOW_OPERATOR_FORTRESS === "1") return;
  for (const home of OPERATOR_HOME_CANDIDATES) {
    if (resolvedPath === join(home, DEFAULT_STORAGE_DIR)) {
      throw new NonHermeticStoragePathError(resolvedPath);
    }
  }
}

/**
 * The default single-tenant fortress location, `<home>/.sanctuary`.
 *
 * Every code path that wants "the fortress this host uses when nothing more
 * specific was supplied" routes through here rather than composing
 * `join(homedir(), ".sanctuary")` itself, so the hermeticity guard sits on one
 * chokepoint instead of N open-coded joins.
 *
 * @param home Optional home directory override (for tests). Defaults to `os.homedir()`.
 */
export function homeFortressPath(home: string = homedir()): string {
  const resolved = join(home, DEFAULT_STORAGE_DIR);
  assertHermeticStoragePath(resolved);
  return resolved;
}

/**
 * Resolve the storage path for a Sanctuary instance.
 *
 * Precedence (highest wins):
 *   1. `SANCTUARY_STORAGE_PATH` env var
 *   2. `~/.sanctuary`
 *
 * Resolving with no arguments reaches for ambient process state, so it belongs
 * at a CLI entry point (where the operator's environment IS the input), not
 * inside a leaf module. A leaf that re-resolves ambiently silently overrides
 * the per-tenant path its caller already chose: that is the bug this module's
 * guard exists to make loud.
 *
 * NOT the same answer as `loadConfig().storage_path`. This function reads only
 * `SANCTUARY_STORAGE_PATH` and the home default; `loadConfig` additionally
 * merges a `storage_path` key from the config FILE. They diverge when that key
 * is present and the env var is not, and that divergence changes which
 * keychain entry holds a fortress's master passphrase. See the "DOCUMENTED
 * BEHAVIOUR CHANGE" block on `loadConfig` in `config.ts` for the full
 * consequence and its fail-closed bound. Pick deliberately: the fortress you
 * OPEN and the fortress you name the passphrase after must be the same one.
 *
 * @param env Optional env object (for tests). Defaults to `process.env`.
 * @param home Optional home directory override (for tests). Defaults to `os.homedir()`.
 */
export function resolveStoragePath(
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir()
): string {
  const override = env.SANCTUARY_STORAGE_PATH;
  if (override && override.length > 0) return override;
  return homeFortressPath(home);
}

/**
 * Strictly parse a whole-string TCP port from an env var.
 *
 * `parseInt("80abc", 10)` returns `80`: it stops at the first non-digit and
 * silently TRUNCATES, which would bind the dashboard to a port the operator
 * never typed. This matches the strict env parse in `config.ts` (the
 * `loadConfig` reader) byte-for-byte on the regex: both accept ASCII digits
 * only (no leading sign), so the same env value never resolves to two different
 * ports across the two readers. After the digit-only screen, enforce the valid
 * TCP range 1..65535. Any non-clean-integer, signed, or out-of-range value
 * yields `undefined` so the caller falls back to the documented default rather
 * than binding a truncated or out-of-spec port.
 *
 * Returns `undefined` for "", "+8443", "-1", "80abc", "0x10", "3501 5",
 * "70000", "0", or any value that is not a clean in-range unsigned integer.
 */
function parseStrictPortEnv(raw: string): number | undefined {
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    return undefined;
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return undefined;
  }
  return parsed;
}

/**
 * Resolve the dashboard starting port.
 *
 * Precedence (highest wins):
 *   1. Explicit port argument (e.g. `--port` CLI flag)
 *   2. `SANCTUARY_DASHBOARD_PORT` env var (strict whole-string parse,
 *      validated to the 1..65535 TCP range)
 *   3. Default 3501
 *
 * The env-var read is strict and range-checked so an invalid value (e.g.
 * "80abc", which the old lenient `parseInt` truncated to 80, or "70000",
 * which is out of the TCP range) does NOT silently bind a wrong port. Such
 * values fall back to the default: the same invalid-port hole that the
 * `loadConfig` reader closes by failing closed, closed here on the wrap
 * (Protect) boot path by ignoring the bad value.
 *
 * Auto-fallback (chosen port, then the next PORT_FALLBACK_ATTEMPTS-1
 * consecutive ports) is handled downstream once a port is chosen.
 */
export function resolveDashboardPort(
  explicitPort?: number,
  env: NodeJS.ProcessEnv = process.env
): number {
  if (typeof explicitPort === "number" && !Number.isNaN(explicitPort)) {
    return explicitPort;
  }
  const envPort = env.SANCTUARY_DASHBOARD_PORT;
  if (envPort) {
    const parsed = parseStrictPortEnv(envPort);
    if (parsed !== undefined) return parsed;
  }
  return DEFAULT_DASHBOARD_PORT;
}
