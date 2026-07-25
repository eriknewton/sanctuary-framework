/**
 * Shared helper for CLI tests that spawn the built `node dist/cli.js`.
 *
 * Why this exists
 * ---------------
 * Every CLI-subprocess test used to copy-paste the same
 * `execFile(... { timeout: 10000 })` block plus `err.code ?? 1`. Under the
 * full vitest suite's parallel load on a constrained machine (CI's
 * 2-core / 7 GB runner, or a loaded dev box at commit time), the spawned
 * node occasionally needs longer than 10 s just to parse the ~2.7 MB
 * single-file bundle and initialize the crypto / MCP module graph. When that
 * happens, `execFile` SIGTERM-kills the child, the promisified rejection
 * carries `code: null`, `null ?? 1` becomes exit-code `1`, and
 * `expect(code).toBe(0)` fails with the misleading "expected 1 to be 0".
 * In isolation a single uncontended spawn finishes in ~0.1 s, so these tests
 * always passed when run alone. Textbook contention flake.
 *
 * The fix has two layers, neither of which weakens any assertion:
 *
 *   1. A generous per-attempt timeout (30 s) so a contention-slowed-but-
 *      healthy spawn is never killed mid-flight.
 *   2. Bounded retry (up to 3 attempts, short backoff) on *transient* failures
 *      only: a signal-kill (timeout SIGTERM, or OOM SIGKILL on the 7 GB
 *      runner, both of which surface as `code: null`) or a fork-level errno
 *      (EAGAIN / ENOMEM / EMFILE, which surface as a string `code`). A genuine
 *      numeric non-zero exit is returned immediately and never retried, so a
 *      real CLI bug still fails fast and is never masked. If every attempt is
 *      a transient failure the helper throws a descriptive error rather than
 *      returning a coerced `1`, so a future regression reads as the
 *      contention / spawn problem it is instead of "expected 1 to be 0".
 */

import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

const HELPER_DIR = dirname(fileURLToPath(import.meta.url));

/** server/test/cli/helpers/run-cli.ts -> server/dist/cli.js */
export const CLI_PATH = join(HELPER_DIR, "../../../dist/cli.js");

/**
 * Per-test vitest timeout for CLI-subprocess tests. Must comfortably exceed
 * the helper's worst-case retry budget (3 attempts * 30 s + backoff ≈ 91.5 s)
 * so vitest never kills the test before the helper exhausts its retries.
 */
export const CLI_SUBPROCESS_TEST_TIMEOUT_MS = 120_000;

export interface RunCliResult {
  code: number;
  stdout: string;
  stderr: string;
  /** stdout + stderr concatenated, for tests that don't care which channel. */
  output: string;
}

export interface RunCliOptions {
  /** Binary to spawn. Defaults to "node". */
  command?: string;
  /** Args placed before the caller's args. Defaults to [CLI_PATH]. */
  prefixArgs?: string[];
  /** Per-attempt timeout in ms. Defaults to 30_000. */
  attemptTimeoutMs?: number;
  /** Total attempts including the first. Defaults to 3. */
  maxAttempts?: number;
  /** Backoff in ms before the given (1-indexed) attempt. Defaults to (n-1)*500. */
  backoffMs?: (nextAttempt: number) => number;
  /** Extra env merged over process.env. SANCTUARY_PASSPHRASE is always stripped. */
  env?: NodeJS.ProcessEnv;
}

const DEFAULT_ATTEMPT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_BACKOFF = (nextAttempt: number): number => (nextAttempt - 1) * 500;

/**
 * A failure is transient (worth retrying) when the child was killed by a
 * signal or never produced a numeric exit code:
 *   - timeout SIGTERM / OOM SIGKILL  -> err.killed true, err.code null
 *   - fork/spawn-level errno         -> err.code is a string (EAGAIN, ENOMEM…)
 * A real numeric non-zero exit is a genuine result, not a flake.
 */
function isTransient(err: { killed?: boolean; signal?: unknown; code?: unknown }): boolean {
  if (err.killed) return true;
  if (err.signal != null) return true;
  if (err.code == null) return true;
  if (typeof err.code === "string") return true;
  return false;
}

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Lower-level entry point with full options. Exported for the helper's own
 * regression tests; production callers use `runCli`.
 */
export async function runCliRaw(
  args: string[],
  opts: RunCliOptions = {},
): Promise<RunCliResult> {
  const command = opts.command ?? "node";
  const prefixArgs = opts.prefixArgs ?? [CLI_PATH];
  const attemptTimeoutMs = opts.attemptTimeoutMs ?? DEFAULT_ATTEMPT_TIMEOUT_MS;
  const maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const backoffMs = opts.backoffMs ?? DEFAULT_BACKOFF;

  const env: NodeJS.ProcessEnv = { ...process.env, NODE_NO_WARNINGS: "1", ...opts.env };
  delete env.SANCTUARY_PASSPHRASE;

  // Hermetic child fortress. A spawned CLI is still part of the test, but it
  // is a fresh process, so none of the in-process isolation a test does
  // (overriding HOME in a beforeEach, passing an explicit storagePath) reaches
  // it. Left alone the child resolves the operator's own `~/.sanctuary` and
  // both reads real custody and writes into it, which is one of the ways that
  // fortress's backup directory grew to thousands of files. Isolate here, at
  // the single place every CLI-subprocess test spawns through, rather than in
  // each test.
  //
  // A caller who names a fortress wins: isolation is SKIPPED entirely when
  // `opts.env` carries HOME or SANCTUARY_STORAGE_PATH, so a test that
  // deliberately points the child at a fixture fortress keeps doing so. Note
  // this cannot be left to the `...opts.env` spread above, because the
  // assignments below run after it and would clobber the caller's choice.
  const isolate =
    opts.env?.HOME === undefined && opts.env?.SANCTUARY_STORAGE_PATH === undefined;
  // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
  const childHome = isolate
    ? await mkdtemp(join(tmpdir(), "sanctuary-run-cli-home-"))
    : undefined;
  if (childHome !== undefined) {
    env.HOME = childHome;
    env.USERPROFILE = childHome;
    env.SANCTUARY_STORAGE_PATH = join(childHome, ".sanctuary");
  }

  try {
    return await attemptRunCli({
      command,
      argv: [...prefixArgs, ...args],
      env,
      attemptTimeoutMs,
      maxAttempts,
      backoffMs,
    });
  } finally {
    if (childHome !== undefined) {
      // A leftover temp dir is not worth failing a test over; the OS reaps it.
      await rm(childHome, { recursive: true, force: true }).catch(() => {});
    }
  }
}

async function attemptRunCli(spec: {
  command: string;
  argv: string[];
  env: NodeJS.ProcessEnv;
  attemptTimeoutMs: number;
  maxAttempts: number;
  backoffMs: (nextAttempt: number) => number;
}): Promise<RunCliResult> {
  const { command, argv, env, attemptTimeoutMs, maxAttempts, backoffMs } = spec;

  let lastErr: any;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    if (attempt > 1) {
      const wait = backoffMs(attempt);
      if (wait > 0) await sleep(wait);
    }
    try {
      const { stdout, stderr } = await execFileAsync(command, argv, {
        timeout: attemptTimeoutMs,
        env,
      });
      return { code: 0, stdout, stderr, output: `${stdout}${stderr}` };
    } catch (err: any) {
      lastErr = err;
      if (!isTransient(err)) {
        // Genuine non-zero exit. Return it verbatim: do not retry, do not mask.
        const stdout = err.stdout ?? "";
        const stderr = err.stderr ?? "";
        return { code: err.code, stdout, stderr, output: `${stdout}${stderr}` };
      }
      // Transient failure: fall through to retry, or exhaust below.
    }
  }

  throw new Error(
    `runCli failed after ${maxAttempts} attempt(s) ` +
      `[${argv.join(" ")}]: killed=${lastErr?.killed} ` +
      `signal=${JSON.stringify(lastErr?.signal)} code=${JSON.stringify(lastErr?.code)} ` +
      `errno=${lastErr?.errno} message=${lastErr?.message}`,
  );
}

/**
 * Spawn `node dist/cli.js <args>` and return its exit code and output, with
 * the contention-resilience described in this module's header. Drop-in
 * replacement for the per-file `runCli(...args)` helpers it consolidates.
 */
export async function runCli(...args: string[]): Promise<RunCliResult> {
  return runCliRaw(args);
}
