/**
 * vitest `globalSetup`: leave a marker directory at the package root for the
 * duration of the run, so a spawned child knows it belongs to a test run even
 * when it was given no environment at all.
 *
 * WHY A CHECKOUT MARKER AND NOT AN ENV VAR. `setupFiles` installs the
 * in-memory credential store in every WORKER, and children spawned by a test
 * inherit VITEST by default, so both of those cases were already covered. The
 * gap was a child spawned with `env: {}`: no VITEST, no setup, no store, and
 * `underTest()` answered "production", which meant spawning the real credential
 * binary against the operator's own keychain. A scrubbed environment cannot
 * erase a filesystem marker, so the marker survives exactly the case the env
 * signals miss.
 *
 * MUST MATCH `TEST_RUN_MARKER_FILENAME` and the package-root derivation in
 * `src/wrap/keychain-exec.ts`, which reads this marker, and `markerOnDiskNow`
 * there, which treats the directory's existence alone as "under test" and
 * never reads the tokens inside it. That file carries a pointer back here. The filename is imported rather than repeated so the two
 * sides cannot drift.
 *
 * FAILURE MODE TO RECOGNIZE: if a run is killed hard enough to skip teardown,
 * its token survives until a later run prunes it after the staleness ceiling.
 * During that window the CLI REFUSES credential work from this checkout. That
 * is the safe direction and it is loud (the refusal names the marker), but the
 * symptom reads as "the CLI suddenly cannot reach my keychain" if you do not
 * know to look. A later run clears an interrupted token within the ceiling;
 * `rm -r .sanctuary-test-run` at the package root removes a leftover marker
 * directory. It is gitignored, so it never shows up as a dirty tree to hint at
 * itself.
 */

import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  rmdirSync,
  statSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { TEST_RUN_MARKER_FILENAME } from "../../src/wrap/keychain-exec.js";

function packageRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  // Same walk as keychain-exec.ts: up to the directory holding package.json.
  for (let i = 0; i < 10; i++) {
    if (existsSync(join(dir, "package.json"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(
    "test-run-marker: could not locate the package root (no package.json above " +
      `${fileURLToPath(import.meta.url)}). The credential chokepoint's marker check ` +
      "would silently degrade to env-only, so this fails loudly instead."
  );
}

const rootPath = packageRoot();
const markerRunId = `${process.pid}-${Date.now()}-${randomUUID()}`;

export function testRunMarkerPath(root: string): string {
  return join(root, TEST_RUN_MARKER_FILENAME);
}

// A run that crashed before teardown leaves its token behind, and with a
// marker directory that token would keep the marker alive forever. A live run
// refreshes its own token once per minute, so every run prunes tokens whose
// mtime has fallen past MAX_TEST_RUN_AGE_MS.
//
// WHY AGE AND NOT PID LIVENESS. The marker exists to stop a scrubbed child of a
// LIVE run from reaching the real credential binary, so pruning a live run's
// token is the one mistake that reopens the breach. A pid probe can make it:
// `kill(pid, 0)` is pid-namespace-local (a live owner in another namespace
// reads as gone) and the token names only the orchestrator, not workers that
// outlive it. Age cannot prune any run younger than the ceiling. The cost is
// that a crash leftover keeps this checkout reading as "under test" (fail
// safe: keychain work refuses) until a run starts after the ceiling, or until
// someone deletes the directory.
//
// 60 s = RUN_TOKEN_REFRESH_INTERVAL_MS: the refresh is only a liveness hint,
// not a scheduler, so the interval stays coarse and unref'd.
export const RUN_TOKEN_REFRESH_INTERVAL_MS = 60 * 1000;
// 15 = one expected refresh period plus 14 missed periods of scheduler/load
// slack. That leaves a live run comfortably above the refresh cadence while
// cutting the old six-hour stale-token cost by 24x.
const STALE_TOKEN_REFRESH_PERIODS = 15;
export const MAX_TEST_RUN_AGE_MS = RUN_TOKEN_REFRESH_INTERVAL_MS * STALE_TOKEN_REFRESH_PERIODS;

type RefreshInterval = ReturnType<typeof setInterval>;

export interface TestRunMarkerTimers {
  setInterval(callback: () => void, ms: number): RefreshInterval;
  clearInterval(interval: RefreshInterval): void;
}

const realTimers: TestRunMarkerTimers = {
  setInterval,
  clearInterval,
};

function pruneStaleRunTokens(markerPath: string, nowMs: number): void {
  for (const token of readdirSync(markerPath)) {
    const tokenPath = join(markerPath, token);
    try {
      if (nowMs - statSync(tokenPath).mtimeMs <= MAX_TEST_RUN_AGE_MS) continue;
      unlinkSync(tokenPath);
    } catch (err) {
      // A concurrent teardown removed it first; nothing left to prune.
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  }
}

export function refreshRunToken(root: string, runId: string, nowMs = Date.now()): void {
  const seconds = nowMs / 1000;
  try {
    utimesSync(join(testRunMarkerPath(root), runId), seconds, seconds);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    // A live run must re-create a pruned token: while it is missing, another
    // run's teardown can find the directory empty and remove it, and a missing
    // directory is the state in which a scrubbed child reaches the real
    // credential store. The exposure lasts at most one refresh period
    // (RUN_TOKEN_REFRESH_INTERVAL_MS) after a paused run resumes.
    createTestRunMarker(root, runId);
    utimesSync(join(testRunMarkerPath(root), runId), seconds, seconds);
  }
}

export function createTestRunMarkerLifecycle(
  root: string,
  runId: string,
  timers: TestRunMarkerTimers = realTimers
): { setup(): void; teardown(): void } {
  let refreshInterval: RefreshInterval | undefined;
  return {
    setup(): void {
      createTestRunMarker(root, runId);
      refreshInterval = timers.setInterval(
        () => refreshRunToken(root, runId),
        RUN_TOKEN_REFRESH_INTERVAL_MS
      );
      // An orphaned timer must never keep a completed or failed vitest process
      // alive; the marker is a fail-closed guard, not a reason to hang teardown.
      refreshInterval.unref?.();
    },
    teardown(): void {
      if (refreshInterval) {
        timers.clearInterval(refreshInterval);
        refreshInterval = undefined;
      }
      removeTestRunMarker(root, runId);
    },
  };
}

// An overlapping run's teardown can remove the directory between our mkdir and
// our token write (it saw the directory empty). That surfaces as ENOENT on the
// write, or as EINVAL from Node's recursive mkdir when the directory is created
// and removed concurrently (measured on macOS with three or more overlapping
// runs). Each retry recreates the directory; 5 attempts is a bound, not a
// tuned value: a failure after it throws, and vitest does not start an
// unmarked run when globalSetup throws.
const CREATE_ATTEMPTS = 5;

export function createTestRunMarker(root: string, runId: string): void {
  const markerPath = testRunMarkerPath(root);
  for (let attempt = 1; ; attempt++) {
    try {
      const existingMarker = statSync(markerPath, { throwIfNoEntry: false });
      if (existingMarker && !existingMarker.isDirectory()) {
        // A single-file marker from before the directory form; replace it.
        try {
          unlinkSync(markerPath);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        }
      }
      mkdirSync(markerPath, { mode: 0o700, recursive: true });
      writeFileSync(
        join(markerPath, runId),
        "A vitest run is in progress in this checkout. src/wrap/keychain-exec.ts\n" +
          "treats this directory's presence as proof that any process loading this package\n" +
          "belongs to the test run, so the real OS credential binary stays unreachable\n" +
          "even from a child spawned with a scrubbed environment.\n" +
          "\n" +
          "Safe to delete if no test run is active.\n",
        { mode: 0o600 }
      );
      break;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if ((code !== "ENOENT" && code !== "EINVAL") || attempt >= CREATE_ATTEMPTS) throw err;
    }
  }
  pruneStaleRunTokens(markerPath, Date.now());
}

export function removeTestRunMarker(root: string, runId: string): void {
  const markerPath = testRunMarkerPath(root);
  try {
    unlinkSync(join(markerPath, runId));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  try {
    if (existsSync(markerPath) && readdirSync(markerPath).length === 0) {
      rmdirSync(markerPath);
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT" && code !== "ENOTEMPTY" && code !== "EEXIST") throw err;
  }
}

const lifecycle = createTestRunMarkerLifecycle(rootPath, markerRunId);

export function teardown(): void {
  lifecycle.teardown();
}

export function setup(): void {
  lifecycle.setup();
}
