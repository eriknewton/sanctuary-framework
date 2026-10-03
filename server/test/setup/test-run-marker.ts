/**
 * vitest `globalSetup`: leave a marker directory at the package root for the
 * duration of the run, so a spawned child knows it belongs to a test run even
 * when it was given no environment at all.
 *
 * WHY A FILE AND NOT AN ENV VAR. `setupFiles` installs the in-memory credential
 * store in every WORKER, and children spawned by a test inherit VITEST by
 * default, so both of those cases were already covered. The gap was a child
 * spawned with `env: {}`: no VITEST, no setup, no store, and `underTest()`
 * answered "production", which meant spawning the real credential binary
 * against the operator's own keychain. A scrubbed environment cannot erase a
 * filesystem marker, so the marker survives exactly the case the env signals
 * miss.
 *
 * MUST MATCH `TEST_RUN_MARKER_FILENAME` and the package-root derivation in
 * `src/wrap/keychain-exec.ts`, which reads this marker. That file carries a
 * pointer back here. The filename is imported rather than repeated so the two
 * sides cannot drift.
 *
 * FAILURE MODE TO RECOGNIZE: if a run is killed hard enough to skip teardown,
 * the marker survives and the CLI then REFUSES credential work from this
 * checkout until it is deleted. That is the safe direction and it is loud (the
 * refusal names the file), but the symptom reads as "the CLI suddenly cannot
 * reach my keychain" if you do not know to look. Delete `.sanctuary-test-run`
 * at the package root. It is gitignored, so it never shows up as a dirty tree
 * to hint at itself.
 */

import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  rmdirSync,
  statSync,
  unlinkSync,
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
// marker directory that token would keep the marker alive forever. Every run
// therefore prunes tokens older than MAX_TEST_RUN_AGE_MS at setup.
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
// 6 h = MAX_TEST_RUN_AGE_MS: the full suite measures 8 to 19 minutes (AGENTS.md)
// and the slowest observed run under load was about 25 minutes, so a run older
// than 14x that is hung, not working.
export const MAX_TEST_RUN_AGE_MS = 6 * 60 * 60 * 1000;

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
  if (existsSync(markerPath) && !statSync(markerPath).isDirectory()) {
    // A single-file marker from before the directory form; replace it.
    unlinkSync(markerPath);
  }
  for (let attempt = 1; ; attempt++) {
    try {
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

export function setup(): void {
  createTestRunMarker(rootPath, markerRunId);
}

export function teardown(): void {
  removeTestRunMarker(rootPath, markerRunId);
}
