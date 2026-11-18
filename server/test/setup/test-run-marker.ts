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
  readFileSync,
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
/**
 * A parent test that launches a whole child vitest run (which inherits this
 * globalSetup) may assign the child's token name, so that after killing the
 * child it can delete exactly that token and nothing else. Must match
 * TEST_RUN_TOKEN_ID_ENV in test/structure/git-env-scrub.test.ts.
 *
 * Invariant: an assigned id is used only if it is a canonical lowercase UUID
 * (so it is a plain file name, never a path), and it is CONSUMED here:
 * deleted from process.env so this run's workers and descendants do not
 * inherit it. That alone cannot stop two SIBLING runs being launched with the
 * same value, so an assigned token is also CLAIMED: created exclusively
 * (`wx`) and tagged with a per-process owner nonce, and this run refreshes,
 * re-creates or removes it only while the token still carries that nonce
 * (see `RunTokenClaim`). A second run given an id already in use fails at
 * setup and never touches the first run's token. An invalid id fails the run
 * loudly rather than falling back to an unowned name.
 */
export const TEST_RUN_TOKEN_ID_ENV = "SANCTUARY_TEST_RUN_TOKEN_ID";
// 36 = the canonical 8-4-4-4-12 hex UUID; fixed counts, so the check is linear.
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

function consumeAssignedRunId(): string | undefined {
  const assigned = process.env[TEST_RUN_TOKEN_ID_ENV];
  delete process.env[TEST_RUN_TOKEN_ID_ENV];
  if (assigned === undefined) return undefined;
  if (!CANONICAL_UUID.test(assigned)) {
    throw new Error(`test-run-marker: ${TEST_RUN_TOKEN_ID_ENV} must be a canonical lowercase UUID`);
  }
  return assigned;
}

const assignedRunId = consumeAssignedRunId();
const markerRunId = assignedRunId ?? `${process.pid}-${Date.now()}-${randomUUID()}`;

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

/**
 * Exclusive ownership of an ASSIGNED token name. The nonce is written into
 * the token, and every later write or removal first checks that the token
 * still carries it, so a token another run holds under the same name is never
 * refreshed, rewritten or deleted by this one.
 */
export interface RunTokenClaim {
  ownerNonce: string;
}

function ownerLine(claim: RunTokenClaim): string {
  return `owner: ${claim.ownerNonce}\n`;
}

/** True only if the token exists and carries this claim's nonce. */
export function ownsRunToken(root: string, runId: string, claim: RunTokenClaim): boolean {
  try {
    return readFileSync(join(testRunMarkerPath(root), runId), "utf8").endsWith(ownerLine(claim));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw err;
  }
}

function lostClaimError(runId: string): Error {
  return new Error(
    `test-run-marker: token ${runId} is held by another run; an assigned ${TEST_RUN_TOKEN_ID_ENV} ` +
      "must be unique per run, so this run stops rather than share or remove it"
  );
}

/**
 * Refreshes a claimed token. A pruned token is re-claimed exclusively; a token
 * now carrying another run's nonce is a lost claim and throws (loud: an
 * unref'd interval throwing fails the vitest run) instead of being touched.
 */
export function refreshClaimedRunToken(root: string, runId: string, claim: RunTokenClaim, nowMs = Date.now()): void {
  const seconds = nowMs / 1000;
  if (ownsRunToken(root, runId, claim)) {
    utimesSync(join(testRunMarkerPath(root), runId), seconds, seconds);
    return;
  }
  if (existsSync(join(testRunMarkerPath(root), runId))) throw lostClaimError(runId);
  // Pruned while paused: re-claim, exclusively, so a run that took the name meanwhile wins.
  createTestRunMarker(root, runId, claim);
  utimesSync(join(testRunMarkerPath(root), runId), seconds, seconds);
}

/** Removes a claimed token only while it still carries this claim's nonce. */
export function removeClaimedRunToken(root: string, runId: string, claim: RunTokenClaim): void {
  if (ownsRunToken(root, runId, claim)) removeTestRunMarker(root, runId);
}

export function createTestRunMarkerLifecycle(
  root: string,
  runId: string,
  timers: TestRunMarkerTimers = realTimers,
  claim?: RunTokenClaim
): { setup(): void; teardown(): void } {
  let refreshInterval: RefreshInterval | undefined;
  // Set only once this process has created its claimed token; a failed claim
  // leaves it false, so teardown cannot remove the holder's token.
  let acquired = false;
  return {
    setup(): void {
      createTestRunMarker(root, runId, claim);
      acquired = true;
      refreshInterval = timers.setInterval(
        () => (claim ? refreshClaimedRunToken(root, runId, claim) : refreshRunToken(root, runId)),
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
      if (!claim) removeTestRunMarker(root, runId);
      else if (acquired) removeClaimedRunToken(root, runId, claim);
      acquired = false;
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

const TOKEN_TEXT =
  "A vitest run is in progress in this checkout. src/wrap/keychain-exec.ts\n" +
  "treats this directory's presence as proof that any process loading this package\n" +
  "belongs to the test run, so the real OS credential binary stays unreachable\n" +
  "even from a child spawned with a scrubbed environment.\n" +
  "\n" +
  "Safe to delete if no test run is active.\n";

/**
 * Creates the marker directory and this run's token. With a `claim`, the token
 * is created exclusively (`wx`) and tagged with the claim's nonce, and an
 * existing token of that name throws instead of being overwritten.
 */
export function createTestRunMarker(root: string, runId: string, claim?: RunTokenClaim): void {
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
      writeFileSync(join(markerPath, runId), claim ? TOKEN_TEXT + ownerLine(claim) : TOKEN_TEXT, {
        mode: 0o600,
        flag: claim ? "wx" : "w",
      });
      break;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (claim && code === "EEXIST") throw lostClaimError(runId);
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

const lifecycle = createTestRunMarkerLifecycle(
  rootPath,
  markerRunId,
  realTimers,
  assignedRunId === undefined ? undefined : { ownerNonce: randomUUID() }
);

export function teardown(): void {
  lifecycle.teardown();
}

export function setup(): void {
  lifecycle.setup();
}
