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

// A run token is named `<pid>-...` after the vitest main process that owns it.
// A run that crashed before teardown leaves its token behind; with a marker
// directory that token would keep the marker alive forever, so every later
// run prunes tokens whose owning process is gone. EPERM means the process
// exists under another uid, so only ESRCH counts as dead.
function runTokenOwnerIsGone(token: string): boolean {
  const pid = Number.parseInt(token.split("-", 1)[0] ?? "", 10);
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ESRCH";
  }
}

function pruneDeadRunTokens(markerPath: string): void {
  for (const token of readdirSync(markerPath)) {
    if (!runTokenOwnerIsGone(token)) continue;
    try {
      unlinkSync(join(markerPath, token));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  }
}

export function createTestRunMarker(root: string, runId: string): void {
  const markerPath = testRunMarkerPath(root);
  if (existsSync(markerPath) && !statSync(markerPath).isDirectory()) {
    // A single-file marker from before the directory form; replace it.
    unlinkSync(markerPath);
  }
  // Two attempts: an overlapping run's teardown can remove the directory
  // between our mkdir and our token write (it saw the directory empty), which
  // surfaces here as ENOENT on the write. Recreating once closes that window.
  for (let attempt = 0; ; attempt++) {
    mkdirSync(markerPath, { mode: 0o700, recursive: true });
    try {
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
      if ((err as NodeJS.ErrnoException).code !== "ENOENT" || attempt >= 1) throw err;
    }
  }
  pruneDeadRunTokens(markerPath);
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
