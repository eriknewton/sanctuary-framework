import { randomUUID } from "node:crypto";
import { chmodSync, lstatSync, mkdtempSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

// Must match the allocations in selector-roots-isolation.ts and private-tmpdir.ts;
// shared constants keep the run teardown's allowlist identical to the creators'.
export const SELECTOR_ROOT_PREFIX = "k1-selector-worker-";
export const PRIVATE_ROOT_PREFIX = "sanctuary-test-tmp-";
const OWNED_PREFIXES = [SELECTOR_ROOT_PREFIX, PRIVATE_ROOT_PREFIX] as const;
const OWNER_DIRECTORY_MODE = 0o700;
const OWNER_FILE_MODE = 0o600;

// Must match the provide/inject key in setup/test-temp-roots.ts and both creators.
export const TEMP_ROOT_REGISTRY = "testTempRootRegistry";
declare module "vitest" {
  export interface ProvidedContext {
    testTempRootRegistry: string;
  }
}

export interface OwnedTempRoot {
  path: string;
  dev: number;
  ino: number;
  uid: number;
  record?: string;
}

export function createOwnedTempRoot(prefix: typeof OWNED_PREFIXES[number], registry?: string): OwnedTempRoot {
  const path = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const { dev, ino, uid } = lstatSync(path);
  const root: OwnedTempRoot = { path, dev, ino, uid };
  try {
    // Only this run's workers receive its fresh registry through Vitest's provided context.
    // Record before exposing the root to collection code; child Vitest runs get a fresh registry.
    if (registry) {
      const record = join(registry, randomUUID());
      writeFileSync(record, JSON.stringify(root), { flag: "wx", mode: OWNER_FILE_MODE });
      root.record = record;
    }
  } catch (error) {
    removeOwnedTempRoot(root);
    throw error;
  }
  // Shared worker state cannot mutate the captured allocation or its registry record.
  return Object.freeze(root);
}

/** Reopen fixture directories without following symlinks out of the owned root. */
function reopen(path: string): void {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (!stat?.isDirectory()) return;
  chmodSync(path, OWNER_DIRECTORY_MODE);
  for (const name of readdirSync(path)) reopen(join(path, name));
}

export function removeOwnedTempRoot(root: OwnedTempRoot): void {
  // Invariant: the captured mkdtemp identity (or its run-private record) authorizes only
  // this allocation, never a replacement, a symlink, another uid, or an unowned prefix.
  if (!OWNED_PREFIXES.some(prefix => basename(root.path).startsWith(prefix))) throw new Error("Unowned temp root prefix");
  const stat = lstatSync(root.path, { throwIfNoEntry: false });
  if (!stat) {
    if (root.record) rmSync(root.record, { force: true });
    return;
  }
  if (!stat.isDirectory() || stat.uid !== process.getuid!() || stat.uid !== root.uid
    || stat.dev !== root.dev || stat.ino !== root.ino) throw new Error(`Temp root ownership changed: ${root.path}`);
  reopen(root.path);
  // Retire the record before deletion so a later mkdtemp reuse cannot authorize another run.
  // A removal error restores the record for global teardown; no async work intervenes.
  if (root.record) rmSync(root.record, { force: true });
  try { rmSync(root.path, { recursive: true, force: true }); }
  catch (error) {
    if (root.record) {
      const { record, ...identity } = root;
      writeFileSync(record, JSON.stringify(identity), { flag: "wx", mode: OWNER_FILE_MODE });
    }
    throw error;
  }
}
