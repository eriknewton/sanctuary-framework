import { randomUUID } from "node:crypto";
import { chmodSync, lstatSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, isAbsolute, join } from "node:path";

// Must match the allocations in selector-roots-isolation.ts and private-tmpdir.ts;
// shared constants keep the run teardown's allowlist identical to the creators'.
export const SELECTOR_ROOT_PREFIX = "k1-selector-worker-";
// Socket-path reserve: 26 bytes = 1 separator + 19 ASCII bytes in PRIVATE_ROOT_PREFIX + 6 mkdtemp suffix bytes.
// Must match the 26-byte figure beside SHORT_SOCKET_TMP_PARENT in
// test/castle-wall/runtime/enforcement-availability.test.ts.
export const PRIVATE_ROOT_PREFIX = "sanctuary-test-tmp-";
const OWNED_PREFIXES = [SELECTOR_ROOT_PREFIX, PRIVATE_ROOT_PREFIX] as const;
const OWNER_DIRECTORY_MODE = 0o700;
const OWNER_FILE_MODE = 0o600;

export const TEMP_ROOT_REGISTRY = "testTempRootRegistry" as const;
declare module "vitest" {
  export interface ProvidedContext {
    [TEMP_ROOT_REGISTRY]: string | undefined;
  }
}

export interface OwnedTempRoot {
  path: string;
  dev: number;
  ino: number;
  uid: number;
  record?: string;
}

type TempRootIdentity = Omit<OwnedTempRoot, "record">;
const IDENTITY_KEYS = ["path", "dev", "ino", "uid"] as const;

function parseOwnedTempRootIdentity(value: unknown): TempRootIdentity {
  // Only validated allocation fields authorize deletion; a record cannot supply a retirement path.
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some(key => !IDENTITY_KEYS.some(allowed => allowed === key))) {
    throw new Error("Invalid temp root record");
  }
  const identity = value as Record<string, unknown>;
  if (typeof identity.path !== "string" || !isAbsolute(identity.path)
    || ![identity.dev, identity.ino, identity.uid].every(field => typeof field === "number" && Number.isFinite(field))) {
    throw new Error("Invalid temp root record identity");
  }
  return { path: identity.path, dev: identity.dev as number, ino: identity.ino as number, uid: identity.uid as number };
}

export function readOwnedTempRootRecord(record: string): OwnedTempRoot {
  return Object.freeze({ ...parseOwnedTempRootIdentity(JSON.parse(readFileSync(record, "utf8"))), record });
}

function writeOwnedTempRootRecord(record: string, identity: TempRootIdentity): void {
  writeFileSync(record, JSON.stringify(parseOwnedTempRootIdentity(identity)), { flag: "wx", mode: OWNER_FILE_MODE });
}

export function requireTempRootRegistry(registry: unknown): string {
  // A live Vitest runner must provide its run-private registry before any allocation.
  if (typeof registry !== "string" || !registry.trim()) throw new Error("Test temp root registry is missing");
  return registry;
}

export function createOwnedTempRoot(prefix: typeof OWNED_PREFIXES[number], registry: string | null): OwnedTempRoot {
  // Null explicitly selects the plain-Node exit lifecycle; undefined is a configuration error.
  if (registry !== null) requireTempRootRegistry(registry);
  // On macOS tmpdir() uses /var -> /private/var; consumers compare canonical paths.
  const path = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const { dev, ino, uid } = lstatSync(path);
  const root: OwnedTempRoot = { path, dev, ino, uid };
  try {
    // Only this run's workers receive its fresh registry through Vitest's provided context.
    // Record before exposing the root to collection code; child Vitest runs get a fresh registry.
    if (registry) {
      const record = join(registry, randomUUID());
      writeOwnedTempRootRecord(record, root);
      root.record = record;
    }
  } catch (error) {
    removeOwnedTempRoot(root);
    throw error;
  }
  // Shared worker state cannot mutate the captured allocation or its registry record.
  return Object.freeze(root);
}

/** Reopen fixture directories and verify their identity before recursion. */
function reopen(path: string): void {
  try {
    const stat = lstatSync(path, { throwIfNoEntry: false });
    if (!stat?.isDirectory()) return;
    chmodSync(path, OWNER_DIRECTORY_MODE);
    // Re-check after chmod so recursion only enters the same real directory.
    const reopened = lstatSync(path, { throwIfNoEntry: false });
    if (!reopened) return;
    if (!reopened.isDirectory() || reopened.dev !== stat.dev || reopened.ino !== stat.ino) {
      throw new Error(`Temp directory changed during permission reopening: ${path}`);
    }
    for (const name of readdirSync(path)) reopen(join(path, name));
  } catch (error) {
    // An entry removed concurrently has no permissions left to reopen; other failures stay visible.
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
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
      try { writeOwnedTempRootRecord(record, identity); }
      catch (restoreError) { throw new AggregateError([error, restoreError], "Temp root removal and record restoration both failed"); }
    }
    throw error;
  }
}
