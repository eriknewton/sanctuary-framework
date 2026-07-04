/**
 * Thin persistence layer for the fleet license ledger (PR-1).
 *
 * Separated from `ledger.ts` (pure core) so the tamper-evidence logic stays
 * I/O-free and unit-testable. This layer only reads/writes the JSON document
 * under the fortress state dir; it resolves the path via the same config other
 * modules use (NEVER hardcodes `~/.sanctuary`), and it defers ALL trust
 * decisions to `verifyLedgerIntegrity`  -  a load NEVER silently trusts a ledger
 * that fails its integrity check.
 */

import { readFile, writeFile, mkdir, open, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { loadConfig } from "../config.js";
import { emptyLedger, type Ledger } from "./ledger.js";

/**
 * Resolve the on-disk path of the issuer's license ledger. Under the fortress
 * state dir (`<storage_path>/state/fleet-license-ledger.json`), NOT a hardcoded
 * home path  -  honors `SANCTUARY_STORAGE_PATH` / `--fortress` via loadConfig.
 */
export async function resolveLedgerPath(): Promise<string> {
  const config = await loadConfig();
  return join(config.storage_path, "state", "fleet-license-ledger.json");
}

/**
 * Load the ledger from `path`. A missing file yields a fresh empty ledger (an
 * issuer that has never issued anything). A present-but-unparseable file throws
 * (fail-closed: the CLI reports it rather than overwriting a corrupt/tampered
 * ledger). Integrity verification is the CALLER's responsibility via
 * `verifyLedgerIntegrity`  -  this only parses.
 */
export async function loadLedger(path: string): Promise<Ledger> {
  let bytes: Buffer;
  try {
    bytes = await readFile(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return emptyLedger();
    }
    throw err;
  }
  const parsed = JSON.parse(bytes.toString("utf-8")) as unknown;
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !Array.isArray((parsed as Ledger).rows)
  ) {
    throw new Error(`fleet license ledger at ${path} is malformed`);
  }
  return parsed as Ledger;
}

/**
 * Persist the ledger to `path` atomically-ish (write a temp file then rename)
 * with owner-only permissions on the containing dir. The ledger holds no secret
 * material (signed tokens + public metadata only), but it is issuer state, so
 * it is written under the 0700 state dir.
 */
export async function saveLedger(path: string, ledger: Ledger): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  // Unique temp name per call so two concurrent writers never clobber each
  // other's temp file. (The advisory lock below serializes mutate sequences;
  // this uniqueness is belt-and-suspenders for any non-locked write.)
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}-${Math.random()
    .toString(36)
    .slice(2, 8)}`;
  const json = JSON.stringify(ledger, null, 2) + "\n";
  await writeFile(tmp, json, { mode: 0o600 });
  const { rename } = await import("node:fs/promises");
  await rename(tmp, path);
}

/** Options for the advisory ledger mutation lock. */
export interface LedgerLockOptions {
  /** Max attempts to acquire the lock before failing closed. */
  maxAttempts?: number;
  /** Base backoff between attempts, in ms (grows linearly with the attempt). */
  backoffMs?: number;
  /**
   * Age (ms) past which an existing lockfile is treated as STALE (a crashed
   * holder that never released) and force-broken. Keeps a single crashed mutate
   * from wedging the CLI forever. Generous relative to a mutate's duration.
   */
  staleMs?: number;
}

const DEFAULT_LOCK_MAX_ATTEMPTS = 50;
const DEFAULT_LOCK_BACKOFF_MS = 20;
const DEFAULT_LOCK_STALE_MS = 30_000;

/**
 * Run `fn` while holding an ADVISORY exclusive lock for the ledger at `path`.
 * The lock is a native `O_CREAT|O_EXCL` lockfile (`fs.open(..., 'wx')`), NO new
 * dependency, so two concurrent `issue`/`revoke` sequences cannot interleave
 * their load -> verify -> mutate -> save -> bump-anchor and lost-update the
 * ledger or race the anchor. It is ALWAYS released in a `finally`.
 *
 * The whole read-modify-write-then-advance-anchor sequence for a mutation MUST
 * run inside this callback so the anchor bump is serialized with the blob write
 * that it trails (write-ordering §4: blob durable first, then anchor; the lock
 * keeps a second writer from observing the in-between state).
 *
 * Fail-closed: if the lock cannot be acquired within the retry budget, this
 * THROWS rather than proceeding unlocked (a silent unlocked mutate is exactly
 * the lost-update this guards against). A lockfile older than `staleMs` is
 * treated as a crashed holder and force-broken once, then re-contended.
 */
export async function withLedgerMutationLock<T>(
  path: string,
  fn: () => Promise<T>,
  opts: LedgerLockOptions = {},
): Promise<T> {
  const maxAttempts = opts.maxAttempts ?? DEFAULT_LOCK_MAX_ATTEMPTS;
  const backoffMs = opts.backoffMs ?? DEFAULT_LOCK_BACKOFF_MS;
  const staleMs = opts.staleMs ?? DEFAULT_LOCK_STALE_MS;
  const lockPath = `${path}.lock`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });

  let acquired = false;
  let staleBroken = false;
  for (let attempt = 0; attempt < maxAttempts && !acquired; attempt++) {
    try {
      // 'wx' = O_CREAT | O_EXCL: fails with EEXIST if the lockfile already
      // exists, giving an atomic test-and-set across processes on one host.
      const handle = await open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(`${process.pid}\n${Date.now()}\n`);
      } finally {
        await handle.close();
      }
      acquired = true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Contended. Check whether the existing lock is stale (crashed holder).
      if (!staleBroken) {
        try {
          const { stat } = await import("node:fs/promises");
          const st = await stat(lockPath);
          if (Date.now() - st.mtimeMs > staleMs) {
            // Break a stale lock exactly once, then re-contend from the top.
            await unlink(lockPath).catch(() => {});
            staleBroken = true;
            continue;
          }
        } catch {
          // The lock vanished between EEXIST and stat (holder released); retry.
        }
      }
      await new Promise((r) => setTimeout(r, backoffMs * (attempt + 1)));
    }
  }
  if (!acquired) {
    throw new Error(
      `could not acquire the license ledger lock at ${lockPath} after ` +
        `${maxAttempts} attempts; another 'sanctuary license' mutation may be ` +
        "in progress. Retry shortly.",
    );
  }
  try {
    return await fn();
  } finally {
    // Release the lock unconditionally. Best-effort unlink: a failure to remove
    // the lockfile (e.g. it was already broken as stale by a peer) must not mask
    // the mutation's own result/error.
    await unlink(lockPath).catch(() => {});
  }
}
