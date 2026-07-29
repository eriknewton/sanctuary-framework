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

import { readFile, mkdir, open, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { loadConfig } from "../config.js";
import { writeFileCustody } from "../storage/custody-fs.js";
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
 * Persist the ledger to `path` with a DURABLE atomic rename and owner-only
 * permissions on the containing dir. The ledger holds no secret material (signed
 * tokens + public metadata only), but it is issuer state, so it is written under
 * the 0700 state dir with a 0600 file mode.
 *
 * DURABILITY (Fix 1, the F1 write-ordering class): this reuses
 * {@link writeFileCustody} (minimalism ladder rung 4: the proven custody-fs
 * durable-write helper) which writes to a unique `O_CREAT|O_EXCL|O_NOFOLLOW`
 * temp file, `fsync`s the temp FILE, renames it over `path`, then `fsync`s the
 * parent DIRECTORY (best-effort; the helper swallows EINVAL/ENOTSUP/EISDIR/EPERM
 * that some filesystems throw on a dir fsync). Net effect: when `saveLedger`
 * RETURNS, the blob is on stable storage, so the subsequent external anchor
 * write in the mutate path (`ledger-antirollback.ts`) CANNOT outrun it. The
 * crash window is therefore always the SAFE direction
 * (`ledger.generation >= anchor.generation` -> a benign lag under the `>=`
 * freshness check), never the false-brick direction. Before Fix 1 the temp file
 * was written with an un-fsync'd `writeFile` + `rename`, so a power loss could
 * leave the durable anchor ahead of a lost blob -> false-brick with no
 * re-baseline verb to recover.
 */
export async function saveLedger(path: string, ledger: Ledger): Promise<void> {
  const json = JSON.stringify(ledger, null, 2) + "\n";
  // writeFileCustody creates the parent dir (mode 0700), writes a unique
  // O_EXCL temp so two concurrent writers never clobber each other's temp file,
  // fsyncs file-then-dir, and renames atomically over `path`.
  await writeFileCustody(path, json, { mode: 0o600, parentMode: 0o700 });
}

/** Options for the advisory ledger mutation lock. */
export interface LedgerLockOptions {
  /** Max attempts to acquire the lock before failing closed. */
  maxAttempts?: number;
  /** Base backoff between attempts, in ms (grows linearly with the attempt). */
  backoffMs?: number;
}

const DEFAULT_LOCK_MAX_ATTEMPTS = 50;
const DEFAULT_LOCK_BACKOFF_MS = 20;

/**
 * Run `fn` while holding an ADVISORY exclusive lock for the ledger at `path`.
 * The lock is a native `O_CREAT|O_EXCL` lockfile (`fs.open(..., 'wx')`), NO new
 * dependency, so two concurrent `issue`/`revoke` sequences cannot interleave
 * their load -> verify -> mutate -> save -> bump-anchor and lost-update the
 * ledger or race the anchor. It is ALWAYS released in a `finally`.
 *
 * The whole read-modify-write-then-advance-anchor sequence for a mutation MUST
 * run inside this callback so the anchor bump is serialized with the blob write
 * that it trails (write-ordering section 4: blob durable first, then anchor; the
 * lock keeps a second writer from observing the in-between state).
 *
 * MINIMAL O_EXCL CONTRACT (fix-round 3, a NET DELETION): this is issuer-local,
 * single-operator, millisecond-duration locking, so the whole guard is exactly
 * one atomic exclusive-create. There is NO token, NO nonce, NO temp+link
 * publish, and NO auto-stale-break:
 *   - ACQUIRE: `open(lockPath, 'wx', 0o600)` atomically creates the lockfile or
 *     fails EEXIST if it already exists. On success we write
 *     `${pid}\n${iso}\n` purely as a HUMAN diagnostic (an operator can `cat` the
 *     lockfile to see who holds it) and close.
 *   - CONTENDED (EEXIST): back off (linear) and retry up to the budget. We do
 *     NOT `stat`, do NOT read/parse the lockfile, do NOT probe a pid, and do NOT
 *     unlink anyone else's lock. There is no check-then-act on the lock path, so
 *     the `js/file-system-race` class (the old `stat`->`unlink` /
 *     `readFile`->`unlink` stale-break) is structurally gone.
 *   - BUDGET EXHAUSTED: FAIL CLOSED (throw) with a self-service recovery hint
 *     naming the lock path (`rm '<lockPath>'`). A silent unlocked mutate is
 *     exactly the lost-update this guards against, so we never proceed unlocked.
 *   - RELEASE: `unlink(lockPath)` in `finally` (best-effort). We are the SOLE
 *     holder by O_EXCL  -  nobody else could have created this exact file  -  so
 *     there is nothing to verify: we simply delete what we created.
 *
 * TRADEOFF (recorded intentionally): with no auto-stale-break, a holder that
 * crashes MID-mutation leaves the lockfile behind and wedges the next mutation
 * until a one-time manual `rm` (which the fail-closed error hints). For a local
 * single-operator CLI this FAIL-SAFE wedge is strictly better than a fail-OPEN
 * auto-break that could double-acquire (which is what created every prior narrow
 * race: the empty-lockfile fail-open AND the concurrent-breaker
 * check-then-act). Correctness of the security primitive beats convenience.
 * (memory: build-correct-simple-elegant; whack-a-mole -> simplify to a
 * chokepoint.)
 */
export async function withLedgerMutationLock<T>(
  path: string,
  fn: () => Promise<T>,
  opts: LedgerLockOptions = {},
): Promise<T> {
  const maxAttempts = opts.maxAttempts ?? DEFAULT_LOCK_MAX_ATTEMPTS;
  const backoffMs = opts.backoffMs ?? DEFAULT_LOCK_BACKOFF_MS;
  const lockPath = `${path}.lock`;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });

  let acquired = false;
  for (let attempt = 0; attempt < maxAttempts && !acquired; attempt++) {
    try {
      // Atomic exclusive create: succeeds iff no lockfile exists, else EEXIST.
      // This IS the lock. There is no separate token/nonce and no
      // check-then-act on the lock path.
      const handle = await open(lockPath, "wx", 0o600);
      try {
        // Human diagnostic only (never read back for a trust decision): lets an
        // operator `cat` the lockfile to see which pid/time holds it.
        await handle.writeFile(`${process.pid}\n${new Date().toISOString()}\n`);
      } finally {
        await handle.close();
      }
      acquired = true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Contended: back off and retry. We NEVER stat/read/unlink the existing
      // lockfile here, so there is no check-then-act race to auto-break.
      await new Promise((r) => setTimeout(r, backoffMs * (attempt + 1)));
    }
  }
  if (!acquired) {
    throw new Error(
      `could not acquire the license ledger lock at ${lockPath} after ` +
        `${maxAttempts} attempts; another 'sanctuary license' mutation may be ` +
        "running. If you are certain none is, remove the stale lock file: " +
        `rm '${lockPath}'`,
    );
  }
  try {
    return await fn();
  } finally {
    // We are the sole holder by O_EXCL, so release is an unconditional unlink of
    // the file WE created  -  no token/nonce verification needed. Best-effort: a
    // release failure must not mask fn's own result/error.
    await unlink(lockPath).catch(() => {});
  }
}
