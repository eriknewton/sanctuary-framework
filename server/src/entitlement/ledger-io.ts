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

import { readFile, mkdir, open, stat, unlink } from "node:fs/promises";
import { randomUUID } from "node:crypto";
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

/** The parsed contents of an owner-verified lockfile token. */
interface LockToken {
  pid: number;
  ts: number;
  nonce: string;
}

/**
 * Serialize a lock token to the on-disk form `${pid}\n${ts}\n${nonce}\n`. The
 * nonce is what makes the lock OWNER-VERIFIED: only the holder that wrote it
 * knows the value, so release only unlinks a lockfile that still carries it.
 */
function serializeLockToken(token: LockToken): string {
  return `${token.pid}\n${token.ts}\n${token.nonce}\n`;
}

/** Parse a lockfile's bytes back into a token, or null if it is not our shape. */
function parseLockToken(raw: string): LockToken | null {
  const lines = raw.split("\n");
  if (lines.length < 3) return null;
  const pid = Number.parseInt(lines[0], 10);
  const ts = Number.parseInt(lines[1], 10);
  const nonce = lines[2];
  if (!Number.isInteger(pid) || pid <= 0 || !Number.isFinite(ts) || !nonce) {
    return null;
  }
  return { pid, ts, nonce };
}

/**
 * Is `pid` a live process on this host? Uses `process.kill(pid, 0)` which sends
 * NO signal but performs the permission/existence check: it throws ESRCH when
 * the process does not exist (safe to break the lock) and EPERM when it exists
 * but is owned by another user (still ALIVE -> we must NOT break). Any other
 * error (or a successful no-op signal) is treated conservatively as ALIVE so we
 * never break a lock we cannot prove is dead.
 */
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false; // no such process -> provably dead
    // EPERM (exists, other owner) or anything unexpected -> assume alive.
    return true;
  }
}

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
 * OWNER-VERIFIED (Fix 2): this is issuer-local single-host locking (not a
 * distributed lock), so the guard is the pid-liveness + token-verify pair, with
 * NO dependency and NO heartbeat thread:
 *   - ACQUIRE writes a unique token `${pid}\n${ts}\n${nonce}` (nonce =
 *     `randomUUID`) and remembers the nonce.
 *   - STALE-BREAK happens ONLY when the lockfile is BOTH older than `staleMs`
 *     AND its recorded pid is provably gone (`process.kill(pid, 0)` -> ESRCH).
 *     A live-but-slow holder (age > staleMs but pid still alive) is NEVER
 *     broken, so a stale-break can no longer create two live holders. A
 *     malformed/unparseable lockfile past staleMs is treated as debris and
 *     broken (there is no live owner to protect).
 *   - RELEASE reads the lockfile and unlinks ONLY if it still carries OUR nonce.
 *     If it holds a different token (a peer broke ours as stale and now holds
 *     it), we leave it (never unlink a foreign token).
 *
 * Fail-closed: if the lock cannot be acquired within the retry budget, this
 * THROWS rather than proceeding unlocked (a silent unlocked mutate is exactly
 * the lost-update this guards against).
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

  // Our unique ownership token. The nonce is never reused, so no other holder
  // (even one that reuses our pid after we exit) can impersonate this lock.
  const ourToken: LockToken = {
    pid: process.pid,
    ts: Date.now(),
    nonce: randomUUID(),
  };

  let acquired = false;
  for (let attempt = 0; attempt < maxAttempts && !acquired; attempt++) {
    try {
      // 'wx' = O_CREAT | O_EXCL: fails with EEXIST if the lockfile already
      // exists, giving an atomic test-and-set across processes on one host.
      const handle = await open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(serializeLockToken(ourToken));
      } finally {
        await handle.close();
      }
      acquired = true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Contended. Only break a lock that is BOTH stale by age AND whose
      // recorded holder is provably dead (never break a live-but-slow holder).
      let broke = false;
      try {
        const st = await stat(lockPath);
        if (Date.now() - st.mtimeMs > staleMs) {
          let holderAlive = true;
          try {
            const holder = parseLockToken(await readFile(lockPath, "utf-8"));
            // A parseable token: break only if its pid is provably gone. An
            // UNparseable/legacy lockfile past staleMs has no owner we can
            // protect, so treat it as debris and break it.
            holderAlive = holder ? isProcessAlive(holder.pid) : false;
          } catch {
            // The lockfile vanished between stat and read (holder released).
            holderAlive = true; // nothing to break; fall through to retry.
          }
          if (!holderAlive) {
            await unlink(lockPath).catch(() => {});
            broke = true;
          }
        }
      } catch {
        // The lock vanished between EEXIST and stat (holder released); retry.
      }
      // If we just broke a dead holder's lock, re-contend immediately without
      // burning the backoff so we grab the freed lock promptly.
      if (broke) continue;
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
    // OWNER-VERIFIED release: unlink ONLY if the lockfile still carries OUR
    // nonce. If a peer broke ours as stale and now holds it, the on-disk nonce
    // differs and we leave it: unlinking a foreign token would vanish B's lock
    // mid-run. Best-effort throughout: a release failure must not mask fn's
    // own result/error.
    try {
      const current = parseLockToken(await readFile(lockPath, "utf-8"));
      if (current && current.nonce === ourToken.nonce) {
        await unlink(lockPath).catch(() => {});
      }
    } catch {
      // Lockfile already gone (or unreadable) -> nothing for us to release.
    }
  }
}
