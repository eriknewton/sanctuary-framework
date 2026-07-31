/**
 * Fortress custody repair + never-root-owned normalize chokepoint
 * (fortress-ownership spec 2026-07-30, ratified option (a)).
 *
 * WHY this exists: on the first real install (Mini2, 2026-07-27) the operator
 * fortress (`~/.sanctuary`) was created BY ROOT during a sudo flow and stayed
 * `root:staff 0700`. Enforcement kept working (root daemons bypass DAC), but
 * every OPERATOR-side surface went dark at directory traversal: `castle-wall
 * status` printed a stuck-at-`undetermined` availability reason
 * (`connect EACCES`), the `disable` dead-man lever could not reach
 * `castle.sock`, and the operator could not `ls` their own state (hard
 * constraint #2). The intended ownership model (fortress = operator-owned
 * 0700, socket = operator-owned 0600, root reaches both via superuser
 * bypass) was already documented; this module makes deviations from it
 * repairable (the `repair-custody` verb) and non-reproducible (the
 * `normalizeFortressCustody` chokepoint every euid-0 flow calls on exit).
 *
 * Semantics shared by the verb and the chokepoint (ratification amendment 2:
 * one semantic, two call sites, no per-entry bookkeeping):
 *   - chown (lchown semantics, never following symlinks) every ROOT-owned
 *     entry under the fortress to the resolved operator uid:gid;
 *   - restore mode 0700 on the fortress top-level dir and 0600 on
 *     `castle.sock` only where they deviate;
 *   - SKIP and report any entry owned by a uid that is neither root nor the
 *     operator (never touch a third party's files);
 *   - a vanished entry (a live root daemon deletes transient lock files
 *     mid-walk; observed on hardware 2026-07-30) is a skip-and-note, never a
 *     failure;
 *   - idempotent: a clean tree yields an empty plan.
 *
 * Safety posture:
 *   - The walk NEVER descends through symlinks (lstat + explicit type check);
 *     symlink entries are lchown-only and never chmod'd.
 *   - Apply re-verifies identity: files/dirs are opened O_NOFOLLOW and the
 *     open fd's dev/ino must match the observed entry before fchown/fchmod
 *     (a swapped path component or replaced file is a reported skip, not a
 *     chown of something else). Sockets cannot be opened; they get a fresh
 *     lstat identity re-check immediately before lchown.
 *   - No entry is ever read, and no destructive verb exists here: this module
 *     only records metadata (uid/gid/mode) and applies chown/chmod.
 *   - Fail-closed operator resolution: uid 0 / gid 0 is never a valid
 *     operator (FIX G4); the verb and the chokepoint both refuse.
 */

import { constants as fsConstants, type Stats } from "node:fs";
import {
  chmod as fsChmod,
  lchown as fsLchown,
  lstat as fsLstat,
  mkdir as fsMkdir,
  open as fsOpen,
  readdir as fsReaddir,
} from "node:fs/promises";
import { join } from "node:path";

/** Basename of the Castle Wall IPC socket inside the fortress. */
const CASTLE_SOCKET_BASENAME = "castle.sock";

/** Root-owned (deliberately) manifest home OUTSIDE the fortress. */
export const CUSTODY_REPAIR_MANIFEST_DIR =
  "/Library/Application Support/Sanctuary/custody-repair";

// ---------------------------------------------------------------------------
// Sudo-aware operator-identity resolution (moved verbatim from
// wrap/auto-provision.ts so castle-wall/cli consumers can share the G4
// chokepoint without an import cycle; auto-provision re-exports it).
// ---------------------------------------------------------------------------

/**
 * Pure decision logic behind sudo-aware operator-identity resolution (fix R2
 * chokepoint seam): given the raw env values `sudo` sets
 * (`SUDO_UID`/`SUDO_GID`/`SUDO_USER`) and a name-validity check, decide
 * whether the operator identity is resolvable and, if so, from which env
 * vars. Exported so the real-ops unit-test suite can drive every branch
 * (both present, one missing, malformed) without touching a real process
 * environment or `dscl`.
 *
 * FIX R2: the pre-fix-round-2 code called `homedir()`/`userInfo()`
 * unconditionally, which under `sudo sanctuary protect --hermes` (this
 * function's only supported invocation shape, per the root check above every
 * caller) resolves to root's own identity (`/var/root`, 0/0) -- NOT the
 * operator. Two concrete failures followed: (1) the re-home SOURCE path
 * resolved to `/var/root/.hermes/...`, which is never where the operator's
 * real Hermes config lives, so re-home silently found nothing to move and
 * the wall armed over un-re-homed secrets; (2) F3's custody handback chowned
 * restored secrets to root, leaving the operator unable to read their own
 * recovered `.env` after a failed/aborted run.
 *
 * Fail-closed: `SUDO_UID`/`SUDO_GID` must both be present and parse as
 * non-negative integers, and (when present) `SUDO_USER` must match a safe
 * account-name shape; any other combination resolves `undefined` (never a
 * fabricated or root-fallback identity).
 *
 * FIX G4 (MEDIUM, 2026-07-07 re-gate 3 / fix-round 3): a ROOT sudo context
 * (e.g. `sudo su -` then running `sanctuary protect --hermes` from that root
 * shell) sets `SUDO_UID=0`/`SUDO_GID=0` (and often `SUDO_USER=root`). The
 * pre-fix code accepted uid/gid `0` as a perfectly well-formed "operator"
 * identity, which resolves the operator's home to `/var/root` and custody
 * to `0:0` -- reintroducing the EXACT root-home path this whole R2 fix
 * exists to fail closed against (re-home would look for secrets under
 * `/var/root/.hermes/...`, never where they actually live, and any restored
 * secret would be chowned back to root instead of a real operator account).
 * Reject uid `0`, gid `0`, and `SUDO_USER === "root"` outright -- fail closed
 * to the same `undefined` the caller already treats as "abort at the
 * root-check stage", never silently resolving root as the operator.
 */
export function resolveSudoIdentityDecision(env: {
  SUDO_UID?: string;
  SUDO_GID?: string;
  SUDO_USER?: string;
}): { uid: number; gid: number; user?: string } | undefined {
  const { SUDO_UID, SUDO_GID, SUDO_USER } = env;
  if (SUDO_UID === undefined || SUDO_GID === undefined) {
    return undefined;
  }
  if (!/^\d+$/.test(SUDO_UID) || !/^\d+$/.test(SUDO_GID)) {
    return undefined;
  }
  const uid = Number(SUDO_UID);
  const gid = Number(SUDO_GID);
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid)) {
    return undefined;
  }
  // FIX G4: a root sudo context is never a valid "operator" -- fail closed
  // rather than resolve /var/root + custody 0:0.
  if (uid === 0 || gid === 0 || SUDO_USER === "root") {
    return undefined;
  }
  if (SUDO_USER !== undefined && !/^[a-zA-Z0-9._-]+$/.test(SUDO_USER)) {
    // A SUDO_USER value that fails the safe-name shape is refused outright
    // (fail-closed), even though uid/gid alone would be enough to chown
    // with: an unparseable SUDO_USER is a signal something about this
    // invocation is not a normal sudo call, and the home-directory lookup
    // below needs a trustworthy name to pass to `dscl`.
    return undefined;
  }
  return { uid, gid, user: SUDO_USER };
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type FortressCustodyEntryType =
  | "dir"
  | "file"
  | "socket"
  | "symlink"
  | "other";

/** One observed fortress entry: metadata only, never contents. */
export interface FortressCustodyEntry {
  /** Path relative to the fortress root; `"."` is the root itself. */
  path: string;
  type: FortressCustodyEntryType;
  uid: number;
  gid: number;
  /** Permission bits (st_mode & 0o7777). */
  mode: number;
  /** Identity pin for the apply-phase re-verification. */
  dev: number;
  ino: number;
}

/** Filesystem seam so tests can simulate root-owned / vanishing entries. */
export interface FortressCustodyOpenHandle {
  stat(): Promise<Stats>;
  chown(uid: number, gid: number): Promise<void>;
  chmod(mode: number): Promise<void>;
  close(): Promise<void>;
}

export interface FortressCustodyFsOps {
  lstat(path: string): Promise<Stats>;
  readdir(path: string): Promise<string[]>;
  lchown(path: string, uid: number, gid: number): Promise<void>;
  chmod(path: string, mode: number): Promise<void>;
  /**
   * Open for the fd-pinned chown path (files/dirs). Must honor O_NOFOLLOW.
   * Returns a minimal handle; tests fake it.
   */
  open(
    path: string,
    flags: number,
  ): Promise<FortressCustodyOpenHandle>;
}

export function realFortressCustodyFsOps(): FortressCustodyFsOps {
  return {
    lstat: (path) => fsLstat(path),
    readdir: (path) => fsReaddir(path),
    lchown: (path, uid, gid) => fsLchown(path, uid, gid),
    chmod: (path, mode) => fsChmod(path, mode),
    open: async (path, flags) => {
      const handle = await fsOpen(path, flags);
      return {
        stat: () => handle.stat(),
        chown: (uid, gid) => handle.chown(uid, gid),
        chmod: (mode) => handle.chmod(mode),
        close: () => handle.close(),
      };
    },
  };
}

export interface FortressWalkResult {
  entries: FortressCustodyEntry[];
  /** Relative paths that disappeared between listing and lstat (skip-and-note). */
  vanished: string[];
}

export interface CustodyRepairAction {
  entry: FortressCustodyEntry;
  /** Chown target, when the entry is root-owned. */
  chownTo?: { uid: number; gid: number };
  /** Mode restore (top-level dir 0700 / castle.sock 0600), when deviant. */
  chmodTo?: number;
}

export interface CustodySkip {
  path: string;
  uid: number;
  gid: number;
  reason: "foreign_owner";
}

export interface CustodyRepairPlan {
  actions: CustodyRepairAction[];
  skips: CustodySkip[];
  /**
   * Sockets whose mode deviates from the canonical 0600. REPORTED rather than
   * repaired: a socket cannot be opened, so restoring its mode could only be
   * a pathname chmod, which is a root chmod primitive under a final-component
   * symlink swap (2026-07-31 gate round 3). The daemon re-establishes the
   * mode when it rebinds.
   */
  socketModeDeviations: { path: string; mode: number }[];
  /**
   * EVERY observed entry (not just the actionable ones), keyed for the
   * apply phase's ancestor verification: repairing `a/b/c` must prove that
   * `a` and `a/b` are still the exact directories the walk observed, so a
   * swapped ANCESTOR cannot redirect a root chown outside the fortress.
   */
  observed: readonly FortressCustodyEntry[];
}

export interface CustodyApplyResult {
  /** Relative paths actually repaired (chown and/or chmod applied). */
  repaired: string[];
  /** Entries that vanished between observe and apply (skip-and-note). */
  vanished: string[];
  /** Entries whose on-disk identity changed since observation (skipped, reported). */
  identityChanged: string[];
  failed: { path: string; reason: string }[];
}

// ---------------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------------

function entryType(stats: Stats): FortressCustodyEntryType {
  if (stats.isDirectory()) return "dir";
  if (stats.isFile()) return "file";
  if (stats.isSocket()) return "socket";
  if (stats.isSymbolicLink()) return "symlink";
  return "other";
}

function toEntry(relPath: string, stats: Stats): FortressCustodyEntry {
  return {
    path: relPath,
    type: entryType(stats),
    uid: stats.uid,
    gid: stats.gid,
    mode: stats.mode & 0o7777,
    dev: stats.dev,
    ino: stats.ino,
  };
}

function isEnoent(err: unknown): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    ((err as NodeJS.ErrnoException).code === "ENOENT" ||
      (err as NodeJS.ErrnoException).code === "ENOTDIR")
  );
}

/**
 * Depth-first observe walk. Records every entry's uid/gid/mode; never
 * descends through symlinks; a mid-walk ENOENT is a vanished note, not a
 * failure. Throws on a non-directory or symlinked fortress root (the caller
 * refuses) and on unexpected errors (fail closed, never guess).
 */
export async function walkFortressCustody(
  fortressPath: string,
  ops: FortressCustodyFsOps = realFortressCustodyFsOps(),
): Promise<FortressWalkResult> {
  const rootStats = await ops.lstat(fortressPath);
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) {
    throw new Error(
      `fortress root ${fortressPath} is not a plain directory; refusing to walk it`,
    );
  }
  const entries: FortressCustodyEntry[] = [toEntry(".", rootStats)];
  const vanished: string[] = [];

  const walkDir = async (absDir: string, relDir: string): Promise<void> => {
    let names: string[];
    try {
      names = await ops.readdir(absDir);
    } catch (err) {
      if (isEnoent(err)) {
        vanished.push(relDir);
        return;
      }
      throw err;
    }
    for (const name of [...names].sort()) {
      const absChild = join(absDir, name);
      const relChild = relDir === "." ? name : `${relDir}/${name}`;
      let stats: Stats;
      try {
        stats = await ops.lstat(absChild);
      } catch (err) {
        if (isEnoent(err)) {
          vanished.push(relChild);
          continue;
        }
        throw err;
      }
      entries.push(toEntry(relChild, stats));
      if (stats.isDirectory() && !stats.isSymbolicLink()) {
        await walkDir(absChild, relChild);
      }
    }
  };

  await walkDir(fortressPath, ".");
  return { entries, vanished };
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/**
 * Plan the repair for an observed tree: root-owned entries chown to the
 * operator; the top-level dir and `castle.sock` get their canonical modes
 * restored only where deviant; foreign-uid entries are skipped and reported.
 * A clean tree yields an empty plan (idempotence).
 */
export function planFortressCustodyRepairs(
  entries: readonly FortressCustodyEntry[],
  operator: { uid: number; gid: number },
): CustodyRepairPlan {
  const actions: CustodyRepairAction[] = [];
  const skips: CustodySkip[] = [];
  const socketModeDeviations: { path: string; mode: number }[] = [];
  for (const entry of entries) {
    if (entry.uid !== 0 && entry.uid !== operator.uid) {
      skips.push({
        path: entry.path,
        uid: entry.uid,
        gid: entry.gid,
        reason: "foreign_owner",
      });
      continue;
    }
    const action: CustodyRepairAction = { entry };
    if (entry.uid === 0) {
      action.chownTo = { uid: operator.uid, gid: operator.gid };
    }
    if (entry.path === "." && entry.type === "dir" && entry.mode !== 0o700) {
      action.chmodTo = 0o700;
    }
    // A deviant castle.sock mode is REPORTED, never chmod'd by pathname (a
    // socket cannot be opened, and a pathname chmod after an lstat is a root
    // chmod primitive; 2026-07-31 gate round 3). The daemon re-establishes
    // 0600 when it rebinds, which is the honest remedy.
    if (
      entry.path === CASTLE_SOCKET_BASENAME &&
      entry.type === "socket" &&
      entry.mode !== 0o600
    ) {
      socketModeDeviations.push({ path: entry.path, mode: entry.mode });
    }
    if (action.chownTo !== undefined || action.chmodTo !== undefined) {
      actions.push(action);
    }
  }
  return { actions, skips, socketModeDeviations, observed: entries };
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

function sameIdentity(entry: FortressCustodyEntry, stats: Stats): boolean {
  return (
    stats.dev === entry.dev &&
    stats.ino === entry.ino &&
    entryType(stats) === entry.type
  );
}

/** Directory-open flags: never follow a symlink, never open a non-directory. */
function dirOpenFlags(): number {
  return (
    fsConstants.O_RDONLY |
    (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0) |
    (typeof fsConstants.O_DIRECTORY === "number" ? fsConstants.O_DIRECTORY : 0)
  );
}

/**
 * ANCESTOR VERIFICATION (2026-07-31 gate BLOCKER-1/BLOCKER-2 fix).
 *
 * The walk records paths as strings, but apply must not keep resolving
 * descendants through mutable absolute ancestor paths. `O_NOFOLLOW` only
 * rejects the final component; a previously verified `a/` can otherwise be
 * renamed aside and replaced by a symlink before opening `a/b`.
 *
 * Node does not expose openat/fchownat, and macOS cannot address child paths
 * through `/dev/fd/<dirfd>/<child>`. The portable containment we can enforce is:
 * open every ancestor `O_NOFOLLOW | O_DIRECTORY`, hold those handles, then
 * re-open every ancestor path and compare it to the held handle immediately
 * before applying any root chown/chmod. If an ancestor was renamed aside and
 * replaced by a symlink or different directory, the revalidation fails and the
 * caller reports the entry instead of applying the root operation.
 */
async function openVerifiedAncestors(
  fortressPath: string,
  relPath: string,
  observed: ReadonlyMap<string, FortressCustodyEntry>,
  ops: FortressCustodyFsOps,
): Promise<
  | { handles: { prefix: string; path: string; handle: FortressCustodyOpenHandle }[] }
  | null
> {
  const handles: { prefix: string; path: string; handle: FortressCustodyOpenHandle }[] = [];
  const closeAll = async (): Promise<void> => {
    for (const { handle } of handles.reverse()) {
      await handle.close().catch(() => undefined);
    }
  };
  const verify = async (
    prefix: string,
    handle: FortressCustodyOpenHandle,
  ): Promise<boolean> => {
    const expected = observed.get(prefix);
    if (expected === undefined || expected.type !== "dir") {
      // An ancestor we never observed as a plain directory is not a path we
      // are willing to traverse as root.
      return false;
    }
    let stats: Stats;
    try {
      stats = await handle.stat();
    } catch {
      return false;
    }
    return sameIdentity(expected, stats);
  };

  const prefixes: string[] = ["."];
  const segments = relPath === "." ? [] : relPath.split("/");
  for (let i = 0; i < segments.length - 1; i++) {
    prefixes.push(segments.slice(0, i + 1).join("/"));
  }

  for (const prefix of prefixes) {
    const path = prefix === "." ? fortressPath : join(fortressPath, prefix);
    let handle: FortressCustodyOpenHandle;
    try {
      handle = await ops.open(path, dirOpenFlags());
    } catch {
      // ELOOP (symlinked ancestor), ENOTDIR, ENOENT, EACCES: refuse.
      await closeAll();
      return null;
    }
    handles.push({ prefix, path, handle });
    if (!(await verify(prefix, handle))) {
      await closeAll();
      return null;
    }
  }
  return { handles };
}

async function revalidateHeldAncestors(
  ancestors: { handles: { prefix: string; path: string; handle: FortressCustodyOpenHandle }[] },
  ops: FortressCustodyFsOps,
): Promise<boolean> {
  for (const ancestor of ancestors.handles) {
    let held: Stats;
    let freshHandle: FortressCustodyOpenHandle;
    try {
      held = await ancestor.handle.stat();
      freshHandle = await ops.open(ancestor.path, dirOpenFlags());
    } catch {
      return false;
    }
    try {
      const fresh = await freshHandle.stat();
      if (!sameIdentity(
        {
          path: ancestor.prefix,
          type: "dir",
          uid: held.uid,
          gid: held.gid,
          mode: held.mode & 0o7777,
          dev: held.dev,
          ino: held.ino,
        },
        fresh,
      )) {
        return false;
      }
    } finally {
      await freshHandle.close().catch(() => undefined);
    }
  }
  const allAncestorsStillMatch = true;
  return allAncestorsStillMatch;
}

/**
 * Apply one action with the full ancestor + final-component verification
 * described on {@link openVerifiedAncestors}. Returns the disposition so the
 * caller records it; NEVER chowns without both checks passing.
 */
async function applyOneAction(
  fortressPath: string,
  action: CustodyRepairAction,
  observed: ReadonlyMap<string, FortressCustodyEntry>,
  ops: FortressCustodyFsOps,
): Promise<"repaired" | "vanished" | "identity_changed" | "ancestor_changed"> {
  const relPath = action.entry.path;
  // 1. Every ancestor must still be the exact directory we observed, opened
  //    no-follow, and is HELD OPEN for the duration of this operation.
  const ancestors = await openVerifiedAncestors(fortressPath, relPath, observed, ops);
  if (ancestors === null) {
    return "ancestor_changed";
  }
  try {
    if (action.entry.type === "file" || action.entry.type === "dir") {
      const flags =
        fsConstants.O_RDONLY |
        (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0) |
        (action.entry.type === "dir" && typeof fsConstants.O_DIRECTORY === "number"
          ? fsConstants.O_DIRECTORY
          : 0);
      let handle: FortressCustodyOpenHandle;
      try {
        handle = await ops.open(relPath === "." ? fortressPath : join(fortressPath, relPath), flags);
      } catch (err) {
        if (isEnoent(err)) return "vanished";
        throw err;
      }
      try {
        // 2. The opened inode must be the one we observed.
        const fresh = await handle.stat();
        if (!sameIdentity(action.entry, fresh)) return "identity_changed";
        // 3. Two-sided close-out: resolve the path again and require it to
        //    name the observed inode, then revalidate every held ancestor path
        //    immediately before the root operation.
        let viaPath: Stats;
    try {
          viaPath = await ops.lstat(relPath === "." ? fortressPath : join(fortressPath, relPath));
        } catch (err) {
          if (isEnoent(err)) return "vanished";
          throw err;
        }
        if (!sameIdentity(action.entry, viaPath)) return "identity_changed";
        if (!(await revalidateHeldAncestors(ancestors, ops))) return "ancestor_changed";
        if (action.chownTo !== undefined) {
          await handle.chown(action.chownTo.uid, action.chownTo.gid);
        }
        if (action.chmodTo !== undefined) {
          await handle.chmod(action.chmodTo);
        }
      } finally {
        await handle.close().catch(() => undefined);
      }
      return "repaired";
    }
    // Socket / symlink / other: not openable, so the ancestor verification
    // above is the containment guarantee; re-verify the entry's own identity
    // by a fresh no-follow lstat immediately before the no-follow chown.
    let fresh: Stats;
    try {
      fresh = await ops.lstat(join(fortressPath, relPath));
    } catch (err) {
      if (isEnoent(err)) return "vanished";
      throw err;
    }
    if (!sameIdentity(action.entry, fresh)) return "identity_changed";
    if (!(await revalidateHeldAncestors(ancestors, ops))) return "ancestor_changed";
    if (action.chownTo !== undefined) {
      await ops.lchown(join(fortressPath, relPath), action.chownTo.uid, action.chownTo.gid);
    }
    // NOTE (2026-07-31 gate round 3): sockets and symlinks cannot be opened,
    // so a mode restore here could only be a PATHNAME chmod -- and a pathname
    // chmod after an lstat is a root chmod primitive (swap the final
    // component for a symlink in the window). We therefore chown these types
    // (lchown never follows) but never chmod them. `castle.sock`'s 0600 is
    // re-established by the daemon that binds it; a deviant socket mode is
    // REPORTED by the plan instead of silently left, see `socketModeDeviations`.
    return "repaired";
  } finally {
    for (const { handle } of ancestors.handles.reverse()) {
      await handle.close().catch(() => undefined);
    }
  }
}

/**
 * Apply a plan. Every action is ancestor-verified (no symlinked or swapped
 * ancestor can redirect a root chown outside the fortress) and
 * final-component identity-pinned on both the descriptor and a fresh path
 * resolution. A vanished entry is noted; an identity or ancestor change is
 * reported and skipped; any other failure is recorded and surfaced.
 */
export async function applyFortressCustodyRepairs(
  fortressPath: string,
  plan: CustodyRepairPlan,
  ops: FortressCustodyFsOps = realFortressCustodyFsOps(),
): Promise<CustodyApplyResult> {
  const result: CustodyApplyResult = {
    repaired: [],
    vanished: [],
    identityChanged: [],
    failed: [],
  };
  const observed = new Map<string, FortressCustodyEntry>(
    plan.observed.map((entry) => [entry.path, entry]),
  );
  for (const action of plan.actions) {
    const relPath = action.entry.path;
    try {
      const disposition = await applyOneAction(fortressPath, action, observed, ops);
      if (disposition === "vanished") {
        result.vanished.push(relPath);
      } else if (disposition === "identity_changed") {
        result.identityChanged.push(relPath);
      } else if (disposition === "ancestor_changed") {
        // Reported, never silently dropped: a changed ancestor is the
        // symlink-escape attack shape, so it is surfaced distinctly.
        result.identityChanged.push(`${relPath} (ancestor changed)`);
      } else {
        result.repaired.push(relPath);
      }
    } catch (err) {
      if (isEnoent(err)) {
        result.vanished.push(relPath);
        continue;
      }
      result.failed.push({
        path: relPath,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Manifest (observe-first, versioned, never clobbered)
// ---------------------------------------------------------------------------

export const CUSTODY_REPAIR_MANIFEST_KIND = "castle-wall-custody-repair";

export interface CustodyRepairManifest {
  version: 1;
  kind: typeof CUSTODY_REPAIR_MANIFEST_KIND;
  generated_at: string;
  fortress_path: string;
  operator: { uid: number; gid: number };
  /** PRE-repair observed state of every entry (metadata only, no contents). */
  entries: FortressCustodyEntry[];
  /** Entries that vanished during the observe walk. */
  vanished: string[];
}

/** Reject any relative path that could escape the fortress root. */
export function isSafeManifestRelPath(relPath: string): boolean {
  if (relPath === ".") return true;
  if (relPath.length === 0) return false;
  if (relPath.startsWith("/")) return false;
  const segments = relPath.split("/");
  return segments.every(
    (segment) => segment.length > 0 && segment !== "." && segment !== "..",
  );
}

/**
 * Persist an observe manifest to `dir` as a NEW file (O_EXCL; a re-run gets a
 * fresh timestamped name, an existing file is never overwritten -- the
 * rehome-clobber/unversioned-backup class is the named defect shape).
 * Returns the written path. The write goes through the injected ops-free
 * node fs on purpose: the manifest lives OUTSIDE the fortress in a
 * root-owned dir, and a failure to persist it must abort the repair
 * (observe-first is a hard precondition, so the caller treats a throw as
 * refusal to mutate).
 */
export async function writeCustodyRepairManifest(
  manifest: CustodyRepairManifest,
  dir: string = CUSTODY_REPAIR_MANIFEST_DIR,
): Promise<string> {
  await fsMkdir(dir, { recursive: true, mode: 0o755 });
  const stamp = manifest.generated_at.replace(/[:.]/g, "-");
  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
  for (let attempt = 0; attempt < 100; attempt++) {
    const name =
      attempt === 0 ? `custody-${stamp}.json` : `custody-${stamp}-${attempt + 1}.json`;
    const path = join(dir, name);
    let handle;
    try {
      handle = await fsOpen(
        path,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
        0o600,
      );
    } catch (err) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "EEXIST"
      ) {
        continue;
      }
      throw err;
    }
    try {
      await handle.writeFile(serialized);
      await handle.sync();
    } finally {
      await handle.close();
    }
    return path;
  }
  throw new Error(
    `could not allocate a fresh custody-repair manifest name under ${dir} after 100 attempts`,
  );
}

/** Parse + validate a manifest; returns null on any shape violation. */
export function parseCustodyRepairManifest(
  raw: string,
): CustodyRepairManifest | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const candidate = parsed as Record<string, unknown>;
  if (candidate.version !== 1) return null;
  if (candidate.kind !== CUSTODY_REPAIR_MANIFEST_KIND) return null;
  if (typeof candidate.generated_at !== "string") return null;
  if (typeof candidate.fortress_path !== "string" || candidate.fortress_path.length === 0) {
    return null;
  }
  const operator = candidate.operator as Record<string, unknown> | undefined;
  if (
    typeof operator !== "object" ||
    operator === null ||
    typeof operator.uid !== "number" ||
    typeof operator.gid !== "number"
  ) {
    return null;
  }
  if (!Array.isArray(candidate.entries)) return null;
  const types: FortressCustodyEntryType[] = [
    "dir",
    "file",
    "socket",
    "symlink",
    "other",
  ];
  for (const entry of candidate.entries) {
    if (typeof entry !== "object" || entry === null) return null;
    const record = entry as Record<string, unknown>;
    if (typeof record.path !== "string" || !isSafeManifestRelPath(record.path)) {
      return null;
    }
    if (!types.includes(record.type as FortressCustodyEntryType)) return null;
    for (const key of ["uid", "gid", "mode", "dev", "ino"]) {
      if (typeof record[key] !== "number" || !Number.isFinite(record[key] as number)) {
        return null;
      }
    }
  }
  if (
    !Array.isArray(candidate.vanished) ||
    !candidate.vanished.every((value) => typeof value === "string")
  ) {
    return null;
  }
  return candidate as unknown as CustodyRepairManifest;
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

/** Setuid / setgid / sticky. A fortress entry never legitimately carries these. */
const MODE_PRIVILEGE_BITS = 0o7000;

/**
 * True iff any manifest entry records a setuid/setgid/sticky bit. Such a
 * manifest is REFUSED wholesale rather than replayed (2026-07-31 gate
 * BLOCKER-2): "restore the recorded mode" plus an attacker-authored manifest
 * is otherwise a root setuid-creation primitive. Our own writer never
 * produces one from a healthy fortress, so a refusal here means the manifest
 * is not ours or the fortress was already compromised.
 */
export function manifestCarriesPrivilegeBits(
  manifest: CustodyRepairManifest,
): boolean {
  return manifest.entries.some((entry) => (entry.mode & MODE_PRIVILEGE_BITS) !== 0);
}

/**
 * Replay the recorded ownership (and modes) of a manifest exactly. Entries
 * already matching are untouched; vanished entries are noted; type changes
 * are reported as identityChanged (dev/ino is deliberately NOT required to
 * match here: legitimate rewrites via tmp+rename change the inode, and
 * rollback replays METADATA onto the path's current occupant of the same
 * type). Symlinks are never chmod'd.
 *
 * SECURITY (2026-07-31 gate BLOCKER-2): rollback is a root chown/chmod
 * primitive driven by file contents, so it carries the SAME containment as
 * the repair walk and then some:
 *   - the fortress root must be a plain directory (never a symlink);
 *   - every entry is ancestor-verified against the MANIFEST's own recorded
 *     directory identities, opened `O_NOFOLLOW | O_DIRECTORY`, so a
 *     symlinked parent (`escape -> /Users/operator`) cannot redirect the
 *     chown/chmod outside the fortress;
 *   - privilege bits are refused by the caller before we get here
 *     ({@link manifestCarriesPrivilegeBits}), and the applied mode is masked
 *     to 0o777 so no path can create a setuid root binary;
 *   - the CLI additionally accepts only root-owned manifests from the
 *     root-owned manifest directory.
 */
export async function applyCustodyRollback(
  fortressPath: string,
  manifest: CustodyRepairManifest,
  ops: FortressCustodyFsOps = realFortressCustodyFsOps(),
): Promise<CustodyApplyResult> {
  const result: CustodyApplyResult = {
    repaired: [],
    vanished: [],
    identityChanged: [],
    failed: [],
  };
  const rootStats = await ops.lstat(fortressPath);
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) {
    throw new Error(
      `fortress root ${fortressPath} is not a plain directory; refusing to roll back into it`,
    );
  }
  const observed = new Map<string, FortressCustodyEntry>(
    manifest.entries.map((entry) => [entry.path, entry]),
  );
  for (const entry of manifest.entries) {
    if (!isSafeManifestRelPath(entry.path)) {
      result.failed.push({ path: entry.path, reason: "unsafe relative path" });
      continue;
    }
        try {
      // Ancestor containment FIRST: no symlinked or substituted parent may
      // carry a root chown/chmod out of the fortress.
      const ancestors = await openVerifiedAncestors(
        fortressPath,
        entry.path,
        observed,
        ops,
      );
      if (ancestors === null) {
        result.identityChanged.push(`${entry.path} (ancestor changed)`);
        continue;
      }
      try {
        let current: Stats;
        try {
          current = await ops.lstat(entry.path === "." ? fortressPath : join(fortressPath, entry.path));
        } catch (err) {
          if (isEnoent(err)) {
            result.vanished.push(entry.path);
            continue;
          }
          throw err;
        }
        if (entryType(current) !== entry.type) {
          result.identityChanged.push(entry.path);
          continue;
        }
        const targetMode = entry.mode & 0o777;
        const needsChown = current.uid !== entry.uid || current.gid !== entry.gid;
        const needsChmod =
          entry.type !== "symlink" && (current.mode & 0o7777) !== targetMode;
        if (!needsChown && !needsChmod) continue;
        if (entry.type === "file" || entry.type === "dir") {
          // 2026-07-31 re-gate BLOCKER: a PATHNAME chmod after an lstat is a
          // root chmod primitive (swap the final component for a symlink in
          // the window and chmod follows it). Go through an O_NOFOLLOW
          // descriptor pinned to the observed inode instead.
          const flags =
            fsConstants.O_RDONLY |
            (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0) |
            (entry.type === "dir" && typeof fsConstants.O_DIRECTORY === "number"
              ? fsConstants.O_DIRECTORY
              : 0);
          let handle: FortressCustodyOpenHandle;
          try {
            handle = await ops.open(entry.path === "." ? fortressPath : join(fortressPath, entry.path), flags);
          } catch (err) {
            if (isEnoent(err)) {
              result.vanished.push(entry.path);
              continue;
            }
            throw err;
          }
          try {
            const pinned = await handle.stat();
            if (entryType(pinned) !== entry.type || entryType(current) !== entry.type) {
              result.identityChanged.push(entry.path);
              continue;
            }
            if (!(await revalidateHeldAncestors(ancestors, ops))) {
              result.identityChanged.push(`${entry.path} (ancestor changed)`);
              continue;
            }
            if (needsChown) await handle.chown(entry.uid, entry.gid);
            if (needsChmod) await handle.chmod(targetMode);
          } finally {
            await handle.close().catch(() => undefined);
          }
        } else {
          // Sockets/symlinks cannot be opened. lchown never follows, so
          // ownership is safe; a pathname CHMOD is not, so rollback does not
          // restore modes for these types. Stated bound, not a silent skip:
          // the socket's 0600 is re-established by the daemon that binds it,
          // and symlink modes are meaningless.
          if (needsChown) {
            if (!(await revalidateHeldAncestors(ancestors, ops))) {
              result.identityChanged.push(`${entry.path} (ancestor changed)`);
              continue;
            }
            await ops.lchown(
              entry.path === "." ? fortressPath : join(fortressPath, entry.path),
              entry.uid,
              entry.gid,
            );
          }
        }
        result.repaired.push(entry.path);
      } finally {
        for (const { handle } of ancestors.handles.reverse()) {
          await handle.close().catch(() => undefined);
        }
      }
    } catch (err) {
      if (isEnoent(err)) {
        result.vanished.push(entry.path);
        continue;
      }
      result.failed.push({
        path: entry.path,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Normalize chokepoint (end of every euid-0 flow that touches the fortress)
// ---------------------------------------------------------------------------

export interface NormalizeFortressCustodyInput {
  fortressPath: string;
  /** Resolved operator identity; uid/gid 0 is refused (G4). */
  operator: { uid: number; gid: number };
  /** Loud operator-facing reporting sink (stderr in production). */
  log: (line: string) => void;
  ops?: FortressCustodyFsOps;
}

export interface NormalizeFortressCustodyOutcome {
  status: "clean" | "changed" | "refused" | "failed" | "no_fortress";
  repaired: string[];
  skips: CustodySkip[];
  vanished: string[];
  failed: { path: string; reason: string }[];
}

/**
 * The custody-normalize chokepoint (spec §4(a2)(1), amendment 2): the SAME
 * walk/plan/apply semantics as the `repair-custody` verb, minus the
 * manifest (the verb is the deliberate, rollback-capable form; this runs at
 * the tail of every euid-0 flow so an install can never LEAVE a root-owned
 * fortress behind silently). Never throws: a failure here must not turn a
 * completed privileged flow into a reported failure, but it is always LOUD
 * (never a silent degradation) and names the repair verb as the remedy.
 */
export async function normalizeFortressCustody(
  input: NormalizeFortressCustodyInput,
): Promise<NormalizeFortressCustodyOutcome> {
  const ops = input.ops ?? realFortressCustodyFsOps();
  const outcome: NormalizeFortressCustodyOutcome = {
    status: "clean",
    repaired: [],
    skips: [],
    vanished: [],
    failed: [],
  };
  if (input.operator.uid === 0 || input.operator.gid === 0) {
    outcome.status = "refused";
    input.log(
      "Warning: fortress custody was NOT normalized: the resolved operator is root (uid/gid 0), which is never a valid fortress owner. " +
        "Run 'sudo sanctuary castle-wall repair-custody' from a normal operator sudo session.",
    );
    return outcome;
  }
  try {
    let walk: FortressWalkResult;
    try {
      walk = await walkFortressCustody(input.fortressPath, ops);
    } catch (err) {
      if (isEnoent(err)) {
        outcome.status = "no_fortress";
        return outcome;
      }
      throw err;
    }
    outcome.vanished.push(...walk.vanished);
    const plan = planFortressCustodyRepairs(walk.entries, input.operator);
    outcome.skips = plan.skips;
    if (plan.skips.length > 0) {
      for (const skip of plan.skips) {
        input.log(
          `Warning: fortress entry ${skip.path} is owned by uid ${skip.uid} (neither root nor the operator); left untouched.`,
        );
      }
    }
    if (plan.actions.length === 0) {
      return outcome;
    }
    const applied = await applyFortressCustodyRepairs(input.fortressPath, plan, ops);
    outcome.repaired = applied.repaired;
    outcome.vanished.push(...applied.vanished);
    outcome.failed = applied.failed;
    if (applied.repaired.length > 0) {
      outcome.status = "changed";
      input.log(
        `Fortress custody normalized: ${applied.repaired.length} root-owned entr${
          applied.repaired.length === 1 ? "y" : "ies"
        } under ${input.fortressPath} handed back to the operator (uid ${input.operator.uid}).`,
      );
    }
    // 2026-07-31 gate round 3 (LOW): identity/ancestor changes were dropped
    // here, so a race could leave root-owned residue behind a "clean"
    // outcome. Surface them as loudly as a failure.
    if (applied.identityChanged.length > 0) {
      outcome.status = "failed";
      input.log(
        `Warning: fortress custody normalize left ${applied.identityChanged.length} entr${
          applied.identityChanged.length === 1 ? "y" : "ies"
        } unrepaired under ${input.fortressPath} because the entry or an ancestor changed mid-run (${applied.identityChanged.join(
          "; ",
        )}). Run 'sudo sanctuary castle-wall repair-custody' once the fortress is quiescent.`,
      );
    }
    if (applied.failed.length > 0) {
      outcome.status = "failed";
      input.log(
        `Warning: fortress custody normalize could not repair ${applied.failed.length} entr${
          applied.failed.length === 1 ? "y" : "ies"
        } under ${input.fortressPath} (${applied.failed
          .map((failure) => `${failure.path}: ${failure.reason}`)
          .join("; ")}). Run 'sudo sanctuary castle-wall repair-custody' to finish the repair.`,
      );
    }
    return outcome;
  } catch (err) {
    outcome.status = "failed";
    outcome.failed.push({
      path: ".",
      reason: err instanceof Error ? err.message : String(err),
    });
    input.log(
      `Warning: fortress custody normalize failed for ${input.fortressPath} (${
        err instanceof Error ? err.message : String(err)
      }). Run 'sudo sanctuary castle-wall repair-custody' to repair operator custody.`,
    );
    return outcome;
  }
}
