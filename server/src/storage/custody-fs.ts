import { constants as fsConstants, type Stats } from "node:fs";
import { mkdir, open, rename, unlink, lstat } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { basename, dirname, join, relative, sep, resolve as resolvePath } from "node:path";
import { isBenignDirectoryFsyncError } from "./directory-fsync.js";

export type CustodyFsErrorCode =
  | "symlink_rejected"
  | "not_regular_file"
  | "read_size_rejected"
  | "path_identity_changed"
  | "mode_rejected"
  | "uid_rejected"
  | "gid_rejected"
  | "directory_symlink_rejected"
  | "directory_not_directory"
  | "directory_mode_rejected"
  | "directory_uid_rejected"
  | "directory_gid_rejected"
  | "parent_not_directory"
  | "parent_symlink_rejected"
  | "parent_mode_rejected"
  | "parent_uid_rejected"
  | "parent_gid_rejected";

export class CustodyFsError extends Error {
  constructor(
    public readonly code: CustodyFsErrorCode,
    message: string,
    options: { cause?: unknown; details?: Record<string, unknown> } = {},
  ) {
    super(message, options);
    this.name = "CustodyFsError";
    this.details = options.details ?? {};
  }

  public readonly details: Record<string, unknown>;
}

export function isCustodyFsError(error: unknown): error is CustodyFsError {
  return error instanceof CustodyFsError;
}

export interface CustodyModeCheck {
  /** Require the complete permission mode, masked to 0777, to match exactly. */
  exact?: number;
  /** Reject any group/other permission bit. Useful for key and token files. */
  rejectGroupOrOther?: boolean;
  /** Reject group/other write bits while allowing read/execute traversal. */
  rejectGroupOrOtherWrite?: boolean;
}

export interface DirectoryCustodyOptions {
  uid?: number;
  gid?: number;
  mode?: CustodyModeCheck;
}

export interface DirectoryWithinBaseCustodyOptions extends DirectoryCustodyOptions {
  /** Permit the leaf directory itself to be absent, while still verifying its existing parent chain. */
  allowMissingLeaf?: boolean;
  /** Apply the custody predicate to every opened directory from base through leaf, not only the leaf. */
  verifyEveryComponent?: boolean;
}

export interface ReadFileCustodyBaseOptions {
  uid?: number;
  gid?: number;
  mode?: CustodyModeCheck;
  parent?: DirectoryCustodyOptions;
  /**
   * After opening and fstat'ing the descriptor, verify the pathname still names
   * the same inode before reading. This is stricter than descriptor custody and
   * is intended for singleton security files where concurrent replacement
   * should fail closed instead of reading a stale-but-valid descriptor.
   */
  verifyPathIdentity?: boolean;
  /**
   * Hook used by tests and tightly controlled callers to coordinate an external
   * custody probe after descriptor verification but before the read.
   */
  onDescriptorVerified?: (info: {
    path: string;
    stats: Stats;
  }) => void | Promise<void>;
  /**
   * Hard ceiling for bytes read from the already-open descriptor. The reader
   * pulls at most maxBytes+1 bytes so same-inode growth after fstat is refused
   * by the descriptor read itself, not by a stale path stat.
   */
  maxBytes?: number;
}

export interface ReadFileCustodyBufferOptions extends ReadFileCustodyBaseOptions {
  encoding?: undefined;
}

export interface ReadFileCustodyTextOptions extends ReadFileCustodyBaseOptions {
  encoding: BufferEncoding;
}

export type ReadFileCustodyOptions =
  | ReadFileCustodyBufferOptions
  | ReadFileCustodyTextOptions;

export interface WriteFileCustodyOptions {
  /** Must match strictDurability in filesystem.ts and directory-capability-worker.ts. */
  strictDurability?: boolean;
  /** Existing held boundary through which strict directory barriers are repeated. */
  strictDirectoryBase?: string;
  mode: number;
  /**
   * Create the parent directory before writing. Defaults to true. Set false for
   * root-owned custody directories that must already exist.
   */
  createParent?: boolean;
  parentMode?: number;
  parent?: DirectoryCustodyOptions;
  /**
   * Called after the temp file is opened and chmod'ed but before any bytes are
   * written. Use only when custody has to be applied before secret bytes exist
   * on disk, e.g. root:wheel boot-token provisioning.
   */
  prepareTemp?: (tempPath: string) => void | Promise<void>;
  /**
   * Create-with-fchown (fortress-ownership spec 2026-07-30, open question 5):
   * chown the file via its open descriptor before the atomic rename. Root
   * daemons that write inside an operator-owned fortress pass the fortress
   * owner here so fortress-internal files never accrete root ownership boot
   * over boot. Parent directories must already exist and verify no-follow
   * inside `ownerBase`; this API deliberately will not recursively create
   * directories as root through a mutable path.
   * FAIL-CLOSED: if the chown fails the write fails (never silently leave the
   * file with the wrong owner).
   */
  owner?: { uid: number; gid: number };
  /**
   * Containment base for `owner` writes (2026-07-31 gate round 3). Every path
   * component from this directory down to the parent is opened
   * `O_NOFOLLOW | O_DIRECTORY` before the write and revalidated immediately
   * before the path-based calls. This refuses pre-existing/static symlinked
   * ancestors and narrows the race window, but Node does not expose the
   * `renameat`/`openat` primitives needed to bind the final path syscall to
   * the held descriptors. Required whenever `owner` is set; the fortress path
   * is the natural value.
   */
  ownerBase?: string;
  /**
   * Internal storage-backend capability: `path` and `ownerBase` are rooted at
   * a live `/dev/fd/<n>` or `/proc/self/fd/<n>` directory descriptor. The
   * descriptor, rather than a revalidated pathname, provides containment and
   * rename resistance. Callers outside FilesystemStorage must never set this.
   */
  stableDirectoryCapability?: boolean;
}

const O_NOFOLLOW =
  typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0;

function fileMode(stats: Stats): number {
  return stats.mode & 0o777;
}

function modeRejected(mode: number, check: CustodyModeCheck | undefined): boolean {
  if (!check) return false;
  if (check.exact !== undefined && mode !== check.exact) return true;
  if (check.rejectGroupOrOther === true && (mode & 0o077) !== 0) return true;
  if (check.rejectGroupOrOtherWrite === true && (mode & 0o022) !== 0) return true;
  return false;
}

function sameFile(a: Stats, b: Stats): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

function throwModeRejected(
  code: "mode_rejected" | "parent_mode_rejected",
  path: string,
  mode: number,
): never {
  throw new CustodyFsError(
    code,
    `File custody check failed for ${path}: mode is not permitted.`,
    { details: { mode } },
  );
}

function verifyDirectoryStats(
  path: string,
  stats: Stats,
  custody: DirectoryCustodyOptions,
): void {
  if (stats.isSymbolicLink()) {
    throw new CustodyFsError(
      "directory_symlink_rejected",
      `Directory custody check failed for ${path}: symbolic links are not permitted.`,
    );
  }
  if (!stats.isDirectory()) {
    throw new CustodyFsError(
      "directory_not_directory",
      `Directory custody check failed for ${path}: not a directory.`,
    );
  }
  if (custody.uid !== undefined && stats.uid !== custody.uid) {
    throw new CustodyFsError(
      "directory_uid_rejected",
      `Directory custody check failed for ${path}: owner is not permitted.`,
      { details: { uid: stats.uid, expected_uid: custody.uid } },
    );
  }
  if (custody.gid !== undefined && stats.gid !== custody.gid) {
    throw new CustodyFsError(
      "directory_gid_rejected",
      `Directory custody check failed for ${path}: group is not permitted.`,
      { details: { gid: stats.gid, expected_gid: custody.gid } },
    );
  }
  if (modeRejected(fileMode(stats), custody.mode)) {
    throw new CustodyFsError(
      "directory_mode_rejected",
      `Directory custody check failed for ${path}: mode is not permitted.`,
      { details: { mode: fileMode(stats) } },
    );
  }
}

async function verifyParentCustody(
  path: string,
  parent: DirectoryCustodyOptions | undefined,
): Promise<void> {
  if (!parent) return;
  const parentPath = dirname(path);
  const parentStats = await lstat(parentPath);
  if (parentStats.isSymbolicLink()) {
    throw new CustodyFsError(
      "parent_symlink_rejected",
      `File custody check failed for ${path}: parent directory is a symlink.`,
    );
  }
  if (!parentStats.isDirectory()) {
    throw new CustodyFsError(
      "parent_not_directory",
      `File custody check failed for ${path}: parent is not a directory.`,
    );
  }
  if (parent.uid !== undefined && parentStats.uid !== parent.uid) {
    throw new CustodyFsError(
      "parent_uid_rejected",
      `File custody check failed for ${path}: parent owner is not permitted.`,
    );
  }
  if (parent.gid !== undefined && parentStats.gid !== parent.gid) {
    throw new CustodyFsError(
      "parent_gid_rejected",
      `File custody check failed for ${path}: parent group is not permitted.`,
    );
  }
  if (modeRejected(fileMode(parentStats), parent.mode)) {
    throwModeRejected("parent_mode_rejected", path, fileMode(parentStats));
  }
}

async function openReadHandle(path: string) {
  // Read only, never through a link, never blocking: O_NOFOLLOW refuses a
  // symlink at open time and O_NONBLOCK keeps a FIFO from stalling the open
  // before the regular-file check on this descriptor refuses it. No O_CREAT,
  // no mode: this call creates nothing. CodeQL reads the numeric flag word as
  // a possible write and reports js/insecure-temporary-file when a caller's
  // path came from the OS temp dir (test fixtures do); that is the same false
  // positive already dismissed on claude-code-file-adapter.ts.
  try {
    return await open(path, fsConstants.O_RDONLY | O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ELOOP") {
      throw new CustodyFsError(
        "symlink_rejected",
        `File custody check failed for ${path}: symbolic links are not permitted.`,
        { cause: err },
      );
    }
    throw err;
  }
}

const READ_BOUND_SENTINEL_BYTES = 1;
const READ_BOUND_CHUNK_BYTES = 64 * 1024; // 64 KiB keeps allocation bounded while streaming descriptor reads.

async function readDescriptorBytesBounded(
  handle: Awaited<ReturnType<typeof open>>,
  path: string,
  maxBytes: number,
): Promise<Buffer> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new CustodyFsError(
      "read_size_rejected",
      `File custody check failed for ${path}: invalid read size bound.`,
    );
  }
  const chunks: Buffer[] = [];
  let total = 0;
  while (total <= maxBytes) {
    const remainingWithSentinel =
      maxBytes + READ_BOUND_SENTINEL_BYTES - total;
    const nextLength = Math.min(READ_BOUND_CHUNK_BYTES, remainingWithSentinel);
    const buffer = Buffer.allocUnsafe(nextLength);
    const { bytesRead } = await handle.read(buffer, 0, nextLength, null);
    if (bytesRead === 0) {
      return Buffer.concat(chunks, total);
    }
    total += bytesRead;
    if (total > maxBytes) {
      throw new CustodyFsError(
        "read_size_rejected",
        `File custody check failed for ${path}: file exceeds read size bound.`,
      );
    }
    chunks.push(buffer.subarray(0, bytesRead));
  }
  throw new CustodyFsError(
    "read_size_rejected",
    `File custody check failed for ${path}: file exceeds read size bound.`,
  );
}

export async function readFileCustody(
  path: string,
  options?: ReadFileCustodyBufferOptions,
): Promise<Buffer>;
export async function readFileCustody(
  path: string,
  options: ReadFileCustodyTextOptions,
): Promise<string>;
export async function readFileCustody(
  path: string,
  options: ReadFileCustodyOptions = {},
): Promise<Buffer | string> {
  const { data } = await readFileCustodyWithStats(path, options);
  return data;
}

export async function readFileCustodyWithStats(
  path: string,
  options?: ReadFileCustodyBufferOptions,
): Promise<{ data: Buffer; stats: Stats }>;
export async function readFileCustodyWithStats(
  path: string,
  options: ReadFileCustodyTextOptions,
): Promise<{ data: string; stats: Stats }>;
export async function readFileCustodyWithStats(
  path: string,
  options: ReadFileCustodyOptions,
): Promise<{ data: Buffer | string; stats: Stats }>;
export async function readFileCustodyWithStats(
  path: string,
  options: ReadFileCustodyOptions = {},
): Promise<{ data: Buffer | string; stats: Stats }> {
  const handle = await openReadHandle(path);
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) {
      throw new CustodyFsError(
        "not_regular_file",
        `File custody check failed for ${path}: not a regular file.`,
      );
    }
    if (options.uid !== undefined && stats.uid !== options.uid) {
      throw new CustodyFsError(
        "uid_rejected",
        `File custody check failed for ${path}: owner is not permitted.`,
      );
    }
    if (options.gid !== undefined && stats.gid !== options.gid) {
      throw new CustodyFsError(
        "gid_rejected",
        `File custody check failed for ${path}: group is not permitted.`,
      );
    }
    if (modeRejected(fileMode(stats), options.mode)) {
      throwModeRejected("mode_rejected", path, fileMode(stats));
    }
    if (options.maxBytes !== undefined && stats.size > options.maxBytes) {
      throw new CustodyFsError(
        "read_size_rejected",
        `File custody check failed for ${path}: file exceeds read size bound.`,
      );
    }
    await verifyParentCustody(path, options.parent);
    await options.onDescriptorVerified?.({ path, stats });
    if (options.verifyPathIdentity === true) {
      const pathStats = await lstat(path);
      if (pathStats.isSymbolicLink() || !sameFile(stats, pathStats)) {
        throw new CustodyFsError(
          "path_identity_changed",
          `File custody check failed for ${path}: path identity changed before read.`,
        );
      }
    }
    const bytes =
      options.maxBytes === undefined
        ? await handle.readFile()
        : await readDescriptorBytesBounded(handle, path, options.maxBytes);
    return {
      data: options.encoding ? bytes.toString(options.encoding) : bytes,
      stats,
    };
  } finally {
    await handle.close();
  }
}

async function fsyncDirectoryLegacy(dir: string): Promise<void> {
  let handle;
  try {
    handle = await open(dir, fsConstants.O_RDONLY);
    await handle.sync();
  } catch (err) {
    if (!isBenignDirectoryFsyncError(err)) throw err;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Sync the captured directory only while its pathname still names that inode. */
export async function syncDirectoryStrict(dir: string, expected?: Stats): Promise<void> {
  // Descriptor roots name held authority, so the final dot avoids following a symlink at the opened component.
  const path = /^\/(?:proc\/self\/fd|dev\/fd)\/\d+$/.test(dir) ? `${dir}/.` : dir;
  const before = expected ?? await lstat(path);
  const handle = await openExistingDirectoryNoFollow(path);
  const failures: unknown[] = [];
  try {
    // A barrier on a substituted directory cannot establish durability for the published entry.
    if (!before.isDirectory() || before.isSymbolicLink() || !sameFile(before, await handle.stat())) {
      throw new Error("strict directory identity changed");
    }
    await handle.sync();
    if (!sameFile(before, await lstat(path))) throw new Error("strict directory identity changed");
  } catch (error) { failures.push(error); }
  try { await handle.close(); } catch (error) { failures.push(error); }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "strict directory sync and close failed");
}

/** Capture and sync every directory from the held boundary through the leaf on every attempt. */
export async function ensureDirectoryStrict(dir: string, mode: number, base: string): Promise<Stats> {
  const suffix = relative(base, dir);
  // The boundary limits creation and retries to directories covered by the caller's held authority.
  if (suffix.split(sep).includes("..")) throw new Error("strict directory escapes its held boundary");
  const entries: Array<{ path: string; handle: Awaited<ReturnType<typeof open>>; identity: Stats; closed: boolean }> = [];
  const failures: unknown[] = [];
  let identity!: Stats;
  try {
    let cursor = base;
    for (const part of ["", ...suffix.split(sep).filter(Boolean)]) {
      if (part) {
        cursor = join(cursor, part);
        try { await mkdir(cursor, { mode }); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
      }
      const path = /^\/(?:proc\/self\/fd|dev\/fd)\/\d+$/.test(cursor) ? `${cursor}/.` : cursor;
      const handle = await openExistingDirectoryNoFollow(path);
      const entry = { path, handle, identity: undefined as unknown as Stats, closed: false };
      entries.push(entry);
      // Creation records descriptor identity immediately so a later name replacement cannot supply barrier evidence.
      entry.identity = await handle.stat();
      if (!entry.identity.isDirectory() || !sameFile(entry.identity, await lstat(path))) throw new Error("strict directory identity changed");
      identity = entry.identity;
    }
    for (const entry of [...entries].reverse()) {
      // Every retry syncs the same captured chain because an existing directory can still have an uncertain parent entry.
      if (!sameFile(entry.identity, await entry.handle.stat()) || !sameFile(entry.identity, await lstat(entry.path))) throw new Error("strict directory identity changed");
      await entry.handle.sync();
      if (!sameFile(entry.identity, await lstat(entry.path))) throw new Error("strict directory identity changed");
      entry.closed = true;
      await entry.handle.close();
    }
    // Later parent barriers cannot excuse a child name that changed after its own barrier.
    for (const entry of entries) {
      if (!sameFile(entry.identity, await lstat(entry.path))) throw new Error("strict directory identity changed");
    }
  } catch (error) { failures.push(error); }
  finally {
    for (const entry of entries) {
      if (!entry.closed) try { await entry.handle.close(); } catch (error) { failures.push(error); }
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "strict directory setup and close failed");
  return identity;
}

async function openExistingDirectoryNoFollow(
  path: string,
): Promise<Awaited<ReturnType<typeof open>>> {
  return open(
    path,
    fsConstants.O_RDONLY |
      O_NOFOLLOW |
      (typeof fsConstants.O_DIRECTORY === "number" ? fsConstants.O_DIRECTORY : 0),
    // Ignored unless O_CREAT is present. We do not pass O_CREAT here; the mode
    // is explicit so static scanners can see there is no broad temp-file mode.
    0o600,
  );
}

/**
 * Chown every directory on the segment chain from `firstCreated` down to
 * `leafDir` (inclusive) to `owner`. `firstCreated` is the value `mkdir
 * {recursive:true}` returns: the FIRST directory it actually created, so the
 * chain covers exactly the dirs this call minted (pre-existing parents are
 * never touched). Retained for non-root/future descriptor-chown creation
 * paths; current root owner-writes require parents to pre-exist because Node
 * does not expose mkdirat/openat.
 *
 * SECURITY (2026-07-31 re-gate BLOCKER): this used to `lchown` PATH STRINGS.
 * `lchown` refuses to follow only the FINAL component, so a pre-existing
 * symlinked ANCESTOR (`<fortress>/policy -> /outside`) made the recursive
 * `mkdir` create `/outside/egress/rules` and this function then chowned that
 * outside chain to the operator -- a root ownership-transfer primitive
 * reachable by anyone who could plant one symlink.
 *
 * Every component from the created chain's PARENT downward is now opened with
 * `O_NOFOLLOW | O_DIRECTORY`, so a symlink at or below that point fails the
 * open; the created chain is then chowned through those descriptors (never by
 * name). Handles are held open across the whole operation so the inodes
 * cannot be recycled. Fail-closed: any refusal throws, which fails the
 * enclosing write rather than leaving a directory misowned.
 *
 * BOUND, STATED PLAINLY: verification starts at the created chain's parent,
 * not at `/`, because legitimate system symlinks sit above it (on macOS
 * `/var` is itself a symlink to `/private/var`, so a root-anchored check
 * would refuse every real write under a temp or var path). A symlink planted
 * ABOVE the first created directory is therefore not caught here; that region
 * is governed by the fortress custody walk, which refuses a symlinked
 * fortress root outright, and by `resolveFortressCreateOwner`, which lstats
 * (never stats) the fortress so a symlinked fortress yields no owner at all.
 */
export async function chownCreatedDirChain(
  firstCreated: string,
  leafDir: string,
  owner: { uid: number; gid: number },
): Promise<void> {
  // Normalize both ends so a non-normalized caller path (double slash,
  // trailing slash) cannot silently break the chain match. If the chain still
  // cannot be established, FAIL (never silently skip the chown): callers use
  // the owner option fail-closed, and a misowned created dir is exactly the
  // defect class this exists to prevent.
  const stop = resolvePath(firstCreated);
  const leaf = resolvePath(leafDir);
  let current = leaf;
  const createdChain = new Set<string>();
  for (;;) {
    createdChain.add(current);
    if (current === stop) break;
    const parent = dirname(current);
    if (parent === current) {
      throw new Error(
        `chownCreatedDirChain: ${stop} is not an ancestor of ${leaf}; refusing to leave created directories misowned`,
      );
    }
    current = parent;
  }

  // Components from the created chain's PARENT down to the leaf, opened
  // no-follow (see the BOUND note above for why this does not start at "/").
  const verifyFrom = dirname(stop);
  const components: string[] = [];
  let walk = leaf;
  for (;;) {
    components.push(walk);
    if (walk === verifyFrom) break;
    const parent = dirname(walk);
    if (parent === walk) break;
    walk = parent;
  }
  components.reverse();

  const handles: Array<{
    path: string;
    handle: Awaited<ReturnType<typeof open>>;
  }> = [];
  try {
    for (const component of components) {
      let handle;
      try {
        // Read-only, no-create open of an existing directory for verification.
        // O_NOFOLLOW is the point of the call: a symlinked component must fail.
        handle = await openExistingDirectoryNoFollow(component);
      } catch (err) {
        throw new Error(
          `chownCreatedDirChain: refusing to chown through ${component} (${
            (err as NodeJS.ErrnoException).code ?? "open failed"
          }); a symlinked path component would transfer ownership outside the intended tree`,
          { cause: err },
        );
      }
      handles.push({ path: component, handle });
    }
    for (const entry of handles) {
      if (createdChain.has(entry.path)) {
        await entry.handle.chown(owner.uid, owner.gid);
      }
    }
  } finally {
    for (const entry of handles.reverse()) {
      await entry.handle.close().catch(() => undefined);
    }
  }
}

/**
 * Assert that every path component from `base` down to `leafDir` is a real
 * directory reachable WITHOUT following a symlink, by opening each one
 * `O_NOFOLLOW | O_DIRECTORY`. Throws otherwise (fail-closed).
 *
 * `base` is required for owner-writes: without a declared containment root
 * there is no correct place to stop, and starting at `/` is impossible on
 * macOS (`/var` is itself a symlink). A caller that passes `owner` without
 * `ownerBase` is refused rather than silently given weaker containment.
 */
export type NoFollowDirectoryGuard = {
  resolvedBase: string;
  handles: Array<{ path: string; handle: Awaited<ReturnType<typeof open>> }>;
  revalidate(): Promise<void>;
  close(): Promise<void>;
};

async function openNoFollowPathWithinBase(
  leafDir: string,
  base: string | undefined,
): Promise<NoFollowDirectoryGuard> {
  if (base === undefined || base.length === 0) {
    throw new Error(
      "writeFileCustody: `owner` requires `ownerBase` (the directory the write must stay inside); refusing an owner-write without a containment root",
    );
  }
  const resolvedBase = resolvePath(base);
  const leaf = resolvePath(leafDir);
  const components: string[] = [];
  let walk = leaf;
  for (;;) {
    components.push(walk);
    if (walk === resolvedBase) break;
    const parent = dirname(walk);
    if (parent === walk) {
      throw new Error(
        `writeFileCustody: ${leaf} is not inside the declared ownerBase ${resolvedBase}; refusing the owner-write`,
      );
    }
    walk = parent;
  }
  components.reverse();
  const handles: Array<{ path: string; handle: Awaited<ReturnType<typeof open>> }> = [];
  const close = async (): Promise<void> => {
    for (const entry of handles.reverse()) {
      await entry.handle.close().catch(() => undefined);
    }
  };
  const revalidate = async (): Promise<void> => {
    for (const entry of handles) {
      let held;
      let fresh;
      try {
        held = await entry.handle.stat();
        fresh = await openExistingDirectoryNoFollow(entry.path);
      } catch (err) {
        throw new Error(
          `writeFileCustody: refusing an owner-write through ${entry.path} (${
            (err as NodeJS.ErrnoException).code ?? "open failed"
          }); a path component changed after containment verification`,
          { cause: err },
        );
      }
      try {
        const freshStats = await fresh.stat();
        if (!sameFile(held, freshStats)) {
          throw new Error(
            `writeFileCustody: refusing an owner-write through ${entry.path}; path identity changed after containment verification`,
          );
        }
      } finally {
        await fresh.close().catch(() => undefined);
      }
    }
  };
  try {
    for (const component of components) {
      try {
        // Read-only, no-create open of an existing directory for verification.
        // O_NOFOLLOW is the point of the call: a symlinked component must fail.
        handles.push({ path: component, handle: await openExistingDirectoryNoFollow(component) });
      } catch (err) {
        throw new Error(
          `writeFileCustody: refusing an owner-write through ${component} (${
            (err as NodeJS.ErrnoException).code ?? "open failed"
          }); a symlinked path component would place the file outside ${resolvedBase}`,
          { cause: err },
        );
      }
    }
    return { resolvedBase, handles, revalidate, close };
  } catch (err) {
    await close();
    throw err;
  }
}

async function verifyDirectoryGuardStats(
  guard: NoFollowDirectoryGuard,
  custody: DirectoryCustodyOptions,
  verifyEveryComponent: boolean,
): Promise<void> {
  const handles = verifyEveryComponent ? guard.handles : guard.handles.slice(-1);
  for (const entry of handles) {
    verifyDirectoryStats(entry.path, await entry.handle.stat(), custody);
  }
}

/**
 * Open and hold every directory component from `base` through `leafDir`
 * without following symlinks. The returned guard mirrors the owner-write
 * pattern: keep descriptors live, then call `revalidate()` immediately before
 * the path-based syscall that depends on the chain. That syscall still
 * re-resolves the path by name: a swap between revalidation and the syscall is
 * not prevented in Node because there is no `renameat`/`openat` binding here.
 * The guard bounds that window and refuses pre-existing/static hostile shapes.
 */
export async function openDirectoryCustodyWithinBase(
  leafDir: string,
  base: string,
  options: Omit<DirectoryWithinBaseCustodyOptions, "allowMissingLeaf"> = {},
): Promise<NoFollowDirectoryGuard> {
  const { verifyEveryComponent = false, ...custody } = options;
  const guard = await openNoFollowPathWithinBase(leafDir, base);
  const revalidate = async (): Promise<void> => {
    await guard.revalidate();
    await verifyDirectoryGuardStats(guard, custody, verifyEveryComponent);
  };
  try {
    await verifyDirectoryGuardStats(guard, custody, verifyEveryComponent);
    return {
      resolvedBase: guard.resolvedBase,
      handles: guard.handles,
      revalidate,
      close: guard.close,
    };
  } catch (err) {
    await guard.close();
    throw err;
  }
}

/**
 * Verify an existing directory chain from `base` to `leafDir` with the same
 * per-component `O_NOFOLLOW | O_DIRECTORY` guard used by owner writes.
 * When `allowMissingLeaf` is true, a missing leaf is accepted only after the
 * existing parent chain inside `base` verifies no-follow.
 */
export async function verifyDirectoryCustodyWithinBase(
  leafDir: string,
  base: string,
  options: DirectoryWithinBaseCustodyOptions = {},
): Promise<void> {
  const resolvedLeaf = resolvePath(leafDir);
  const resolvedBase = resolvePath(base);
  const { allowMissingLeaf = false, verifyEveryComponent = false, ...custody } = options;
  try {
    const leafStats = await lstat(resolvedLeaf);
    verifyDirectoryStats(resolvedLeaf, leafStats, custody);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT" || !allowMissingLeaf) {
      throw err;
    }
    const parentGuard = await openNoFollowPathWithinBase(dirname(resolvedLeaf), resolvedBase);
    await parentGuard.close();
    return;
  }

  const guard = await openDirectoryCustodyWithinBase(resolvedLeaf, resolvedBase, {
    ...custody,
    verifyEveryComponent,
  });
  try {
    await guard.revalidate();
  } finally {
    await guard.close();
  }
}

async function withOwnerEffectiveIdentity<T>(
  owner: { uid: number; gid: number } | undefined,
  fn: (dropped: boolean) => Promise<T>,
): Promise<T> {
  if (
    owner === undefined ||
    process.geteuid?.() !== 0 ||
    process.seteuid === undefined ||
    process.setegid === undefined
  ) {
    return fn(false);
  }
  const oldUid = process.geteuid();
  const oldGid = process.getegid?.();
  try {
    process.setegid(owner.gid);
    process.seteuid(owner.uid);
    return await fn(true);
  } finally {
    process.seteuid(oldUid);
    if (oldGid !== undefined) {
      process.setegid(oldGid);
    }
  }
}

export async function writeFileCustody(
  path: string,
  data: string | Uint8Array,
  options: WriteFileCustodyOptions,
): Promise<void> {
  await writeFileCustodyWithDurability(path, data, { ...options, strictDurability: options.strictDurability === true });
}

// Must match the required strictDurability argument at storage call sites in filesystem.ts and directory-capability-worker.ts.
export async function writeFileCustodyWithDurability(
  path: string,
  data: string | Uint8Array,
  options: WriteFileCustodyOptions & { strictDurability: boolean },
): Promise<Stats | undefined> {
  const dir = dirname(path);
  let publishedDirectory: Stats | undefined;
  let ownerGuard: NoFollowDirectoryGuard | undefined;
  if (options.owner !== undefined && !options.stableDirectoryCapability) {
    // 2026-07-31 fix-round: verify containment BEFORE any recursive mkdir.
    // There is no mkdirat-style API here; creating missing parents by path as
    // root can be redirected by a symlinked ancestor before the later
    // no-follow check runs. Owner writes therefore require the parent chain to
    // already exist as real directories inside ownerBase.
    ownerGuard = await openNoFollowPathWithinBase(dir, options.ownerBase);
  }
  const failures: unknown[] = [];
  try {
    await withOwnerEffectiveIdentity(options.owner, async (droppedToOwner) => {
      if (options.createParent !== false && options.owner === undefined) {
        if (options.strictDurability) {
          // A strict write needs the caller's held boundary so retries cannot forget a failed parent barrier.
          if (!options.strictDirectoryBase) throw new Error("strict directory setup requires a held boundary");
          publishedDirectory = await ensureDirectoryStrict(dir, options.parentMode ?? 0o700, options.strictDirectoryBase);
        } else {
          await mkdir(dir, { recursive: true, mode: options.parentMode ?? 0o700 });
        }
      }
      if (options.strictDurability && ownerGuard) {
        // Owner writes cannot skip uncertain parent barriers merely because creation is forbidden.
        await ownerGuard.revalidate();
        for (const entry of ownerGuard.handles) await entry.handle.sync();
        await ownerGuard.revalidate();
      }
      await verifyParentCustody(path, options.parent);
      const tempPath = join(
        dir,
        `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
      );
      let handle;
      let directoryHandle;
      let directoryIdentity: Stats | undefined;
      let cleanupTemp = true;
      const writeFailures: unknown[] = [];
      try {
        await ownerGuard?.revalidate();
        if (options.strictDurability) {
          const directoryPath = /^\/(?:proc\/self\/fd|dev\/fd)\/\d+$/.test(dir) ? `${dir}/.` : dir;
          directoryIdentity = publishedDirectory ?? await lstat(directoryPath);
          directoryHandle = await openExistingDirectoryNoFollow(directoryPath);
          // Publication and its barrier must refer to the same captured parent inode.
          if (!directoryIdentity.isDirectory() || !sameFile(directoryIdentity, await directoryHandle.stat())) throw new Error("strict publication directory changed");
          publishedDirectory = directoryIdentity;
        }
        handle = await open(
          tempPath,
          fsConstants.O_WRONLY |
            fsConstants.O_CREAT |
            fsConstants.O_EXCL |
            O_NOFOLLOW,
          options.mode,
        );
        await handle.chmod(options.mode);
        if (options.owner !== undefined && !droppedToOwner) {
          // Create-with-fchown: applied on the DESCRIPTOR before the atomic
          // rename, so the destination never exists with the wrong owner. A
          // failure here fails the whole write (fail-closed). When running as
          // root, the path operations are performed under the target effective
          // uid/gid instead, so an ancestor race is not a root write primitive.
          await handle.chown(options.owner.uid, options.owner.gid);
        }
        await options.prepareTemp?.(tempPath);
        await handle.writeFile(data);
        await handle.sync();
        const completedHandle = handle;
        handle = undefined;
        await completedHandle.close();
        await ownerGuard?.revalidate();
        await rename(tempPath, path);
        cleanupTemp = false;
        if (directoryHandle) {
          // A successful return requires the held publishing directory's barrier and unchanged identity.
          await directoryHandle.sync();
          const directoryPath = /^\/(?:proc\/self\/fd|dev\/fd)\/\d+$/.test(dir) ? `${dir}/.` : dir;
          if (!sameFile(directoryIdentity!, await lstat(directoryPath))) throw new Error("strict publication directory changed");
        } else await fsyncDirectoryLegacy(dir);
      } catch (error) { writeFailures.push(error); }
      finally {
        // Deferred close and cleanup errors retain the primary failure as evidence of uncertain durability.
        try { await handle?.close(); } catch (error) { if (options.strictDurability) writeFailures.push(error); }
        if (cleanupTemp) {
          try {
            await unlink(tempPath);
            if (options.strictDurability && directoryHandle) await directoryHandle.sync();
          } catch (error) {
            if (options.strictDurability && (error as NodeJS.ErrnoException).code !== "ENOENT") writeFailures.push(error);
          }
        }
        try { await directoryHandle?.close(); } catch (error) { writeFailures.push(error); }
      }
      if (writeFailures.length === 1) throw writeFailures[0];
      if (writeFailures.length > 1) throw new AggregateError(writeFailures, "strict file write and cleanup failed");
    });
  } catch (error) { failures.push(error); }
  finally {
    if (ownerGuard !== undefined) {
      if (options.strictDurability) {
        // Every held owner descriptor contributes close errors without replacing a write failure.
        for (const entry of ownerGuard.handles) {
          try { await entry.handle.close(); } catch (error) { failures.push(error); }
        }
      } else await ownerGuard.close();
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, "strict owner write and close failed");
  // Must match writeIfAbsentMode in filesystem.ts so publication retains the custody descriptor identity.
  return publishedDirectory;
}
