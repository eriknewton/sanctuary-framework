import { constants as fsConstants, type Stats } from "node:fs";
import { mkdir, open, rename, unlink, lstat } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { basename, dirname, join, resolve as resolvePath } from "node:path";

export type CustodyFsErrorCode =
  | "symlink_rejected"
  | "not_regular_file"
  | "path_identity_changed"
  | "mode_rejected"
  | "uid_rejected"
  | "gid_rejected"
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
}

export interface DirectoryCustodyOptions {
  uid?: number;
  gid?: number;
  mode?: CustodyModeCheck;
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
   * chown the file (via its open descriptor, before the atomic rename) and any
   * parent directories THIS call created to the given owner. Root daemons that
   * write inside an operator-owned fortress pass the fortress owner here so
   * fortress-internal files never accrete root ownership boot over boot.
   * FAIL-CLOSED: if the chown fails the write fails (never silently leave the
   * file with the wrong owner).
   */
  owner?: { uid: number; gid: number };
  /**
   * Containment base for `owner` writes (2026-07-31 gate round 3). Every path
   * component from this directory down to the file is opened
   * `O_NOFOLLOW | O_DIRECTORY` before the write, so a PRE-EXISTING symlinked
   * ancestor cannot make a root process create, chown, and rename a file
   * outside the intended tree -- the case the created-chain check alone
   * missed, because when every directory already exists `mkdir` creates
   * nothing and there is no chain to verify. Required whenever `owner` is
   * set; the fortress path is the natural value.
   */
  ownerBase?: string;
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
  try {
    return await open(path, fsConstants.O_RDONLY | O_NOFOLLOW);
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
    return {
      data: options.encoding
        ? await handle.readFile({ encoding: options.encoding })
        : await handle.readFile(),
      stats,
    };
  } finally {
    await handle.close();
  }
}

async function fsyncDirectory(dir: string): Promise<void> {
  let handle;
  try {
    handle = await open(dir, fsConstants.O_RDONLY);
    await handle.sync();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (!["EINVAL", "ENOTSUP", "EISDIR", "EPERM"].includes(code ?? "")) {
      throw err;
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Chown every directory on the segment chain from `firstCreated` down to
 * `leafDir` (inclusive) to `owner`. `firstCreated` is the value `mkdir
 * {recursive:true}` returns: the FIRST directory it actually created, so the
 * chain covers exactly the dirs this call minted (pre-existing parents are
 * never touched). Exported for the other create-with-fchown sites (the macOS
 * daemon's fortress-internal mkdirs).
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

  const dirFlags =
    fsConstants.O_RDONLY |
    O_NOFOLLOW |
    (typeof fsConstants.O_DIRECTORY === "number" ? fsConstants.O_DIRECTORY : 0);
  const handles: Array<{
    path: string;
    handle: Awaited<ReturnType<typeof open>>;
  }> = [];
  try {
    for (const component of components) {
      let handle;
      try {
        // codeql[js/insecure-temporary-file] -- read-only O_NOFOLLOW|O_DIRECTORY
        // open of an EXISTING directory for verification. No file is created
        // here (no O_CREAT), so there is no temporary-file exposure; the
        // no-follow flag is the whole point of the call.
        handle = await open(component, dirFlags);
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
async function assertNoFollowPathWithinBase(
  leafDir: string,
  base: string | undefined,
): Promise<void> {
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
  const dirFlags =
    fsConstants.O_RDONLY |
    O_NOFOLLOW |
    (typeof fsConstants.O_DIRECTORY === "number" ? fsConstants.O_DIRECTORY : 0);
  const handles: Array<Awaited<ReturnType<typeof open>>> = [];
  try {
    for (const component of components) {
      try {
        // codeql[js/insecure-temporary-file] -- read-only O_NOFOLLOW|O_DIRECTORY
        // open of an EXISTING directory for verification. No file is created
        // here (no O_CREAT), so there is no temporary-file exposure; the
        // no-follow flag is the whole point of the call.
        handles.push(await open(component, dirFlags));
      } catch (err) {
        throw new Error(
          `writeFileCustody: refusing an owner-write through ${component} (${
            (err as NodeJS.ErrnoException).code ?? "open failed"
          }); a symlinked path component would place the file outside ${resolvedBase}`,
          { cause: err },
        );
      }
    }
  } finally {
    for (const handle of handles.reverse()) {
      await handle.close().catch(() => undefined);
    }
  }
}

export async function writeFileCustody(
  path: string,
  data: string | Uint8Array,
  options: WriteFileCustodyOptions,
): Promise<void> {
  const dir = dirname(path);
  if (options.createParent !== false) {
    const firstCreated = await mkdir(dir, {
      recursive: true,
      mode: options.parentMode ?? 0o700,
    });
    if (options.owner !== undefined && firstCreated !== undefined) {
      await chownCreatedDirChain(firstCreated, dir, options.owner);
    }
  }
  if (options.owner !== undefined) {
    // 2026-07-31 gate round 3: containment for owner-writes must NOT depend on
    // `mkdir` having created something. When every directory already exists
    // (including a symlinked ancestor an attacker planted), `firstCreated` is
    // undefined, the chain check never runs, and the temp-file open below
    // would follow the symlink -- letting a root writer create, chown, and
    // rename a file OUTSIDE the tree. Verify the whole base-to-leaf path
    // no-follow, every time.
    await assertNoFollowPathWithinBase(dir, options.ownerBase);
  }
  await verifyParentCustody(path, options.parent);
  const tempPath = join(
    dir,
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  let handle;
  let cleanupTemp = true;
  try {
    handle = await open(
      tempPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        O_NOFOLLOW,
      options.mode,
    );
    await handle.chmod(options.mode);
    if (options.owner !== undefined) {
      // Create-with-fchown: applied on the DESCRIPTOR before the atomic
      // rename, so the destination never exists with the wrong owner. A
      // failure here fails the whole write (fail-closed).
      await handle.chown(options.owner.uid, options.owner.gid);
    }
    await options.prepareTemp?.(tempPath);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(tempPath, path);
    cleanupTemp = false;
    await fsyncDirectory(dir);
  } finally {
    await handle?.close().catch(() => undefined);
    if (cleanupTemp) {
      await unlink(tempPath).catch(() => undefined);
    }
  }
}
