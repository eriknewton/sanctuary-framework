/**
 * Governed File-Grant v1 -- real POSIX filesystem operations (build spec
 * section 4).
 *
 * This is the ONLY module in file-grant/ that touches the real filesystem or
 * reads the agent-origin descriptor. Every other module (planner, lifecycle,
 * mint, revoke, list) takes an injected `FsOps` and is tested with a fake;
 * this implementation is what production wiring passes in.
 *
 * ENFORCEMENT HONESTY (Invariant #5, build spec section 4 + 10): the box-local
 * read-scope boundary is real only when the agent runs as its OWN dedicated
 * uid (`castle-wall/allowlist/agent-origin.ts`'s uid-mode descriptor), distinct
 * from the uid that OWNS the source file. The same-uid decision is derived
 * from the SOURCE file's owner (`sourceOwnerUid`, via `stat`), NEVER from
 * `process.getuid()`, so a `sudo` mint cannot fabricate a false "enforced".
 *
 * FUNCTIONAL PRIMITIVE: `grantAgentRead` receives a pinned source inode and
 * applies the platform ACL operation only through an identity-bound target.
 * Linux uses the pinned `/proc/<pid>/fd/<fd>` path. macOS has path-scoped
 * `chmod +a` and no fd path, so it first replaces the grant-tree entry with a
 * hard link in the operator-owned grant tree, then fstats that link with
 * O_NOFOLLOW | O_NONBLOCK and requires the dev/ino to equal the pinned source.
 * The macOS source and grant tree must be on the same filesystem; EXDEV or identity
 * mismatch fails closed as unverified and applies no read ACE. The grant tree
 * is the agent's reach path, not a second path-scoped boundary. POSIX read
 * ACLs are inode-scoped: the same uid can read the same file through any
 * other path it can reach. `probeAgentRead` verifies readability by running a
 * bounded read through the grant tree as the agent uid.
 *
 * TRAVERSAL NOTE: `ensureTreeRoot` sets the root to `0711` (owner rwx,
 * group/other --x) so a future chowned per-agent leaf stays reachable while
 * the root itself is not listable by non-owners. NOTE the root currently
 * lives under the operator fortress (`<fortressPath>/grants/`). The ACL
 * primitive grants execute-only traversal on the grant-tree ancestors and
 * read/traverse on the canonical source leaf, then the probe proves the
 * effective reach-path result. The execute-only ancestor ACLs are idempotent
 * and information-free, so per-grant revoke leaves them in place. Only the
 * per-grant source leaf read ACE is removed from persisted grant metadata.
 *
 * FORTRESS-DIR TRAVERSAL (F1 fix, 2026-07-14 drill finding): `sanctuary init`
 * creates the fortress dir itself `0700`, ABOVE the grant-tree root. The
 * ancestor ACEs described above only ever covered `<fortressPath>/grants/`
 * downward, so the agent uid could never reach the grant tree at all -- the
 * mint-op read probe EACCESed on the fortress dir before it ever got to the
 * grant tree, and enforcement could never reach `met` on a standard fortress
 * (proven on real uid-split hardware, Mini1, 2026-07-14). `applyAgentReadAcl`
 * now also applies a single execute-only ACE on the fortress dir itself for
 * the agent uid. Unlike the grant-tree ancestor ACEs, this ACE is
 * LIFECYCLE-BOUND, and its lifecycle is keyed on the OS UID, not on a
 * logical agent id: the box's agent-origin descriptor names ONE dedicated
 * uid, every subject agent id resolves to it, and the ACE itself is a
 * uid-level object. So `removeEntry` removes it only when the WHOLE grant
 * tree is drained (no tree entry left under ANY per-agent subdirectory) --
 * see `removeFortressTraverseAceIfTreeDrained`. Draining one logical agent's
 * subtree while another still holds an active grant for the same uid MUST
 * NOT strip the shared ACE. A failed ACL apply also drain-gated-removes the
 * ACE it just added (never left orphaned by a partial apply, never stripped
 * while another live grant needs it). It is still execute-only (traverse,
 * never list or read), applied and removed the same way as every other ACE
 * here (`chmod +a`/`-a` on macOS, `setfacl -m`/`-x` on Linux).
 *
 * CONCURRENCY (fail-closed, round 4): a cross-process O_EXCL lock on the
 * grant-tree root (`withFortressAceLock`, reusing `storage/cross-process-lock`'s
 * `withPathLock`) serializes two critical sections against each other:
 *   (a) the MINT's ACL apply AND its same-operation read probe, held together
 *       as ONE lock hold by `grantAndProbeAgentRead` -- NOT the apply alone;
 *       the probe is inside the critical section, so a revoke cannot run
 *       between a mint's apply and its probe; and
 *   (b) the REVOKE/reconcile drain-check-and-removal
 *       (`removeFortressTraverseAceIfTreeDrained`).
 * Because the probe is inside the mint's hold, a concurrent revoke can never
 * strip the shared fortress ACE in the apply->probe gap, so a mint can never
 * probe a false `met`. (Correctness no longer relies on the subtler
 * "place() happens-before probe, and the revoke's drain-check observes the
 * placed entry" invariant -- that still holds, but the lock makes it not
 * load-bearing.) A place() that slips into the locked REMOVAL is caught by a
 * post-removal re-check and re-applied; a FAILED re-apply THROWS
 * (`FileGrantFortressAceReapplyError`) rather than leaving a silent
 * unreachable-active-grant. Sustained lock contention fails SAFE on the
 * removal side (leave the ACE) and fails CLOSED on the mint side (report
 * `unverified`, never a false `met`; the bounded-wait timeout means a mint
 * never blocks indefinitely -- the operator retries).
 *
 * DEBT (uid-basis re-resolution): cleanup currently re-resolves the agent
 * uid from the live agent-origin descriptor at removal time. The durable fix
 * is to persist the uid basis on the grant record at mint time so cleanup
 * never consults mutable current policy; that lands with a multi-uid
 * descriptor model, not v1.
 *
 * ACCEPTED CONSEQUENCE (documented, not a defect): while the traverse ACE is
 * live, the agent uid can stat() DIRECT fortress-root children by known name
 * (existence, size, mtime -- metadata only, never contents, since the
 * startup tightener and every root-child writer keep child modes owner-only).
 * That metadata visibility is inherent to granting traverse. Consequently,
 * ANY new writer of a direct fortress-root file MUST create it with an
 * explicit owner-only mode from the first byte (`{ mode: 0o600 }` /
 * `writeFileCustody`), never default-mode-then-chmod: the 2026-07-14 review
 * found and fixed exactly that create-window in `broker-policy.json`
 * (disclosure/broker/open.ts) and `first-run-notice-shown`
 * (first-run-notice.ts). Do not add a third.
 */

import { execFile as nodeExecFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  link as fsLink,
  mkdir,
  lstat,
  open as fsOpen,
  readdir,
  readFile,
  realpath as fsRealpath,
  rm,
  stat,
  symlink,
} from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import { withPathLock } from "../storage/cross-process-lock.js";
import type {
  FileGrantAclRemovalResult,
  FileGrantAclResult,
  FileGrantAclStatus,
  FileGrantGrantedReadAce,
  FileGrantPinnedSource,
  FileGrantRemoveEntryResult,
  FileGrantRemoveEntryOptions,
  FileGrantSourceIdentity,
  FsOps,
} from "./types.js";

const GRANT_TREE_DIR_NAME = "grants";
/** Root: traversable (x) by anyone so a chowned per-agent leaf below it stays reachable, but not listable/writable by non-owners. */
const TREE_ROOT_MODE = 0o711;
/** Per-agent leaf: readable/traversable ONLY by its owner. */
const AGENT_SUBDIR_MODE = 0o700;
/**
 * Cross-process lock file (under the grant-tree root) that serializes the
 * uid-level fortress-dir ACE lifecycle: a mint's fortress-ACE APPLICATION and
 * a revoke/reconcile's drain-check-and-REMOVAL for the same fortress must be
 * mutually exclusive across processes, so a concurrent mint can never observe
 * a false `met` while a concurrent revoke strips the shared uid's traverse ACE
 * (the F1 fix-round race). Lives beside the grant subtrees; `isGrantTreeDrained`
 * skips it (it is not a per-agent grant directory).
 */
const FORTRESS_ACE_LOCK_FILE = ".fortress-ace.lock";
export const FILE_GRANT_ACL_COMMAND_TIMEOUT_MS = 2_000;
const EXEC_MAX_BUFFER_BYTES = 64 * 1024;
const FILE_GRANT_PIN_SOURCE_OPEN_FLAGS =
  fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
const FILE_GRANT_MAC_ACL_TARGET_OPEN_FLAGS =
  fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;
const POSIX_MODE_TYPE_MASK = 0o170000;
const POSIX_MODE_TYPE_REGULAR = 0o100000;
const POSIX_MODE_TYPE_DIRECTORY = 0o040000;

export interface FileGrantExecCommand {
  file: string;
  args: string[];
}

export interface FileGrantExecResult {
  stdout: string;
  stderr: string;
}

export interface FileGrantExecRunner {
  execFile(command: FileGrantExecCommand, timeoutMs: number): Promise<FileGrantExecResult>;
}

export interface FileGrantOpenedFileStats {
  dev: bigint | number;
  ino: bigint | number;
  uid?: bigint | number;
  mode?: bigint | number;
  isFile?(): boolean;
  isDirectory?(): boolean;
}

export interface FileGrantOpenedFile {
  readonly fd?: number;
  stat(options: { bigint: true }): Promise<FileGrantOpenedFileStats>;
  close(): Promise<void>;
}

export interface FileGrantMacAclLinkOps {
  link(existingPath: string, newPath: string): Promise<void>;
  open(path: string, flags: number): Promise<FileGrantOpenedFile>;
  rm(path: string, options: { force?: boolean }): Promise<void>;
}

export interface PosixFileGrantFsOpsOptions {
  execRunner?: FileGrantExecRunner;
  macAclLinkOps?: FileGrantMacAclLinkOps;
  commandTimeoutMs?: number;
  platform?: NodeJS.Platform;
  nodePath?: string;
}

export const AGENT_READ_PROBE_SCRIPT =
  "const fs=require('node:fs');" +
  "const p=process.argv[1];" +
  "const expectedDev=process.argv[2];" +
  "const expectedIno=process.argv[3];" +
  "const fd=fs.openSync(p,'r');" +
  "try{const st=fs.fstatSync(fd,{bigint:true});" +
  "if(String(st.dev)!==expectedDev||String(st.ino)!==expectedIno)process.exit(66);" +
  "if(!st.isDirectory()){const b=Buffer.alloc(1);fs.readSync(fd,b,0,1,0);}}" +
  "finally{fs.closeSync(fd);}";

const DEFAULT_EXEC_RUNNER: FileGrantExecRunner = {
  execFile(command: FileGrantExecCommand, timeoutMs: number): Promise<FileGrantExecResult> {
    return new Promise((resolvePromise, rejectPromise) => {
      nodeExecFile(
        command.file,
        command.args,
        {
          timeout: timeoutMs,
          killSignal: "SIGKILL",
          windowsHide: true,
          maxBuffer: EXEC_MAX_BUFFER_BYTES,
        },
        (error, stdout, stderr) => {
          if (error) {
            const enriched = error as Error & { stdout?: string; stderr?: string };
            enriched.stdout = String(stdout);
            enriched.stderr = String(stderr);
            rejectPromise(enriched);
            return;
          }
          resolvePromise({ stdout: String(stdout), stderr: String(stderr) });
        }
      );
    });
  },
};

const DEFAULT_MAC_ACL_LINK_OPS: FileGrantMacAclLinkOps = {
  link: fsLink,
  open: fsOpen,
  rm,
};

function agentOriginDescriptorPath(fortressPath: string): string {
  return join(fortressPath, "policy", "egress", "agent-origin.json");
}

function uidToken(agentUid: number): string {
  if (!Number.isSafeInteger(agentUid) || agentUid < 0) {
    throw new Error(`Governed File-Grant: invalid agent uid ${agentUid}`);
  }
  return String(agentUid);
}

function resolveTreeEntryUnderRoot(
  treeRoot: string,
  relativeTreeEntry: string
): { root: string; dest: string } {
  const root = resolve(treeRoot);
  const dest = resolve(root, relativeTreeEntry);
  if (dest === root || !dest.startsWith(root + sep)) {
    throw new Error(
      `Governed File-Grant: tree entry "${relativeTreeEntry}" escapes the ` +
        `grant-tree root; refusing to touch a path outside the tree.`
    );
  }
  return { root, dest };
}

function ancestorDirectories(root: string, dest: string): string[] {
  const dirs: string[] = [];
  let current = dirname(dest);
  while (current !== root) {
    dirs.push(current);
    const next = dirname(current);
    if (next === current) break;
    current = next;
  }
  dirs.push(root);
  return dirs.reverse();
}

/**
 * The first path segment of a `"<agentId>/<grantId>"` relative tree entry, or
 * null if the entry has no separator (defence in depth; `mint.ts` always
 * writes exactly two segments and `isSafeFileGrantAgentId` already forbids a
 * `/` inside the agent id itself).
 */
function agentIdFromRelativeTreeEntry(relativeTreeEntry: string): string | null {
  const sepIndex = relativeTreeEntry.indexOf("/");
  if (sepIndex <= 0) return null;
  return relativeTreeEntry.slice(0, sepIndex);
}

export function buildLinuxGrantAgentReadCommands(
  treeRoot: string,
  relativeTreeEntry: string,
  agentUid: number,
  sourceRealpath: string
): FileGrantExecCommand[] {
  const uid = uidToken(agentUid);
  const { root, dest } = resolveTreeEntryUnderRoot(treeRoot, relativeTreeEntry);
  return [
    ...ancestorDirectories(root, dest).map((dir) => ({
      file: "setfacl",
      args: ["-m", `u:${uid}:--x`, dir],
    })),
    { file: "setfacl", args: ["-m", `u:${uid}:rX`, sourceRealpath] },
  ];
}

export function buildLinuxRevokeAgentReadCommands(
  agentUid: number,
  sourceRealpath: string
): FileGrantExecCommand[] {
  const uid = uidToken(agentUid);
  return [{ file: "setfacl", args: ["-x", `u:${uid}`, sourceRealpath] }];
}

export function buildMacGrantAgentReadCommands(
  treeRoot: string,
  relativeTreeEntry: string,
  principal: string,
  aclTargetPath: string
): FileGrantExecCommand[] {
  const { root, dest } = resolveTreeEntryUnderRoot(treeRoot, relativeTreeEntry);
  return [
    ...ancestorDirectories(root, dest).map((dir) => ({
      file: "chmod",
      args: ["+a", `user:${principal} allow execute`, dir],
    })),
    { file: "chmod", args: ["+a", `user:${principal} allow read,execute`, aclTargetPath] },
  ];
}

export function buildMacRevokeAgentReadCommands(
  principal: string,
  aclTargetPath: string
): FileGrantExecCommand[] {
  return [{ file: "chmod", args: ["-a", `user:${principal} allow read,execute`, aclTargetPath] }];
}

/**
 * Fortress-dir traversal commands (F1 fix, 2026-07-14 drill finding). See the
 * module doc comment's FORTRESS-DIR TRAVERSAL note. These apply/remove a
 * single execute-only ACE directly on the fortress dir (the operator's
 * `config.storage_path`), one level ABOVE the grant-tree root that
 * `buildLinuxGrantAgentReadCommands` / `buildMacGrantAgentReadCommands`
 * already cover. Grant-side application is idempotent (safe to repeat for a
 * second grant to the same agent, matching the existing ancestor-ACE
 * pattern); removal is lifecycle-bound to "this agent has no more active
 * grants" rather than left in place forever, because the fortress root is a
 * more sensitive boundary than the dedicated grants subtree.
 */
export function buildMacFortressTraverseGrantCommand(
  fortressPath: string,
  principal: string
): FileGrantExecCommand {
  return { file: "chmod", args: ["+a", `user:${principal} allow execute`, fortressPath] };
}

export function buildMacFortressTraverseRevokeCommand(
  fortressPath: string,
  principal: string
): FileGrantExecCommand {
  return { file: "chmod", args: ["-a", `user:${principal} allow execute`, fortressPath] };
}

export function buildLinuxFortressTraverseGrantCommand(
  fortressPath: string,
  agentUid: number
): FileGrantExecCommand {
  const uid = uidToken(agentUid);
  return { file: "setfacl", args: ["-m", `u:${uid}:--x`, fortressPath] };
}

export function buildLinuxFortressTraverseRevokeCommand(
  fortressPath: string,
  agentUid: number
): FileGrantExecCommand {
  const uid = uidToken(agentUid);
  return { file: "setfacl", args: ["-x", `u:${uid}`, fortressPath] };
}

export function buildAgentReadProbeCommand(
  treeRoot: string,
  relativeTreeEntry: string,
  agentUid: number,
  pinnedSource: FileGrantSourceIdentity,
  nodePath: string = process.execPath
): FileGrantExecCommand {
  const uid = uidToken(agentUid);
  const { dest } = resolveTreeEntryUnderRoot(treeRoot, relativeTreeEntry);
  return {
    file: "sudo",
    args: [
      "-n",
      "-u",
      `#${uid}`,
      nodePath,
      "-e",
      AGENT_READ_PROBE_SCRIPT,
      dest,
      pinnedSource.source_dev,
      pinnedSource.source_ino,
    ],
  };
}

function errorText(err: unknown): string {
  if (err instanceof Error) {
    const withOutput = err as Error & { code?: unknown; signal?: unknown; stderr?: unknown };
    return [withOutput.code, withOutput.signal, withOutput.stderr, err.message]
      .filter((part) => part !== undefined && part !== null)
      .map((part) => String(part))
      .join(" ");
  }
  return String(err);
}

function errorCode(err: unknown): unknown {
  return (err as NodeJS.ErrnoException | undefined)?.code;
}

function isCrossDeviceLinkError(err: unknown): boolean {
  return errorCode(err) === "EXDEV";
}

function isMissingPathError(err: unknown): boolean {
  return errorCode(err) === "ENOENT";
}

function classifyAclFailure(err: unknown): FileGrantAclStatus {
  const text = errorText(err).toLowerCase();
  if (
    text.includes("eperm") ||
    text.includes("eacces") ||
    text.includes("operation not permitted") ||
    text.includes("permission denied") ||
    text.includes("not permitted") ||
    text.includes("must be owner")
  ) {
    return "not_privileged";
  }
  return "failed";
}

function inodeIdentityFromStats(stats: { dev: bigint | number; ino: bigint | number }): FileGrantSourceIdentity {
  return {
    source_dev: String(stats.dev),
    source_ino: String(stats.ino),
  };
}

function ownerUidFromStats(stats: { uid?: bigint | number }): number | null {
  if (stats.uid === undefined) return null;
  const uid = Number(stats.uid);
  return Number.isSafeInteger(uid) && uid >= 0 ? uid : null;
}

function sourceKindFromStats(stats: FileGrantOpenedFileStats): "regular_file" | "directory" | "special" | "unknown" {
  if (typeof stats.isFile === "function" && stats.isFile()) return "regular_file";
  if (typeof stats.isDirectory === "function" && stats.isDirectory()) return "directory";
  if (stats.mode === undefined) return "unknown";
  const modeType = Number(stats.mode) & POSIX_MODE_TYPE_MASK;
  if (modeType === POSIX_MODE_TYPE_REGULAR) return "regular_file";
  if (modeType === POSIX_MODE_TYPE_DIRECTORY) return "directory";
  return "special";
}

function isSupportedPinnedSource(stats: FileGrantOpenedFileStats): boolean {
  const sourceKind = sourceKindFromStats(stats);
  return sourceKind === "regular_file" || sourceKind === "directory";
}

function sameSourceIdentity(
  left: FileGrantSourceIdentity,
  right: FileGrantSourceIdentity
): boolean {
  return left.source_dev === right.source_dev && left.source_ino === right.source_ino;
}

function describeSourceIdentity(identity: FileGrantSourceIdentity): string {
  return `dev=${identity.source_dev} ino=${identity.source_ino}`;
}

function sourceIdentityMismatchReason(
  expected: FileGrantSourceIdentity,
  actual: FileGrantSourceIdentity
): string {
  return (
    `source inode mismatch: expected ${describeSourceIdentity(expected)}, ` +
    `got ${describeSourceIdentity(actual)}`
  );
}

function hasPersistedSourceIdentity(
  ace: FileGrantGrantedReadAce
): ace is FileGrantGrantedReadAce & FileGrantSourceIdentity {
  return typeof ace.source_dev === "string" && typeof ace.source_ino === "string";
}

function shouldKeepTreeEntryUntilConfirmedAclRemoval(
  grantedReadAce: FileGrantGrantedReadAce | null | undefined,
  aclRemoval: FileGrantRemoveEntryResult["aclRemoval"]
): boolean {
  return grantedReadAce?.platform === "darwin" && aclRemoval.status !== "removed";
}

function didScrubConfirmedAclTarget(
  grantedReadAce: FileGrantGrantedReadAce | null | undefined,
  aclRemoval: FileGrantRemoveEntryResult["aclRemoval"]
): boolean {
  if (grantedReadAce?.platform === "darwin") {
    return aclRemoval.status === "removed";
  }
  return aclRemoval.status !== "failed";
}

async function closeBestEffort(handle: { close(): Promise<void> }): Promise<void> {
  try {
    await handle.close();
  } catch {
    // Closing an fd after an earlier failure is best effort only.
  }
}

/**
 * Thrown (LOUD, fail-closed) when the fortress-dir traverse ACE could not be
 * re-applied after a concurrent placement was detected mid-removal. A missing
 * shared ACE while an active grant exists is a hard error the caller must
 * see, never a silently-unreachable active grant (F1 fix-round).
 */
export class FileGrantFortressAceReapplyError extends Error {
  constructor(
    public readonly agentUid: number,
    public readonly cause: unknown
  ) {
    super(
      `Governed File-Grant: failed to re-apply the fortress traverse ACE for ` +
        `uid ${agentUid} after a concurrent grant placement; an active grant may ` +
        `be unreachable until the next mint. ` +
        `Cause: ${cause instanceof Error ? cause.message : String(cause)}`
    );
    this.name = "FileGrantFortressAceReapplyError";
  }
}

/**
 * Real POSIX-backed `FsOps`. `fortressPath` is the operator's fortress
 * storage path (`config.storage_path`); the grant tree lives at
 * `<fortressPath>/grants/`, a plain (non-encrypted) directory alongside the
 * encrypted `state/` subdirectory -- grant-tree ENTRIES are operator-chosen
 * file placements, not Sanctuary state, so they do not belong in the
 * encrypted store.
 */
export class PosixFileGrantFsOps implements FsOps {
  private readonly execRunner: FileGrantExecRunner;
  private readonly macAclLinkOps: FileGrantMacAclLinkOps;
  private readonly commandTimeoutMs: number;
  private readonly platform: NodeJS.Platform;
  private readonly nodePath: string;

  constructor(
    private readonly fortressPath: string,
    options: PosixFileGrantFsOpsOptions = {}
  ) {
    this.execRunner = options.execRunner ?? DEFAULT_EXEC_RUNNER;
    this.macAclLinkOps = options.macAclLinkOps ?? DEFAULT_MAC_ACL_LINK_OPS;
    this.commandTimeoutMs = options.commandTimeoutMs ?? FILE_GRANT_ACL_COMMAND_TIMEOUT_MS;
    this.platform = options.platform ?? process.platform;
    this.nodePath = options.nodePath ?? process.execPath;
  }

  private treeRoot(): string {
    return join(this.fortressPath, GRANT_TREE_DIR_NAME);
  }

  private async ensureTreeRoot(): Promise<void> {
    await mkdir(this.treeRoot(), { recursive: true, mode: TREE_ROOT_MODE });
  }

  /**
   * Resolve a relative tree-entry to an absolute path and REJECT it unless it
   * stays strictly under the tree root. Defence in depth behind the mint-level
   * agent-id slug check (`isSafeFileGrantAgentId`): a `..`-bearing entry (or a
   * symlinked/absolute component) must never let a placement or scrub touch a
   * path outside the grant tree.
   */
  private resolveUnderRoot(relativeTreeEntry: string): string {
    return resolveTreeEntryUnderRoot(this.treeRoot(), relativeTreeEntry).dest;
  }

  async realpath(path: string): Promise<string> {
    return fsRealpath(path);
  }

  async pinSource(canonicalPath: string): Promise<FileGrantPinnedSource> {
    const handle = await fsOpen(canonicalPath, FILE_GRANT_PIN_SOURCE_OPEN_FLAGS);
    let closed = false;
    let stats: FileGrantOpenedFileStats;
    try {
      stats = await handle.stat({ bigint: true });
      if (!isSupportedPinnedSource(stats)) {
        throw new Error(
          `Governed File-Grant: source "${canonicalPath}" is ${sourceKindFromStats(stats)}, ` +
            `not a regular file or directory; refusing to grant a special file.`
        );
      }
    } catch (err) {
      await closeBestEffort(handle);
      throw err;
    }
    const identity = inodeIdentityFromStats(stats);
    return {
      source_realpath: canonicalPath,
      source_owner_uid: ownerUidFromStats(stats),
      ...identity,
      ...(this.platform === "linux" ? { source_fd_path: `/proc/${process.pid}/fd/${handle.fd}` } : {}),
      close: async () => {
        if (closed) return;
        closed = true;
        await closeBestEffort(handle);
      },
    };
  }

  async place(canonicalSrc: string, relativeTreeEntry: string): Promise<void> {
    const dest = this.resolveUnderRoot(relativeTreeEntry);
    await this.ensureTreeRoot();
    const agentSubdir = dirname(dest);
    await mkdir(agentSubdir, { recursive: true, mode: AGENT_SUBDIR_MODE });

    // The per-agent subdirectory stays operator-owned so a non-root operator
    // can always unlink the grant-tree symlink during revoke. The read grant
    // itself is the explicit POSIX ACL applied to the canonical source inode,
    // plus execute-only traversal ACLs on grant-tree ancestors. The grant tree
    // is the reach path, not a path-scoped read boundary.

    // Remove a stale entry at the same path before re-linking (mint always
    // allocates a fresh grant_id, so collisions are not expected in normal
    // operation, but a prior crashed mint could have left a partial link).
    try {
      await rm(dest, { force: true });
    } catch {
      // Best-effort cleanup only; symlink() below surfaces any real problem.
    }
    await symlink(canonicalSrc, dest);
  }

  async grantAgentRead(
    relativeTreeEntry: string,
    agentUid: number,
    pinnedSource: FileGrantPinnedSource
  ): Promise<FileGrantAclResult> {
    return this.applyAgentReadAcl(relativeTreeEntry, agentUid, pinnedSource);
  }

  async probeAgentRead(
    relativeTreeEntry: string,
    agentUid: number,
    pinnedSource: FileGrantSourceIdentity
  ): Promise<boolean> {
    if (this.platform !== "linux" && this.platform !== "darwin") return false;
    try {
      await this.runCommand(
        buildAgentReadProbeCommand(
          this.treeRoot(),
          relativeTreeEntry,
          agentUid,
          pinnedSource,
          this.nodePath
        )
      );
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Apply the ACL and run the same-operation probe under ONE fortress-ACE-lock
   * hold (round 4). The lock spans BOTH steps, so a concurrent revoke's
   * drain-check-and-removal cannot run in the gap between this mint's apply and
   * its probe -- closing the "apply outside-lock probe" false-`met` window.
   * The probe is invoked through the overridable `this.probeAgentRead` (it
   * takes no lock of its own, so calling it inside the held lock is safe and
   * not reentrant). Fail-closed: lock CONTENTION (or any throw) yields
   * `readVerified: false` with no `aclResult`, so the mint reports `unverified`
   * and the operator retries -- never a false `met`, never an indefinite block
   * (the lock's bounded-wait timeout governs).
   */
  async grantAndProbeAgentRead(
    relativeTreeEntry: string,
    agentUid: number,
    pinnedSource: FileGrantPinnedSource
  ): Promise<{ aclResult?: FileGrantAclResult; readVerified: boolean }> {
    try {
      return await this.withFortressAceLock(async () => {
        const aclResult = await this.applyAgentReadAclLocked(
          relativeTreeEntry,
          agentUid,
          pinnedSource
        );
        if (aclResult.status !== "applied") {
          return { aclResult, readVerified: false };
        }
        const readVerified = await this.probeAgentRead(
          relativeTreeEntry,
          agentUid,
          pinnedSource
        );
        return { aclResult, readVerified };
      });
    } catch {
      // Lock contention (bounded-wait timeout) or an unexpected internal
      // failure: fail CLOSED. No aclResult -> no ACE persisted, enforcement
      // reports `unverified`, never a false `met`.
      return { readVerified: false };
    }
  }

  async removeEntry(
    relativeTreeEntry: string,
    options: FileGrantRemoveEntryOptions = {}
  ): Promise<FileGrantRemoveEntryResult> {
    const dest = this.resolveUnderRoot(relativeTreeEntry);
    const grantedReadAce = options.grantedReadAce ?? null;
    const aclRemoval = await this.removePersistedAgentReadAcl(grantedReadAce, dest);
    if (shouldKeepTreeEntryUntilConfirmedAclRemoval(grantedReadAce, aclRemoval)) {
      return {
        treeEntryRemoved: false,
        aclRemoval,
        scrubbed: false,
      };
    }
    let treeEntryRemoved = false;
    try {
      const st = await lstat(dest);
      if (st) {
        await rm(dest, { force: true });
        treeEntryRemoved = true;
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
        await this.removeFortressTraverseAceIfTreeDrained(relativeTreeEntry);
        return {
          treeEntryRemoved,
          aclRemoval,
          scrubbed: didScrubConfirmedAclTarget(grantedReadAce, aclRemoval),
        };
      }
      throw err;
    }
    await this.removeFortressTraverseAceIfTreeDrained(relativeTreeEntry);
    return {
      treeEntryRemoved,
      aclRemoval,
      scrubbed: didScrubConfirmedAclTarget(grantedReadAce, aclRemoval),
    };
  }

  /**
   * F1 fix (2026-07-14 drill finding): once a tree entry has been scrubbed
   * (or was already absent), check whether the WHOLE grant tree is now
   * drained -- no tree entry left under ANY per-agent subdirectory. Only
   * then is the execute-only fortress-dir traverse ACE applied at grant time
   * (`applyAgentReadAcl`) removed.
   *
   * WHOLE tree, not this entry's per-agent subtree: the ACE is keyed on the
   * box's single dedicated agent UID, and today every subject agent id
   * resolves to that same uid (`agentUid` ignores its argument). Draining
   * one logical agent's subtree while a DIFFERENT subject agent id still
   * holds an active grant would strip the shared uid's traverse and break
   * the other agent's still-live reach path. See the module doc comment's
   * DEBT note for the durable multi-uid fix (persist the uid basis on the
   * grant record).
   *
   * Revoke-vs-concurrent-mint race close (FIX-ROUND, fail-CLOSED): the
   * drain-check + removal (+ a defensive re-check/re-apply) run UNDER the
   * cross-process fortress-ACE lock (`withFortressAceLock`), which the mint's
   * own fortress-ACE APPLICATION also holds. So a concurrent mint's
   * apply-then-probe can never interleave with this removal: either the mint
   * applied+placed first (this drain-check then observes its entry and does
   * NOT remove), or this removal ran first (the mint's subsequent apply
   * re-adds the idempotent ACE before it probes -- it cannot probe `met`
   * against a missing ACE). If a place() nonetheless slipped in during this
   * locked section (place is not itself locked), the post-removal re-check
   * catches it and re-applies; and if that re-apply FAILS, this throws LOUDLY
   * rather than swallowing -- a now-non-drained tree with the shared ACE
   * removed is a hard error the caller must see, never a silent
   * unreachable-active-grant. On sustained lock contention the ACE is left in
   * place untouched (fail-SAFE: an over-permissive traverse-only ACE lingers
   * until a later touch removes it, versus stripping a possibly-live grant's
   * reach path).
   *
   * Purely internal: the return value is consumed only by unit tests via the
   * recorded exec commands. Returns undefined when there is nothing to do:
   * unsupported platform, some grant still live anywhere in the tree, no
   * agent uid configured, or lock contention.
   */
  private async removeFortressTraverseAceIfTreeDrained(
    relativeTreeEntry: string
  ): Promise<FileGrantAclRemovalResult | undefined> {
    if (this.platform !== "linux" && this.platform !== "darwin") return undefined;
    try {
      return await this.withFortressAceLock(() =>
        this.drainGatedRemoveFortressAceLocked(relativeTreeEntry)
      );
    } catch (err) {
      if (err instanceof FileGrantFortressAceReapplyError) throw err;
      // Lock could not be acquired (sustained contention / unlockable dir):
      // fail SAFE and leave the ACE in place for a later touch to remove.
      return undefined;
    }
  }

  /**
   * Drain-gated fortress-ACE removal for the REVOKE/reconcile path. Caller
   * MUST already hold the fortress-ACE lock (this method never re-acquires
   * it, so it is safe to call from inside `withFortressAceLock`). Re-resolves
   * the agent uid from the live descriptor because a revoke/reconcile call
   * does not carry it. On a place() that slipped into the locked section, the
   * post-removal re-check re-applies and THROWS `FileGrantFortressAceReapplyError`
   * on failure (fail-closed-loud; see the module doc comment).
   */
  private async drainGatedRemoveFortressAceLocked(
    relativeTreeEntry: string
  ): Promise<FileGrantAclRemovalResult | undefined> {
    if (!(await this.isGrantTreeDrained())) return undefined;
    const agentId = agentIdFromRelativeTreeEntry(relativeTreeEntry);
    let agentUid: number | null;
    try {
      agentUid = await this.agentUid(agentId ?? "");
    } catch {
      agentUid = null;
    }
    if (agentUid === null) return undefined;
    const removal = await this.removeFortressTraverseAce(agentUid);
    if (removal.status === "removed" && !(await this.isGrantTreeDrained())) {
      await this.reapplyFortressTraverseAceOrThrow(agentUid);
    }
    return removal;
  }

  /**
   * Drain-gated fortress-ACE cleanup for the failed-APPLY path, keyed on the
   * uid the apply already resolved (never re-resolving the descriptor). Caller
   * MUST already hold the fortress-ACE lock. Best-effort and silent: the apply
   * is already returning a failure result, and the ACE is removed ONLY when
   * the tree is drained (so a concurrent live grant for the same uid is never
   * stripped -- unifying finding #1's drain-gating with finding #2's
   * no-orphan cleanup).
   */
  private async drainGatedRemoveFortressAceForUid(agentUid: number): Promise<void> {
    try {
      if (await this.isGrantTreeDrained()) {
        await this.removeFortressTraverseAce(agentUid);
      }
    } catch {
      // Best-effort cleanup on an already-failing apply.
    }
  }

  /**
   * Serialize a fortress-ACE-mutating critical section across processes on
   * the grant-tree root's lockfile. Reuses the shared `withPathLock`
   * primitive; never invents its own lock discipline. NOT reentrant: callers
   * inside a held lock use the `*Locked` / `*ForUid` non-locking helpers.
   *
   * Degrade is NARROW (opus LOW-1 + round-5 close): it runs `operation`
   * UNLOCKED only when the fortress path is PROVABLY ABSENT -- the unit-rig /
   * unreal-path case (e.g. a synthetic `"/fortress"`), which has no
   * cross-process surface. "Provably absent" means `stat(<fortress>)` reports
   * ENOENT/ENOTDIR. On a REAL, existing fortress a `mkdir` failure is an
   * unexpected error and fails CLOSED (rethrow) rather than silently running
   * the critical section unlocked (a fail-OPEN of the serialization). A
   * PERMISSION anomaly that blocks BOTH the mkdir AND the `stat` (EACCES /
   * EPERM / EIO / etc.) must NOT be mistaken for "absent": `fortressPresence`
   * rethrows any non-ENOENT/ENOTDIR stat error so the lock fails closed
   * (mint -> unverified; revoke/reconcile -> leave the ACE), never unlocked. A
   * real deployment always has the fortress present by grant time.
   */
  private async withFortressAceLock<T>(operation: () => Promise<T>): Promise<T> {
    const lockDir = this.treeRoot();
    try {
      await mkdir(lockDir, { recursive: true, mode: TREE_ROOT_MODE });
    } catch (mkdirErr) {
      // Only a PROVABLY-ABSENT fortress (stat -> ENOENT/ENOTDIR) takes the
      // unit-rig unlocked path. Any other stat error propagates -> fail closed.
      if ((await this.fortressPresence()) === "present") throw mkdirErr;
      return operation();
    }
    return withPathLock(lockDir, FORTRESS_ACE_LOCK_FILE, operation);
  }

  /**
   * "absent" ONLY when `stat(<fortress>)` reports ENOENT/ENOTDIR (the path
   * genuinely does not exist). "present" on success. Any OTHER stat error
   * (EACCES/EPERM/EIO/...) is rethrown: an inability to observe the fortress
   * must never be collapsed to "absent" and drive a fail-open unlocked path.
   */
  private async fortressPresence(): Promise<"present" | "absent"> {
    try {
      await stat(this.fortressPath);
      return "present";
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === "ENOENT" || code === "ENOTDIR") return "absent";
      throw err;
    }
  }

  /**
   * True when no grant-tree entry exists under any per-agent subdirectory
   * (or the tree root itself is absent). Fails toward NOT-drained on any
   * unexpected read error: uncertainty must keep the traverse ACE in place
   * (a later confirmed drain removes it) rather than strip a possibly-live
   * grant's reach path.
   */
  private async isGrantTreeDrained(): Promise<boolean> {
    const root = this.treeRoot();
    let agentDirs: string[];
    try {
      agentDirs = await readdir(root);
    } catch (err) {
      return (err as NodeJS.ErrnoException)?.code === "ENOENT";
    }
    for (const name of agentDirs) {
      try {
        const entries = await readdir(join(root, name));
        if (entries.length > 0) return false;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        // A vanished subdir is drained; a stray non-directory direct child is
        // not a grant entry (entries live at depth 2). Anything else is
        // uncertainty: treat as not drained.
        if (code === "ENOENT" || code === "ENOTDIR") continue;
        return false;
      }
    }
    return true;
  }

  private async removeFortressTraverseAce(
    agentUid: number
  ): Promise<FileGrantAclRemovalResult> {
    try {
      if (this.platform === "linux") {
        await this.runCommand(buildLinuxFortressTraverseRevokeCommand(this.fortressPath, agentUid));
      } else {
        const principal = await this.resolveMacPrincipal(agentUid);
        await this.runCommand(buildMacFortressTraverseRevokeCommand(this.fortressPath, principal));
      }
      return { status: "removed", agent_uid: agentUid, platform: this.platform };
    } catch (err) {
      return {
        status: "failed",
        agent_uid: agentUid,
        platform: this.platform,
        reason: errorText(err),
      };
    }
  }

  private async reapplyFortressTraverseAceOrThrow(agentUid: number): Promise<void> {
    try {
      if (this.platform === "linux") {
        await this.runCommand(buildLinuxFortressTraverseGrantCommand(this.fortressPath, agentUid));
      } else {
        const principal = await this.resolveMacPrincipal(agentUid);
        await this.runCommand(buildMacFortressTraverseGrantCommand(this.fortressPath, principal));
      }
    } catch (err) {
      throw new FileGrantFortressAceReapplyError(agentUid, err);
    }
  }

  async agentUid(_subjectAgentId: string): Promise<number | null> {
    return this.readConfiguredAgentUid(agentOriginDescriptorPath(this.fortressPath));
  }

  async sourceOwnerUid(canonicalPath: string): Promise<number | null> {
    if (process.getuid === undefined) return null;
    let pinnedSource: FileGrantPinnedSource;
    try {
      pinnedSource = await this.pinSource(canonicalPath);
    } catch {
      // The path was realpath'd moments earlier; a stat failure here means it
      // vanished or became unreadable. Return null so the enforcement verdict
      // fails toward "unmet" (no false "enforced") rather than throwing.
      return null;
    }
    try {
      return pinnedSource.source_owner_uid;
    } finally {
      await pinnedSource.close();
    }
  }

  /**
   * The wall's agent-origin descriptor names ONE dedicated agent uid per
   * box today (`castle-wall/allowlist/agent-origin.ts`), so every subject
   * agent id currently resolves to that same uid. Returns null when no
   * descriptor is configured, the descriptor is malformed, or its mode is
   * not "uid" (nat-mode boxes have no uid to enforce with).
   */
  private async readConfiguredAgentUid(originPath: string): Promise<number | null> {
    try {
      const raw = await readFile(originPath, "utf8");
      const descriptor = validateAgentOrigin(JSON.parse(raw));
      if (descriptor === null || descriptor.mode !== "uid") return null;
      return descriptor.agent_uid ?? null;
    } catch {
      return null;
    }
  }

  /**
   * macOS has path-scoped ACL tooling and no proc fd path, so the ACL target
   * is a hard link inside the operator-owned grant tree. The link is accepted
   * only after fstat confirms it is the pinned source inode. Cross-filesystem
   * links fail closed before chmod runs.
   */
  private async prepareMacAclHardLinkTarget(
    relativeTreeEntry: string,
    pinnedSource: FileGrantPinnedSource
  ): Promise<string> {
    const dest = this.resolveUnderRoot(relativeTreeEntry);
    await this.ensureTreeRoot();
    await mkdir(dirname(dest), { recursive: true, mode: AGENT_SUBDIR_MODE });
    try {
      await this.macAclLinkOps.rm(dest, { force: true });
    } catch {
      // link() below surfaces any real collision or permissions problem.
    }

    try {
      await this.macAclLinkOps.link(pinnedSource.source_realpath, dest);
      await this.assertMacAclTargetIdentity(dest, pinnedSource, "after macOS ACL hard link");
      return dest;
    } catch (err) {
      await this.removeMacAclHardLinkBestEffort(dest);
      if (isCrossDeviceLinkError(err)) {
        throw new Error(
          `Governed File-Grant: macOS ACL hard link requires source and ` +
            `grant tree on the same filesystem: ${errorText(err)}`,
          { cause: err }
        );
      }
      throw err;
    }
  }

  private async applyAgentReadAcl(
    relativeTreeEntry: string,
    agentUid: number,
    pinnedSource: FileGrantPinnedSource
  ): Promise<FileGrantAclResult> {
    if (this.platform !== "linux" && this.platform !== "darwin") {
      return {
        status: "unsupported_platform",
        platform: this.platform,
        reason: `unsupported platform ${this.platform}`,
      };
    }
    // Serialize the fortress-ACE application against a concurrent revoke's
    // drain-check-and-removal for the same fortress (F1 fix-round): so a
    // concurrent mint can never probe a false `met` while a concurrent revoke
    // strips the shared uid's traverse ACE. On sustained lock CONTENTION the
    // apply fails CLOSED (no false `met`); the mint reports `unverified`.
    try {
      return await this.withFortressAceLock(() =>
        this.applyAgentReadAclLocked(relativeTreeEntry, agentUid, pinnedSource)
      );
    } catch (err) {
      return {
        status: classifyAclFailure(err),
        platform: this.platform,
        reason: errorText(err),
      };
    }
  }

  private async applyAgentReadAclLocked(
    relativeTreeEntry: string,
    agentUid: number,
    pinnedSource: FileGrantPinnedSource
  ): Promise<FileGrantAclResult> {
    let sourceLeafCommandAttempted = false;
    let fortressTraverseAceApplied = false;
    let macAclHardlinkPath: string | undefined;
    try {
      const macPrincipal =
        this.platform === "darwin" ? await this.resolveMacPrincipal(agentUid) : undefined;
      let fortressCommand: FileGrantExecCommand;
      let commands: FileGrantExecCommand[];
      if (this.platform === "linux") {
        if (!pinnedSource.source_fd_path) {
          throw new Error("Governed File-Grant: pinned source fd path unavailable on Linux");
        }
        fortressCommand = buildLinuxFortressTraverseGrantCommand(this.fortressPath, agentUid);
        commands = buildLinuxGrantAgentReadCommands(
          this.treeRoot(),
          relativeTreeEntry,
          agentUid,
          pinnedSource.source_fd_path
        );
      } else {
        macAclHardlinkPath = await this.prepareMacAclHardLinkTarget(
          relativeTreeEntry,
          pinnedSource
        );
        fortressCommand = buildMacFortressTraverseGrantCommand(this.fortressPath, macPrincipal!);
        commands = buildMacGrantAgentReadCommands(
          this.treeRoot(),
          relativeTreeEntry,
          macPrincipal!,
          macAclHardlinkPath
        );
      }
      // F1 fix (2026-07-14): the fortress dir sits ABOVE the grant-tree root
      // and is 0700 by default, so without this the agent uid can never reach
      // the grant tree at all. Idempotent; a second/third grant for the same
      // uid repeats this harmlessly. Tracked separately from the source-leaf
      // attempt so a failure ANYWHERE after this point (including on a
      // grant-tree ancestor, before the leaf is attempted) still best-effort
      // removes the just-applied fortress ACE in the catch below -- a partial
      // apply must never leave the uid-level traverse ACE orphaned.
      await this.runCommand(fortressCommand);
      fortressTraverseAceApplied = true;
      const sourceLeafCommand = commands.at(-1);
      await this.runCommands(commands.slice(0, -1));
      if (sourceLeafCommand) {
        sourceLeafCommandAttempted = true;
        await this.runCommand(sourceLeafCommand);
      }
      if (this.platform === "darwin") {
        await this.assertMacAclTargetIdentity(
          macAclHardlinkPath!,
          pinnedSource,
          "after macOS ACL apply"
        );
      }
      return {
        status: "applied",
        platform: this.platform,
        grantedReadAce: {
          agent_uid: agentUid,
          platform: this.platform,
          source_realpath: pinnedSource.source_realpath,
          source_dev: pinnedSource.source_dev,
          source_ino: pinnedSource.source_ino,
          ...(macPrincipal ? { mac_principal: macPrincipal } : {}),
          ...(macAclHardlinkPath ? { mac_acl_hardlink_path: macAclHardlinkPath } : {}),
        },
      };
    } catch (err) {
      if (sourceLeafCommandAttempted) {
        await this.bestEffortRemoveAgentReadAcl(agentUid, pinnedSource, macAclHardlinkPath);
      }
      if (fortressTraverseAceApplied) {
        // Clean up the exact ACE this failed apply added, on EVERY non-applied
        // exit after it ran (including an ancestor failure BEFORE the source
        // leaf). Drain-gated: removed ONLY when the tree is drained, so a
        // concurrent live grant for the same uid is never stripped (finding #1)
        // while a genuine orphan (no remaining entry) is never left behind
        // (finding #2). We already hold the fortress-ACE lock here.
        await this.drainGatedRemoveFortressAceForUid(agentUid);
      }
      if (this.platform === "darwin" && macAclHardlinkPath) {
        await this.removeMacAclHardLinkBestEffort(macAclHardlinkPath);
      }
      return {
        status: classifyAclFailure(err),
        platform: this.platform,
        reason: errorText(err),
      };
    }
  }

  private async bestEffortRemoveAgentReadAcl(
    agentUid: number,
    pinnedSource: FileGrantPinnedSource,
    macAclHardlinkPath?: string
  ): Promise<void> {
    if (this.platform !== "linux" && this.platform !== "darwin") return;
    let commands: FileGrantExecCommand[];
    try {
      const macPrincipal =
        this.platform === "darwin" ? await this.resolveMacPrincipal(agentUid) : undefined;
      if (this.platform === "linux" && !pinnedSource.source_fd_path) return;
      commands =
        this.platform === "linux"
          ? buildLinuxRevokeAgentReadCommands(agentUid, pinnedSource.source_fd_path!)
          : macAclHardlinkPath
            ? buildMacRevokeAgentReadCommands(macPrincipal!, macAclHardlinkPath)
            : [];
    } catch {
      return;
    }
    for (const command of commands) {
      try {
        await this.runCommand(command);
      } catch {
        // Best-effort cleanup of a failed grant attempt. The original ACL
        // apply failure remains the structured result returned to the caller.
      }
    }
  }

  private async removePersistedAgentReadAcl(
    grantedReadAce: FileGrantGrantedReadAce | null | undefined,
    expectedTreeEntryPath: string
  ): Promise<FileGrantRemoveEntryResult["aclRemoval"]> {
    if (!grantedReadAce) return { status: "not_applicable" };
    if (grantedReadAce.platform !== "linux" && grantedReadAce.platform !== "darwin") {
      return {
        status: "unsupported_platform",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
      };
    }
    if (!hasPersistedSourceIdentity(grantedReadAce)) {
      return {
        status: "failed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
        reason: "source inode identity missing from persisted ACE",
      };
    }
    if (grantedReadAce.platform === "darwin") {
      return this.removePersistedMacAgentReadAcl(grantedReadAce, expectedTreeEntryPath);
    }
    let pinnedSource: FileGrantPinnedSource;
    try {
      pinnedSource = await this.pinSource(grantedReadAce.source_realpath);
    } catch (err) {
      return {
        status: "failed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
        reason: `source inode unavailable: ${errorText(err)}`,
      };
    }
    try {
      if (!sameSourceIdentity(pinnedSource, grantedReadAce)) {
        return {
          status: "failed",
          agent_uid: grantedReadAce.agent_uid,
          platform: grantedReadAce.platform,
          source_realpath: grantedReadAce.source_realpath,
          reason: sourceIdentityMismatchReason(grantedReadAce, pinnedSource),
        };
      }
      if (!pinnedSource.source_fd_path) {
        throw new Error("Governed File-Grant: pinned source fd path unavailable on Linux");
      }
      const commands = buildLinuxRevokeAgentReadCommands(
        grantedReadAce.agent_uid,
        pinnedSource.source_fd_path
      );
      await this.runCommands(commands);
      return {
        status: "removed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
      };
    } catch (err) {
      return {
        status: "failed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
        reason: errorText(err),
      };
    } finally {
      await pinnedSource.close();
    }
  }

  private async removePersistedMacAgentReadAcl(
    grantedReadAce: FileGrantGrantedReadAce & FileGrantSourceIdentity,
    expectedTreeEntryPath: string
  ): Promise<FileGrantRemoveEntryResult["aclRemoval"]> {
    const aclTargetPath = grantedReadAce.mac_acl_hardlink_path;
    if (!aclTargetPath) {
      return {
        status: "failed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
        reason: "trusted macOS ACL hard link missing from persisted ACE",
      };
    }
    if (resolve(aclTargetPath) !== expectedTreeEntryPath) {
      return {
        status: "failed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
        reason: "trusted macOS ACL hard link does not match the grant tree entry",
      };
    }

    try {
      await this.assertMacAclTargetIdentity(
        aclTargetPath,
        grantedReadAce,
        "before macOS ACL removal"
      );
      const commands = buildMacRevokeAgentReadCommands(
        grantedReadAce.mac_principal ??
          (await this.resolveMacPrincipal(grantedReadAce.agent_uid)),
        aclTargetPath
      );
      await this.runCommands(commands);
      await this.assertMacAclTargetIdentity(
        aclTargetPath,
        grantedReadAce,
        "after macOS ACL removal"
      );
      return {
        status: "removed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
      };
    } catch (err) {
      if (isMissingPathError(err)) {
        return {
          status: "failed",
          agent_uid: grantedReadAce.agent_uid,
          platform: grantedReadAce.platform,
          source_realpath: grantedReadAce.source_realpath,
          reason: "trusted macOS ACL hard link absent; cannot confirm ACE removal",
        };
      }
      return {
        status: "failed",
        agent_uid: grantedReadAce.agent_uid,
        platform: grantedReadAce.platform,
        source_realpath: grantedReadAce.source_realpath,
        reason: errorText(err),
      };
    }
  }

  private async assertMacAclTargetIdentity(
    aclTargetPath: string,
    expected: FileGrantSourceIdentity,
    phase: string
  ): Promise<void> {
    const actual = await this.readMacAclTargetIdentity(aclTargetPath);
    if (!sameSourceIdentity(expected, actual)) {
      throw new Error(
        `Governed File-Grant: ${phase} ${sourceIdentityMismatchReason(expected, actual)}`
      );
    }
  }

  private async readMacAclTargetIdentity(path: string): Promise<FileGrantSourceIdentity> {
    const handle = await this.macAclLinkOps.open(
      path,
      FILE_GRANT_MAC_ACL_TARGET_OPEN_FLAGS
    );
    try {
      const stats = await handle.stat({ bigint: true });
      const sourceKind = sourceKindFromStats(stats);
      if (sourceKind !== "regular_file") {
        throw new Error(
          `Governed File-Grant: trusted macOS ACL target "${path}" is ` +
            `${sourceKind}, not a regular file; refusing to remove an ACE through it.`
        );
      }
      return inodeIdentityFromStats(stats);
    } finally {
      await closeBestEffort(handle);
    }
  }

  private async removeMacAclHardLinkBestEffort(path: string): Promise<void> {
    try {
      await this.macAclLinkOps.rm(path, { force: true });
    } catch {
      // Best-effort cleanup of the trusted hard link after a failed ACL path.
    }
  }

  private async resolveMacPrincipal(agentUid: number): Promise<string> {
    const uid = uidToken(agentUid);
    try {
      const result = await this.runCommand({ file: "id", args: ["-nu", uid] });
      const name = result.stdout.trim();
      if (name.length > 0) return name;
    } catch {
      // macOS chmod accepts a uid-like ACL principal on systems where id lookup
      // is unavailable, and the chmod command below will report any real error.
    }
    return uid;
  }

  private async runCommands(commands: FileGrantExecCommand[]): Promise<void> {
    for (const command of commands) {
      await this.runCommand(command);
    }
  }

  private async runCommand(command: FileGrantExecCommand): Promise<FileGrantExecResult> {
    return this.execRunner.execFile(command, this.commandTimeoutMs);
  }
}
