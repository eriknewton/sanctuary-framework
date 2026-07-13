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
 */

import { execFile as nodeExecFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  link as fsLink,
  mkdir,
  lstat,
  open as fsOpen,
  readFile,
  realpath as fsRealpath,
  rm,
  symlink,
} from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import type {
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
        return {
          treeEntryRemoved,
          aclRemoval,
          scrubbed: didScrubConfirmedAclTarget(grantedReadAce, aclRemoval),
        };
      }
      throw err;
    }
    return {
      treeEntryRemoved,
      aclRemoval,
      scrubbed: didScrubConfirmedAclTarget(grantedReadAce, aclRemoval),
    };
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

    let sourceLeafCommandAttempted = false;
    let macAclHardlinkPath: string | undefined;
    try {
      const macPrincipal =
        this.platform === "darwin" ? await this.resolveMacPrincipal(agentUid) : undefined;
      let commands: FileGrantExecCommand[];
      if (this.platform === "linux") {
        if (!pinnedSource.source_fd_path) {
          throw new Error("Governed File-Grant: pinned source fd path unavailable on Linux");
        }
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
        commands = buildMacGrantAgentReadCommands(
          this.treeRoot(),
          relativeTreeEntry,
          macPrincipal!,
          macAclHardlinkPath
        );
      }
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
