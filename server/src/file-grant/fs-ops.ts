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
 * FUNCTIONAL PRIMITIVE: `grantAgentRead` resolves the source path before this
 * module sees it, applies the platform ACL operation to that canonical source
 * path, and applies execute-only traversal ACLs to grant-tree ancestors. The
 * grant tree is the agent's reach path, not a second path-scoped boundary.
 * POSIX read ACLs are inode-scoped: the same uid can read the same file
 * through any other path it can reach. `probeAgentRead` verifies readability
 * by running a bounded read through the grant tree as the agent uid.
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
import { mkdir, lstat, readFile, realpath as fsRealpath, rm, stat, symlink } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import type {
  FileGrantAclResult,
  FileGrantAclStatus,
  FileGrantGrantedReadAce,
  FileGrantRemoveEntryResult,
  FileGrantRemoveEntryOptions,
  FsOps,
} from "./types.js";

const GRANT_TREE_DIR_NAME = "grants";
/** Root: traversable (x) by anyone so a chowned per-agent leaf below it stays reachable, but not listable/writable by non-owners. */
const TREE_ROOT_MODE = 0o711;
/** Per-agent leaf: readable/traversable ONLY by its owner. */
const AGENT_SUBDIR_MODE = 0o700;
export const FILE_GRANT_ACL_COMMAND_TIMEOUT_MS = 2_000;
const EXEC_MAX_BUFFER_BYTES = 64 * 1024;

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

export interface PosixFileGrantFsOpsOptions {
  execRunner?: FileGrantExecRunner;
  commandTimeoutMs?: number;
  platform?: NodeJS.Platform;
  nodePath?: string;
}

export const AGENT_READ_PROBE_SCRIPT =
  "const fs=require('node:fs');" +
  "const p=process.argv[1];" +
  "const st=fs.statSync(p);" +
  "if(st.isDirectory()){fs.readdirSync(p);process.exit(0);}" +
  "const fd=fs.openSync(p,'r');" +
  "try{const b=Buffer.alloc(1);fs.readSync(fd,b,0,1,0);}finally{fs.closeSync(fd);}";

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
  sourceRealpath: string
): FileGrantExecCommand[] {
  const { root, dest } = resolveTreeEntryUnderRoot(treeRoot, relativeTreeEntry);
  return [
    ...ancestorDirectories(root, dest).map((dir) => ({
      file: "chmod",
      args: ["+a", `user:${principal} allow execute`, dir],
    })),
    { file: "chmod", args: ["+a", `user:${principal} allow read,execute`, sourceRealpath] },
  ];
}

export function buildMacRevokeAgentReadCommands(
  principal: string,
  sourceRealpath: string
): FileGrantExecCommand[] {
  return [{ file: "chmod", args: ["-a", `user:${principal} allow read,execute`, sourceRealpath] }];
}

export function buildAgentReadProbeCommand(
  treeRoot: string,
  relativeTreeEntry: string,
  agentUid: number,
  nodePath: string = process.execPath
): FileGrantExecCommand {
  const uid = uidToken(agentUid);
  const { dest } = resolveTreeEntryUnderRoot(treeRoot, relativeTreeEntry);
  return {
    file: "sudo",
    args: ["-n", "-u", `#${uid}`, nodePath, "-e", AGENT_READ_PROBE_SCRIPT, dest],
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
  private readonly commandTimeoutMs: number;
  private readonly platform: NodeJS.Platform;
  private readonly nodePath: string;

  constructor(
    private readonly fortressPath: string,
    options: PosixFileGrantFsOpsOptions = {}
  ) {
    this.execRunner = options.execRunner ?? DEFAULT_EXEC_RUNNER;
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
    sourceRealpath: string
  ): Promise<FileGrantAclResult> {
    return this.applyAgentReadAcl(relativeTreeEntry, agentUid, sourceRealpath);
  }

  async probeAgentRead(relativeTreeEntry: string, agentUid: number): Promise<boolean> {
    if (this.platform !== "linux" && this.platform !== "darwin") return false;
    try {
      await this.runCommand(
        buildAgentReadProbeCommand(
          this.treeRoot(),
          relativeTreeEntry,
          agentUid,
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
    const aclRemoval = await this.removePersistedAgentReadAcl(options.grantedReadAce);
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
          scrubbed: aclRemoval.status !== "failed",
        };
      }
      throw err;
    }
    return {
      treeEntryRemoved,
      aclRemoval,
      scrubbed: aclRemoval.status !== "failed",
    };
  }

  async agentUid(_subjectAgentId: string): Promise<number | null> {
    return this.readConfiguredAgentUid(agentOriginDescriptorPath(this.fortressPath));
  }

  async sourceOwnerUid(canonicalPath: string): Promise<number | null> {
    if (process.getuid === undefined) return null;
    try {
      const st = await stat(canonicalPath);
      return st.uid;
    } catch {
      // The path was realpath'd moments earlier; a stat failure here means it
      // vanished or became unreadable. Return null so the enforcement verdict
      // fails toward "unmet" (no false "enforced") rather than throwing.
      return null;
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

  private async applyAgentReadAcl(
    relativeTreeEntry: string,
    agentUid: number,
    sourceRealpath: string
  ): Promise<FileGrantAclResult> {
    if (this.platform !== "linux" && this.platform !== "darwin") {
      return {
        status: "unsupported_platform",
        platform: this.platform,
        reason: `unsupported platform ${this.platform}`,
      };
    }

    try {
      const macPrincipal =
        this.platform === "darwin" ? await this.resolveMacPrincipal(agentUid) : undefined;
      const commands =
        this.platform === "linux"
          ? buildLinuxGrantAgentReadCommands(
              this.treeRoot(),
              relativeTreeEntry,
              agentUid,
              sourceRealpath
            )
          : buildMacGrantAgentReadCommands(
              this.treeRoot(),
              relativeTreeEntry,
              macPrincipal!,
              sourceRealpath
            );
      await this.runCommands(commands);
      return {
        status: "applied",
        platform: this.platform,
        grantedReadAce: {
          agent_uid: agentUid,
          platform: this.platform,
          source_realpath: sourceRealpath,
          ...(macPrincipal ? { mac_principal: macPrincipal } : {}),
        },
      };
    } catch (err) {
      await this.bestEffortRemoveAgentReadAcl(agentUid, sourceRealpath);
      return {
        status: classifyAclFailure(err),
        platform: this.platform,
        reason: errorText(err),
      };
    }
  }

  private async bestEffortRemoveAgentReadAcl(agentUid: number, sourceRealpath: string): Promise<void> {
    if (this.platform !== "linux" && this.platform !== "darwin") return;
    let commands: FileGrantExecCommand[];
    try {
      const macPrincipal =
        this.platform === "darwin" ? await this.resolveMacPrincipal(agentUid) : undefined;
      commands =
        this.platform === "linux"
          ? buildLinuxRevokeAgentReadCommands(agentUid, sourceRealpath)
          : buildMacRevokeAgentReadCommands(macPrincipal!, sourceRealpath);
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
    grantedReadAce: FileGrantGrantedReadAce | null | undefined
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
    try {
      const commands =
        grantedReadAce.platform === "linux"
          ? buildLinuxRevokeAgentReadCommands(
              grantedReadAce.agent_uid,
              grantedReadAce.source_realpath
            )
          : buildMacRevokeAgentReadCommands(
              grantedReadAce.mac_principal ??
                (await this.resolveMacPrincipal(grantedReadAce.agent_uid)),
              grantedReadAce.source_realpath
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
