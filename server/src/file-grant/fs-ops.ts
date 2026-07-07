/**
 * Governed File-Grant v1 -- real POSIX filesystem operations (build spec
 * section 4).
 *
 * This is the ONLY module in file-grant/ that touches the real filesystem or
 * reads the agent-origin descriptor. Every other module (planner, lifecycle,
 * mint, revoke, list) takes an injected `FsOps` and is tested with a fake;
 * this implementation is what production wiring passes in.
 *
 * ENFORCEMENT HONESTY (Invariant #5, build spec section 4): POSIX ownership
 * only confines the agent when the agent runs as its OWN dedicated uid
 * (`castle-wall/allowlist/agent-origin.ts`'s uid-mode descriptor), distinct
 * from the operator's uid. On a same-uid box there is nothing to enforce --
 * `agentUid()` returns null (or a uid equal to the operator's), and
 * `mint.ts` reports `enforcement: "unmet"` rather than claiming the grant is
 * governed.
 *
 * TRAVERSAL NOTE: for the per-agent subtree's restrictive ownership to
 * actually confine the agent uid on disk, every ancestor directory up to the
 * tree root needs execute ("traverse") permission for that uid, while the
 * per-agent leaf directory stays owned and mode-restricted to only that uid.
 * `ensureTreeRoot` sets the root to `0711` (owner rwx, group/other --x) for
 * exactly that reason: it is traversable but not listable/writable by
 * anyone except the operator. Actually chowning a leaf to a DIFFERENT uid
 * than the current process requires root (or CAP_CHOWN); on a real
 * dedicated-uid box this mint path is expected to run with that privilege.
 * A same-uid box never attempts the cross-uid chown at all (there is no
 * different uid to chown to). Full on-hardware validation of this ownership
 * boundary is the separate, later Erik-present acceptance drill (build spec
 * section 8) -- this module ships the mechanism, not that proof.
 */

import { mkdir, lstat, readFile, realpath as fsRealpath, rm, symlink } from "node:fs/promises";
import { chownSync } from "node:fs";
import { dirname, join } from "node:path";
import { validateAgentOrigin } from "../castle-wall/allowlist/agent-origin.js";
import type { FsOps } from "./types.js";

const GRANT_TREE_DIR_NAME = "grants";
/** Root: traversable (x) by anyone so a chowned per-agent leaf below it stays reachable, but not listable/writable by non-owners. */
const TREE_ROOT_MODE = 0o711;
/** Per-agent leaf: readable/traversable ONLY by its owner. */
const AGENT_SUBDIR_MODE = 0o700;

function agentOriginDescriptorPath(fortressPath: string): string {
  return join(fortressPath, "policy", "egress", "agent-origin.json");
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
  constructor(private readonly fortressPath: string) {}

  private treeRoot(): string {
    return join(this.fortressPath, GRANT_TREE_DIR_NAME);
  }

  private async ensureTreeRoot(): Promise<void> {
    await mkdir(this.treeRoot(), { recursive: true, mode: TREE_ROOT_MODE });
  }

  async realpath(path: string): Promise<string> {
    return fsRealpath(path);
  }

  async place(canonicalSrc: string, relativeTreeEntry: string): Promise<void> {
    await this.ensureTreeRoot();
    const dest = join(this.treeRoot(), relativeTreeEntry);
    const agentSubdir = dirname(dest);
    await mkdir(agentSubdir, { recursive: true, mode: AGENT_SUBDIR_MODE });

    // Best-effort restrict the per-agent subdirectory to the dedicated agent
    // uid when one is configured and distinct from the process's own uid.
    // chownSync to a DIFFERENT uid than the current process requires root;
    // an EPERM here is a real fail-closed signal (mint.ts rolls back on
    // any throw from place()), never silently swallowed.
    const originPath = agentOriginDescriptorPath(this.fortressPath);
    const agentUid = await this.readConfiguredAgentUid(originPath);
    const operatorUid = process.getuid?.() ?? null;
    if (agentUid !== null && operatorUid !== null && agentUid !== operatorUid) {
      chownSync(agentSubdir, agentUid, -1);
    }

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

  async removeEntry(relativeTreeEntry: string): Promise<void> {
    const dest = join(this.treeRoot(), relativeTreeEntry);
    try {
      const st = await lstat(dest);
      if (st) {
        await rm(dest, { force: true });
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return;
      throw err;
    }
  }

  async agentUid(_subjectAgentId: string): Promise<number | null> {
    return this.readConfiguredAgentUid(agentOriginDescriptorPath(this.fortressPath));
  }

  async operatorUid(): Promise<number | null> {
    return process.getuid?.() ?? null;
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
}
