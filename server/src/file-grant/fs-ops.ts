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
 * DEFERRED FUNCTIONAL PRIMITIVE (v1 = build-spec option B, honest label):
 * conferring cross-uid read on a distinct agent uid needs a real primitive
 * (POSIX.1e ACL via `setfacl`, or a cross-uid chown) AND a readability probe
 * to confirm it, and BOTH are host-specific in ways that cannot be applied or
 * verified in autonomous CI: `setfacl` semantics diverge between Linux and
 * macOS (macOS has no `setfacl`; its ACL model is entirely different), a
 * cross-uid chown requires root/CAP_CHOWN, and verifying "the agent uid can
 * read the placed entry" requires reading AS that uid (a second uid or root
 * `seteuid`). None of those are available to a non-root, single-uid CI run.
 * So v1 ships the RECORDS + the tree placement + the honest label: a real uid
 * split reports `enforcement: "unverified"` ("configured; on-hardware
 * read-scope not yet verified"), NEVER `met`. Applying the ACL primitive and
 * running the agent-uid readability probe is the separate Erik-present
 * acceptance drill (build spec section 8), where `met` is produced. This
 * module therefore never claims read access it has not verified.
 *
 * TRAVERSAL NOTE: `ensureTreeRoot` sets the root to `0711` (owner rwx,
 * group/other --x) so a future chowned per-agent leaf stays reachable while
 * the root itself is not listable by non-owners. NOTE the root currently
 * lives under the operator fortress (`<fortressPath>/grants/`); relocating it
 * to a fully agent-traversable path is part of the same deferred drill-build,
 * and until then the `unverified` label is what keeps v1 honest.
 */

import { mkdir, lstat, readFile, realpath as fsRealpath, rm, stat, symlink } from "node:fs/promises";
import { chownSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
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

  /**
   * Resolve a relative tree-entry to an absolute path and REJECT it unless it
   * stays strictly under the tree root. Defence in depth behind the mint-level
   * agent-id slug check (`isSafeFileGrantAgentId`): a `..`-bearing entry (or a
   * symlinked/absolute component) must never let a placement or scrub touch a
   * path outside the grant tree.
   */
  private resolveUnderRoot(relativeTreeEntry: string): string {
    const root = resolve(this.treeRoot());
    const dest = resolve(root, relativeTreeEntry);
    if (dest !== root && !dest.startsWith(root + sep)) {
      throw new Error(
        `Governed File-Grant: tree entry "${relativeTreeEntry}" escapes the ` +
          `grant-tree root; refusing to touch a path outside the tree.`
      );
    }
    return dest;
  }

  async realpath(path: string): Promise<string> {
    return fsRealpath(path);
  }

  async place(canonicalSrc: string, relativeTreeEntry: string): Promise<void> {
    const dest = this.resolveUnderRoot(relativeTreeEntry);
    await this.ensureTreeRoot();
    const agentSubdir = dirname(dest);
    await mkdir(agentSubdir, { recursive: true, mode: AGENT_SUBDIR_MODE });

    // Best-effort restrict the per-agent subdirectory to the dedicated agent
    // uid when one is configured and distinct from the running PROCESS uid
    // (this is chown MECHANICS -- "does this process need to hand the subdir
    // to another uid" -- not the enforcement-honesty check, which lives in
    // `mint.ts` and compares the agent uid to the SOURCE file's owner).
    //
    // Handing the subdir to a DIFFERENT uid needs privilege (root / CAP_CHOWN).
    // A NON-root operator mint would otherwise EPERM here and roll the whole
    // grant back (R2-5) -- which is wrong: v1 must still RECORD the grant + place
    // the symlink on a real uid-split box even when it cannot apply the
    // ownership primitive. The enforcement label is already the honest
    // `unverified` ("configured; primitive not applied", build spec section 10),
    // never `met`, so skipping the chown does not overclaim. So PRIVILEGE-GATE
    // it: attempt the chown only when running as root, and even then treat an
    // EPERM (restricted container / userns without CAP_CHOWN) as "primitive not
    // applied" rather than a fatal mint failure. Any OTHER chown error is
    // unexpected and stays fatal (fail-closed), as do all other `place` errors
    // (mkdir / symlink).
    const originPath = agentOriginDescriptorPath(this.fortressPath);
    const agentUid = await this.readConfiguredAgentUid(originPath);
    const processUid = process.getuid?.() ?? null;
    if (
      agentUid !== null &&
      processUid !== null &&
      agentUid !== processUid &&
      processUid === 0
    ) {
      try {
        chownSync(agentSubdir, agentUid, -1);
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code !== "EPERM") throw err;
        // EPERM even as root: primitive not applied; the honest `unverified`
        // enforcement label already reflects that, so do not fail the mint.
      }
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
    const dest = this.resolveUnderRoot(relativeTreeEntry);
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
}
