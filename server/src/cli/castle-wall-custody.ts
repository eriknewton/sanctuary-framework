/**
 * `sudo sanctuary castle-wall repair-custody` (fortress-ownership spec
 * 2026-07-30 §4(a1)) -- hand a root-owned fortress back to the operator.
 *
 * WHY: the first real install (Mini2, 2026-07-27) left `~/.sanctuary` owned
 * by `root:staff`, which bricked every OPERATOR-side surface (status stuck at
 * `undetermined:connect EACCES`, the `disable` dead-man lever unable to
 * reach `castle.sock`, the operator unable to `ls` their own state) while
 * root-side enforcement kept working. This verb ships the repair as a
 * tested, reusable product surface instead of a bespoke shell script.
 *
 * Behavior (spec steps 1-5, exactly):
 *   1. Resolve the operator FAIL-CLOSED from SUDO_UID/SUDO_GID (the shared
 *      R2/G4 chokepoint; a root sudo shell refuses).
 *   2. Observe first, versioned, never clobber: every entry's uid/gid/mode
 *      goes to a timestamped manifest OUTSIDE the fortress
 *      (`/Library/Application Support/Sanctuary/custody-repair/<ts>.json`,
 *      root-owned); a re-run writes a NEW file. No manifest, no mutation.
 *   3. lchown-semantics chown of ROOT-owned entries only to operator
 *      uid:gid; restore 0700 on the fortress dir / 0600 on castle.sock only
 *      where deviant; SKIP and report entries owned by any other uid.
 *      A vanished entry (live root daemon deleting transient lock files
 *      mid-walk; observed on hardware 2026-07-30) is a skip-and-note.
 *   4. Idempotent, with exit codes distinguishing changed (0) /
 *      already-clean (3) / refused (2) / failed (1).
 *   5. `--rollback <manifest>` replays the recorded ownership exactly.
 *
 * Never reads or logs key material: manifests and reports carry METADATA
 * only (paths, uid/gid/mode). Never widens the socket mode or moves its
 * path. The trust-anchor dir stays root:wheel (it is outside the fortress
 * and never walked).
 */

import { execFile as nodeExecFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { Writable } from "node:stream";
import { promisify } from "node:util";

import {
  applyCustodyRollback,
  applyFortressCustodyRepairs,
  CUSTODY_REPAIR_MANIFEST_DIR,
  CUSTODY_REPAIR_MANIFEST_KIND,
  manifestCarriesPrivilegeBits,
  parseCustodyRepairManifest,
  planFortressCustodyRepairs,
  realFortressCustodyFsOps,
  resolveSudoIdentityDecision,
  walkFortressCustody,
  writeCustodyRepairManifest,
  type CustodyApplyResult,
  type CustodyRepairManifest,
  type FortressCustodyFsOps,
  type FortressWalkResult,
} from "../castle-wall/provision/fortress-custody.js";
import { appendCastleWallCliAuditBestEffort } from "./castle-wall.js";

const execFileAsync = promisify(nodeExecFile);

/** Exit-code contract (spec step 4). */
export const REPAIR_CUSTODY_EXIT_CHANGED = 0;
export const REPAIR_CUSTODY_EXIT_FAILED = 1;
export const REPAIR_CUSTODY_EXIT_REFUSED = 2;
export const REPAIR_CUSTODY_EXIT_ALREADY_CLEAN = 3;

export interface RepairCustodyContext {
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  getuid?: () => number;
  /** Filesystem seam (tests simulate root-owned / vanishing entries). */
  fsOps?: FortressCustodyFsOps;
  /** Manifest directory override (tests; production uses the root-owned default). */
  manifestDir?: string;
  /** Manifest writer override (tests capture without touching /Library). */
  writeManifest?: (
    manifest: CustodyRepairManifest,
    dir: string,
  ) => Promise<string>;
  /** Operator-home lookup override (tests avoid dscl). */
  lookupOperatorHome?: (user: string) => Promise<string | undefined>;
  /**
   * Manifest-provenance stat override (tests cannot mint a root-owned
   * manifest). Defaults to `fs.lstat`.
   */
  statManifest?: (path: string) => Promise<{
    isFile(): boolean;
    isSymbolicLink(): boolean;
    uid: number;
    mode: number;
  }>;
  /**
   * Manifest reader override (tests cannot mint a root-owned manifest, and
   * the production reader re-verifies root ownership on its own descriptor).
   * Defaults to {@link readManifestBytesNoFollow}.
   */
  readManifestFile?: (path: string) => Promise<string>;
  /**
   * Best-effort audit append override (tests avoid real master-key
   * resolution). Defaults to {@link appendCastleWallCliAuditBestEffort}.
   */
  appendAudit?: typeof appendCastleWallCliAuditBestEffort;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

/**
 * Read a rollback manifest through ONE `O_NOFOLLOW` descriptor, re-verifying
 * root ownership and the not-group/other-writable bits on that descriptor
 * before reading. Closes the check-then-use race a stat-then-`readFile` pair
 * leaves open on a file that drives root chown/chmod.
 */
async function readManifestBytesNoFollow(path: string): Promise<string> {
  const handle = await open(
    path,
    fsConstants.O_RDONLY |
      (typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0),
  );
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) {
      throw new Error("manifest is not a regular file");
    }
    if (stats.uid !== 0) {
      throw new Error(`manifest is owned by uid ${stats.uid}, not root`);
    }
    if ((stats.mode & 0o022) !== 0) {
      throw new Error("manifest is group- or world-writable");
    }
    return await handle.readFile("utf8");
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function defaultLookupOperatorHome(user: string): Promise<string | undefined> {
  try {
    const result = await execFileAsync(
      "/usr/bin/dscl",
      [".", "-read", `/Users/${user}`, "NFSHomeDirectory"],
      { encoding: "utf8", timeout: 5_000 },
    );
    const match = /NFSHomeDirectory:\s*(\S+)/.exec(String(result.stdout ?? ""));
    return match?.[1];
  } catch {
    return undefined;
  }
}

interface ParsedRepairCustodyArgs {
  fortress?: string;
  rollback?: string;
  unknown?: string;
}

export function parseRepairCustodyArgs(argv: string[]): ParsedRepairCustodyArgs {
  const parsed: ParsedRepairCustodyArgs = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--fortress") {
      parsed.fortress = argv[++i];
    } else if (arg === "--rollback") {
      parsed.rollback = argv[++i];
    } else {
      parsed.unknown = arg;
      return parsed;
    }
  }
  return parsed;
}

function describeApply(result: CustodyApplyResult, out: Writable): void {
  for (const path of result.vanished) {
    write(out, `  note: ${path} vanished mid-repair (live daemon churn); skipped.\n`);
  }
  for (const path of result.identityChanged) {
    write(
      out,
      `  note: ${path} changed identity between observe and apply; skipped (re-run to repair it).\n`,
    );
  }
  for (const failure of result.failed) {
    write(out, `  FAILED: ${failure.path}: ${failure.reason}\n`);
  }
}

/**
 * Entry point for `sanctuary castle-wall repair-custody [--fortress <path>]
 * [--rollback <manifest>]`.
 */
export async function runRepairCustody(
  argv: string[] = [],
  ctx: RepairCustodyContext = {},
): Promise<number> {
  const out = ctx.out ?? process.stdout;
  const err = ctx.err ?? process.stderr;
  const env = ctx.env ?? process.env;
  const platform = ctx.platform ?? process.platform;
  const getuid = ctx.getuid ?? process.getuid?.bind(process);
  const ops = ctx.fsOps ?? realFortressCustodyFsOps();

  if (platform !== "darwin") {
    write(err, "castle-wall repair-custody is macOS-only today.\n");
    return REPAIR_CUSTODY_EXIT_REFUSED;
  }

  const parsed = parseRepairCustodyArgs(argv);
  if (parsed.unknown !== undefined) {
    write(
      err,
      `Unknown argument: ${parsed.unknown}. Usage: sudo sanctuary castle-wall repair-custody [--fortress <path>] [--rollback <manifest>]\n`,
    );
    return REPAIR_CUSTODY_EXIT_REFUSED;
  }

  if (getuid?.() !== 0) {
    write(
      err,
      "repair-custody must run as root (it hands root-owned fortress entries back to the operator). Re-run: sudo sanctuary castle-wall repair-custody\n",
    );
    return REPAIR_CUSTODY_EXIT_REFUSED;
  }

  // Step 1: fail-closed operator resolution (shared R2/G4 chokepoint). A raw
  // root shell (SUDO_UID=0 or no SUDO env) refuses: root is never a valid
  // fortress owner and this verb never guesses.
  const identity = resolveSudoIdentityDecision(env);
  if (identity === undefined) {
    write(
      err,
      "Could not determine the operator account under sudo (SUDO_UID/SUDO_GID unset, malformed, or a root shell); refusing to repair.\n" +
        "Run 'sudo sanctuary castle-wall repair-custody' from the operator's own shell, not from a root shell.\n",
    );
    return REPAIR_CUSTODY_EXIT_REFUSED;
  }

  // Fortress resolution: explicit flag, env override, else the OPERATOR's
  // home (never root's).
  let fortressPath = parsed.fortress ?? env.SANCTUARY_STORAGE_PATH;
  if (fortressPath === undefined || fortressPath.length === 0) {
    if (identity.user === undefined) {
      write(
        err,
        "Cannot resolve the operator home (SUDO_USER unset): pass --fortress <path> explicitly.\n",
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    const lookup = ctx.lookupOperatorHome ?? defaultLookupOperatorHome;
    const home = await lookup(identity.user);
    if (home === undefined) {
      write(
        err,
        `Cannot resolve ${identity.user}'s home directory: pass --fortress <path> explicitly.\n`,
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    fortressPath = `${home.replace(/\/+$/, "")}/.sanctuary`;
  }
  if (!isAbsolute(fortressPath)) {
    write(err, `Fortress path must be absolute (got: ${fortressPath}).\n`);
    return REPAIR_CUSTODY_EXIT_REFUSED;
  }
  fortressPath = resolve(fortressPath);

  // ── Rollback mode ──
  if (parsed.rollback !== undefined) {
    const manifestDir = ctx.manifestDir ?? CUSTODY_REPAIR_MANIFEST_DIR;
    // PROVENANCE GATE (2026-07-31 gate BLOCKER-2): rollback applies
    // file-controlled uid/gid/mode AS ROOT, so it accepts ONLY a manifest
    // this verb itself wrote: inside the root-owned manifest directory, a
    // regular file (never a symlink), owned by root, not group/other
    // writable. Without this, any readable JSON became a root chown/chmod
    // primitive.
    const rollbackPath = resolve(parsed.rollback);
    if (dirname(rollbackPath) !== resolve(manifestDir)) {
      write(
        err,
        `Refusing rollback: ${rollbackPath} is not inside the root-owned manifest directory ${manifestDir}.\n` +
          "Only manifests written by 'repair-custody' itself can be replayed.\n",
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    let manifestStats;
    try {
      manifestStats = await (ctx.statManifest ?? lstat)(rollbackPath);
    } catch (error) {
      write(
        err,
        `Cannot read rollback manifest ${rollbackPath}: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return REPAIR_CUSTODY_EXIT_FAILED;
    }
    if (!manifestStats.isFile() || manifestStats.isSymbolicLink()) {
      write(err, `Refusing rollback: ${rollbackPath} is not a regular file.\n`);
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    if (manifestStats.uid !== 0) {
      write(
        err,
        `Refusing rollback: ${rollbackPath} is owned by uid ${manifestStats.uid}, not root. A non-root-owned manifest is not trustworthy input for a root chown.\n`,
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    if ((manifestStats.mode & 0o022) !== 0) {
      write(
        err,
        `Refusing rollback: ${rollbackPath} is group- or world-writable (mode ${(manifestStats.mode & 0o7777).toString(8)}).\n`,
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }

    // Read from the SAME descriptor the provenance was checked on. A
    // stat-then-readFile pair is a check-then-use race: the manifest could be
    // swapped between the root-ownership check and the read, and this file
    // drives root chown/chmod. `readManifestBytes` re-verifies uid/mode on
    // the open fd and reads through it, so no swap can slip between them.
    let raw: string;
    try {
      raw = await (ctx.readManifestFile ?? readManifestBytesNoFollow)(rollbackPath);
    } catch (error) {
      write(
        err,
        `Cannot read rollback manifest ${rollbackPath}: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return REPAIR_CUSTODY_EXIT_FAILED;
    }
    const manifest = parseCustodyRepairManifest(raw);
    if (manifest === null) {
      write(
        err,
        `Refusing rollback: ${rollbackPath} is not a valid ${CUSTODY_REPAIR_MANIFEST_KIND} manifest.\n`,
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    if (manifestCarriesPrivilegeBits(manifest)) {
      write(
        err,
        `Refusing rollback: ${rollbackPath} records setuid/setgid/sticky bits. A fortress entry never legitimately carries them, and replaying one as root would create a privileged binary.\n`,
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    if (resolve(manifest.fortress_path) !== fortressPath) {
      write(
        err,
        `Refusing rollback: the manifest records fortress ${manifest.fortress_path}, but this run targets ${fortressPath}.\n`,
      );
      return REPAIR_CUSTODY_EXIT_REFUSED;
    }
    const result = await applyCustodyRollback(fortressPath, manifest, ops);
    describeApply(result, out);
    if (result.failed.length > 0 || result.identityChanged.length > 0) {
      write(
        err,
        `Rollback incomplete: ${
          result.failed.length + result.identityChanged.length
        } entries could not be restored (see above).\n`,
      );
      return REPAIR_CUSTODY_EXIT_FAILED;
    }
    if (result.repaired.length === 0) {
      write(out, "Rollback: nothing to restore; on-disk ownership already matches the manifest.\n");
      return REPAIR_CUSTODY_EXIT_ALREADY_CLEAN;
    }
    // Audit (best-effort, metadata only). No custody sweep afterwards: a
    // rollback deliberately restores whatever ownership the manifest records,
    // including root ownership.
    await (ctx.appendAudit ?? appendCastleWallCliAuditBestEffort)(
      "fortress_custody_rollback",
      {
        source: "castle-wall-cli",
        manifest_path: parsed.rollback,
        restored: result.repaired.length,
        vanished: result.vanished.length,
        identity_changed: result.identityChanged.length,
      },
      fortressPath,
      env,
      err,
    );
    write(
      out,
      `Rollback complete: ${result.repaired.length} entries restored to the recorded ownership from ${parsed.rollback}.\n`,
    );
    return REPAIR_CUSTODY_EXIT_CHANGED;
  }

  // ── Repair mode ──
  // Step 2: observe first. The walk records every entry's uid/gid/mode; a
  // failure to persist the manifest aborts BEFORE any mutation.
  let walk: FortressWalkResult;
  try {
    walk = await walkFortressCustody(fortressPath, ops);
  } catch (error) {
    const code =
      error instanceof Error && "code" in error
        ? (error as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT" || code === "ENOTDIR") {
      write(out, `No fortress exists at ${fortressPath}; nothing to repair.\n`);
      return REPAIR_CUSTODY_EXIT_ALREADY_CLEAN;
    }
    write(
      err,
      `Refusing to repair: could not observe the fortress at ${fortressPath} (${error instanceof Error ? error.message : String(error)}).\n`,
    );
    return REPAIR_CUSTODY_EXIT_REFUSED;
  }

  const manifest: CustodyRepairManifest = {
    version: 1,
    kind: CUSTODY_REPAIR_MANIFEST_KIND,
    generated_at: new Date().toISOString(),
    fortress_path: fortressPath,
    operator: { uid: identity.uid, gid: identity.gid },
    entries: walk.entries,
    vanished: walk.vanished,
  };
  const writeManifest = ctx.writeManifest ?? writeCustodyRepairManifest;
  let manifestPath: string;
  try {
    manifestPath = await writeManifest(
      manifest,
      ctx.manifestDir ?? CUSTODY_REPAIR_MANIFEST_DIR,
    );
  } catch (error) {
    write(
      err,
      `Refusing to repair: could not persist the observe manifest (${error instanceof Error ? error.message : String(error)}). ` +
        "Observe-first is a hard precondition; nothing was mutated.\n",
    );
    return REPAIR_CUSTODY_EXIT_REFUSED;
  }
  write(out, `Observe manifest written: ${manifestPath} (${walk.entries.length} entries).\n`);

  // Step 3: plan + apply.
  const plan = planFortressCustodyRepairs(walk.entries, {
    uid: identity.uid,
    gid: identity.gid,
  });
  for (const skip of plan.skips) {
    write(
      out,
      `  skipped: ${skip.path} is owned by uid ${skip.uid} (neither root nor operator ${identity.uid}); left untouched.\n`,
    );
  }
  for (const path of walk.vanished) {
    write(out, `  note: ${path} vanished mid-walk (live daemon churn); skipped.\n`);
  }

  for (const deviation of plan.socketModeDeviations) {
    write(
      out,
      `  note: ${deviation.path} has mode ${deviation.mode.toString(8)} (canonical is 600). A socket cannot be repaired safely by path; restart the Castle Wall daemon to rebind it with the canonical mode.\n`,
    );
  }

  if (plan.actions.length === 0) {
    // 2026-07-31 gate round 3 (MED): "every entry is operator-owned" was an
    // OVERCLAIM whenever entries were skipped for foreign ownership or a
    // socket mode deviated. State exactly what was and was not done.
    const caveats = plan.skips.length + plan.socketModeDeviations.length;
    write(
      out,
      caveats === 0
        ? `Already clean: every entry under ${fortressPath} is operator-owned with canonical modes; nothing changed.\n`
        : `Nothing to repair under ${fortressPath}: no root-owned entries remain. ${caveats} entr${
            caveats === 1 ? "y was" : "ies were"
          } left untouched and reported above (foreign owner or socket mode); this verb cannot and does not repair those.\n`,
    );
    return REPAIR_CUSTODY_EXIT_ALREADY_CLEAN;
  }

  const applied = await applyFortressCustodyRepairs(fortressPath, plan, ops);
  describeApply(applied, out);
  if (applied.failed.length > 0) {
    write(
      err,
      `Repair incomplete: ${applied.failed.length} entries failed (see above). Rollback: sudo sanctuary castle-wall repair-custody --rollback ${manifestPath}\n`,
    );
    return REPAIR_CUSTODY_EXIT_FAILED;
  }
  // 2026-07-31 gate LOW: an entry skipped because its inode or an ancestor
  // changed under us is NOT repaired, so the fortress still holds root-owned
  // entries. Reporting success there would be the "green without positive
  // evidence" shape. Exit FAILED and name the re-run.
  if (applied.identityChanged.length > 0) {
    write(
      err,
      `Repair incomplete: ${applied.identityChanged.length} entr${
        applied.identityChanged.length === 1 ? "y" : "ies"
      } changed identity (or had an ancestor change) between observe and apply and were NOT repaired (see above). ` +
        "Re-run 'sudo sanctuary castle-wall repair-custody' once the fortress is quiescent.\n",
    );
    return REPAIR_CUSTODY_EXIT_FAILED;
  }
  // Audit (best-effort, metadata only: counts + manifest path, never contents
  // or key material). Written AS ROOT into the just-repaired fortress, so a
  // follow-up sweep hands any freshly minted root-owned audit files straight
  // back to the operator (same walk/plan/apply semantics; loud on failure).
  await (ctx.appendAudit ?? appendCastleWallCliAuditBestEffort)(
    "fortress_custody_repaired",
    {
      source: "castle-wall-cli",
      manifest_path: manifestPath,
      repaired: applied.repaired.length,
      skipped_foreign_owner: plan.skips.length,
      vanished: walk.vanished.length + applied.vanished.length,
      identity_changed: applied.identityChanged.length,
      operator_uid: identity.uid,
    },
    fortressPath,
    env,
    err,
  );
  try {
    const sweepWalk = await walkFortressCustody(fortressPath, ops);
    const sweepPlan = planFortressCustodyRepairs(sweepWalk.entries, {
      uid: identity.uid,
      gid: identity.gid,
    });
    if (sweepPlan.actions.length > 0) {
      const swept = await applyFortressCustodyRepairs(fortressPath, sweepPlan, ops);
      // 2026-07-31 re-gate LOW: the sweep's own failures used to be dropped
      // on the floor, so an audit write that minted root-owned state the
      // sweep could not repair still exited success. Surface it and downgrade
      // the exit code -- never report a clean repair over known residue.
      if (swept.failed.length > 0 || swept.identityChanged.length > 0) {
        describeApply(swept, out);
        write(
          err,
          "Repair incomplete: the post-audit custody sweep could not hand every freshly written entry back to the operator (see above). " +
            "Re-run 'sudo sanctuary castle-wall repair-custody' once the fortress is quiescent.\n",
        );
        return REPAIR_CUSTODY_EXIT_FAILED;
      }
    }
  } catch (error) {
    write(
      err,
      `Warning: the post-audit custody sweep failed (${error instanceof Error ? error.message : String(error)}); re-run repair-custody if operator surfaces still report EACCES.\n`,
    );
  }
  write(
    out,
    `Repaired ${applied.repaired.length} entries under ${fortressPath}: root-owned entries handed to operator uid ${identity.uid}:${identity.gid}; fortress dir 0700 restored where deviant. Deviant castle.sock modes are reported and repaired when the daemon rebinds the socket.\n`,
  );
  write(
    out,
    `Rollback (replays the recorded ownership exactly): sudo sanctuary castle-wall repair-custody --rollback ${manifestPath}\n`,
  );
  return REPAIR_CUSTODY_EXIT_CHANGED;
}
