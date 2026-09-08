/**
 * Secret disclosure (Finding U + Finding X / v1.1.1 + v1.1.3 hotfixes)
 *
 * Two operator-trust surfaces share this module:
 *   1. Recovery key disclosure (Finding U, v1.1.1) on `sanctuary init`. The
 *      master key on init is random; the operator's only path to fortress
 *      recovery on principal loss is the recovery key generated at first run.
 *   2. Passphrase disclosure (Finding X, v1.1.3) on `sanctuary wrap` when
 *      Sanctuary generated the passphrase itself. The wrap path derives the
 *      master key purely from the passphrase via Argon2id, so the generated
 *      passphrase is the secret-of-last-resort. User-supplied passphrase
 *      (`--passphrase` flag, `SANCTUARY_PASSPHRASE` env) skips disclosure;
 *      the operator already holds the secret.
 *
 * Both surfaces are three-pronged:
 *   1. Print the FULL secret in a bordered banner on stderr (no truncation).
 *   2. Write the plaintext to <storage>/<filename> mode 0600 with explicit
 *      "move off-host immediately" instructions. Single-issuance: never
 *      overwrite an existing file.
 *   3. Optionally prompt the operator to confirm they have saved the secret.
 *      Skippable via mode "no-confirm" / "stdio-server" for CI / scripted use.
 *
 * Common code paths that reach disclosure:
 *   - server/src/index.ts (MCP server stdio first-run, recovery key)
 *   - server/src/dashboard-standalone.ts (standalone dashboard first-run, recovery key)
 *   - server/src/wrap/init.ts (sanctuary init subcommand, recovery key)
 *   - server/src/wrap/cli.ts (sanctuary wrap, generated passphrase only)
 */

import {
  constants,
  lstatSync,
  readlinkSync,
  realpathSync,
  statSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { access, link, lstat, mkdir, open, readdir, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline/promises";

export const RECOVERY_KEY_FILENAME = "recovery-key.txt";
export const PASSPHRASE_BACKUP_FILENAME = "passphrase-backup.txt";
export const RECOVERY_OUT_ENV_VAR = "SANCTUARY_RECOVERY_OUT";

/**
 * Basename of the ONE directory Sanctuary itself owns for staged recovery
 * material: the parent of `agentGuidedRecoveryOutputPath`.
 *
 * Must match `agentGuidedRecoveryOutputPath` in
 * server/src/wrap/custody-flow.ts, which builds the staging path from this
 * constant. The name lives here because the preflight below is the only site
 * that is allowed to CHANGE a directory's mode, and it may only do that to a
 * directory Sanctuary created or to this one; an operator-chosen destination
 * (a home directory, a Desktop) is inspected and refused, never rewritten.
 */
export const AGENT_GUIDED_RECOVERY_DIRNAME = "Sanctuary Recovery";

/**
 * Confirmation policy:
 *   - "interactive": prompt at TTY; on non-TTY without bypass, throw.
 *   - "no-confirm": skip prompt entirely (CI / scripted callers).
 *   - "stdio-server": skip prompt; intended for the MCP server stdio
 *     boot path where stdin is owned by the host harness. The file +
 *     banner are the durable disclosure for that path.
 */
export type DisclosureMode = "interactive" | "no-confirm" | "stdio-server";

export interface DisclosureIo {
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream;
}

interface SecretDisclosureCopy {
  /** Filename for the on-disk plaintext copy. */
  fileName: string;
  /** Banner header line, e.g. "SANCTUARY: First Run, Recovery Key Generated". */
  bannerHeader: string;
  /** Banner display label for the secret value, e.g. "Recovery Key" or "Passphrase". */
  bannerSecretLabel: string;
  /** Banner save-imperative line, e.g. "SAVE THIS KEY. It will not be shown again.". */
  bannerSaveLine: string;
  /** Banner consequence-of-loss line. */
  bannerLossLine: string;
  /** File-level all-caps warning header. */
  fileWarningHeader: string;
  /** File-body label preceding the secret value, e.g. "Recovery key:" or "Passphrase:". */
  fileSecretLabel: string;
  /** File-body paragraph after the secret value. */
  fileBody: string;
  /** Inline phrasing for the confirm prompt, e.g. "recovery key" or "passphrase". */
  promptLabel: string;
}

/**
 * Body paragraph of the plaintext recovery-key file, as lines.
 *
 * ONE source, not a mirrored literal: `assertRecoveryResidueContent` in
 * server/src/storage/fresh-fortress.ts must recognize this exact text before
 * it will delete a crash-residue recovery file, so a body that changed on one
 * side and not the other turns every interrupted init into an uncleanable
 * fortress. It imports this constant rather than restating it.
 *
 * The destination is whatever the banner named: `sanctuary init` always writes
 * this file OUTSIDE the fortress, so the body may not tell the operator to
 * look in the fortress directory for it.
 */
export const RECOVERY_KEY_FILE_BODY_LINES = [
  "This file was created when this recovery key was generated. Sanctuary will NOT",
  "regenerate it on later runs and will NOT display the key again. After moving it",
  "off this host (encrypted backup, password manager, paper safe), delete this",
  "file. Never keep it inside the fortress directory it protects; the recovery key",
  "bypasses the fortress passphrase by design.",
] as const;

const RECOVERY_KEY_COPY: SecretDisclosureCopy = {
  fileName: RECOVERY_KEY_FILENAME,
  bannerHeader: "SANCTUARY: First Run, Recovery Key Generated",
  bannerSecretLabel: "Recovery Key",
  bannerSaveLine: "SAVE THIS KEY. It will not be shown again.",
  bannerLossLine: "Without it, your encrypted state is unrecoverable.",
  fileWarningHeader:
    "SANCTUARY RECOVERY KEY, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.",
  fileSecretLabel: "Recovery key:",
  fileBody: `${RECOVERY_KEY_FILE_BODY_LINES.join("\n")}\n`,
  promptLabel: "recovery key",
};

const PASSPHRASE_BACKUP_COPY: SecretDisclosureCopy = {
  fileName: PASSPHRASE_BACKUP_FILENAME,
  bannerHeader: "SANCTUARY: First Run, Passphrase Generated",
  bannerSecretLabel: "Passphrase",
  bannerSaveLine:
    "SAVE THIS PASSPHRASE. It will not be shown again.",
  bannerLossLine: "Without it, your encrypted state is unrecoverable.",
  fileWarningHeader:
    "SANCTUARY PASSPHRASE, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.",
  fileSecretLabel: "Passphrase:",
  fileBody:
    "This file was created on first wrap when Sanctuary generated the passphrase.\n" +
    "Sanctuary will NOT regenerate this file on subsequent runs and will NOT display\n" +
    "the passphrase again. After moving this file off the host (encrypted backup,\n" +
    "password manager, paper safe), delete it from the fortress directory. Do NOT\n" +
    "keep it in the fortress; the keychain copy is recoverable only while the host\n" +
    "and its OS keyring are intact.\n",
  promptLabel: "passphrase",
};

/**
 * v1.1.1 (Finding U) error: operator answered "n" to the recovery-key
 * confirmation prompt. Callers should treat this as a hard refusal: the
 * fortress state should be rolled back and the process should exit non-zero.
 */
export class RecoveryKeyConfirmationDeclinedError extends Error {
  constructor() {
    super(
      "Recovery key confirmation declined. " +
        "Save the recovery key (printed above, and written to the file the banner " +
        "names) before re-running init."
    );
    this.name = "RecoveryKeyConfirmationDeclinedError";
  }
}

/**
 * v1.1.1 (Finding U) error: non-TTY stdin without --no-confirm bypass.
 * Callers exit non-zero with operator guidance.
 */
export class RecoveryKeyConfirmationNonInteractiveError extends Error {
  constructor() {
    super(
      "Recovery key confirmation requires an interactive terminal. " +
        "Re-run with --no-confirm for CI/scripted use, or run from a TTY."
    );
    this.name = "RecoveryKeyConfirmationNonInteractiveError";
  }
}

/**
 * Sovereign-custody build (F13): operator failed re-entry verification of
 * the recovery key. Callers treat this as a hard refusal, like the declined
 * error: the fortress holds nothing trust-bearing yet (the custody floor
 * guarantees it), so the operator can safely re-run init.
 */
export class RecoveryKeyReentryMismatchError extends Error {
  constructor() {
    super(
      "Recovery key re-entry did not match. " +
        "The key you save must be the exact key shown above — it is the only " +
        "thing that can recover this fortress. Save it, then re-run init."
    );
    this.name = "RecoveryKeyReentryMismatchError";
  }
}

export class RecoveryKeyOutputPathInsideFortressError extends Error {
  constructor(filePath: string, fortressPath: string) {
    super(
      "Recovery key output path must be outside the fortress directory.\n" +
        `Requested path: ${filePath}\n` +
        `Fortress path: ${fortressPath}`
    );
    this.name = "RecoveryKeyOutputPathInsideFortressError";
  }
}

export class RecoveryKeyOutputPathExistsError extends Error {
  constructor(filePath: string) {
    super(
      "refusing to reuse an existing --recovery-out file; " +
        "the new recovery key was NOT written; " +
        "choose a path that does not exist.\n" +
        `Requested path: ${filePath}`
    );
    this.name = "RecoveryKeyOutputPathExistsError";
  }
}

export class RecoveryKeyOutputPathSymlinkError extends Error {
  constructor(filePath: string) {
    super(
      "refusing to write the recovery key through a symlink.\n" +
        `Requested path: ${filePath}`
    );
    this.name = "RecoveryKeyOutputPathSymlinkError";
  }
}

function isPathInsideOrEqual(parentPath: string, candidatePath: string): boolean {
  const rel = relative(parentPath, candidatePath);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function caseFoldPathForContainment(path: string): string {
  return path.normalize("NFC").toLowerCase();
}

function resolveExistingSymlinkComponents(absPath: string, depth = 0): string {
  if (depth > 40) {
    throw new Error(`Too many symbolic links while resolving path: ${absPath}`);
  }

  const parsed = parse(absPath);
  const segments = absPath
    .slice(parsed.root.length)
    .split(/[\\/]+/)
    .filter((segment) => segment.length > 0);

  let current = parsed.root;
  for (let i = 0; i < segments.length; i++) {
    const next = resolve(current, segments[i]);
    try {
      const entry = lstatSync(next);
      if (entry.isSymbolicLink()) {
        const target = readlinkSync(next);
        const resolvedTarget = isAbsolute(target)
          ? target
          : resolve(dirname(next), target);
        return resolveExistingSymlinkComponents(
          resolve(resolvedTarget, ...segments.slice(i + 1)),
          depth + 1
        );
      }
      current = next;
    } catch (err) {
      if (isMissingPathError(err)) {
        return resolve(current, ...segments.slice(i));
      }
      throw err;
    }
  }

  return current;
}

function realpathAnchoredPathForContainment(path: string): string {
  const resolvedPath = resolveExistingSymlinkComponents(resolve(path));
  let ancestor = resolvedPath;

  while (true) {
    try {
      const entry = statSync(ancestor);
      if (entry.isDirectory()) {
        const rest = relative(ancestor, resolvedPath);
        return resolve(realpathSync(ancestor), rest);
      }
      ancestor = dirname(ancestor);
    } catch (err) {
      if (!isMissingPathError(err)) {
        throw err;
      }
      const parent = dirname(ancestor);
      if (parent === ancestor) {
        return resolvedPath;
      }
      ancestor = parent;
    }
  }
}

function assertPathOutsideFortress(filePath: string, fortressPath: string): void {
  const resolvedFile = resolve(filePath);
  const realTarget = realpathAnchoredPathForContainment(resolvedFile);
  const realFortress = realpathAnchoredPathForContainment(fortressPath);
  if (
    isPathInsideOrEqual(realFortress, realTarget) ||
    isPathInsideOrEqual(
      caseFoldPathForContainment(realFortress),
      caseFoldPathForContainment(realTarget)
    )
  ) {
    throw new RecoveryKeyOutputPathInsideFortressError(
      realTarget,
      realFortress
    );
  }
}

/**
 * Resolve an optional durable recovery-key output path. The env var is a
 * path, not a boolean: only an explicit non-empty path opts in.
 */
export function resolveRecoveryKeyOutputPath(opts: {
  recoveryOut?: string;
  storagePath: string;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
}): string | undefined {
  const flag = opts.recoveryOut?.trim();
  const envValue = opts.env?.[RECOVERY_OUT_ENV_VAR]?.trim();
  const raw = flag && flag.length > 0 ? flag : envValue;
  if (!raw || raw.length === 0) {
    return undefined;
  }

  const resolved = resolve(opts.cwd ?? process.cwd(), raw);
  assertPathOutsideFortress(resolved, opts.storagePath);
  return resolved;
}

/**
 * Best-effort early failure for operator-specified output locations. The
 * real write remains authoritative, but init/rotation call this before
 * mutating fortress state so unwritable destinations fail before custody
 * material is minted.
 */
export async function preflightRecoveryKeyOutputFile(
  filePath: string
): Promise<void> {
  try {
    const existing = await lstat(filePath);
    if (existing.isSymbolicLink()) {
      throw new RecoveryKeyOutputPathSymlinkError(filePath);
    }
    if (existing.isFile()) {
      throw new RecoveryKeyOutputPathExistsError(filePath);
    }
    throw new Error(
      `Recovery key output path exists but is not a file: ${filePath}`
    );
  } catch (err) {
    if (!isMissingPathError(err)) {
      throw err;
    }
    // File does not exist, ensure the parent can be created and written.
  }
  const parent = await prepareRecoveryOutputParent(filePath);
  await assertNoRecoveryOutputStages(filePath);
  await access(parent, constants.W_OK);
}

/**
 * Create (if needed) and validate the directory a recovery key is about to be
 * written into, and return it.
 *
 * ONE site decides whether the parent's mode may be CHANGED, because the
 * preflight and the authoritative write both have to reach the same answer:
 * a rule applied on one of the two is a rule an operator can route around.
 * The decision is made BEFORE `mkdir`, since afterwards a directory Sanctuary
 * minted one line ago and one the operator has kept for years look identical.
 */
async function prepareRecoveryOutputParent(filePath: string): Promise<string> {
  const parent = dirname(filePath);
  let parentExisted = true;
  try {
    await lstat(parent);
  } catch (err) {
    if (!isMissingPathError(err)) throw err;
    parentExisted = false;
  }
  await mkdir(parent, { recursive: true, mode: 0o700 });
  await assertRecoveryOutputParentSafe(parent, {
    // Sanctuary owns exactly two kinds of parent: one it just created, and its
    // own staging directory. Everything else belongs to the operator and is
    // inspected, never rewritten.
    mayTighten:
      !parentExisted || basename(parent) === AGENT_GUIDED_RECOVERY_DIRNAME,
  });
  return parent;
}

/**
 * The directory a plaintext recovery key is about to be written into must be
 * a real directory, owned by this process, and readable by nobody else.
 *
 * `mkdir(..., { recursive: true, mode: 0o700 })` guarantees none of that for a
 * directory that ALREADY exists: `mode` applies only to directories the call
 * creates, and `recursive: true` succeeds silently on an existing path,
 * including a symlink to somewhere else entirely. So a pre-existing
 * world-readable `Sanctuary Recovery/` (or one an attacker pre-created as a
 * link) was accepted as-is, and the 0600 file inside it sat under a directory
 * anyone could traverse.
 *
 * Rules, in the order they are applied:
 *   - a symlink or non-directory parent is REFUSED; there is no safe way to
 *     tighten one, and following it is how the key leaves its intended tree;
 *   - a parent owned by another uid is REFUSED (this covers the classic
 *     world-writable shared directory, e.g. `--recovery-out /tmp/key.txt`);
 *   - a parent that is group- or other-WRITABLE is REFUSED: another principal
 *     who can write the directory can replace the file after it lands;
 *   - a parent SANCTUARY OWNS (one this preflight just created, or the staging
 *     directory named by AGENT_GUIDED_RECOVERY_DIRNAME) that is group- or
 *     world-accessible is TIGHTENED to 0700 and re-checked.
 *
 * `mayTighten` is the whole point of the split, and it is a security property,
 * not a convenience: `--recovery-out ~/recovery-key.txt` makes the operator's
 * HOME the parent, and an earlier revision chmod'ed any owned parent with
 * group/other bits to 0700, so one flag silently relocked the operator's home
 * or Desktop with no rollback. A directory the operator chose is inspected and
 * refused when it is unsafe; only a directory Sanctuary itself minted is ours
 * to rewrite. A conventional 0755 home is accepted as-is: the key file is 0600
 * and a traversable-but-unwritable parent does not expose it.
 *
 * Mirrors the identity discipline `recoveryOutputParentIdentity` applies on
 * the rotation reconciliation path: same question, asked before the write
 * rather than after a crash.
 *
 * Failure mode from the outside: none of this is visible in a directory
 * listing after the fact, because the file itself is 0600 either way. The
 * exposure is the directory, and it looks completely normal.
 */
async function assertRecoveryOutputParentSafe(
  parent: string,
  opts: { mayTighten: boolean },
): Promise<void> {
  // Every check AND the mode change run against ONE directory descriptor, not
  // against the path: `lstat` then `chmod` is two lookups, and an attacker who
  // swaps the last component between them redirects the chmod onto a directory
  // of their choosing. O_NOFOLLOW | O_DIRECTORY refuses a symlinked or
  // non-directory last component at open time; fstat/fchmod on the resulting
  // fd cannot be redirected afterwards. Must match the no-follow directory
  // open in `openExistingDirectoryNoFollow`, server/src/storage/custody-fs.ts.
  const handle = await openRecoveryOutputParentNoFollow(parent);
  try {
    const before = await handle.stat();
    if (!before.isDirectory()) {
      throw new Error(
        `Recovery key output parent is not a stable directory: ${parent}`,
      );
    }
    const uid = process.getuid?.();
    if (uid !== undefined && before.uid !== uid) {
      throw new Error(
        `Recovery key output parent ${parent} is owned by uid ${before.uid}, not by this ` +
          `process (uid ${uid}); refusing to write a plaintext recovery key into a directory ` +
          "this account does not control. Choose a --recovery-out path under a directory you own.",
      );
    }
    // 0o077 = every group and other permission bit; 0o022 = the group-write and
    // other-write bits inside it. Anything in 0o077 means a principal other
    // than the owner can reach the directory; anything in 0o022 means they can
    // replace what is in it.
    if ((before.mode & 0o077) === 0) return;
    if (!opts.mayTighten) {
      if ((before.mode & 0o022) !== 0) {
        throw new Error(
          `Recovery key output parent ${parent} is writable by group or other ` +
            `(mode ${(before.mode & 0o777).toString(8)}); refusing to write a plaintext recovery ` +
            "key into a directory another account can replace files in. Sanctuary does not change " +
            "the permissions of a directory you chose: either chmod it to 0700 yourself, or pass " +
            "a --recovery-out path under a directory only you can write.",
        );
      }
      // A group/other-READABLE parent the operator chose (the conventional
      // 0755 home) is accepted with its mode untouched. Tightening it here is
      // the regression this branch exists to prevent.
      return;
    }
    await handle.chmod(0o700);
    const after = await handle.stat();
    if (
      !after.isDirectory() ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      (after.mode & 0o077) !== 0
    ) {
      throw new Error(
        `Recovery key output parent ${parent} could not be tightened to owner-only (0700); ` +
          "refusing to write a plaintext recovery key into a directory other accounts can read.",
      );
    }
  } finally {
    await handle.close();
  }
}

/**
 * Open `parent` as a directory descriptor that cannot be a symlink.
 *
 * ELOOP (a symlinked last component) and ENOTDIR (a file where a directory was
 * expected) are the same answer to the caller: this is not a stable directory
 * to write a plaintext recovery key into, so they are translated rather than
 * surfaced as raw errno text.
 */
async function openRecoveryOutputParentNoFollow(
  parent: string,
): Promise<Awaited<ReturnType<typeof open>>> {
  try {
    // Read only, never through a link, and only a directory. No O_CREAT, no
    // mode: this call creates nothing; every stat and the fchmod that may
    // follow run on THIS descriptor, which is what closes the lstat-then-chmod
    // swap window. CodeQL reads the numeric flag word as a possible write and
    // reports js/insecure-temporary-file when a caller's directory came from
    // the OS temp dir (test fixtures do); that is the same false positive
    // already dismissed on audit-log.ts and claude-code-file-adapter.ts.
    return await open(
      parent,
      constants.O_RDONLY |
        (typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0) |
        (typeof constants.O_DIRECTORY === "number" ? constants.O_DIRECTORY : 0),
    );
  } catch (err) {
    if (isErrnoCode(err, "ELOOP") || isErrnoCode(err, "ENOTDIR")) {
      throw new Error(
        `Recovery key output parent is not a stable directory: ${parent}`,
        { cause: err },
      );
    }
    throw err;
  }
}

async function assertNoRecoveryOutputStages(filePath: string): Promise<void> {
  const parent = dirname(filePath);
  const stagePrefix = recoveryOutputStagePrefix(filePath);
  const abandonedStages = (await readdir(parent)).filter((name) =>
    name.startsWith(stagePrefix),
  );
  if (abandonedStages.length > 0) {
    throw new Error(
      `Recovery key output has ${abandonedStages.length} staged artifact(s) from another or interrupted issuance beside ${filePath}. ` +
        `Refusing to overwrite or delete potentially authoritative recovery material; inspect and securely remove those files before retrying.`,
    );
  }
}

function recoveryOutputStagePrefix(filePath: string): string {
  return `.${basename(filePath)}.sanctuary-recovery-stage-`;
}

function isMissingPathError(err: unknown): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function isErrnoCode(err: unknown, code: string): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === code
  );
}

async function throwAtomicCustomOutputError(
  err: unknown,
  filePath: string
): Promise<never> {
  if (isErrnoCode(err, "ELOOP")) {
    throw new RecoveryKeyOutputPathSymlinkError(filePath);
  }
  if (isErrnoCode(err, "EEXIST")) {
    try {
      const existing = await lstat(filePath);
      if (existing.isSymbolicLink()) {
        throw new RecoveryKeyOutputPathSymlinkError(filePath);
      }
    } catch (lstatErr) {
      if (lstatErr instanceof RecoveryKeyOutputPathSymlinkError) {
        throw lstatErr;
      }
      if (!isMissingPathError(lstatErr)) {
        throw lstatErr;
      }
    }
    throw new RecoveryKeyOutputPathExistsError(filePath);
  }
  throw err;
}

async function writeCustomRecoveryOutputFile(
  filePath: string,
  content: string,
  faultAfter?: (stage: CustomRecoveryOutputStage) => void | Promise<void>,
  failIfExists = true,
): Promise<boolean> {
  // Re-checked here and not only in the preflight: the write is the
  // authoritative step, and a caller may reach it without a preflight. Same
  // helper, so the may-we-change-this-directory's-mode answer cannot differ
  // between the two.
  const parent = await prepareRecoveryOutputParent(filePath);
  await assertNoRecoveryOutputStages(filePath);
  const stagePath = join(
    parent,
    `${recoveryOutputStagePrefix(filePath)}${process.pid}-${randomBytes(12).toString("hex")}`,
  );

  // Stage beside the destination, sync the complete plaintext, then use link(2)
  // as an atomic no-replace publication primitive. A crash can therefore leave
  // either a discoverable staging artifact or the complete final artifact, never
  // a partially written final path. Preflight refuses both rather than deleting
  // recovery material whose custody publication may not have completed.
  //
  // Residual limitation: a parent directory can still be swapped for a symlink
  // between validation and open. Final-component substitution and overwrite
  // races are closed by O_NOFOLLOW/O_EXCL plus link's EEXIST behavior.
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const flags =
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let stageCreated = false;
  let finalPublished = false;
  let publicationAttempted = false;
  try {
    handle = await open(stagePath, flags, 0o600);
    stageCreated = true;
    await handle.writeFile(content, { encoding: "utf-8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await faultAfter?.("stage-synced");

    publicationAttempted = true;
    await link(stagePath, filePath);
    finalPublished = true;
    await faultAfter?.("final-linked");
    const directory = await open(parent, "r");
    try {
      await directory.sync();
      await faultAfter?.("directory-synced");
      await unlink(stagePath);
      stageCreated = false;
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch (err) {
    if (publicationAttempted && isErrnoCode(err, "EEXIST")) {
      if (failIfExists) await throwAtomicCustomOutputError(err, filePath);
      const existing = await lstat(filePath);
      if (existing.isSymbolicLink() || !existing.isFile()) {
        throw new Error(`Recovery key output path exists but is not a file: ${filePath}`, {
          cause: err,
        });
      }
      return false;
    }
    if (publicationAttempted && isErrnoCode(err, "ELOOP")) {
      await throwAtomicCustomOutputError(err, filePath);
    }
    throw err;
  } finally {
    if (handle) {
      await handle.close();
    }
    // Normal pre-publication failures do not strand partial plaintext. Once
    // link(2) has published the final inode, retain any stage alias on failure:
    // it is a crash-recovery signal and preflight will fail closed around it.
    if (stageCreated && !finalPublished) {
      await unlink(stagePath).catch(() => undefined);
    }
  }
  return true;
}

const RECOVERY_KEY_REENTRY_ATTEMPTS = 3;

/**
 * Force capture verification: prompt the operator to re-enter the recovery
 * key. The caller supplies the check, typically "does the entered key
 * actually unwrap the master?" (an end-to-end proof, not a string compare).
 * Throws {@link RecoveryKeyReentryMismatchError} after the attempts run out
 * and {@link RecoveryKeyConfirmationNonInteractiveError} on a non-TTY stdin.
 */
export async function verifyRecoveryKeyReentry(opts: {
  check: (entered: string) => Promise<boolean>;
  io?: DisclosureIo;
  attempts?: number;
  /**
   * What this success line is allowed to claim. It fires the moment the
   * re-entered key unwraps the master, which can be well before the calling
   * command has finished its remaining steps, so a caller with work left
   * supplies wording that describes only what was verified at that moment.
   * Default: the bare statement, for callers where verification IS the last
   * trust-bearing step.
   */
  verifiedMessage?: string;
}): Promise<void> {
  const input = opts.io?.input ?? process.stdin;
  const output = opts.io?.output ?? process.stderr;
  const attempts = opts.attempts ?? RECOVERY_KEY_REENTRY_ATTEMPTS;

  const realStdin = !opts.io && process.stdin.isTTY !== true;
  if (realStdin) {
    throw new RecoveryKeyConfirmationNonInteractiveError();
  }

  const rl = createInterface({ input, output });
  try {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      let answer: string;
      try {
        answer = (
          await rl.question("Re-enter the recovery key to verify you saved it: ")
        ).trim();
      } catch {
        // Input closed mid-verification (EOF): treat as a failed capture,
        // never as success.
        break;
      }
      if (await opts.check(answer)) {
        output.write(
          `${opts.verifiedMessage ?? "Recovery key verified."}\n`,
        );
        return;
      }
      output.write(
        attempt < attempts
          ? "That does not match. Check what you saved and try again.\n"
          : ""
      );
    }
  } finally {
    rl.close();
  }
  throw new RecoveryKeyReentryMismatchError();
}

/**
 * v1.1.3 (Finding X) error: operator answered "n" to the passphrase
 * confirmation prompt. Mirrors the recovery-key declined error shape so
 * callers can roll back fortress state and exit non-zero.
 */
export class PassphraseConfirmationDeclinedError extends Error {
  constructor() {
    super(
      "Passphrase confirmation declined. " +
        "Save the passphrase (printed above and written to passphrase-backup.txt) " +
        "before re-running wrap."
    );
    this.name = "PassphraseConfirmationDeclinedError";
  }
}

/**
 * v1.1.3 (Finding X) error: non-TTY stdin without bypass on the wrap path.
 * Callers exit non-zero with operator guidance.
 */
export class PassphraseConfirmationNonInteractiveError extends Error {
  constructor() {
    super(
      "Passphrase confirmation requires an interactive terminal. " +
        "Re-run with --no-open for scripted use, or run from a TTY."
    );
    this.name = "PassphraseConfirmationNonInteractiveError";
  }
}

/**
 * Print a bordered first-run secret-disclosure banner on stderr. Box width
 * is sized to the secret length so the right border lines up. The original
 * v1.1.0 banner truncated to a fixed visual width; the fix is to size the
 * box dynamically and never touch the secret value.
 */
function printSecretBanner(
  secret: string,
  filePath: string,
  copy: SecretDisclosureCopy,
  output: NodeJS.WritableStream = process.stderr,
  destination: "storage" | "custom" = "storage",
  fileWritten = true
): void {
  // Save first, delete second, always in that order and always about a file
  // that already exists at this point: the banner is printed after the write.
  // Failure mode this ordering exists for: an operator who reads "delete" and
  // acts on it before the copy is safely off-host destroys the only thing
  // that can recover the fortress.
  const deleteLine =
    destination === "custom"
      ? "then delete this file. Never move it into the fortress directory."
      : "then delete the file from the fortress directory.";
  const lines = fileWritten
    ? [
        copy.bannerHeader,
        "",
        `${copy.bannerSecretLabel}: ${secret}`,
        "",
        copy.bannerSaveLine,
        copy.bannerLossLine,
        "",
        "Plaintext copy written to:",
        `  ${filePath}`,
        "Move it off-host (password manager, encrypted backup),",
        deleteLine,
      ]
    : [
        copy.bannerHeader,
        "",
        `${copy.bannerSecretLabel}: ${secret}`,
        "",
        copy.bannerSaveLine,
        copy.bannerLossLine,
        "",
        "Plaintext copy was NOT written this run:",
        `  ${filePath}`,
        "That file already exists and may hold a prior key.",
        "The authoritative new key is the value shown above.",
      ];
  const inner = Math.max(...lines.map((l) => l.length));
  const horizontal = "═".repeat(inner + 2);
  const top = `╔${horizontal}╗`;
  const bottom = `╚${horizontal}╝`;
  const body = lines.map((l) => `║ ${l.padEnd(inner)} ║`).join("\n");
  output.write(`\n${top}\n${body}\n${bottom}\n\n`);
}

/**
 * Public banner for recovery-key disclosure (Finding U). Kept exported for
 * any caller that wants to print without the file-write side effect.
 */
export function printRecoveryKeyBanner(
  recoveryKey: string,
  filePath: string,
  output: NodeJS.WritableStream = process.stderr,
  fileWritten = true
): void {
  printSecretBanner(
    recoveryKey,
    filePath,
    RECOVERY_KEY_COPY,
    output,
    "storage",
    fileWritten
  );
}

/**
 * Public banner for passphrase disclosure (Finding X).
 */
export function printPassphraseBanner(
  passphrase: string,
  filePath: string,
  output: NodeJS.WritableStream = process.stderr,
  fileWritten = true
): void {
  printSecretBanner(
    passphrase,
    filePath,
    PASSPHRASE_BACKUP_COPY,
    output,
    "storage",
    fileWritten
  );
}

/**
 * Write the one-time secret-backup file with mode 0600. Single-issuance
 * semantics: if the file already exists, return its path without overwriting.
 * The fortress is the authoritative state and we must never regenerate or
 * replace a secret that an operator may have already saved.
 */
async function writeSecretFile(opts: {
  storagePath: string;
  filePath?: string;
  secret: string;
  copy: SecretDisclosureCopy;
  fortressId?: string;
  now?: () => Date;
  failIfExists?: boolean;
  metadataLines?: readonly string[];
  owner?: { uid: number; gid: number };
  ownerBase?: string;
  __testFaultAfterCustomOutputStage?: (
    stage: CustomRecoveryOutputStage,
  ) => void | Promise<void>;
}): Promise<{ filePath: string; written: boolean }> {
  const filePath =
    opts.filePath !== undefined
      ? resolve(opts.filePath)
      : join(opts.storagePath, opts.copy.fileName);

  const now = (opts.now ?? (() => new Date()))().toISOString();
  const fortressLine = opts.fortressId
    ? `Fortress: ${opts.fortressId}\n`
    : "";

  const content =
    `${opts.copy.fileWarningHeader}\n` +
    `Generated: ${now}\n` +
    fortressLine +
    "\n" +
    `${opts.copy.fileSecretLabel}\n` +
    `${opts.secret}\n` +
    (opts.metadataLines && opts.metadataLines.length > 0
      ? `\n${opts.metadataLines.join("\n")}\n`
      : "") +
    "\n" +
    opts.copy.fileBody;

  if (opts.owner) {
    if (!opts.ownerBase) {
      throw new Error("recovery output owner requires an ownerBase containment root");
    }
    const relativePath = relative(resolve(opts.ownerBase), filePath);
    if (
      relativePath === "" ||
      relativePath === ".." ||
      relativePath.startsWith(`..${sep}`) ||
      isAbsolute(relativePath)
    ) {
      throw new Error("recovery output path escaped its ownerBase containment root");
    }
  }
  const written = await writeCustomRecoveryOutputFile(
    filePath,
    content,
    opts.__testFaultAfterCustomOutputStage,
    opts.failIfExists === true,
  );
  if (written && opts.owner) {
    // The stage and final path are hard links to the same inode. Chowning the
    // published final therefore applies to the durable object created above.
    const handle = await open(
      filePath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      await handle.chown(opts.owner.uid, opts.owner.gid);
      await handle.sync();
    } finally {
      await handle.close();
    }
    const directory = await open(dirname(filePath), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  }
  return { filePath, written };
}

/**
 * Public entry point for recovery-key file write (Finding U).
 */
export async function writeRecoveryKeyFile(opts: {
  storagePath: string;
  recoveryKeyFilePath?: string;
  recoveryKey: string;
  fortressId?: string;
  /** Authenticated crash-resume receipt; not secret, but bound to this envelope. */
  recoveryReceipt?: string;
  owner?: { uid: number; gid: number };
  ownerBase?: string;
  now?: () => Date;
  /** TEST ONLY: pause or fault at a durable custom-output boundary. */
  __testFaultAfterCustomOutputStage?: (
    stage: CustomRecoveryOutputStage,
  ) => void | Promise<void>;
}): Promise<{ filePath: string; written: boolean }> {
  if (opts.recoveryKeyFilePath !== undefined) {
    assertPathOutsideFortress(opts.recoveryKeyFilePath, opts.storagePath);
  }
  const writeOpts: Parameters<typeof writeSecretFile>[0] = {
    storagePath: opts.storagePath,
    secret: opts.recoveryKey,
    copy: RECOVERY_KEY_COPY,
  };
  if (opts.recoveryKeyFilePath !== undefined) {
    writeOpts.filePath = opts.recoveryKeyFilePath;
    writeOpts.failIfExists = true;
  }
  if (opts.fortressId !== undefined) writeOpts.fortressId = opts.fortressId;
  if (opts.recoveryReceipt !== undefined) {
    writeOpts.metadataLines = [
      "Recovery staging receipt:",
      opts.recoveryReceipt,
    ];
  }
  if (opts.owner !== undefined) writeOpts.owner = opts.owner;
  if (opts.ownerBase !== undefined) writeOpts.ownerBase = opts.ownerBase;
  if (opts.now !== undefined) writeOpts.now = opts.now;
  if (opts.__testFaultAfterCustomOutputStage !== undefined) {
    writeOpts.__testFaultAfterCustomOutputStage =
      opts.__testFaultAfterCustomOutputStage;
  }
  return writeSecretFile(writeOpts);
}

export interface RotationRecoveryFileAuthority {
  kind: "recovery-file";
  path: string;
  parent_dev: string;
  parent_ino: string;
  file_dev: string | null;
  file_ino: string | null;
}

export interface RotationRecoveryFileMutation {
  readonly authority: RotationRecoveryFileAuthority;
  commit(): void;
  rollback(): Promise<void>;
}

async function recoveryOutputParentIdentity(
  filePath: string,
): Promise<{ dev: string; ino: string }> {
  const parent = dirname(filePath);
  const stats = await lstat(parent, { bigint: true });
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new Error(`Recovery key output parent is not a stable directory: ${parent}`);
  }
  return { dev: String(stats.dev), ino: String(stats.ino) };
}

function sameBigintIdentity(
  stats: { dev: bigint; ino: bigint },
  dev: string,
  ino: string,
): boolean {
  return String(stats.dev) === dev && String(stats.ino) === ino;
}

function recoveryKeyFromOutput(bytes: Uint8Array): string {
  if (bytes.byteLength > 64 * 1024) {
    throw new Error("Recovery key output exceeds the reconciliation size bound");
  }
  const text = Buffer.from(bytes).toString("utf8");
  const match = text.match(/(?:^|\n)Recovery key:\n([A-Za-z0-9_-]{43})\n/);
  if (!match) throw new Error("Recovery key output has an invalid recovery-key record");
  return match[1]!;
}

/**
 * Reconcile only the exact inode family authorized before publication. A hard
 * kill can leave the final name, its same-inode stage alias, or only the
 * synced stage. Every surviving candidate must contain a key that actually
 * unlocks the staged envelope before any unlink is allowed.
 */
export async function reconcileRotationRecoveryKeyFile(
  authority: RotationRecoveryFileAuthority,
  verify: (candidate: string) => Promise<boolean>,
): Promise<void> {
  const filePath = resolve(authority.path);
  if (filePath !== authority.path) {
    throw new Error("Pending recovery output path is not canonical and absolute");
  }
  const parent = dirname(filePath);
  const parentIdentity = await recoveryOutputParentIdentity(filePath);
  if (
    parentIdentity.dev !== authority.parent_dev ||
    parentIdentity.ino !== authority.parent_ino
  ) {
    throw new Error("Recovery output parent inode changed; refusing cleanup");
  }
  const names = [
    basename(filePath),
    ...(await readdir(parent)).filter((name) =>
      name.startsWith(recoveryOutputStagePrefix(filePath)),
    ),
  ];
  const candidates: Array<{
    path: string;
    dev: string;
    ino: string;
    recoveryKey: string;
  }> = [];
  for (const name of [...new Set(names)]) {
    const path = join(parent, name);
    const stats = await lstat(path, { bigint: true }).catch((error) => {
      if (isMissingPathError(error)) return null;
      throw error;
    });
    if (stats === null) continue;
    if (
      stats.isSymbolicLink() || !stats.isFile()
      || Number(stats.mode) & 0o077
      || (authority.file_dev !== null && String(stats.dev) !== authority.file_dev)
      || (authority.file_ino !== null && String(stats.ino) !== authority.file_ino)
    ) {
      throw new Error(`Recovery output inode is not the authenticated pending file: ${path}`);
    }
    const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const heldBefore = await handle.stat({ bigint: true });
      if (!sameBigintIdentity(heldBefore, String(stats.dev), String(stats.ino))) {
        throw new Error("Recovery output inode changed during open");
      }
      const bytes = await handle.readFile();
      const heldAfter = await handle.stat({ bigint: true });
      if (!sameBigintIdentity(heldAfter, String(stats.dev), String(stats.ino))) {
        throw new Error("Recovery output inode changed during verification");
      }
      const recoveryKey = recoveryKeyFromOutput(bytes);
      if (!(await verify(recoveryKey))) {
        throw new Error("Recovery output does not unlock the authenticated staged envelope");
      }
      candidates.push({
        path,
        dev: String(stats.dev),
        ino: String(stats.ino),
        recoveryKey,
      });
    } finally {
      await handle.close();
    }
  }
  if (candidates.length === 0) return;
  const [first] = candidates;
  if (candidates.some((candidate) => (
    candidate.dev !== first!.dev
    || candidate.ino !== first!.ino
    || candidate.recoveryKey !== first!.recoveryKey
  ))) {
    throw new Error("Recovery output aliases do not resolve to one authenticated inode");
  }
  for (const candidate of candidates) {
    const named = await lstat(candidate.path, { bigint: true });
    if (!sameBigintIdentity(named, candidate.dev, candidate.ino)) {
      throw new Error("Recovery output inode changed before cleanup");
    }
    await unlink(candidate.path);
  }
  const parentAfter = await recoveryOutputParentIdentity(filePath);
  if (
    parentAfter.dev !== authority.parent_dev ||
    parentAfter.ino !== authority.parent_ino
  ) {
    throw new Error("Recovery output parent inode changed during cleanup");
  }
  const directory = await open(parent, "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

/** Write an explicit rotation output as a rollback-capable inode transaction. */
export async function writeRotationRecoveryKeyFileTransactional(opts: {
  storagePath: string;
  recoveryKeyFilePath: string;
  recoveryKey: string;
  fortressId: string;
  registerPendingAuthority: (
    authority: RotationRecoveryFileAuthority,
  ) => Promise<void>;
  __testFaultAfterCustomOutputStage?: (
    stage: CustomRecoveryOutputStage,
  ) => void | Promise<void>;
}): Promise<RotationRecoveryFileMutation> {
  const filePath = resolve(opts.recoveryKeyFilePath);
  assertPathOutsideFortress(filePath, opts.storagePath);
  // Direct callers historically received parent creation and single-issuance
  // validation from writeRecoveryKeyFile. Do it before capturing the parent
  // inode so the authority binds the directory that will actually own the
  // published file.
  await preflightRecoveryKeyOutputFile(filePath);
  const parentIdentity = await recoveryOutputParentIdentity(filePath);
  const intended: RotationRecoveryFileAuthority = {
    kind: "recovery-file",
    path: filePath,
    parent_dev: parentIdentity.dev,
    parent_ino: parentIdentity.ino,
    file_dev: null,
    file_ino: null,
  };
  await opts.registerPendingAuthority(intended);
  let authority = intended;
  try {
    await writeRecoveryKeyFile({
      storagePath: opts.storagePath,
      recoveryKeyFilePath: filePath,
      recoveryKey: opts.recoveryKey,
      fortressId: opts.fortressId,
      ...(opts.__testFaultAfterCustomOutputStage
        ? { __testFaultAfterCustomOutputStage: opts.__testFaultAfterCustomOutputStage }
        : {}),
    });
    const parentAfter = await recoveryOutputParentIdentity(filePath);
    if (
      parentAfter.dev !== intended.parent_dev ||
      parentAfter.ino !== intended.parent_ino
    ) {
      throw new Error("Recovery output parent inode changed during publication");
    }
    const published = await lstat(filePath, { bigint: true });
    if (published.isSymbolicLink() || !published.isFile()) {
      throw new Error("Recovery output publication did not produce a regular file");
    }
    authority = {
      ...intended,
      file_dev: String(published.dev),
      file_ino: String(published.ino),
    };
    await opts.registerPendingAuthority(authority);
  } catch (error) {
    try {
      await reconcileRotationRecoveryKeyFile(
        intended,
        async (candidate) => candidate === opts.recoveryKey,
      );
    } catch (rollbackError) {
      throw new AggregateError(
        [error, rollbackError],
        "Recovery output publication failed and its inode did not roll back cleanly",
        { cause: rollbackError },
      );
    }
    throw error;
  }
  let finished = false;
  return {
    get authority() { return authority; },
    commit: () => { finished = true; },
    rollback: async () => {
      if (finished) return;
      await reconcileRotationRecoveryKeyFile(
        authority,
        async (candidate) => candidate === opts.recoveryKey,
      );
      finished = true;
    },
  };
}

export type CustomRecoveryOutputStage =
  | "stage-synced"
  | "final-linked"
  | "directory-synced";

/**
 * Public entry point for passphrase backup file write (Finding X).
 */
export async function writePassphraseBackupFile(opts: {
  storagePath: string;
  passphrase: string;
  fortressId?: string;
  now?: () => Date;
}): Promise<{ filePath: string; written: boolean }> {
  const writeOpts: Parameters<typeof writeSecretFile>[0] = {
    storagePath: opts.storagePath,
    secret: opts.passphrase,
    copy: PASSPHRASE_BACKUP_COPY,
  };
  if (opts.fortressId !== undefined) writeOpts.fortressId = opts.fortressId;
  if (opts.now !== undefined) writeOpts.now = opts.now;
  return writeSecretFile(writeOpts);
}

/**
 * Prompt the operator to confirm they have saved the secret. Returns when
 * the operator answers "y" or "yes" (case-insensitive). Throws the supplied
 * declined-error class on "n" or any other answer; throws the non-interactive
 * error class when stdin is not a TTY (caller should bypass with mode
 * "no-confirm" instead).
 */
async function confirmSecretSaved(
  copy: SecretDisclosureCopy,
  declinedError: new () => Error,
  nonInteractiveError: new () => Error,
  io?: DisclosureIo
): Promise<void> {
  const input = io?.input ?? process.stdin;
  const output = io?.output ?? process.stderr;

  // tty detection: real stdin exposes isTTY; injected streams in tests do not
  // and are treated as TTY-like (the test owns the stream).
  const realStdin = !io && process.stdin.isTTY !== true;
  if (realStdin) {
    throw new nonInteractiveError();
  }

  const rl = createInterface({ input, output });
  try {
    const answer = await rl.question(
      `Have you saved the ${copy.promptLabel}? [y/N] `
    );
    const normalized = answer.trim().toLowerCase();
    if (normalized !== "y" && normalized !== "yes") {
      throw new declinedError();
    }
  } finally {
    rl.close();
  }
}

/**
 * Public confirmation prompt for the recovery-key path (Finding U).
 */
export async function confirmRecoveryKeySaved(
  io?: DisclosureIo
): Promise<void> {
  await confirmSecretSaved(
    RECOVERY_KEY_COPY,
    RecoveryKeyConfirmationDeclinedError,
    RecoveryKeyConfirmationNonInteractiveError,
    io
  );
}

/**
 * Public confirmation prompt for the passphrase path (Finding X).
 */
export async function confirmPassphraseSaved(
  io?: DisclosureIo
): Promise<void> {
  await confirmSecretSaved(
    PASSPHRASE_BACKUP_COPY,
    PassphraseConfirmationDeclinedError,
    PassphraseConfirmationNonInteractiveError,
    io
  );
}

interface DiscloseSecretInternalOptions {
  /** Full secret value (do NOT pre-truncate). */
  secret: string;
  /** Resolved fortress storage path; backup file lands here. */
  storagePath: string;
  /** Optional exact plaintext backup path, used for durable off-fortress capture. */
  filePath?: string;
  /** File write completed by the caller before disclosure. */
  prewrittenFile?: { filePath: string; written: boolean };
  /** Stable lexical path shown to the operator when I/O used a dirfd path. */
  operatorFilePath?: string;
  /** Optional fortress identifier; embedded in the file content. */
  fortressId?: string;
  /** Confirmation policy. */
  mode?: DisclosureMode;
  /** Test seam: clock injection for the file timestamp. */
  now?: () => Date;
  /** Test seam: stdin/stdout streams. */
  io?: DisclosureIo;
  /**
   * Invoked immediately BEFORE the banner is written, never after.
   *
   * The banner is the moment the operator is told the secret and the path it
   * was written to; from that instant the file is theirs and no later failure
   * may delete it. Callers that own rollback (init) flip their announced bit
   * here, inside the helper, because the alternative -- flipping it after the
   * disclosure call returns -- leaves a window in which the banner has
   * printed, the caller's post-call custody fence throws, and rollback then
   * unlinks the only plaintext copy of a key the operator was just told to
   * save. Before, not after, so even a partially written banner counts as
   * announced.
   */
  onBeforeBannerPrint?: () => void;
}

interface DiscloseSecretInternalResult {
  filePath: string;
  fileWritten: boolean;
  confirmed: boolean;
}

/**
 * Disclose a freshly generated secret end-to-end: write the file, print the
 * banner, and (in interactive mode) prompt for confirmation.
 *
 * Order matters: file write happens first so the operator can recover the
 * secret even if banner output is lost (terminal scrollback, redirected
 * stderr). Banner print is second so the operator sees the value live.
 * Confirmation is last so the operator has the file path on screen before
 * deciding.
 */
async function discloseSecret(
  opts: DiscloseSecretInternalOptions,
  copy: SecretDisclosureCopy,
  declinedError: new () => Error,
  nonInteractiveError: new () => Error
): Promise<DiscloseSecretInternalResult> {
  const mode = opts.mode ?? "interactive";

  const expectedFilePath =
    opts.filePath !== undefined
      ? resolve(opts.filePath)
      : join(opts.storagePath, copy.fileName);
  let fileResult: { filePath: string; written: boolean };
  if (opts.prewrittenFile !== undefined) {
    if (resolve(opts.prewrittenFile.filePath) !== expectedFilePath) {
      throw new Error(
        `prewritten disclosure file path mismatch: ${opts.prewrittenFile.filePath}`
      );
    }
    fileResult = opts.prewrittenFile;
  } else {
    const writeOpts: Parameters<typeof writeSecretFile>[0] = {
      storagePath: opts.storagePath,
      secret: opts.secret,
      copy,
    };
    if (opts.filePath !== undefined) {
      writeOpts.filePath = opts.filePath;
      writeOpts.failIfExists = true;
    }
    if (opts.fortressId !== undefined) writeOpts.fortressId = opts.fortressId;
    if (opts.now !== undefined) writeOpts.now = opts.now;
    fileResult = await writeSecretFile(writeOpts);
  }

  // Announced-from-here: see DiscloseSecretInternalOptions.onBeforeBannerPrint.
  opts.onBeforeBannerPrint?.();
  printSecretBanner(
    opts.secret,
    opts.operatorFilePath ?? fileResult.filePath,
    copy,
    opts.io?.output,
    opts.filePath ? "custom" : "storage",
    fileResult.written
  );

  if (mode === "no-confirm" || mode === "stdio-server") {
    return {
      filePath: opts.operatorFilePath ?? fileResult.filePath,
      fileWritten: fileResult.written,
      confirmed: false,
    };
  }

  await confirmSecretSaved(copy, declinedError, nonInteractiveError, opts.io);
  return {
    filePath: opts.operatorFilePath ?? fileResult.filePath,
    fileWritten: fileResult.written,
    confirmed: true,
  };
}

export interface DiscloseRecoveryKeyOptions {
  /** Full base64url-encoded recovery key (do NOT pre-truncate). */
  recoveryKey: string;
  /**
   * Resolved fortress storage path. It is the containment reference, not the
   * destination: every output path is refused unless it resolves outside this
   * directory. `sanctuary init` always supplies recoveryKeyFilePath, so the
   * plaintext key never lands here; only callers that pass no explicit path
   * fall back to a file inside the fortress.
   */
  storagePath: string;
  /** Optional exact plaintext recovery-key path; must be outside storagePath. */
  recoveryKeyFilePath?: string;
  /** File write completed by the caller before disclosure. */
  prewrittenFile?: { filePath: string; written: boolean };
  /** Stable lexical path shown to the operator when writing through a dirfd. */
  operatorFilePath?: string;
  /** Optional fortress identifier; embedded in the file content. */
  fortressId?: string;
  /** Confirmation policy. */
  mode?: DisclosureMode;
  /** Test seam: clock injection for the file timestamp. */
  now?: () => Date;
  /** Test seam: stdin/stdout streams. */
  io?: DisclosureIo;
  /**
   * Invoked immediately before the recovery-key banner prints. See
   * DiscloseSecretInternalOptions.onBeforeBannerPrint: `sanctuary init` uses
   * it to mark the recovery file as announced at the exact instant the
   * operator learns about it, so rollback can never delete an announced file.
   */
  onBeforeBannerPrint?: () => void;
}

export interface DiscloseRecoveryKeyResult {
  /** Absolute path to the written recovery-key.txt (or existing one). */
  filePath: string;
  /** True if a file was written this call; false if it already existed. */
  fileWritten: boolean;
  /** True if the operator confirmed; false if confirmation was skipped. */
  confirmed: boolean;
}

export interface DisclosePassphraseOptions {
  /** Full passphrase (do NOT pre-truncate). */
  passphrase: string;
  /** Resolved fortress storage path; passphrase-backup.txt lands here. */
  storagePath: string;
  /** Optional fortress identifier; embedded in the file content. */
  fortressId?: string;
  /** Confirmation policy. */
  mode?: DisclosureMode;
  /** Test seam: clock injection for the file timestamp. */
  now?: () => Date;
  /** Test seam: stdin/stdout streams. */
  io?: DisclosureIo;
}

export interface DisclosePassphraseResult {
  /** Absolute path to the written passphrase-backup.txt (or existing one). */
  filePath: string;
  /** True if a file was written this call; false if it already existed. */
  fileWritten: boolean;
  /** True if the operator confirmed; false if confirmation was skipped. */
  confirmed: boolean;
}

/**
 * Public entry point for recovery-key disclosure (Finding U / v1.1.1).
 */
export async function discloseRecoveryKey(
  opts: DiscloseRecoveryKeyOptions
): Promise<DiscloseRecoveryKeyResult> {
  if (opts.recoveryKeyFilePath !== undefined) {
    assertPathOutsideFortress(opts.recoveryKeyFilePath, opts.storagePath);
  }
  const internalOpts: DiscloseSecretInternalOptions = {
    secret: opts.recoveryKey,
    storagePath: opts.storagePath,
  };
  if (opts.recoveryKeyFilePath !== undefined) {
    internalOpts.filePath = opts.recoveryKeyFilePath;
  }
  if (opts.prewrittenFile !== undefined) {
    internalOpts.prewrittenFile = opts.prewrittenFile;
  }
  if (opts.operatorFilePath !== undefined) {
    internalOpts.operatorFilePath = opts.operatorFilePath;
  }
  if (opts.fortressId !== undefined) internalOpts.fortressId = opts.fortressId;
  if (opts.mode !== undefined) internalOpts.mode = opts.mode;
  if (opts.now !== undefined) internalOpts.now = opts.now;
  if (opts.io !== undefined) internalOpts.io = opts.io;
  if (opts.onBeforeBannerPrint !== undefined) {
    internalOpts.onBeforeBannerPrint = opts.onBeforeBannerPrint;
  }

  return discloseSecret(
    internalOpts,
    RECOVERY_KEY_COPY,
    RecoveryKeyConfirmationDeclinedError,
    RecoveryKeyConfirmationNonInteractiveError
  );
}

/**
 * Public entry point for passphrase disclosure (Finding X / v1.1.3).
 */
export async function disclosePassphrase(
  opts: DisclosePassphraseOptions
): Promise<DisclosePassphraseResult> {
  const internalOpts: DiscloseSecretInternalOptions = {
    secret: opts.passphrase,
    storagePath: opts.storagePath,
  };
  if (opts.fortressId !== undefined) internalOpts.fortressId = opts.fortressId;
  if (opts.mode !== undefined) internalOpts.mode = opts.mode;
  if (opts.now !== undefined) internalOpts.now = opts.now;
  if (opts.io !== undefined) internalOpts.io = opts.io;

  return discloseSecret(
    internalOpts,
    PASSPHRASE_BACKUP_COPY,
    PassphraseConfirmationDeclinedError,
    PassphraseConfirmationNonInteractiveError
  );
}
