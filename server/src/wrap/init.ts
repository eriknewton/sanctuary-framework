/**
 * `sanctuary init` — Standalone fortress initialization (v1.1.1 hotfix)
 *
 * Creates a fresh fortress at a chosen path without wrapping any agent
 * harness. The drill needed this primitive to satisfy "stand up a
 * side-by-side isolated fortress" guardrails (Findings S + T): v1.1.0's
 * `sanctuary wrap --fortress <path>` silently ignored the flag, and
 * there was no other way to provision an isolated fortress.
 *
 * Differences from `sanctuary wrap`:
 *   - No agent harness config detection or rewrite.
 *   - Default key-derivation path is recovery-key (random 32-byte master
 *     key, hash persisted, plaintext disclosed). Operators who want a
 *     passphrase-mode fortress can run wrap.
 *   - Honors --fortress <path> (and SANCTUARY_FORTRESS_PATH env var) as
 *     the operator-friendly alias for SANCTUARY_STORAGE_PATH.
 *
 * Honors --force, --no-confirm. The plaintext recovery key ALWAYS lands
 * outside the fortress: --recovery-out names the destination, and without it
 * init uses the agent-guided staging path beside the fortress (the same path
 * the install contract names). Interactive init also discloses the key in a
 * banner and forces re-entry; headless init prints only the destination.
 */

import { lstat, mkdir, open, readdir, unlink } from "node:fs/promises";
import { homedir, platform } from "node:os";
import { dirname, join, isAbsolute, resolve } from "node:path";
import { Writable } from "node:stream";

import { tightenStoragePermissions } from "../storage/permissions.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  isFreshFortressOrExactLockScaffold,
  isRecoveryKeyStageFileName,
} from "../storage/fresh-fortress.js";
import { generateRandomKey } from "../core/random.js";
import { toBase64url } from "../core/encoding.js";
import {
  wrapMasterWithRecoveryKey,
  wrapMasterWithPassphrase,
  wrapMasterWithKeychainKey,
  writeCustodyEnvelope,
  verifyRecoveryWrapByReentry,
  readCustodyEnvelope,
  withCustodyWriteLock,
  CUSTODY_SENTINEL_KEY,
  ROTATION_JOURNAL_KEY,
  CUSTODY_WRITE_LOCK_FILE,
  type CustodyEnvelope,
  type CustodyWrap,
} from "../core/master-custody.js";
import {
  getOrCreateKeychainCustodyKeyTransactional,
  probeKeychainRecoveryKey,
  storeRecoveryKeyInKeychainTransactional,
  type KeychainCustodyOptions,
  type KeychainMutation,
} from "./keychain-custody.js";
import { AuditLog } from "../operational/audit-log.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { createIdentity } from "../core/identity.js";
import { IdentityManager } from "../cognitive/tools.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  discloseRecoveryKey,
  preflightRecoveryKeyOutputFile,
  resolveRecoveryKeyOutputPath,
  verifyRecoveryKeyReentry,
  writeRecoveryKeyFile,
  RecoveryKeyConfirmationDeclinedError,
  RecoveryKeyConfirmationNonInteractiveError,
  RecoveryKeyOutputPathInsideFortressError,
  RecoveryKeyReentryMismatchError,
} from "./recovery-key-disclosure.js";
import {
  agentGuidedRecoveryDefaultCollidesWithFortress,
  agentGuidedRecoveryDefaultCollisionMessage,
  agentGuidedRecoveryOutputPath,
} from "./custody-flow.js";
import {
  DEFAULT_STORAGE_DIR,
  formatFortressPathWritableError,
  preflightFortressPathWritable,
} from "../paths.js";
import {
  runProvisionPin,
  runProvisionPinAlreadyLocked,
} from "../cli/castle-wall.js";
// The named wall state this fortress persists, and the one sentence every
// surface prints for it. Must match `classifyMetaKey` in
// core/master-rotation.ts (an unrecognized `_meta` key makes master rotation
// refuse every fortress that carries it).
import {
  CASTLE_WALL_NOT_YET_WALLED,
  CASTLE_WALL_NOT_YET_WALLED_SENTENCE,
  CASTLE_WALL_PROVISION_META_KEY,
} from "../castle-wall/provision-state.js";
import { stringToBytes } from "../core/encoding.js";
import { mkdirSafeUnderRoot } from "./config-reader.js";
import {
  preflightPrincipalPolicyFile,
  principalPolicyPath,
  writeDefaultPrincipalPolicyFile,
} from "../principal-policy/loader.js";
import { runLocalIntelligenceSetup } from "./local-intelligence.js";
// The dependency-free consent leaf, not the `intelligence` barrel: this file
// is on the CLI boot path and must not pull the selector graph in for one
// string. Must match the flag names parsed below.
import { LOCAL_INTELLIGENCE_OPT_IN_HINT } from "../intelligence/provisioning-consent.js";
import type { CrossProcessLockLease } from "../storage/cross-process-lock.js";
import { kernelBackedCrossProcessLockPlatformSupported } from "../storage/cross-process-lock.js";


export interface InitOptions {
  /** Operator-supplied fortress path. Wins over env + default. */
  fortress?: string;
  /** Skip the recovery-key Y/N confirmation. Required for non-TTY callers. */
  noConfirm?: boolean;
  /** Allow init against a non-empty directory. Refuses without this flag. */
  force?: boolean;
  /**
   * Exact plaintext recovery-key destination. When unset, init uses the
   * agent-guided staging path beside the fortress. Either way the path must
   * resolve (symlinks followed) outside the fortress directory: the recovery
   * key unlocks everything the fortress holds, so keeping it there makes one
   * directory read total.
   */
  recoveryOut?: string;
  /**
   * DEPRECATED no-op, still parsed and still accepted.
   *
   * It used to skip an init-time write of the machine-wide Castle Wall anchor.
   * Default init no longer touches that anchor at all, so there is nothing left
   * to skip. The flag stays because saved operator commands, the release
   * acceptance kit, and published install docs pass it; init prints one
   * deprecation line when it sees it. Also settable via SANCTUARY_INIT_NO_PIN.
   */
  noPin?: boolean;
  /**
   * Skip seeding the default operator identity. Default init mints a single
   * Ed25519 operator identity (the one every Tier-1 operator-signed surface,
   * federation, did:web, exit, needs) under the fortress's existing custody,
   * so a stock `init` fortress can drive federation admin verbs with no extra
   * step. With this flag set, init mints NO identity (the "custody-only,
   * bring-your-own-identity-later" path); run `sanctuary identity create`
   * later when ready. Mirrors --no-pin. Default behavior (no flag) is to seed.
   */
  noIdentity?: boolean;
  /** Pre-answer the local-intelligence setup choice; TTY confirm still gates mutation. */
  provisionLocalIntelligence?: boolean;
  /**
   * `--model-manifest <path>`: verify an operator-supplied signed model
   * manifest instead of the packaged one; same loader, parser, byte cap, and
   * pinned catalog root. Nothing is fetched.
   */
  modelManifestPath?: string;
}

/**
 * Explicit opt-in values for SANCTUARY_INIT_NO_PIN. The variable now selects
 * only whether the deprecation line prints, but the allowlist (NOT "anything
 * truthy") is kept so an inherited shell value or a `no`/`off` cannot be read
 * as an opt-in if this ever regains meaning.
 */
const NO_PIN_ENV_OPT_IN = new Set(["1", "true", "yes", "on"]);

/**
 * Resolve whether the operator asked for the retired no-pin behavior.
 * Precedence: the --no-pin CLI flag wins; otherwise SANCTUARY_INIT_NO_PIN
 * opts in only at an explicit allowlisted value (1/true/yes/on,
 * case-insensitive). The result now selects a deprecation line, nothing more.
 */
export function resolveNoPin(
  options: { noPin?: boolean },
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (options.noPin) {
    return true;
  }
  const raw = env.SANCTUARY_INIT_NO_PIN;
  if (raw === undefined) {
    return false;
  }
  return NO_PIN_ENV_OPT_IN.has(raw.trim().toLowerCase());
}

/**
 * Explicit opt-in values for SANCTUARY_INIT_NO_IDENTITY. Skipping the default
 * operator-identity seed leaves a fortress that cannot drive any Tier-1
 * operator-signed surface, so the env var is an allowlist (NOT "anything
 * truthy"): only these exact values opt out. Mirrors NO_PIN_ENV_OPT_IN.
 */
const NO_IDENTITY_ENV_OPT_IN = new Set(["1", "true", "yes", "on"]);

/**
 * Resolve whether the default operator-identity seed should be skipped.
 * Precedence: the --no-identity CLI flag wins; otherwise
 * SANCTUARY_INIT_NO_IDENTITY opts out only when set to an explicit
 * allowlisted value (1/true/yes/on, case-insensitive). Default is to seed.
 */
export function resolveNoIdentity(
  options: { noIdentity?: boolean },
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (options.noIdentity) {
    return true;
  }
  const raw = env.SANCTUARY_INIT_NO_IDENTITY;
  if (raw === undefined) {
    return false;
  }
  return NO_IDENTITY_ENV_OPT_IN.has(raw.trim().toLowerCase());
}

export interface InitResult {
  fortressPath: string;
  recoveryKeyDisclosurePath: string;
}

/**
 * Resolve the fortress path with documented precedence:
 *   1. --fortress <path> CLI flag
 *   2. SANCTUARY_FORTRESS_PATH env var
 *   3. SANCTUARY_STORAGE_PATH env var (back-compat)
 *   4. ~/.sanctuary
 *
 * Every source, absolute included, goes through `resolve` so `.` and `..`
 * segments are normalized away before anything is derived from the path.
 * An ABSOLUTE flag used to be taken verbatim, and the default recovery
 * destination is derived as `dirname(fortress)/Sanctuary Recovery/...`, so
 * `--fortress /a/b/c/..` produced `dirname` = `/a/b/c` and put the plaintext
 * recovery key INSIDE the `/a/b` fortress it protects. Normalizing here is
 * the fix at its source: `resolve("/a/b/c/..")` is `/a/b`, and every consumer
 * (the recovery destination, the containment guard, the messages) then agrees
 * about which directory the fortress is.
 *
 * Deliberately NOT realpath'd: `fortressIdFromStoragePath` derives the
 * fortress identity, the OS-keyring service name, and the recovery filename
 * from this string, so resolving symlinks here would silently re-key every
 * existing fortress reached through a symlinked path (on macOS `/var` alone
 * is a symlink). Symlink safety belongs to the guards that need it, and it
 * is already there: `assertPathOutsideFortress` realpath-anchors BOTH sides
 * before deciding containment, so a symlinked fortress cannot smuggle the
 * recovery destination inside itself.
 */
export function resolveFortressPath(
  options: { fortress?: string },
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
): string {
  const flag = options.fortress?.trim();
  if (flag && flag.length > 0) {
    return resolveFortressCandidate(flag);
  }
  const fortressEnv = env.SANCTUARY_FORTRESS_PATH;
  if (fortressEnv && fortressEnv.length > 0) {
    return resolveFortressCandidate(fortressEnv);
  }
  const storageEnv = env.SANCTUARY_STORAGE_PATH;
  if (storageEnv && storageEnv.length > 0) {
    return resolveFortressCandidate(storageEnv);
  }
  return join(home, DEFAULT_STORAGE_DIR);
}

/** Absolute + normalized. Relative candidates anchor on cwd, as documented. */
function resolveFortressCandidate(candidate: string): string {
  return isAbsolute(candidate)
    ? resolve(candidate)
    : resolve(process.cwd(), candidate);
}

/**
 * Check a would-be fresh fortress while tolerating only the inert persistent
 * scaffold created by the shared kernel custody lock: `state/_meta` and its
 * regular lock path. The kernel releases ownership after normal exit or holder
 * death, but intentionally leaves this file in place for future acquisitions.
 * A missing root is fresh; non-ENOENT inspection failures propagate.
 */
const isEmptyExceptCustodyLockScaffold = (root: string): Promise<boolean> =>
  isFreshFortressOrExactLockScaffold(root, CUSTODY_WRITE_LOCK_FILE);

async function isEmptyOrPotentialRecoveryCrashResidue(root: string): Promise<boolean> {
  if (await isEmptyExceptCustodyLockScaffold(root)) return true;
  try {
    const rootEntries = await readdir(root);
    const candidates = rootEntries.filter((name) =>
      name === "recovery-key.txt" || isRecoveryKeyStageFileName(name),
    );
    if (candidates.length !== 1) return false;
    const candidate = candidates[0]!;
    const residue = await lstat(join(root, candidate));
    if (residue.isSymbolicLink() || !residue.isFile() || residue.nlink !== 1) {
      return false;
    }
    return isFreshFortressOrExactLockScaffold(
      root,
      CUSTODY_WRITE_LOCK_FILE,
      candidate,
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

/**
 * Read-only early refusal for a pre-existing unsafe policy path. The same
 * components are checked again by `mkdirSafeUnderRoot` while the custody lock
 * is held; this preflight only avoids creating lock/state scaffolding for an
 * input that is already known to be unsafe.
 */
async function preflightPolicyAncestors(root: string): Promise<void> {
  let current = root;
  for (const component of ["policy", "egress", "rules"]) {
    current = join(current, component);
    try {
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) {
        throw new Error(`symlink at ${current}; refusing to mkdir through it`);
      }
      if (!stat.isDirectory()) {
        throw new Error(`non-directory policy ancestor at ${current}; refusing to mkdir through it`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
  }
}

/**
 * Test seams for init. `provisionPin` lets a test observe or replace the
 * fortress-local Castle key-pair provisioning call (it is fortress-local only:
 * no init path reads or writes the machine-wide anchor). Not part of the CLI
 * surface.
 */
export interface RunInitDeps {
  provisionPin?: typeof runProvisionPin;
  /** Test seam: inject a mock OS-keyring backend for recovery-key storage. */
  recoveryKeychain?: KeychainCustodyOptions;
  /** Test seam: simulate a race immediately before recovery-file O_EXCL capture. */
  beforeRecoveryKeyOutputWrite?: (filePath: string) => void | Promise<void>;
  /** Test seam: drive attended recovery-key re-entry without real terminal input. */
  verifyRecoveryKeyReentry?: typeof verifyRecoveryKeyReentry;
  /** Test seam: pause after unlocked preflight and mkdir, before custody lock. */
  beforeCustodyLockAcquire?: () => void | Promise<void>;
  runLocalIntelligenceSetup?: typeof runLocalIntelligenceSetup;
  /** Test seam for proving generated custody material is zeroed on every exit. */
  observeSecretBuffer?: (
    label: "master" | "recovery-key" | "keychain" | "local-setup-master",
    buffer: Uint8Array,
  ) => void;
  /** Test only: observe the real kernel holder for holder-loss fencing. */
  __testAfterKernelHolderAcquired?: (pid: number) => void;
  /** Test only: pause after custody-key ownership transfers to init. */
  __testAfterKeychainCustodyKeyResolved?: () => void | Promise<void>;
  /** Test only: pause/throw after the pre-mutation lease fence. */
  beforeDurableMutation?: (label: string) => void | Promise<void>;
  /**
   * Test only: pause/throw in the window AFTER the recovery-key banner has
   * printed and BEFORE the disclosure fence's post-mutation assertion, which
   * is the exact window in which a holder loss must not cost the operator the
   * file they were just told to save.
   */
  __testAfterRecoveryKeyBannerPrinted?: () => void | Promise<void>;
}

/** Assert custody ownership before and after every durable init helper. */
async function fencedInit<T>(
  lease: CrossProcessLockLease,
  deps: RunInitDeps,
  label: string,
  mutation: () => Promise<T>,
): Promise<T> {
  lease.assertHeld();
  await deps.beforeDurableMutation?.(label);
  lease.assertHeld();
  const result = await mutation();
  lease.assertHeld();
  return result;
}

/**
 * Success line for recovery-key re-entry DURING init. Scoped deliberately:
 * re-entry happens before the operator-identity seed and the Castle Wall pin
 * step, so this may not claim the ceremony finished. The completion claim is
 * INIT_COMPLETE_MESSAGE, printed only after the last step.
 */
const INIT_RECOVERY_KEY_VERIFIED_MESSAGE =
  "Recovery key verified: the key you re-entered unlocks this fortress. " +
  "Initialization has more steps; wait for the completion line before " +
  "treating this fortress as built.";

/** The only line in init that claims the ceremony finished. */
const INIT_COMPLETE_MESSAGE = "Sanctuary init: complete.";

/** What a failed init actually undid, for the one-line operator summary. */
interface InitCleanupSummary {
  rolledBack: boolean;
  rollbackIncomplete: boolean;
  /**
   * The announced recovery-key file this run's rollback REMOVED, because the
   * rollback also removed the custody that key unwrapped. Set only when the
   * removal actually happened.
   */
  removedAnnouncedRecoveryFile?: string;
  /**
   * The announced recovery-key file this run could NOT remove (it had changed
   * identity, or the unlink failed). It is still on disk and still opens
   * nothing, so the operator has to clear it before a retry can write there.
   */
  preservedRecoveryFile?: string;
}

/**
 * One operator-facing line after a failed init: what was cleaned, what was
 * deliberately left, and the single next step. Failure mode this exists for:
 * a run that printed a recovery key and then died left a half-built fortress
 * and said nothing, so the operator could not tell whether to retry, whether
 * the key they just saved was still worth anything, or what was on disk.
 */
function printInitCleanupSummary(
  fortressPath: string,
  summary: InitCleanupSummary,
): void {
  const parts: string[] = [];
  const cleanRollback = summary.rolledBack && !summary.rollbackIncomplete;
  if (summary.rolledBack) {
    parts.push(
      summary.rollbackIncomplete
        ? `Cleanup was attempted at ${fortressPath} but did not finish; inspect that directory before retrying.`
        : `Cleaned up: everything this run wrote under ${fortressPath} was removed (the empty state/ scaffold is inert and is reused by a retry).`,
    );
  } else {
    parts.push(
      `Nothing was cleaned up automatically; inspect ${fortressPath} before retrying.`,
    );
  }
  const removed = summary.removedAnnouncedRecoveryFile;
  if (removed) {
    // The file this run announced is GONE, and saying so is the whole point:
    // an operator who was told to save a recovery key and then reads a silent
    // failure summary keeps guarding a key for a fortress that no longer
    // exists. The rollback removed the custody that key unwrapped, so the key
    // could open nothing; leaving it behind only made the retry fail on it.
    parts.push(
      `Removed: ${removed} (the recovery key this run told you to save). The cleanup above removed the custody it unwrapped, so it could no longer open anything; if you already copied it somewhere, that copy is equally useless and can be deleted.`,
    );
  }
  const kept = summary.preservedRecoveryFile;
  if (kept) {
    // Reached only when the removal could NOT be completed (the file changed
    // identity under us, or the unlink failed). Failure mode from the outside:
    // the retry refuses on exactly this path, so the summary must name it.
    parts.push(
      cleanRollback
        ? `Still on disk: ${kept} (the recovery key this run told you to save). It could not be removed automatically. The cleanup above removed the custody it unwrapped, so it opens nothing.`
        : `Still on disk: ${kept} (the recovery key this run told you to save). ${fortressPath} was NOT fully cleaned up, so this key may still be the only way into whatever custody survived there; keep it until you have inspected that directory.`,
    );
  }
  if (cleanRollback) {
    const retry = `sanctuary init --fortress ${shellQuote(fortressPath)}`;
    // The next step has to be a step that WORKS. Init refuses to reuse an
    // existing recovery-key destination (single issuance: overwriting one
    // would destroy a key that may still be authoritative), and --force does
    // not relax that refusal, so a retry can only be a bare re-run once the
    // destination is clear. It IS clear on the ordinary path now, because the
    // rollback removed the file it announced; the `rm` line survives only for
    // the case where that removal did not complete.
    parts.push(
      kept
        ? `Next step: fix the reported cause, then clear the leftover recovery file before retrying. Init refuses to write over an existing recovery-key destination (and --force does not change that), so the retry fails while that path exists:\n      rm ${shellQuote(kept)}\n      ${retry}`
        : `Next step: fix the reported cause, then re-run \`${retry}\`.`,
    );
  } else {
    parts.push(
      `Next step: fix the reported cause and inspect the directory; do NOT re-run with --force until you have.`,
    );
  }
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary init: ${parts.join("\n  ")}\n`);
}

/**
 * POSIX single-quote a path for a command line printed to an operator.
 *
 * The default recovery destination contains a space ("Sanctuary Recovery"),
 * so an unquoted `rm <path>` printed here would be a command that silently
 * targets the wrong files when pasted. Single quotes suppress every shell
 * expansion; the only character that cannot appear inside them is the single
 * quote itself, which is closed, escaped, and reopened.
 */
function shellQuote(value: string): string {
  return `'${value.split("'").join("'\\''")}'`;
}

export async function runInit(
  options: InitOptions,
  deps: RunInitDeps = {},
): Promise<InitResult> {
  const provisionPin = deps.provisionPin ?? runProvisionPin;
  const fortressPath = resolveFortressPath(options);
  const host = platform();
  if (!kernelBackedCrossProcessLockPlatformSupported(host)) {
    throw new Error(
      `Sanctuary init requires process-owned custody locking; unsupported host platform ${host}. ` +
        "No fortress layout was created.",
    );
  }

  // Check the fortress parent before staging any external recovery destination:
  // a failed fortress-path preflight must not leave recovery scaffolding behind.
  const fortressWritable = await preflightFortressPathWritable(fortressPath);
  if (!fortressWritable.ok) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary init: ${formatFortressPathWritableError(
        fortressPath,
        fortressWritable,
      )}\n`,
    );
    throw new Error("fortress path is not writable");
  }

  // The plaintext recovery key NEVER defaults into the fortress it protects:
  // it is the one credential that unlocks everything the fortress holds, so
  // storing it there means a single directory loss (or a single directory
  // read) is total. An operator-named --recovery-out / SANCTUARY_RECOVERY_OUT
  // wins; otherwise the destination is the agent-guided staging path the
  // install contract already names (beside the fortress, never inside it).
  // Both go through the SAME guards (realpath-anchored inside-fortress
  // refusal, symlink refusal, single-issuance preflight) before any fortress
  // mutation, so a bad destination fails before custody material is minted.
  let operatorNamedRecoveryOut = false;
  let recoveryKeyOutputPath: string;
  try {
    const named = resolveRecoveryKeyOutputPath({
      recoveryOut: options.recoveryOut,
      storagePath: fortressPath,
      env: process.env,
    });
    operatorNamedRecoveryOut = named !== undefined;
    // Availability, checked before minting: for a fortress directory named
    // `Sanctuary Recovery` the DEFAULT staging path resolves back inside that
    // fortress, and the containment guard then refuses a destination the
    // operator never chose. The containment refusal is correct and stays; this
    // one names the remedy instead of reporting a path collision as a
    // containment violation.
    if (named === undefined && agentGuidedRecoveryDefaultCollidesWithFortress(fortressPath)) {
      // One sentence, two callers: `establishWrapCustody` refuses the same
      // collision with the same text; only the remedy clause differs, because
      // `init` is the command that accepts --recovery-out.
      throw new Error(agentGuidedRecoveryDefaultCollisionMessage(fortressPath, "init"));
    }
    const resolved =
      named ??
      resolveRecoveryKeyOutputPath({
        recoveryOut: agentGuidedRecoveryOutputPath(fortressPath),
        storagePath: fortressPath,
        env: {},
      });
    if (resolved === undefined) {
      throw new Error(
        "no recovery-key destination resolved; refusing to mint custody material",
      );
    }
    await preflightRecoveryKeyOutputFile(resolved);
    recoveryKeyOutputPath = resolved;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const prefix =
      err instanceof RecoveryKeyOutputPathInsideFortressError
        ? "recovery key output refused"
        : "recovery key output unavailable";
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary init: ${prefix}: ${message}\n`);
    throw err;
  }

  if (!options.force) {
    const empty = await isEmptyOrPotentialRecoveryCrashResidue(fortressPath);
    if (!empty) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Sanctuary init: refusing to overwrite a non-empty fortress at:\n` +
          `    ${fortressPath}\n\n` +
          `  Either pick a different --fortress path, run with --force to overwrite,\n` +
          `  or use \`sanctuary wrap --fortress ${fortressPath}\` to bind an existing\n` +
          `  fortress to a new agent harness.\n`,
      );
      throw new Error("fortress directory is not empty");
    }
  }

  const interactive = !options.noConfirm;
  if (interactive && process.stdin.isTTY !== true) {
    const err = new RecoveryKeyConfirmationNonInteractiveError();
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`\n  Sanctuary init: ${err.message}\n`);
    throw err;
  }

  await mkdir(fortressPath, { recursive: true, mode: 0o700 });
  await preflightPolicyAncestors(fortressPath);
  // Pre-mint refusal of a planted (non-regular) principal-policy entry, using
  // the SAME lstat rule the writer applies under the lock. The writer runs at
  // the END of init, after the recovery-key file and the custody envelope, and
  // `--force` skips rollback: refusing there left the staged recovery file on
  // disk, unannounced, so the cleanup summary could not name it and the next
  // `--force` retry died at the single-issuance preflight on a file the
  // operator had never been told about. Failure mode from the outside: init
  // reports "recovery key output unavailable" on a retry and the operator has
  // no idea which file to move.
  await preflightPrincipalPolicyFile(fortressPath);
  await deps.beforeCustodyLockAcquire?.();

  const storage = new FilesystemStorage(`${fortressPath}/state`);
  let runPostLockLocalSetup: (() => Promise<void>) | undefined;
  let localSetupMaster: Uint8Array | undefined;
  // What a failed run actually did, so the failure message can say it out
  // loud instead of leaving the operator to inspect the directory. Failure
  // mode from the outside: a half-built fortress looks like a working one
  // until the next verb refuses to open it.
  const cleanupSummary: InitCleanupSummary = {
    rolledBack: false,
    rollbackIncomplete: false,
  };
  const result = await withCustodyWriteLock(
    storage,
    async (lease) => {
      lease.assertHeld();
      const lockedFortressPath = lease.stableStorageParent;
      if (!lockedFortressPath) {
        throw new Error(
          "custody lock did not provide a stable fortress-directory capability",
        );
      }
      const keychainMutations: Array<Pick<KeychainMutation<unknown>, "rollback" | "commit">> = [];
      const externalRollback: Array<() => Promise<void>> = [];
      /**
       * Rollback steps that may run ONLY AFTER the custody they depend on is
       * confirmed gone.
       *
       * ORDERING INVARIANT, and the reason this is a second list rather than
       * one more entry in `externalRollback`: the recovery key this run wrote
       * unwraps the custody this run wrote. Removing the key first and then
       * failing to remove the custody leaves custody on disk with its recovery
       * factor destroyed, while the cleanup summary tells the operator the key
       * "could no longer open anything" — the one sentence that is false in
       * exactly that case. Removing custody first is safe in the mirror case:
       * a recovery key with no custody opens nothing whether or not the file
       * survives, and the summary already has a branch that names a surviving
       * file. Deletion order therefore follows the dependency, never the write
       * order.
       */
      const afterCustodyRemovalRollback: Array<() => Promise<void>> = [];
      /**
       * The recovery-key file this run actually wrote, or null when it wrote
       * none. Recorded at write time so the rollback can name it without
       * re-deriving a path: the summary must never claim a file is still on
       * disk when no file was ever written there.
       */
      let writtenRecoveryKeyFilePath: string | null = null;
      // The preflight emptiness check happened before the lock existed. Repeat
      // both the broad filesystem check and custody-current-state reads now,
      // under the same lock used by reset and rotation, so a concurrent winner
      // can never be overwritten from a stale preflight observation.
      if (!options.force) {
        await lease.stableFortressFiles?.cleanupFreshInitRecoveryResidue(
          CUSTODY_WRITE_LOCK_FILE,
        );
        const empty = lease.stableFortressCapability
          ? await lease.stableFortressCapability.isFreshExceptLockScaffold(
              CUSTODY_WRITE_LOCK_FILE,
            )
          : await isEmptyExceptCustodyLockScaffold(lockedFortressPath);
        const [currentEnvelope, sentinel, rotationJournal] = await Promise.all([
          readCustodyEnvelope(storage),
          storage.read("_meta", CUSTODY_SENTINEL_KEY),
          storage.read("_meta", ROTATION_JOURNAL_KEY),
        ]);
        if (!empty || currentEnvelope || sentinel || rotationJournal) {
          // SAFETY: stderr is the operator-facing init channel; no logger exists yet.
          console.error(
            `\n  Sanctuary init: refusing because fortress state appeared after preflight:\n` +
              `    ${fortressPath}\n\n` +
              `  Another init, reset, or rotation may have completed. Nothing from this\n` +
              `  init ceremony was written; inspect the current fortress or use --force\n` +
              `  only when you intentionally accept destructive re-initialization.\n`,
          );
          throw new Error("fortress state changed during init preflight");
        }
      }
      if (options.force) {
        const existingRecoveryEscrow = await probeKeychainRecoveryKey(
          fortressPath,
          deps.recoveryKeychain,
        );
        if (existingRecoveryEscrow.status === "found") {
          throw new Error(
            `--force refused before fortress mutation because OS-keyring service ` +
              `'${existingRecoveryEscrow.service}' already contains the prior ` +
              "recovery escrow. Sanctuary will not overwrite or silently leave " +
              "a stale canonical recovery copy. First preserve an independent " +
              "recovery/export, deliberately remove that exact old keyring item, " +
              "then rerun with --recovery-out <path outside the fortress>.",
          );
        }
        if (existingRecoveryEscrow.status === "unreachable") {
          throw new Error(
            `--force refused before fortress mutation because OS-keyring service ` +
              `'${existingRecoveryEscrow.service}' is unreachable and its ` +
              "absence cannot be proven. Unlock the keyring and retry; an explicit " +
              "--recovery-out does not make an unknown canonical escrow safe.",
          );
        }
      }
      // The freshness refusal above observes a concurrent winner and performs
      // no mutation of its own. Keep it outside this attempt's rollback scope:
      // rolling back after observing winner state would erase that winner.
      try {
      await fencedInit(lease, deps, "storage-permissions", () =>
        lease.stableFortressCapability
          ? lease.stableFortressCapability.tightenPermissions()
          : tightenStoragePermissions(lockedFortressPath),
      );

  // The root Castle Wall daemon intentionally refuses to recursively mkdir
  // through an operator-mutable policy tree: Node has no mkdirat/openat API
  // with which to make that operation race-safe as root. Seed the one true
  // rule-source directory while init is still running as the fortress owner,
  // walking each component without following symlinks. A fresh fortress is
  // then boot-service-ready even before it contains any allow rules.
  await fencedInit(lease, deps, "policy-directory", () =>
    lease.stableFortressCapability
      ? lease.stableFortressCapability.mkdir("policy/egress/rules", 0o700)
      : mkdirSafeUnderRoot(
          join(lockedFortressPath, "policy", "egress", "rules"),
          lockedFortressPath,
          0o700,
        ),
  );

  // Unified custody (master-custody.ts): one master per fortress, stored
  // only as wraps. The recovery key is a WRAP of the true master — never a
  // second, parallel master (the 2026-06-12 incident class).
  const masterKey = generateRandomKey();
  let recoveryKeyBytes: Uint8Array | undefined;
  try {
  deps.observeSecretBuffer?.("master", masterKey);
  recoveryKeyBytes = generateRandomKey();
  deps.observeSecretBuffer?.("recovery-key", recoveryKeyBytes);
  let recoveryKey: string;
  const wraps: CustodyWrap[] = [];
  try {
    recoveryKey = toBase64url(recoveryKeyBytes);
    wraps.push(wrapMasterWithRecoveryKey(masterKey, recoveryKeyBytes, {
      // Interactive installs verify by operator re-entry below; headless
      // installs stay unverified (the audited degraded mode records that).
      verified: false,
    }));
  } finally {
    recoveryKeyBytes.fill(0);
    recoveryKeyBytes = undefined;
  }
  const fortressId = fortressIdFromStoragePath(fortressPath);

  // OS-keyring recovery escrow accompanies the DEFAULT interactive
  // destination only. An operator who named --recovery-out has chosen where
  // the canonical copy lives, and headless installs are the audited degraded
  // mode that never touches the host keyring.
  if (interactive && !operatorNamedRecoveryOut) {
    await fencedInit(lease, deps, "recovery-key-keychain", async () => {
      const mutation = await storeRecoveryKeyInKeychainTransactional(
        fortressPath,
        recoveryKey,
        deps.recoveryKeychain,
      );
      keychainMutations.push(mutation);
    });
  }

  // Second factor. Interactive installs MUST enroll one (the two-factor
  // floor refuses trust-bearing writes — including the Castle pin below —
  // for interactive installs that never did): an OS-keyring custody key
  // when a keyring is available, else an operator-supplied passphrase.
  // Headless installs enroll a passphrase wrap when one is supplied but
  // never touch the host keyring (they are the audited degraded mode).
  const passphrase = process.env.SANCTUARY_PASSPHRASE;
  if (passphrase) {
    wraps.push(await wrapMasterWithPassphrase(masterKey, passphrase, { verified: true }));
  } else if (interactive) {
    // Do not use generic fencedInit for a secret-returning provider. Its
    // post-mutation assertion runs before the result reaches this scope, so a
    // holder-loss throw there would strand the resolved key with no owner able
    // to scrub it. Assign the key under this encompassing lifetime first, then
    // run the post-fence inside the same try/finally that owns the buffer.
    let keychainKey: Uint8Array | null | undefined;
    try {
      lease.assertHeld();
      await deps.beforeDurableMutation?.("keychain-custody-key");
      lease.assertHeld();
      const mutation = await getOrCreateKeychainCustodyKeyTransactional(
        fortressPath,
        deps.recoveryKeychain,
      );
      keychainKey = mutation?.value;
      if (mutation) keychainMutations.push(mutation);
      if (keychainKey) deps.observeSecretBuffer?.("keychain", keychainKey);
      await deps.__testAfterKeychainCustodyKeyResolved?.();
      lease.assertHeld();
      if (keychainKey) {
        wraps.push(wrapMasterWithKeychainKey(masterKey, keychainKey, { verified: true }));
        lease.assertHeld();
      } else {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(
          `\n  Sanctuary init: no OS keyring is available on this system, so the recovery\n` +
            `  key would be the ONLY way to unlock this fortress — a single point of failure.\n` +
            `  Supply a second custody factor via SANCTUARY_PASSPHRASE, or run with\n` +
            `  --no-confirm to accept an audited single-factor headless install.\n`,
        );
        throw new Error("second custody factor required for interactive init");
      }
    } finally {
      keychainKey?.fill(0);
    }
  }

  let prewrittenRecoveryKeyFile:
    | Awaited<ReturnType<typeof writeRecoveryKeyFile>>
    | undefined;
  // Announced-file bookkeeping for the rollback below. The announcement used to
  // make the file untouchable; it no longer does, and the reason is at the
  // rollback site.
  let recoveryKeyFileAnnounced = false;
  {
    try {
      await deps.beforeRecoveryKeyOutputWrite?.(recoveryKeyOutputPath);
      prewrittenRecoveryKeyFile = await fencedInit(
        lease,
        deps,
        "recovery-key-file",
        () => writeRecoveryKeyFile({
          storagePath: fortressPath,
          recoveryKeyFilePath: recoveryKeyOutputPath,
          recoveryKey,
          fortressId,
        }),
      );
      if (prewrittenRecoveryKeyFile.written) {
        const writtenIdentity = await lstat(recoveryKeyOutputPath);
        writtenRecoveryKeyFilePath = recoveryKeyOutputPath;
        // Deferred until custody removal is CONFIRMED; see the ordering
        // invariant on `afterCustodyRemovalRollback`.
        afterCustodyRemovalRollback.push(async () => {
          // INVARIANT: this rollback runs only when init FAILED, and it runs
          // alongside the removal of the custody this key unwraps. A key whose
          // custody is gone opens nothing, so leaving it behind announced a
          // live recovery key for a fortress that no longer exists: the
          // operator guarded a useless secret, and the retry then refused on
          // exactly that path (init never overwrites a recovery destination).
          // The announcement therefore does NOT protect the file; the removal
          // is reported in the cleanup summary in one sentence.
          //
          // Failure mode from the outside if the identity guard below is
          // dropped: a destination that was replaced between the write and the
          // failure (a symlink swapped in, a different file at the same path)
          // gets unlinked, and this rollback deletes something it never wrote.
          // A file it cannot prove it wrote is left alone and named instead.
          let current: Awaited<ReturnType<typeof lstat>>;
          try {
            current = await lstat(recoveryKeyOutputPath);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
            throw error;
          }
          if (
            current.isSymbolicLink() ||
            current.dev !== writtenIdentity.dev ||
            current.ino !== writtenIdentity.ino
          ) {
            if (recoveryKeyFileAnnounced) {
              // Announced, and not provably ours any more. Say it is still
              // there rather than throwing: a rollback that aborts here would
              // report an incomplete cleanup for a file it must not touch.
              cleanupSummary.preservedRecoveryFile = recoveryKeyOutputPath;
              return;
            }
            throw new Error("recovery-key output changed before init rollback");
          }
          await unlink(recoveryKeyOutputPath);
          const parent = await open(dirname(recoveryKeyOutputPath), "r");
          try {
            await parent.sync();
          } finally {
            await parent.close();
          }
          if (recoveryKeyFileAnnounced) {
            cleanupSummary.removedAnnouncedRecoveryFile = recoveryKeyOutputPath;
          }
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary init: recovery key output unavailable: ${message}\n`);
      throw err;
    }
  }

  let envelope: CustodyEnvelope = await fencedInit(
    lease,
    deps,
    "custody-envelope",
    () => writeCustodyEnvelope(
      storage,
      {
        v: 1,
        install_mode: interactive ? "interactive" : "headless",
        wraps,
        created_at: new Date().toISOString(),
      },
      masterKey,
    ),
  );

  // Write the Principal Policy the runtime reads and `sanctuary doctor`
  // checks for. The runtime (principal-policy/loader.ts loadPrincipalPolicy)
  // treats a missing file as first boot and self-heals from the SAME default
  // template, so init writing it changes no policy semantics; it only stops a
  // freshly initialized fortress from reporting a doctor FAIL whose remedy
  // ("run sanctuary init") had already been performed. One writer, one
  // template: writeDefaultPrincipalPolicyFile.
  //
  // Placed AFTER the custody-envelope commit on purpose: everything written
  // before it must stay inside the inert scaffold that
  // isFreshFortressOrExactLockScaffold recognizes, so a killed init is still
  // retryable. Failure mode from the outside: a policy file that never lands
  // looks like a clean init until the first doctor run, so a write failure
  // here fails the init rather than warning.
  const principalPolicy = await fencedInit(lease, deps, "principal-policy", () =>
    writeDefaultPrincipalPolicyFile(lockedFortressPath),
  );

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary init`);
  console.error(`  Fortress: ${fortressPath}\n`);
  // The writer NEVER overwrites an existing policy, so on `--force` over a
  // fortress that already had one, init's silence read as "init wrote the
  // default policy" while the file on disk was the pre-existing one. An init
  // that did not write the policy it is credited with says so out loud; the
  // operator's approval tiers are decided by that file.
  if (!principalPolicy.written) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      // Printed in the operator's own terms (the fortress path they named, as
      // the Fortress line above prints it), not the lock's stable capability
      // path, which is the same directory reached through a canonical route
      // and differs textually on some platforms.
      `  Principal policy: kept the existing file at\n    ${principalPolicyPath(fortressPath)}\n` +
        `  It was NOT rewritten, so this fortress runs the approval tiers that file already\n` +
        `  defines, not the Sanctuary defaults. Delete it and re-run init if you want the\n` +
        `  default policy.\n`,
    );
  }

  // Disclose first (the banner naming the external recovery file written
  // above), then force re-entry verification on the interactive path. The
  // file is never `<fortress>/recovery-key.txt`: init resolved an
  // outside-the-fortress destination before any custody material was minted. Verification is end-to-end: the
  // re-entered key must actually unwrap the master.
  //
  // Init phase boundary: this attended prompt remains inside the fresh-fortress
  // custody claim because releasing it after writing an unverified envelope
  // would let a competing init/reset mutate the exact envelope being verified.
  // The operator's re-entry wait is intentionally unbounded and visible; the
  // holder is therefore the crash-recoverable kernel lock (not an existence
  // file), so process death releases ownership. No network/download work occurs
  // in this phase. Potentially unbounded model download/local-intelligence work
  // is deliberately deferred until AFTER this custody callback returns
  // (runPostLockLocalSetup below).
  try {
    if (!interactive) {
      // Headless: do NOT call discloseRecoveryKey. The key was prewritten to an
      // external destination before the custody-envelope commit. Calling the
      // disclosure helper here would print the full key to stderr. Print only
      // the durable external destination.
      if (!prewrittenRecoveryKeyFile) {
        throw new Error(
          "headless init requires a prewritten external recovery-key file; path selection failed",
        );
      }
      if (
        resolve(prewrittenRecoveryKeyFile.filePath) !== recoveryKeyOutputPath ||
        !prewrittenRecoveryKeyFile.written
      ) {
        throw new Error(
          "headless init requires a newly written recovery-key file at the selected external path",
        );
      }
      // The file exists at this point (written + verified above), so naming it
      // is a statement about something real, never a path the operator would
      // go looking for and not find.
      // Announced BEFORE the print, never after: from the operator's side the
      // file is theirs the instant the path reaches their terminal, and a
      // failure between the print and the flip would let rollback unlink it.
      recoveryKeyFileAnnounced = true;
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Sanctuary init: recovery key written to:\n    ${prewrittenRecoveryKeyFile.filePath}\n` +
          `  Move it off-host (password manager, encrypted backup), then delete this file\n` +
          `  from this host. Keep it outside the fortress directory.\n`,
      );
    } else {
      // Interactive: existing banner disclosure and end-to-end re-entry
      // verification. The operator is present at a TTY.
      const disclosureOptions: Parameters<typeof discloseRecoveryKey>[0] = {
        recoveryKey,
        storagePath: fortressPath,
        fortressId,
        mode: "no-confirm", // capture/verification below replaces the Y/N prompt
        recoveryKeyFilePath: recoveryKeyOutputPath,
        // The announced bit flips INSIDE the helper, at the instant the
        // banner prints, not after this call returns. fencedInit re-asserts
        // the lease after its mutation, so a holder loss there used to throw
        // between "the operator has seen the key and its path" and "the
        // rollback knows not to delete it", and rollback then unlinked the
        // only plaintext copy of a key the banner had just told them to save.
        onBeforeBannerPrint: () => {
          recoveryKeyFileAnnounced = true;
        },
      };
      if (!prewrittenRecoveryKeyFile) {
        throw new Error("recovery-key output file was not captured");
      }
      disclosureOptions.prewrittenFile = prewrittenRecoveryKeyFile;
      await fencedInit(lease, deps, "recovery-key-disclosure", async () => {
        const disclosed = await discloseRecoveryKey(disclosureOptions);
        // Test-only window: the banner has printed and the old code had not
        // yet flipped the announced bit. A throw here is what the fence's own
        // post-mutation assertHeld would do on holder loss.
        await deps.__testAfterRecoveryKeyBannerPrinted?.();
        return disclosed;
      });
      await (deps.verifyRecoveryKeyReentry ?? verifyRecoveryKeyReentry)({
        // Say only what is true at this instant. Re-entry proves the key
        // unwraps the master; identity seeding and this vault's Castle Wall
        // key provisioning still follow, and a failure in either used to leave
        // the operator holding a bare "Recovery key verified." from a run
        // that then died.
        verifiedMessage: INIT_RECOVERY_KEY_VERIFIED_MESSAGE,
        check: async (entered) => {
          try {
            envelope = await fencedInit(
              lease,
              deps,
              "recovery-wrap-verification",
              () => verifyRecoveryWrapByReentry(storage, envelope, entered),
            );
            return true;
          } catch {
            return false;
          }
        },
      });
    }
  } catch (err) {
    if (
      err instanceof RecoveryKeyConfirmationDeclinedError ||
      err instanceof RecoveryKeyConfirmationNonInteractiveError ||
      err instanceof RecoveryKeyReentryMismatchError
    ) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary init: ${err.message}\n`);
      throw err;
    }
    throw err;
  }

  // Custody audit trail: envelope creation, and the explicit headless mode
  // when --no-confirm was used (a distinct, audited install path — never a
  // silent relaxation of the interactive one). Lenient integrity mode: a
  // `--force` re-init over an old fortress leaves a foreign audit chain
  // (encrypted under the previous master) that the fresh master cannot
  // verify; init must still record its custody entries. Nothing is
  // repaired or deleted — the old chain stays on disk.
  const auditLog = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
  await fencedInit(lease, deps, "audit-custody-created", () => auditLog.appendCritical({
    layer: "l2",
    operation: "custody_envelope_created",
    identity_id: fortressId,
    result: "success",
    details: {
      install_mode: envelope.install_mode,
      wrap_types: envelope.wraps.map((w) => w.type),
      verified_wraps: envelope.wraps.filter((w) => w.verified).length,
      origin: "init",
    },
  }));
  if (!interactive) {
    await fencedInit(lease, deps, "audit-headless-install", () => auditLog.appendCritical({
      layer: "l2",
      operation: "custody_headless_install",
      identity_id: fortressId,
      result: "success",
      details: {
        source: "sanctuary-init",
        flag: "--no-confirm",
      },
    }));
  }

  // Default operator identity seed. Every Tier-1 operator-signed surface
  // (federation admin verbs, did:web, exit) needs a default operator
  // identity, and a fortress with none is a half-provisioned state. By
  // default init mints ONE Ed25519 operator identity under the fortress's
  // EXISTING custody: the private key is encrypted with the master-derived
  // "identity-encryption" purpose key (the same key sign() decrypts under),
  // so the existing master-key recovery/escrow path recovers it too: no new
  // independently-orphanable secret, nothing written to disk in plaintext.
  // --no-identity (or SANCTUARY_INIT_NO_IDENTITY) skips it. Reuses the
  // existing createIdentity + IdentityManager.saveNew primitives; no new
  // crypto. A defensive guard (below) skips minting if a default identity is
  // already visible under the current master; note a normal --force re-init
  // derives a NEW master, so the prior identity is invisible (not skipped) and
  // a fresh "operator" identity is minted under the new custody.
  const skipIdentity = resolveNoIdentity(options);
  if (skipIdentity) {
    await fencedInit(lease, deps, "audit-identity-skip", () => auditLog.appendCritical({
      layer: "l2",
      operation: "operator_identity_seed_skipped",
      identity_id: fortressId,
      result: "success",
      details: {
        source: "sanctuary-init",
        reason: options.noIdentity ? "--no-identity" : "SANCTUARY_INIT_NO_IDENTITY",
      },
    }));
  } else {
    try {
      const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
      try {
        const identityManager = new IdentityManager(storage, masterKey);
        await identityManager.load();
        const existing = identityManager.getDefault();
        if (existing) {
          // Defensive: skip minting if a default operator identity is already
          // visible under the CURRENT master. Not reachable via a normal
          // `runInit` (a fresh init has an empty fortress, and a --force
          // re-init derives a brand-new random master under which the prior
          // `_identities` blobs cannot decrypt, so getDefault() returns
          // undefined), but this guards any future path that seeds under an
          // already-established master.
          await fencedInit(lease, deps, "audit-existing-identity", () => auditLog.appendCritical({
            layer: "l2",
            operation: "operator_identity_seed_skipped",
            identity_id: fortressId,
            result: "success",
            details: {
              source: "sanctuary-init",
              reason: "default-operator-identity-already-exists",
              existing_identity_id: existing.identity_id,
            },
          }));
          // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
          console.error(
            `\n  Sanctuary init: a default operator identity already exists` +
              ` (${existing.identity_id}); leaving it unchanged.\n`,
          );
        } else {
          const { storedIdentity } = createIdentity(
            "operator",
            identityEncKey,
            passphrase ? "passphrase" : "recovery-key",
          );
          await fencedInit(lease, deps, "operator-identity", () =>
            identityManager.saveNew(storedIdentity),
          );
          await fencedInit(lease, deps, "audit-identity-seeded", () => auditLog.appendCritical({
            layer: "l2",
            operation: "operator_identity_seeded",
            identity_id: fortressId,
            result: "success",
            details: {
              source: "sanctuary-init",
              seeded_identity_id: storedIdentity.identity_id,
              label: "operator",
            },
          }));
        }
      } finally {
        // Zero the symmetric key that wraps the new private key as soon as it
        // has done its job (success, the skip path, or error), mirroring how
        // the raw private key is zeroed inside createIdentity. masterKey
        // itself is zeroed on the error path below and on the success path
        // after the fortress-local Castle key provisioning.
        identityEncKey.fill(0);
      }
    } catch (err) {
      // Fail-closed (AGENTS.md #5): never leave a half-provisioned fortress
      // with custody but no operator identity when the operator did not opt
      // out. --no-identity is the only supported way to skip the seed.
      const message = err instanceof Error ? err.message : String(err);
      await fencedInit(lease, deps, "audit-identity-failure-flush", () => auditLog.flush());
      masterKey.fill(0);
      // ONE truth about what is on disk, decided by whether this throw is
      // about to be rolled back.
      //
      // Without --force the outer handler restores the fresh-fortress
      // scaffold: the custody envelope, the policy, and the identity store
      // are all removed, so custody is NOT intact and `identity create`
      // against this path would fail. Saying so here and having
      // printInitCleanupSummary immediately say the opposite is how an
      // operator ends up running a command that cannot work. On that path
      // this site prints only the cause, and the cleanup summary is the
      // single place that states what survives and what to do next.
      //
      // With --force rollback is deliberately skipped (a --force re-init has
      // already overwritten a prior fortress; unwinding would destroy state
      // that was never this run's to restore), so the custody envelope and
      // the disclosed recovery key really are intact and the two
      // remediations below are the ones that work.
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        options.force
          ? `\n  Sanctuary init: failed to seed the default operator identity:` +
              ` ${message}\n` +
              `  Nothing was rolled back (--force). The fortress custody was provisioned` +
              ` and the recovery key shown above is valid, but it has NO operator` +
              ` identity yet. To finish, do ONE of:\n` +
              `    - add the identity to this existing fortress (custody is intact):\n` +
              `        sanctuary identity create --fortress ${fortressPath}\n` +
              `    - OR start over with a fresh master (this DISCARDS the recovery key` +
              ` shown above; a new one will be minted):\n` +
              `        sanctuary init --force --fortress ${fortressPath}\n` +
              `  A plain \`sanctuary init\` re-run will refuse: this fortress directory` +
              ` is no longer empty.\n`
          : `\n  Sanctuary init: failed to seed the default operator identity:` +
              ` ${message}\n`,
      );
      throw new Error(`operator identity seed failed: ${message}`, {
        cause: err,
      });
    }
  }

  // Local intelligence may prompt a human or download a runtime/model. Never
  // hold the custody/master lock across that unbounded interaction. Transfer
  // only an owned master copy into a post-lock closure and scrub it on every
  // outcome; its own provisioning/config locks serialize the writes it makes.
  const setupMaster = new Uint8Array(masterKey);
  localSetupMaster = setupMaster;
  deps.observeSecretBuffer?.("local-setup-master", setupMaster);
  runPostLockLocalSetup = async () => {
    const postLockAudit = new AuditLog(storage, setupMaster, { integrityMode: "lenient" });
    try {
      const localSetup = deps.runLocalIntelligenceSetup ?? runLocalIntelligenceSetup;
      const outcome = await localSetup({
        storage,
        masterKey: setupMaster,
        auditLog: postLockAudit,
        identityId: fortressId,
        preAnswered: options.provisionLocalIntelligence,
        ...(options.modelManifestPath === undefined
          ? {}
          : { modelManifestPath: options.modelManifestPath }),
        isTty: process.stdin.isTTY === true,
        // SAFETY: stderr is the operator-facing CLI channel for this subcommand.
        print: (line) => console.error(`  ${line}`),
      });
      if (outcome.kind === "not-requested") {
        // Nothing was read, recorded, or degraded: this run never asked. The
        // line is informational, never a failure the operator must act on.
        // SAFETY: stderr is the operator-facing init channel; no logger exists yet.
        console.error(
          `  Local intelligence was not set up; ${LOCAL_INTELLIGENCE_OPT_IN_HINT}.`,
        );
      } else if (outcome.kind === "refused") {
        // SAFETY: stderr is the operator-facing init channel; no logger exists yet.
        console.error(`  Local intelligence remains DEGRADED (${outcome.reason}).`);
      }
    } catch (err) {
      // SAFETY: stderr is the operator-facing init channel; no logger exists yet.
      console.error(
        `  Note: local intelligence setup did not complete (${err instanceof Error ? err.message : String(err)}); ` +
          `the fortress remains initialized and local surfaces remain DEGRADED.`,
      );
    } finally {
      try {
        await postLockAudit.flush();
      } finally {
        setupMaster.fill(0);
      }
    }
  };
  // Castle Wall provisioning for THIS FORTRESS.
  //
  // INVARIANT (one anchor writer, 2026-09-09): init mints this fortress's own
  // Castle key pair and writes the fortress-local `castle-pinned-pubkey.bin`.
  // It does not read, compare, or write the machine-wide enforcement anchor.
  // In production the Castle Wall daemon signs through the ROOT SIGNER HELPER
  // and the trust anchor is DEFINED as "machine-wide pin == signer-helper key"
  // (cli/install.ts parseTrustAnchor), so an init-time publication of a
  // fortress-local key there contradicted that definition: on a fresh Mac it
  // wrote a key the arm step then had to overwrite, and on any Mac that had
  // ever been armed it refused, so `sanctuary init` could not create a first
  // vault at all. Turning the wall ON for this vault is a separate, confirmed
  // operator step (`castle-wall re-pin`, then arm), and it is the only thing
  // that touches the machine-wide anchor.
  //
  // Failure mode from the outside if this is ever re-added: `init` on an
  // upgrader's Mac refuses with trust-anchor vocabulary on the operator's very
  // first command, and the fortress it half-built is rolled back.
  const skipPin = resolveNoPin(options);
  if (skipPin) {
    await fencedInit(lease, deps, "audit-pin-skip", () => auditLog.appendCritical({
      layer: "l2",
      operation: "castle_pin_provision_skipped",
      identity_id: fortressId,
      result: "success",
      details: {
        source: "sanctuary-init",
        reason: options.noPin ? "--no-pin" : "SANCTUARY_INIT_NO_PIN",
      },
    }));
  }

  // The named wall state for THIS VAULT, persisted as an explicit token rather
  // than left as an absence: every consumer used to infer wall state from
  // host-wide facts (an activated system extension, a machine-wide pin file),
  // and none of those is a claim about a vault. `not_yet_walled` is the only
  // value anything ever writes; `walled` is derived at read time from the
  // helper-authoritative anchor verdict AND this fortress's own arm evidence.
  // See castle-wall/provision-state.ts.
  await fencedInit(lease, deps, "castle-wall-provision-state", () =>
    storage.write(
      "_meta",
      CASTLE_WALL_PROVISION_META_KEY,
      stringToBytes(CASTLE_WALL_NOT_YET_WALLED),
    ),
  );
  // The init decision is audited with the SAME operation name the skip uses;
  // the reason string is what tells a later reader which decision was made. A
  // new operation name would be a new audit surface for no added meaning.
  await fencedInit(lease, deps, "audit-castle-wall-provision-state", () =>
    auditLog.appendCritical({
      layer: "l2",
      operation: "castle_pin_provision_skipped",
      identity_id: fortressId,
      result: "success",
      details: {
        source: "sanctuary-init",
        reason: "init-does-not-touch-machine-wide-anchor",
      },
    }),
  );
  await fencedInit(lease, deps, "audit-final-flush", () => auditLog.flush());

  if (skipPin) {
    const skipSource = options.noPin ? "--no-pin" : "SANCTUARY_INIT_NO_PIN";
    // DEPRECATION, not a behavior branch. The flag and the environment variable
    // are still PARSED and still ACCEPTED (the acceptance kit and the install
    // docs pass them, and an operator's saved command must not start failing),
    // but there is nothing left for them to skip: default init already leaves
    // the machine-wide anchor alone. Keep the parser; say so once.
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary init: ${skipSource} is accepted but no longer does anything.\n` +
        `  Creating a vault never changes this Mac's Castle Wall settings, with or\n` +
        `  without that option. You can stop passing it.\n`,
    );
  }

  {
    type PinExecution = number | {
      code: number;
      stdout: string;
      stderr: string;
      warnings: string[];
    };
    const pinExecution = await fencedInit<PinExecution>(
      lease,
      deps,
      "fortress-castle-key",
      async () => {
        // The injected implementation is a test seam and must remain observable
        // in the parent. Production uses the inode-bound worker so its
        // per-fortress pin write cannot be redirected by a root replacement.
        if (deps.provisionPin) {
          return provisionPin([], {
            out: new Writable({
              write(_chunk, _encoding, callback) {
                callback();
              },
            }),
            env: {
              ...process.env,
              SANCTUARY_STORAGE_PATH: lockedFortressPath,
              SANCTUARY_RECOVERY_KEY: recoveryKey,
            },
          });
        }
        if (lease.stableFortressCapability) {
          return lease.stableFortressCapability.provisionPin({
            masterKey,
          });
        }
        return runProvisionPinAlreadyLocked([], {
          out: new Writable({
            write(_chunk, _encoding, callback) {
              callback();
            },
          }),
          env: {
            ...process.env,
            SANCTUARY_STORAGE_PATH: lockedFortressPath,
          },
          __resolvedProvisionMasterKey: masterKey,
        });
      },
    );
    const pinResult = typeof pinExecution === "number"
      ? pinExecution
      : pinExecution.code;
    if (typeof pinExecution !== "number") {
      // SAFETY: stderr is the operator-facing init channel; no logger exists yet.
      if (pinExecution.stderr) console.error(pinExecution.stderr.trimEnd());
      for (const warning of pinExecution.warnings) console.warn(warning);
    }
    if (pinResult !== 0) {
      // This step is now purely fortress-local (mint a key pair, write two
      // files under the fortress root), so a non-zero exit means the FORTRESS
      // could not be provisioned, not that some other install owns a
      // machine-wide file. MUST-NEVER #5: fail, never degrade.
      throw new Error(
        `Castle Wall key provisioning failed for this fortress (exit ${pinResult}); ` +
          "the fortress-local Castle key pair was not created",
      );
    }
    // The one operator sentence about the wall, in the words of someone who has
    // not yet met the word "pin".
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary init: your vault is created.\n` +
        `  ${CASTLE_WALL_NOT_YET_WALLED_SENTENCE}\n`,
    );
  }

  masterKey.fill(0);
  for (const mutation of keychainMutations) mutation.commit();
  return {
    fortressPath,
    recoveryKeyDisclosurePath: recoveryKeyOutputPath,
  };
  } finally {
    recoveryKeyBytes?.fill(0);
    masterKey.fill(0);
  }
      } catch (error) {
        if (!options.force) {
          // A lost lease means another process may already own the namespace;
          // never race its work with rollback. Ordinary failures retain the
          // live lease and restore every external side effect plus the exact
          // inert filesystem scaffold, making a plain retry safe.
          lease.assertHeld();
          let rollbackFailure: unknown;
          for (const rollback of [...externalRollback].reverse()) {
            try {
              await rollback();
            } catch (rollbackError) {
              rollbackFailure ??= rollbackError;
            }
          }
          for (const mutation of [...keychainMutations].reverse()) {
            try {
              await mutation.rollback();
            } catch (rollbackError) {
              rollbackFailure ??= rollbackError;
            }
          }
          const files = lease.stableFortressFiles;
          if (!files) {
            throw new Error(
              "fresh-init rollback requires an inode-bound fortress file capability",
              { cause: error },
            );
          }
          // CUSTODY REMOVAL. Everything in `afterCustodyRemovalRollback` waits
          // on this succeeding; see the ordering invariant where that list is
          // declared. Failure mode from the outside if this is reordered: the
          // announced recovery key is gone and the custody it unwrapped is
          // still on disk, so the operator has destroyed their only recovery
          // factor for a fortress that survived — and the summary says the
          // opposite.
          let custodyRemoved = true;
          try {
            await files.restoreFreshLockScaffold(CUSTODY_WRITE_LOCK_FILE);
          } catch (rollbackError) {
            custodyRemoved = false;
            rollbackFailure ??= rollbackError;
          }
          if (custodyRemoved) {
            for (const rollback of [...afterCustodyRemovalRollback].reverse()) {
              try {
                await rollback();
              } catch (rollbackError) {
                rollbackFailure ??= rollbackError;
              }
            }
          } else if (writtenRecoveryKeyFilePath !== null) {
            // Keep the key. It is the only thing that can still open whatever
            // custody survived, and the summary's `preservedRecoveryFile`
            // branch is the one sentence that says so.
            cleanupSummary.preservedRecoveryFile = writtenRecoveryKeyFilePath;
          }
          lease.assertHeld();
          // Record what this run undid so the outer handler can say it in one
          // line.
          //
          // What restoreFreshLockScaffold actually removes (see
          // storage/fresh-fortress.ts): every entry under the fortress root
          // except `state/`, the reset-history log and its quarantine files;
          // every entry under `state/` except `_meta/`; and every entry under
          // `state/_meta/` except the custody lock file. It is scoped to the
          // fortress root and never follows a link out of it, so the fortress
          // directory itself, its siblings, and the external recovery-key file
          // survive. It is NOT scoped to authorship: it removes anything at
          // those paths, including a same-uid file that appeared after the
          // under-lock freshness check, because that check is what proves the
          // root was empty when this init claimed it. The refusal guards ahead
          // of it (symlink, non-directory, changed lock scaffold) are what keep
          // that reach safe.
          cleanupSummary.rolledBack = true;
          cleanupSummary.rollbackIncomplete = rollbackFailure !== undefined;
          if (rollbackFailure) {
            throw new AggregateError(
              [error, rollbackFailure],
              "fresh init failed and rollback did not complete",
              { cause: error },
            );
          }
        }
        throw error;
      }
    },
    {
      metadata: { owner: "sanctuary-init" },
      ...(deps.__testAfterKernelHolderAcquired !== undefined
        ? { __testAfterKernelHolderAcquired: deps.__testAfterKernelHolderAcquired }
        : {}),
    },
  ).catch((err: unknown) => {
    // A late lock-phase failure can happen after the setup copy is created but
    // before its post-lock closure is eligible to run.
    localSetupMaster?.fill(0);
    printInitCleanupSummary(fortressPath, cleanupSummary);
    throw err;
  });
  try {
    await runPostLockLocalSetup?.();
    // The ONLY completion claim in this command, and it is reachable only
    // after every step that can fail has run. Anything printed earlier
    // (including recovery-key verification) describes that moment, not the
    // ceremony.
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  ${INIT_COMPLETE_MESSAGE} Fortress ${result.fortressPath} is built,` +
        ` and its recovery key is at ${result.recoveryKeyDisclosurePath}.\n`,
    );
    return result;
  } finally {
    // The post-lock closure normally owns this scrub. Keep an outer lifetime
    // fence as well so every normal and exceptional completion is covered.
    localSetupMaster?.fill(0);
  }
}

export interface ParsedInitArgs extends InitOptions {
  helpRequested?: boolean;
}

export function parseInitArgs(argv: string[]): ParsedInitArgs {
  const opts: ParsedInitArgs = {};
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--fortress":
        opts.fortress = argv[++i];
        break;
      case "--force":
        opts.force = true;
        break;
      case "--no-confirm":
        opts.noConfirm = true;
        break;
      case "--no-pin":
        opts.noPin = true;
        break;
      case "--no-identity":
        opts.noIdentity = true;
        break;
      case "--provision-local-intelligence":
        opts.provisionLocalIntelligence = true;
        break;
      case "--no-provision-local-intelligence":
        opts.provisionLocalIntelligence = false;
        break;
      case "--model-manifest":
        opts.modelManifestPath = readRequiredPathArg(argv, i, "--model-manifest");
        i++;
        break;
      case "--recovery-out":
        opts.recoveryOut = readRequiredPathArg(argv, i, "--recovery-out");
        i++;
        break;
      case "--help":
      case "-h":
        opts.helpRequested = true;
        break;
    }
  }
  return opts;
}

function readRequiredPathArg(
  argv: string[],
  index: number,
  flag: string,
): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new Error(`${flag} requires a path value`);
  }
  return value;
}

export function printInitHelp(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(`
sanctuary init. Create a fresh Sanctuary fortress at a chosen path.

Usage:
  sanctuary init [options]

Options:
  --fortress <path>    Fortress directory (default: ~/.sanctuary). Honors
                       SANCTUARY_FORTRESS_PATH and SANCTUARY_STORAGE_PATH
                       env vars in that order; the flag wins over both.
  --force              Allow init against a non-empty directory.
  --no-confirm         Skip the recovery-key Y/N confirmation. Required
                       for non-TTY callers (CI, launchd, systemd).
  --recovery-out <path>
                       Write the plaintext recovery key to this exact path.
                       The path must resolve outside the fortress directory.
                       Also honors SANCTUARY_RECOVERY_OUT when this flag is
                       absent. Without either, init writes the key to
                       "<parent of fortress>/Sanctuary Recovery/
                       <fortress-id>-recovery-key.txt" (directory mode 0700,
                       file mode 0600). The key is NEVER written inside the
                       fortress it protects.
  --no-pin             Accepted, does nothing. Creating a vault never
                       changes this Mac's Castle Wall settings, so there is
                       nothing for this option to skip. It stays accepted so
                       saved commands keep working. Also settable via
                       SANCTUARY_INIT_NO_PIN=1.
  --no-identity        Do NOT seed the default operator identity. Default
                       init mints one Ed25519 operator identity under the
                       fortress's existing custody so federation admin verbs
                       work from a stock init; use this for a custody-only
                       fortress and add an identity later with
                       \`sanctuary identity create\`. Also settable via
                       SANCTUARY_INIT_NO_IDENTITY=1.
  --provision-local-intelligence
                       Enter the disclosed local-model setup ceremony. The
                       plan and TTY confirmation still precede any mutation.
  --no-provision-local-intelligence
                       Decline local-model setup without printing a plan.
  --model-manifest <path>
                       With --provision-local-intelligence: verify an
                       operator-supplied signed model manifest instead of the
                       one packaged with this release. Same pinned catalog
                       root, parser, and byte cap; nothing is fetched.
  --help, -h           Show this help.

What init does:
  1. Creates the fortress directory with mode 0700.
  2. Generates a random 32-byte master key, stored ONLY as encrypted wraps
     in the custody envelope. The recovery key is a wrap of that master —
     it unlocks everything the fortress holds (state, identity, Castle pin).
  3. Enrolls a second custody factor on interactive installs: an OS-keyring
     custody key when available, else a passphrase from SANCTUARY_PASSPHRASE.
  4. Writes the recovery key mode 0600 to --recovery-out, or to the default
     staging path beside the fortress, and (interactive) prints it in a
     bordered banner with save-then-delete instructions, then requires you to
     re-enter it — the re-entered key must actually unwrap the master.
     Single-issuance: an existing recovery-key file is never overwritten.
  5. With --no-confirm: records an explicit, audited headless install
     (custody_headless_install in the audit log) instead of the
     re-entry verification.
  6. Seeds the default operator identity (a single Ed25519 key encrypted
     under the fortress's existing custody) unless --no-identity (or
     SANCTUARY_INIT_NO_IDENTITY) is set. This is the identity every Tier-1
     operator-signed surface (federation admin verbs, did:web, exit) signs
     with. Idempotent: an existing default identity is left unchanged.
  7. Writes the default principal-policy.yaml, the approval-gate policy the
     runtime loads at startup and \`sanctuary doctor\` checks for.
  8. Creates this vault's own Castle Wall key pair, inside the fortress
     directory, and records that the vault is not yet on the Castle Wall of
     this Mac. Init never reads or changes this Mac's Castle Wall settings:
     turning the wall on for a vault is a separate step you run when you
     mean to, and it is the installer's next action.

After init:
  - Run \`sanctuary wrap --fortress <path>\` to bind the fortress to an
    agent harness.
  - Or set SANCTUARY_RECOVERY_KEY and run \`sanctuary\` (stdio MCP) or
    \`sanctuary dashboard\` directly against the fortress path.
`);
}
