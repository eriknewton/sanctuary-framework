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
 * Honors --force, --no-confirm. The recovery key is fully disclosed via
 * the shared helper at server/src/wrap/recovery-key-disclosure.ts.
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
  type DiscloseRecoveryKeyResult,
} from "./recovery-key-disclosure.js";
import {
  DEFAULT_STORAGE_DIR,
  formatFortressPathWritableError,
  preflightFortressPathWritable,
} from "../paths.js";
import {
  runProvisionPin,
  runProvisionPinAlreadyLocked,
} from "../cli/castle-wall.js";
import { mkdirSafeUnderRoot } from "./config-reader.js";
import { runLocalIntelligenceSetup } from "./local-intelligence.js";
// The dependency-free consent leaf, not the `intelligence` barrel: this file
// is on the CLI boot path and must not pull the selector graph in for one
// string. Must match the flag names parsed below.
import { LOCAL_INTELLIGENCE_OPT_IN_HINT } from "../intelligence/provisioning-consent.js";
import type { CrossProcessLockLease } from "../storage/cross-process-lock.js";
import { kernelBackedCrossProcessLockPlatformSupported } from "../storage/cross-process-lock.js";

/**
 * Operator-facing display path of the machine-wide Castle Wall enforcement
 * anchor that default init provisions (and --no-pin skips). Kept in sync with
 * server/src/cli/castle-wall.ts CASTLE_GLOBAL_PINNED_PUBKEY_PATH; used only
 * for the --no-pin notice, never for I/O here.
 */
const GLOBAL_CASTLE_PIN_PATH =
  "/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin";

export interface InitOptions {
  /** Operator-supplied fortress path. Wins over env + default. */
  fortress?: string;
  /** Skip the recovery-key Y/N confirmation. Required for non-TTY callers. */
  noConfirm?: boolean;
  /** Allow init against a non-empty directory. Refuses without this flag. */
  force?: boolean;
  /**
   * Exact plaintext recovery-key destination. When set, the key is written
   * here instead of <fortress>/recovery-key.txt. Must be outside fortress.
   */
  recoveryOut?: string;
  /**
   * Skip the Castle Wall global-pin provisioning step. Default init writes
   * the machine-wide enforcement anchor at
   * /Library/Application Support/Sanctuary/castle-pinned-pubkey, so a
   * test/isolated fortress would silently touch the host-wide trust anchor.
   * With this flag set, init provisions NO global pin and prints a notice
   * telling the operator to run `sanctuary castle-wall provision-pin`
   * explicitly when ready. Also settable via SANCTUARY_INIT_NO_PIN=1 for
   * non-interactive harnesses. Default behavior (no flag) is unchanged.
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
 * Explicit opt-in values for SANCTUARY_INIT_NO_PIN. Skipping the host-wide
 * Castle Wall pin is a security-relevant downgrade, so the env var is an
 * allowlist (NOT "anything truthy"): only these exact values opt out. A
 * typo, an inherited shell value, or `no`/`off` therefore does NOT silently
 * disable global-pin provisioning.
 */
const NO_PIN_ENV_OPT_IN = new Set(["1", "true", "yes", "on"]);

/**
 * Resolve whether the Castle Wall global-pin step should be skipped.
 * Precedence: the --no-pin CLI flag wins; otherwise SANCTUARY_INIT_NO_PIN
 * opts out only when set to an explicit allowlisted value (1/true/yes/on,
 * case-insensitive). Default is to provision the pin exactly as before.
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
 * Relative paths resolve against cwd.
 */
export function resolveFortressPath(
  options: { fortress?: string },
  env: NodeJS.ProcessEnv = process.env,
  home: string = homedir(),
): string {
  const flag = options.fortress?.trim();
  if (flag && flag.length > 0) {
    return isAbsolute(flag) ? flag : resolve(process.cwd(), flag);
  }
  const fortressEnv = env.SANCTUARY_FORTRESS_PATH;
  if (fortressEnv && fortressEnv.length > 0) {
    return isAbsolute(fortressEnv)
      ? fortressEnv
      : resolve(process.cwd(), fortressEnv);
  }
  const storageEnv = env.SANCTUARY_STORAGE_PATH;
  if (storageEnv && storageEnv.length > 0) {
    return isAbsolute(storageEnv)
      ? storageEnv
      : resolve(process.cwd(), storageEnv);
  }
  return join(home, DEFAULT_STORAGE_DIR);
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
 * Test seam: lets tests observe/replace the global-pin provisioning call so
 * they can prove `--no-pin` never invokes it (and default init does), without
 * writing to the real machine-wide anchor. Not part of the CLI surface.
 */
export interface RunInitDeps {
  provisionPin?: typeof runProvisionPin;
  /** Test seam: inject a mock OS-keyring backend for recovery-key storage. */
  recoveryKeychain?: KeychainCustodyOptions;
  /** Test seam: simulate a race immediately before recovery-file O_EXCL capture. */
  beforeRecoveryKeyOutputWrite?: (filePath: string) => void | Promise<void>;
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
  let recoveryKeyOutputPath: string | undefined;
  try {
    recoveryKeyOutputPath = resolveRecoveryKeyOutputPath({
      recoveryOut: options.recoveryOut,
      storagePath: fortressPath,
      env: process.env,
    });
    if (recoveryKeyOutputPath) {
      await preflightRecoveryKeyOutputFile(recoveryKeyOutputPath);
    }
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
  await deps.beforeCustodyLockAcquire?.();

  const storage = new FilesystemStorage(`${fortressPath}/state`);
  let runPostLockLocalSetup: (() => Promise<void>) | undefined;
  let localSetupMaster: Uint8Array | undefined;
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

  if (!recoveryKeyOutputPath) {
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
  if (recoveryKeyOutputPath) {
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
        externalRollback.push(async () => {
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
            throw new Error("recovery-key output changed before init rollback");
          }
          await unlink(recoveryKeyOutputPath);
          const parent = await open(dirname(recoveryKeyOutputPath), "r");
          try {
            await parent.sync();
          } finally {
            await parent.close();
          }
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary init: recovery key output unavailable: ${message}\n`);
      throw err;
    }
  } else if (lease.stableFortressCapability) {
    const result = await fencedInit(
      lease,
      deps,
      "recovery-key-file",
      () => lease.stableFortressCapability!.writeRecoveryKey(
        recoveryKey,
        fortressId,
      ),
    );
    prewrittenRecoveryKeyFile = {
      filePath: join(fortressPath, "recovery-key.txt"),
      written: result.written,
    };
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

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary init`);
  console.error(`  Fortress: ${fortressPath}\n`);

  // Disclose first (banner + recovery-key.txt), then force re-entry
  // verification on the interactive path. Verification is end-to-end: the
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
  let disclosure: DiscloseRecoveryKeyResult;
  try {
    const disclosureOptions: Parameters<typeof discloseRecoveryKey>[0] = {
      recoveryKey,
      storagePath: recoveryKeyOutputPath ? fortressPath : lockedFortressPath,
      fortressId,
      mode: "no-confirm", // capture/verification below replaces the Y/N prompt
    };
    if (!recoveryKeyOutputPath && lockedFortressPath !== fortressPath) {
      // Linux writes through the inode-bound /proc/self/fd capability, but that
      // ephemeral descriptor path must never be disclosed as recovery guidance.
      disclosureOptions.operatorFilePath = join(
        fortressPath,
        "recovery-key.txt",
      );
    }
    if (recoveryKeyOutputPath) {
      if (!prewrittenRecoveryKeyFile) {
        throw new Error("custom recovery-key output was not captured");
      }
      disclosureOptions.recoveryKeyFilePath = recoveryKeyOutputPath;
    }
    if (prewrittenRecoveryKeyFile) {
      disclosureOptions.prewrittenFile = prewrittenRecoveryKeyFile;
    }
    disclosure = await fencedInit(lease, deps, "recovery-key-disclosure", () =>
      discloseRecoveryKey(disclosureOptions),
    );
    if (interactive && !recoveryKeyOutputPath && disclosure.fileWritten) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        "\n  WARNING: the only plaintext recovery-key copy currently lives inside\n" +
          "  the fortress directory. It will be lost if that directory is cleared;\n" +
          "  a later master rotation also mints a new recovery key.\n" +
          "  Re-run with --recovery-out <path outside the fortress>, or move this\n" +
          "  file now.\n",
      );
    }
    if (interactive && !recoveryKeyOutputPath && !disclosure.fileWritten) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        "\n  WARNING: the default recovery-key.txt already existed and was not\n" +
          "  overwritten. It may contain a prior recovery key. The authoritative\n" +
          "  new recovery key is the one shown above and re-entered now; save\n" +
          "  that key outside the fortress.\n",
      );
    }
    if (interactive) {
      await verifyRecoveryKeyReentry({
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
        // after pin provisioning.
        identityEncKey.fill(0);
      }
    } catch (err) {
      // Fail-closed (AGENTS.md #5): never leave a half-provisioned fortress
      // with custody but no operator identity when the operator did not opt
      // out. --no-identity is the only supported way to skip the seed.
      const message = err instanceof Error ? err.message : String(err);
      await fencedInit(lease, deps, "audit-identity-failure-flush", () => auditLog.flush());
      masterKey.fill(0);
      // Honesty (Finding 2, 2026-06-25): the custody envelope and the recovery
      // key just shown are already written and INTACT at this point; only the
      // operator-identity seed failed. The old message said "Re-run init", but
      // a plain `init` re-run REFUSES (the fortress dir is now non-empty) and a
      // `--force` re-init mints a brand-new random master, ORPHANING the
      // recovery key the operator was just told to save. Give the two
      // remediations that actually work and do not contradict the
      // non-empty/--force guards.
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Sanctuary init: failed to seed the default operator identity:` +
          ` ${message}\n` +
          `  The fortress custody was provisioned and the recovery key shown above` +
          ` is valid, but it has NO operator identity yet. To finish, do ONE of:\n` +
          `    - add the identity to this existing fortress (custody is intact):\n` +
          `        sanctuary identity create --fortress ${fortressPath}\n` +
          `    - OR start over with a fresh master (this DISCARDS the recovery key` +
          ` shown above; a new one will be minted):\n` +
          `        sanctuary init --force --fortress ${fortressPath}\n` +
          `  A plain \`sanctuary init\` re-run will refuse: this fortress directory` +
          ` is no longer empty.\n`,
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
  // Castle Wall global-pin provisioning. By default init writes the
  // machine-wide enforcement anchor; --no-pin (or SANCTUARY_INIT_NO_PIN)
  // skips it so a test/isolated fortress never silently touches the
  // host-wide trust anchor. The skip is audited, not silent.
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
  await fencedInit(lease, deps, "audit-final-flush", () => auditLog.flush());

  if (skipPin) {
    const skipSource = options.noPin ? "--no-pin" : "SANCTUARY_INIT_NO_PIN";
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `\n  Sanctuary init: global Castle Wall pin NOT provisioned (${skipSource}).\n` +
        `  This fortress did NOT touch the machine-wide enforcement anchor at\n` +
        `    ${GLOBAL_CASTLE_PIN_PATH}\n` +
        `  Run \`sanctuary castle-wall provision-pin\` against this fortress when ready.\n`,
    );
  } else {
    type PinExecution = number | {
      code: number;
      stdout: string;
      stderr: string;
      warnings: string[];
    };
    const pinExecution = await fencedInit<PinExecution>(
      lease,
      deps,
      "hostwide-castle-pin",
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
      throw new Error("Castle Wall provision-pin auto-bootstrap failed");
    }
  }

  masterKey.fill(0);
  for (const mutation of keychainMutations) mutation.commit();
  return {
    fortressPath,
    recoveryKeyDisclosurePath:
      recoveryKeyOutputPath ?? join(fortressPath, "recovery-key.txt"),
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
          try {
            await files.restoreFreshLockScaffold(CUSTODY_WRITE_LOCK_FILE);
          } catch (rollbackError) {
            rollbackFailure ??= rollbackError;
          }
          lease.assertHeld();
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
    throw err;
  });
  try {
    await runPostLockLocalSetup?.();
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
                       Write the plaintext recovery key to this exact path
                       instead of <fortress>/recovery-key.txt. The path must
                       be outside the fortress directory. Also honors
                       SANCTUARY_RECOVERY_OUT when this flag is absent.
  --no-pin             Do NOT provision the machine-wide Castle Wall pin.
                       Default init writes the host-wide enforcement anchor
                       at /Library/Application Support/Sanctuary/; use this
                       for a test or side-by-side isolated fortress so it
                       never touches that anchor. The skip is audited, and
                       init prints a reminder to run
                       \`sanctuary castle-wall provision-pin\` when ready.
                       Also settable via SANCTUARY_INIT_NO_PIN=1 for
                       non-interactive harnesses.
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
  4. Prints the full recovery key in a bordered banner AND writes it to
     <fortress>/recovery-key.txt mode 0600, or to --recovery-out when set,
     with explicit move-off-host instructions, then (interactive) requires
     you to re-enter it — the re-entered key must actually unwrap the
     master. Single-issuance: existing recovery-key files are never
     overwritten.
  5. With --no-confirm: records an explicit, audited headless install
     (custody_headless_install in the audit log) instead of the
     re-entry verification.
  6. Seeds the default operator identity (a single Ed25519 key encrypted
     under the fortress's existing custody) unless --no-identity (or
     SANCTUARY_INIT_NO_IDENTITY) is set. This is the identity every Tier-1
     operator-signed surface (federation admin verbs, did:web, exit) signs
     with. Idempotent: an existing default identity is left unchanged.
  7. Provisions the machine-wide Castle Wall pin (the host-wide enforcement
     anchor) unless --no-pin (or SANCTUARY_INIT_NO_PIN) is set, in which
     case it records an audited castle_pin_provision_skipped entry and
     prints a reminder to provision the pin explicitly when ready.

After init:
  - Run \`sanctuary wrap --fortress <path>\` to bind the fortress to an
    agent harness.
  - Or set SANCTUARY_RECOVERY_KEY and run \`sanctuary\` (stdio MCP) or
    \`sanctuary dashboard\` directly against the fortress path.
`);
}
