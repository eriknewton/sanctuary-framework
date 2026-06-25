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

import { mkdir, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join, isAbsolute, resolve } from "node:path";
import { Writable } from "node:stream";

import { tightenStoragePermissions } from "../storage/permissions.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { generateRandomKey } from "../core/random.js";
import { toBase64url } from "../core/encoding.js";
import {
  wrapMasterWithRecoveryKey,
  wrapMasterWithPassphrase,
  wrapMasterWithKeychainKey,
  writeCustodyEnvelope,
  verifyRecoveryWrapByReentry,
  type CustodyEnvelope,
  type CustodyWrap,
} from "../core/master-custody.js";
import {
  getOrCreateKeychainCustodyKey,
  storeRecoveryKeyInKeychain,
  type KeychainCustodyOptions,
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
import { runProvisionPin } from "../cli/castle-wall.js";

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

async function isDirectoryEmpty(path: string): Promise<boolean> {
  try {
    const entries = await readdir(path);
    return entries.length === 0;
  } catch {
    // Path does not exist; treat as empty (we will mkdir).
    return true;
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
  /** Test seam: simulate a race after preflight but before O_EXCL capture. */
  beforeRecoveryKeyOutputWrite?: (filePath: string) => void | Promise<void>;
}

export async function runInit(
  options: InitOptions,
  deps: RunInitDeps = {},
): Promise<InitResult> {
  const provisionPin = deps.provisionPin ?? runProvisionPin;
  const fortressPath = resolveFortressPath(options);
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
    const empty = await isDirectoryEmpty(fortressPath);
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
  await tightenStoragePermissions(fortressPath);

  const storage = new FilesystemStorage(`${fortressPath}/state`);

  // Unified custody (master-custody.ts): one master per fortress, stored
  // only as wraps. The recovery key is a WRAP of the true master — never a
  // second, parallel master (the 2026-06-12 incident class).
  const masterKey = generateRandomKey();
  const recoveryKeyBytes = generateRandomKey();
  const recoveryKey = toBase64url(recoveryKeyBytes);
  const fortressId = fortressIdFromStoragePath(fortressPath);

  const wraps: CustodyWrap[] = [
    wrapMasterWithRecoveryKey(masterKey, recoveryKeyBytes, {
      // Interactive installs verify by operator re-entry below; headless
      // installs stay unverified (the audited degraded mode records that).
      verified: false,
    }),
  ];
  recoveryKeyBytes.fill(0);

  await storeRecoveryKeyInKeychain(
    fortressPath,
    recoveryKey,
    deps.recoveryKeychain
  );

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
    const keychainKey = await getOrCreateKeychainCustodyKey(fortressPath);
    if (keychainKey) {
      wraps.push(wrapMasterWithKeychainKey(masterKey, keychainKey, { verified: true }));
      keychainKey.fill(0);
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
  }

  let prewrittenRecoveryKeyFile:
    | Awaited<ReturnType<typeof writeRecoveryKeyFile>>
    | undefined;
  if (recoveryKeyOutputPath) {
    try {
      await deps.beforeRecoveryKeyOutputWrite?.(recoveryKeyOutputPath);
      prewrittenRecoveryKeyFile = await writeRecoveryKeyFile({
        storagePath: fortressPath,
        recoveryKeyFilePath: recoveryKeyOutputPath,
        recoveryKey,
        fortressId,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`\n  Sanctuary init: recovery key output unavailable: ${message}\n`);
      throw err;
    }
  }

  let envelope: CustodyEnvelope = await writeCustodyEnvelope(
    storage,
    {
      v: 1,
      install_mode: interactive ? "interactive" : "headless",
      wraps,
      created_at: new Date().toISOString(),
    },
    masterKey
  );

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`\n  Sanctuary init`);
  console.error(`  Fortress: ${fortressPath}\n`);

  // Disclose first (banner + recovery-key.txt), then force re-entry
  // verification on the interactive path. Verification is end-to-end: the
  // re-entered key must actually unwrap the master.
  let disclosure: DiscloseRecoveryKeyResult;
  try {
    const disclosureOptions: Parameters<typeof discloseRecoveryKey>[0] = {
      recoveryKey,
      storagePath: fortressPath,
      fortressId,
      mode: "no-confirm", // capture/verification below replaces the Y/N prompt
    };
    if (recoveryKeyOutputPath) {
      if (!prewrittenRecoveryKeyFile) {
        throw new Error("custom recovery-key output was not captured");
      }
      disclosureOptions.recoveryKeyFilePath = recoveryKeyOutputPath;
      disclosureOptions.prewrittenFile = prewrittenRecoveryKeyFile;
    }
    disclosure = await discloseRecoveryKey(disclosureOptions);
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
            envelope = await verifyRecoveryWrapByReentry(storage, envelope, entered);
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
  await auditLog.appendCritical({
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
  });
  if (!interactive) {
    await auditLog.appendCritical({
      layer: "l2",
      operation: "custody_headless_install",
      identity_id: fortressId,
      result: "success",
      details: {
        source: "sanctuary-init",
        flag: "--no-confirm",
      },
    });
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
    await auditLog.appendCritical({
      layer: "l2",
      operation: "operator_identity_seed_skipped",
      identity_id: fortressId,
      result: "success",
      details: {
        source: "sanctuary-init",
        reason: options.noIdentity ? "--no-identity" : "SANCTUARY_INIT_NO_IDENTITY",
      },
    });
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
          await auditLog.appendCritical({
            layer: "l2",
            operation: "operator_identity_seed_skipped",
            identity_id: fortressId,
            result: "success",
            details: {
              source: "sanctuary-init",
              reason: "default-operator-identity-already-exists",
              existing_identity_id: existing.identity_id,
            },
          });
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
          await identityManager.saveNew(storedIdentity);
          await auditLog.appendCritical({
            layer: "l2",
            operation: "operator_identity_seeded",
            identity_id: fortressId,
            result: "success",
            details: {
              source: "sanctuary-init",
              seeded_identity_id: storedIdentity.identity_id,
              label: "operator",
            },
          });
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
      await auditLog.flush();
      masterKey.fill(0);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(
        `\n  Sanctuary init: failed to seed the default operator identity:` +
          ` ${message}\n  The fortress was NOT fully provisioned. Re-run init,` +
          ` or pass --no-identity to create a custody-only fortress and add an` +
          ` identity later with \`sanctuary identity create\`.\n`,
      );
      throw new Error(`operator identity seed failed: ${message}`);
    }
  }
  // Castle Wall global-pin provisioning. By default init writes the
  // machine-wide enforcement anchor; --no-pin (or SANCTUARY_INIT_NO_PIN)
  // skips it so a test/isolated fortress never silently touches the
  // host-wide trust anchor. The skip is audited, not silent.
  const skipPin = resolveNoPin(options);
  if (skipPin) {
    await auditLog.appendCritical({
      layer: "l2",
      operation: "castle_pin_provision_skipped",
      identity_id: fortressId,
      result: "success",
      details: {
        source: "sanctuary-init",
        reason: options.noPin ? "--no-pin" : "SANCTUARY_INIT_NO_PIN",
      },
    });
  }
  await auditLog.flush();
  masterKey.fill(0);

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
    const pinResult = await provisionPin([], {
      out: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
      env: {
        ...process.env,
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_RECOVERY_KEY: recoveryKey,
      },
    });
    if (pinResult !== 0) {
      throw new Error("Castle Wall provision-pin auto-bootstrap failed");
    }
  }

  return {
    fortressPath,
    recoveryKeyDisclosurePath: disclosure.filePath,
  };
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
