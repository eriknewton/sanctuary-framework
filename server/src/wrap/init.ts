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
import { getOrCreateKeychainCustodyKey } from "./keychain-custody.js";
import { AuditLog } from "../l2-operational/audit-log.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  discloseRecoveryKey,
  verifyRecoveryKeyReentry,
  RecoveryKeyConfirmationDeclinedError,
  RecoveryKeyConfirmationNonInteractiveError,
  RecoveryKeyReentryMismatchError,
} from "./recovery-key-disclosure.js";
import { DEFAULT_STORAGE_DIR } from "../paths.js";
import { runProvisionPin } from "../cli/castle-wall.js";

export interface InitOptions {
  /** Operator-supplied fortress path. Wins over env + default. */
  fortress?: string;
  /** Skip the recovery-key Y/N confirmation. Required for non-TTY callers. */
  noConfirm?: boolean;
  /** Allow init against a non-empty directory. Refuses without this flag. */
  force?: boolean;
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

export async function runInit(options: InitOptions): Promise<InitResult> {
  const fortressPath = resolveFortressPath(options);

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

  const wraps: CustodyWrap[] = [
    wrapMasterWithRecoveryKey(masterKey, recoveryKeyBytes, {
      // Interactive installs verify by operator re-entry below; headless
      // installs stay unverified (the audited degraded mode records that).
      verified: false,
    }),
  ];
  recoveryKeyBytes.fill(0);

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
  let disclosure: { filePath: string };
  try {
    disclosure = await discloseRecoveryKey({
      recoveryKey,
      storagePath: fortressPath,
      fortressId: fortressIdFromStoragePath(fortressPath),
      mode: "no-confirm", // capture/verification below replaces the Y/N prompt
    });
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
    identity_id: fortressIdFromStoragePath(fortressPath),
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
      identity_id: fortressIdFromStoragePath(fortressPath),
      result: "success",
      details: {
        source: "sanctuary-init",
        flag: "--no-confirm",
      },
    });
  }
  await auditLog.flush();
  masterKey.fill(0);

  const pinResult = await runProvisionPin({
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
      case "--help":
      case "-h":
        opts.helpRequested = true;
        break;
    }
  }
  return opts;
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
  --help, -h           Show this help.

What init does:
  1. Creates the fortress directory with mode 0700.
  2. Generates a random 32-byte master key, stored ONLY as encrypted wraps
     in the custody envelope. The recovery key is a wrap of that master —
     it unlocks everything the fortress holds (state, identity, Castle pin).
  3. Enrolls a second custody factor on interactive installs: an OS-keyring
     custody key when available, else a passphrase from SANCTUARY_PASSPHRASE.
  4. Prints the full recovery key in a bordered banner AND writes it to
     <fortress>/recovery-key.txt mode 0600 with explicit move-off-host
     instructions, then (interactive) requires you to re-enter it — the
     re-entered key must actually unwrap the master. Single-issuance:
     existing recovery-key.txt is never overwritten.
  5. With --no-confirm: records an explicit, audited headless install
     (custody_headless_install in the audit log) instead of the
     re-entry verification.

After init:
  - Run \`sanctuary wrap --fortress <path>\` to bind the fortress to an
    agent harness.
  - Or set SANCTUARY_RECOVERY_KEY and run \`sanctuary\` (stdio MCP) or
    \`sanctuary dashboard\` directly against the fortress path.
`);
}
