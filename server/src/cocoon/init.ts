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
 * the shared helper at server/src/cocoon/recovery-key-disclosure.ts.
 */

import { mkdir, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join, isAbsolute, resolve } from "node:path";

import { tightenStoragePermissions } from "../storage/permissions.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { generateRandomKey } from "../core/random.js";
import { hashToString } from "../core/hashing.js";
import { stringToBytes, toBase64url } from "../core/encoding.js";
import {
  discloseRecoveryKey,
  RecoveryKeyConfirmationDeclinedError,
  RecoveryKeyConfirmationNonInteractiveError,
} from "./recovery-key-disclosure.js";
import { DEFAULT_STORAGE_DIR } from "../paths.js";

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

  await mkdir(fortressPath, { recursive: true, mode: 0o700 });
  await tightenStoragePermissions(fortressPath);

  const storage = new FilesystemStorage(`${fortressPath}/state`);

  const masterKey = generateRandomKey();
  const recoveryKey = toBase64url(masterKey);
  const keyHash = hashToString(masterKey);
  await storage.write("_meta", "recovery-key-hash", stringToBytes(keyHash));

  console.error(`\n  Sanctuary init`);
  console.error(`  Fortress: ${fortressPath}\n`);

  try {
    const disclosure = await discloseRecoveryKey({
      recoveryKey,
      storagePath: fortressPath,
      mode: options.noConfirm ? "no-confirm" : "interactive",
    });
    return {
      fortressPath,
      recoveryKeyDisclosurePath: disclosure.filePath,
    };
  } catch (err) {
    if (
      err instanceof RecoveryKeyConfirmationDeclinedError ||
      err instanceof RecoveryKeyConfirmationNonInteractiveError
    ) {
      console.error(`\n  Sanctuary init: ${err.message}\n`);
      throw err;
    }
    throw err;
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
      case "--help":
      case "-h":
        opts.helpRequested = true;
        break;
    }
  }
  return opts;
}

export function printInitHelp(): void {
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
  2. Generates a random 32-byte master key. The base64url-encoded form is
     the recovery key.
  3. Persists the recovery-key hash so subsequent boots can verify the
     key the operator supplies.
  4. Prints the full recovery key in a bordered banner AND writes it to
     <fortress>/recovery-key.txt mode 0600 with explicit move-off-host
     instructions. Single-issuance: existing recovery-key.txt is never
     overwritten.

After init:
  - Run \`sanctuary wrap --fortress <path>\` to bind the fortress to an
    agent harness.
  - Or set SANCTUARY_RECOVERY_KEY and run \`sanctuary\` (stdio MCP) or
    \`sanctuary dashboard\` directly against the fortress path.
`);
}
