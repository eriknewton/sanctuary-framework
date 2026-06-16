/**
 * Sanctuary MCP Server -- `sanctuary identity` CLI subcommand
 *
 * Read-only identity inspection. Requires passphrase because identities
 * are encrypted at rest under the master key.
 *
 * Verbs:
 *   - `show`  Print the active identity DID, identity_id, public key, and
 *             storage path. Defaults to the primary identity.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { FilesystemStorage } from "../storage/filesystem.js";
import { IdentityManager } from "../cognitive/tools.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { loadConfig } from "../config.js";

export interface IdentityCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function flagValue(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary identity <command> [options]

Commands:
  show           Print the active identity (DID, identity_id, public key).

Options:
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --json              Output as JSON.
  --help, -h          Show this help.

Environment variables:
  SANCTUARY_PASSPHRASE    Key derivation passphrase.
  SANCTUARY_STORAGE_PATH  State directory (default: ~/.sanctuary).
  SANCTUARY_FORTRESS_PATH Operator-friendly alias for STORAGE_PATH.
  SANCTUARY_RECOVERY_KEY  Recovery key (alternative to passphrase).

Identity data is encrypted at rest. A passphrase or recovery key is
required to decrypt and display identity information.
`
  );
}

export async function runIdentityCommand(
  args: IdentityCommandArgs
): Promise<number> {
  const argv = args.argv;
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printUsage(out);
    return 0;
  }

  const command = argv[0]!;

  if (command === "show") {
    if (hasFlag(argv.slice(1), "--help") || hasFlag(argv.slice(1), "-h")) {
      printIdentityShowHelp(out);
      return 0;
    }
    return await cmdShow(argv.slice(1), out, err, env);
  }

  write(err, `Unknown identity command: ${command}\n`);
  write(err, `Run "sanctuary identity --help" for usage.\n`);
  return 2;
}

export function printIdentityShowHelp(out: Writable = process.stdout): void {
  write(
    out,
    `sanctuary identity show. Display the active identity for a fortress.

Usage:
  sanctuary identity show [--fortress <path>] [--json]

Description:
  Decrypts and prints the active identity DID, identity_id, public key, and
  storage path. Identity data is encrypted at rest, so a passphrase or recovery
  key is required for normal execution.

Options:
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --json              Output as JSON.
  --help, -h          Show this help.

Environment:
  SANCTUARY_PASSPHRASE    Key derivation passphrase.
  SANCTUARY_RECOVERY_KEY  Recovery key alternative to passphrase.

Examples:
  sanctuary identity show
  sanctuary identity show --fortress ~/.sanctuary-work --json
`
  );
}

async function cmdShow(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  const json = hasFlag(argv, "--json");

  // Resolve fortress path: --fortress flag > env > default.
  // loadConfig() reads process.env.SANCTUARY_STORAGE_PATH directly.
  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
  }

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;

  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary identity show requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n"
    );
    return 1;
  }

  try {
    const config = await loadConfig();
    await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
    const stateStoragePath = join(config.storage_path, "state");
    const storage = new FilesystemStorage(stateStoragePath);

    // Unified custody (master-custody.ts): never derive a fortress master verb-locally.
    const masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: config.storage_path,
    });

    const identityManager = new IdentityManager(storage, masterKey);
    const loadResult = await identityManager.load();

    if (loadResult.loaded === 0) {
      write(
        err,
        loadResult.total > 0
          ? "Error: identity files found but none could be decrypted. Wrong passphrase?\n"
          : "No identities found in this fortress.\n"
      );
      return 1;
    }

    const primary = identityManager.getDefault();
    if (!primary) {
      write(err, "No primary identity set.\n");
      return 1;
    }

    if (json) {
      write(
        out,
        JSON.stringify(
          {
            identity_id: primary.identity_id,
            did: primary.did,
            public_key: primary.public_key,
            label: primary.label,
            key_type: primary.key_type,
            created_at: primary.created_at,
            storage_path: config.storage_path,
            total_identities: loadResult.loaded,
          },
          null,
          2
        ) + "\n"
      );
    } else {
      write(out, `identity_id:      ${primary.identity_id}\n`);
      write(out, `did:              ${primary.did}\n`);
      write(out, `public_key:       ${primary.public_key}\n`);
      write(out, `label:            ${primary.label}\n`);
      write(out, `key_type:         ${primary.key_type}\n`);
      write(out, `created_at:       ${primary.created_at}\n`);
      write(out, `storage_path:     ${config.storage_path}\n`);
      write(out, `total_identities: ${loadResult.loaded}\n`);
    }

    return 0;
  } catch (error) {
    write(
      err,
      error instanceof Error ? `Error: ${error.message}\n` : `Error: ${String(error)}\n`
    );
    return 1;
  }
}
