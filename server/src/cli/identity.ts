/**
 * Sanctuary MCP Server -- `sanctuary identity` CLI subcommand
 *
 * Identity inspection and creation. Requires a passphrase or recovery key
 * because identities are encrypted at rest under the master key.
 *
 * Verbs:
 *   - `show`    Print the active identity DID, identity_id, public key, and
 *               storage path. Defaults to the primary identity.
 *   - `create`  Mint a new Ed25519 operator identity under the fortress's
 *               existing custody. The first identity becomes the primary
 *               (default) one. For a fortress that already has a default
 *               identity, this adds an additional labeled identity without
 *               touching the primary.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { FilesystemStorage } from "../storage/filesystem.js";
import { IdentityManager } from "../cognitive/tools.js";
import { createIdentity } from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { loadConfig } from "../config.js";
import {
  consumeFlagValue,
  flagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";

export interface IdentityCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
}

function write(stream: Writable, text: string): void {
  stream.write(text);
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
  create         Mint a new operator identity under the fortress custody.

Options:
  --label <l>         Label for the new identity (create only; default
                      "operator").
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
required to decrypt, display, or create identity information.
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

  if (command === "create") {
    if (hasFlag(argv.slice(1), "--help") || hasFlag(argv.slice(1), "-h")) {
      printIdentityCreateHelp(out);
      return 0;
    }
    return await cmdCreate(argv.slice(1), out, err, env);
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

export function printIdentityCreateHelp(out: Writable = process.stdout): void {
  write(
    out,
    `sanctuary identity create. Mint a new operator identity for a fortress.

Usage:
  sanctuary identity create [--label <l>] [--fortress <path>] [--json]

Description:
  Mints a new Ed25519 operator identity. The private key is encrypted at rest
  under the fortress's existing master-derived custody (the same key the
  fortress recovery path recovers), so no separate orphanable secret is
  created and nothing is written to disk in plaintext. The FIRST identity in a
  fortress becomes the primary (default) one that federation admin verbs,
  did:web, and exit sign with. Running create on a fortress that already has a
  default identity adds an additional labeled identity and leaves the primary
  unchanged. A passphrase or recovery key is required.

Options:
  --label <l>         Label for the new identity (default "operator").
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --json              Output as JSON.
  --help, -h          Show this help.

Environment:
  SANCTUARY_PASSPHRASE    Key derivation passphrase.
  SANCTUARY_RECOVERY_KEY  Recovery key alternative to passphrase.

Examples:
  sanctuary identity create
  sanctuary identity create --label operator --fortress ~/.sanctuary-work
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
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // identity operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  if (consumedFortress.value !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;
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

async function cmdCreate(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv
): Promise<number> {
  const json = hasFlag(argv, "--json");
  const label = flagValue(argv, "--label")?.trim() || "operator";

  // Resolve fortress path: --fortress flag > env > default.
  // loadConfig() reads process.env.SANCTUARY_STORAGE_PATH directly.
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value must
  // refuse, never silently resolve the default fortress; wrong-fortress
  // identity operations are a constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  if (consumedFortress.value !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;
  }

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;

  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary identity create requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n"
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

    try {
      const identityManager = new IdentityManager(storage, masterKey);
      // Load any existing identities so we can report whether this is the
      // first (becomes primary) and so saveNew's conflict check has the
      // current set.
      await identityManager.load();
      const hadDefault = identityManager.getDefault() !== undefined;

      // The private key is encrypted under derivePurposeKey(master,
      // "identity-encryption"), the same custody the fortress recovery
      // path recovers (constraint 6: never written to disk in plaintext,
      // no separate orphanable secret). The custody floor is enforced
      // inside save() for every new identity.
      const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
      let storedIdentity;
      try {
        ({ storedIdentity } = createIdentity(
          label,
          identityEncKey,
          passphrase ? "passphrase" : "recovery-key",
        ));
        await identityManager.saveNew(storedIdentity);
      } finally {
        // Zero the symmetric key that wraps the new private key as soon as
        // it has done its job (success or error), mirroring how the raw
        // private key is zeroed inside createIdentity. masterKey itself is
        // zeroed by the outer finally below.
        identityEncKey.fill(0);
      }

      const isPrimary =
        identityManager.getPrimaryIdentityId() === storedIdentity.identity_id;

      if (json) {
        write(
          out,
          JSON.stringify(
            {
              identity_id: storedIdentity.identity_id,
              did: storedIdentity.did,
              public_key: storedIdentity.public_key,
              label: storedIdentity.label,
              key_type: storedIdentity.key_type,
              created_at: storedIdentity.created_at,
              storage_path: config.storage_path,
              is_primary: isPrimary,
            },
            null,
            2
          ) + "\n"
        );
      } else {
        write(out, `Created operator identity.\n`);
        write(out, `identity_id:  ${storedIdentity.identity_id}\n`);
        write(out, `did:          ${storedIdentity.did}\n`);
        write(out, `public_key:   ${storedIdentity.public_key}\n`);
        write(out, `label:        ${storedIdentity.label}\n`);
        write(out, `key_type:     ${storedIdentity.key_type}\n`);
        write(out, `created_at:   ${storedIdentity.created_at}\n`);
        write(out, `storage_path: ${config.storage_path}\n`);
        write(out, `is_primary:   ${isPrimary}\n`);
        if (!isPrimary && hadDefault) {
          write(
            out,
            `\nNote: this fortress already had a default identity, so the new\n` +
              `identity was added without changing the primary. Run\n` +
              `"sanctuary identity show" to see the active (primary) identity.\n`
          );
        }
      }

      return 0;
    } finally {
      masterKey.fill(0);
    }
  } catch (error) {
    write(
      err,
      error instanceof Error ? `Error: ${error.message}\n` : `Error: ${String(error)}\n`
    );
    return 1;
  }
}
