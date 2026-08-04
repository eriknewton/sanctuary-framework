/**
 * Sanctuary MCP Server -- `sanctuary checkpoint` CLI subcommand.
 *
 * Operator-facing surface for local memory checkpoints: create encrypted
 * content-addressed StateStore export snapshots, list/show plaintext metadata,
 * and prune expired local checkpoint directories. Checkpoint creation is
 * ROUTINE and never opens a network or fleet-sync path.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";

import { StateStore } from "../cognitive/state-store.js";
import { IdentityManager } from "../cognitive/tools.js";
import type { StoredIdentity } from "../core/identity.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { loadConfig, type SanctuaryConfig } from "../config.js";
import { AuditLog } from "../operational/audit-log.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  CHECKPOINT_RETENTION_ENV,
  MemoryCheckpointStore,
  createCheckpoint,
  nodeMemoryCheckpointFsOps,
  pruneExpiredCheckpoints,
  type MemoryCheckpointRecord,
} from "../memory-checkpoint/index.js";

export interface CheckpointCommandArgs {
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

function positionalArgs(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--fortress" || arg === "--passphrase") {
      i++;
      continue;
    }
    if (arg === "--json" || arg === "--help" || arg === "-h") continue;
    if (arg.startsWith("-")) continue;
    out.push(arg);
  }
  return out;
}

function printUsage(out: Writable): void {
  write(
    out,
    `Usage: sanctuary checkpoint <command> [options]

Local encrypted memory checkpoints for exportable StateStore namespaces.

Commands:
  create     Create an on-demand checkpoint. ROUTINE, audited.
  list       List checkpoint metadata. Read-only.
  show <id>  Show one checkpoint record. Read-only.
  prune      Delete checkpoints whose retention expiry has passed. Audited.

Run "sanctuary checkpoint <command> --help" for command-specific options.
`,
  );
}

function printCreateHelp(out: Writable): void {
  write(
    out,
    `sanctuary checkpoint create. Create a local encrypted memory checkpoint.

Usage:
  sanctuary checkpoint create [--fortress <path>] [--passphrase <val>]

Options:
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.

Environment:
  SANCTUARY_PASSPHRASE          Key derivation passphrase.
  SANCTUARY_RECOVERY_KEY        Recovery key alternative to passphrase.
  ${CHECKPOINT_RETENTION_ENV}  Retention window, default 30d; "off" means no expiry.
`,
  );
}

function printListHelp(out: Writable): void {
  write(
    out,
    `sanctuary checkpoint list. List local memory checkpoints.

Usage:
  sanctuary checkpoint list [--json] [--fortress <path>] [--passphrase <val>]

Options:
  --json              Output as JSON.
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.
`,
  );
}

function printShowHelp(out: Writable): void {
  write(
    out,
    `sanctuary checkpoint show. Show one checkpoint metadata record.

Usage:
  sanctuary checkpoint show <checkpoint-id> [--json] [--fortress <path>] \\
    [--passphrase <val>]

Options:
  --json              Output as JSON.
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.
`,
  );
}

function printPruneHelp(out: Writable): void {
  write(
    out,
    `sanctuary checkpoint prune. Delete expired local memory checkpoints.

Usage:
  sanctuary checkpoint prune [--fortress <path>] [--passphrase <val>]

Options:
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.
`,
  );
}

export async function runCheckpointCommand(
  args: CheckpointCommandArgs,
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
  const rest = argv.slice(1);
  switch (command) {
    case "create":
      if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
        printCreateHelp(out);
        return 0;
      }
      return cmdCreate(rest, out, err, env);
    case "list":
      if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
        printListHelp(out);
        return 0;
      }
      return cmdList(rest, out, err, env);
    case "show":
      if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
        printShowHelp(out);
        return 0;
      }
      return cmdShow(rest, out, err, env);
    case "prune":
      if (hasFlag(rest, "--help") || hasFlag(rest, "-h")) {
        printPruneHelp(out);
        return 0;
      }
      return cmdPrune(rest, out, err, env);
    default:
      write(err, `Unknown checkpoint command: ${command}\n`);
      printUsage(err);
      return 2;
  }
}

interface Bootstrapped {
  config: SanctuaryConfig;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  stateStore: StateStore;
  auditLog: AuditLog;
  checkpointStore: MemoryCheckpointStore;
  primary: StoredIdentity;
}

/**
 * Shared bootstrap for every checkpoint subcommand: resolves the fortress
 * storage path, derives the master key from a passphrase or recovery key,
 * loads the primary identity, and wires the StateStore, AuditLog, and real
 * checkpoint FsOps over `<fortress>/checkpoints/`.
 */
async function bootstrap(
  argv: string[],
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<Bootstrapped | null> {
  const fortressFlag = flagValue(argv, "--fortress");
  if (fortressFlag) {
    process.env.SANCTUARY_STORAGE_PATH = fortressFlag;
  }

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;

  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: sanctuary checkpoint requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n",
    );
    return null;
  }

  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const stateStoragePath = join(config.storage_path, "state");
  const storage = new FilesystemStorage(stateStoragePath);

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
        : "No identities found in this fortress. Run `sanctuary identity create` first.\n",
    );
    return null;
  }
  const primary = identityManager.getDefault();
  if (!primary) {
    write(err, "No primary identity set.\n");
    return null;
  }

  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const checkpointStore = new MemoryCheckpointStore({
    fortressPath: config.storage_path,
    fsOps: nodeMemoryCheckpointFsOps,
  });

  return {
    config,
    storage,
    masterKey,
    stateStore,
    auditLog,
    checkpointStore,
    primary,
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function renderRecord(record: MemoryCheckpointRecord): string {
  const namespaceLines = Object.entries(record.completeness_summary.per_namespace)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(
      ([namespace, item]) =>
        `  ${namespace}: items=${item.item_count} content_sha256=${item.content_sha256}`,
    )
    .join("\n");
  return (
    `${record.id}\n` +
    `  created_at: ${record.created_at}\n` +
    `  source: ${record.source}\n` +
    `  namespaces: ${record.namespaces.join(", ") || "(none)"}\n` +
    `  total_keys: ${record.total_keys}\n` +
    `  bundle_hash: ${record.bundle_hash}\n` +
    `  retention_expires_at: ${record.retention_expires_at ?? "none"}\n` +
    `  format_version: ${record.format_version}\n` +
    (namespaceLines.length > 0 ? `  per_namespace:\n${namespaceLines}\n` : "")
  );
}

async function cmdCreate(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const boot = await bootstrap(argv, err, env);
  if (!boot) return 1;

  try {
    const record = await createCheckpoint({
      stateStore: boot.stateStore,
      store: boot.checkpointStore,
      masterKey: boot.masterKey,
      auditLog: boot.auditLog,
      identityId: boot.primary.identity_id,
      source: "on_demand",
      retentionValue: env[CHECKPOINT_RETENTION_ENV],
    });
    write(out, `Checkpoint created: ${record.id}\n`);
    write(out, `  namespaces: ${record.namespaces.join(", ") || "(none)"}\n`);
    write(out, `  total_keys: ${record.total_keys}\n`);
    write(out, `  retention_expires_at: ${record.retention_expires_at ?? "none"}\n`);
    return 0;
  } catch (createErr) {
    write(err, `Error: checkpoint create failed. ${errorMessage(createErr)}\n`);
    return 1;
  }
}

async function cmdList(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const json = hasFlag(argv, "--json");
  const boot = await bootstrap(argv, err, env);
  if (!boot) return 1;

  try {
    const records = await boot.checkpointStore.list();
    if (json) {
      write(out, `${JSON.stringify(records, null, 2)}\n`);
      return 0;
    }
    if (records.length === 0) {
      write(out, "No memory checkpoints.\n");
      return 0;
    }
    for (const record of records) {
      write(
        out,
        `${record.id}  created_at=${record.created_at}  source=${record.source}  ` +
          `namespaces=${record.namespaces.length}  total_keys=${record.total_keys}  ` +
          `retention_expires_at=${record.retention_expires_at ?? "none"}\n`,
      );
    }
    return 0;
  } catch (listErr) {
    write(err, `Error: checkpoint list failed. ${errorMessage(listErr)}\n`);
    return 1;
  }
}

async function cmdShow(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const json = hasFlag(argv, "--json");
  const id = positionalArgs(argv)[0];
  if (!id) {
    write(err, "Usage: sanctuary checkpoint show <checkpoint-id> [--json]\n");
    return 2;
  }

  const boot = await bootstrap(argv, err, env);
  if (!boot) return 1;

  try {
    const record = await boot.checkpointStore.get(id);
    if (!record) {
      write(err, `No such checkpoint: ${id}\n`);
      return 1;
    }
    write(
      out,
      json ? `${JSON.stringify(record, null, 2)}\n` : renderRecord(record),
    );
    return 0;
  } catch (showErr) {
    write(err, `Error: checkpoint show failed. ${errorMessage(showErr)}\n`);
    return 1;
  }
}

async function cmdPrune(
  argv: string[],
  out: Writable,
  err: Writable,
  env: NodeJS.ProcessEnv,
): Promise<number> {
  const boot = await bootstrap(argv, err, env);
  if (!boot) return 1;

  try {
    const prunedIds = await pruneExpiredCheckpoints({
      store: boot.checkpointStore,
      auditLog: boot.auditLog,
      identityId: boot.primary.identity_id,
      now: new Date(),
    });
    write(out, `Pruned ${prunedIds.length} memory checkpoint(s).\n`);
    for (const id of prunedIds) {
      write(out, `  ${id}\n`);
    }
    return 0;
  } catch (pruneErr) {
    write(err, `Error: checkpoint prune failed. ${errorMessage(pruneErr)}\n`);
    return 1;
  }
}
