/**
 * Sanctuary MCP Server -- `sanctuary results` and `sanctuary local` CLI subcommands.
 *
 * Operator-only access to the local model's results and the operator log.
 * Both verbs refuse without an unlocked fortress. Every export and delete
 * writes its operator-log row before the effect; when the row fails, the
 * effect does not happen.
 */

import { constants } from "node:fs";
import { open, rm, type FileHandle } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";

import { loadConfig } from "../config.js";
import { FORTRESS_STATE_DIRECTORY } from "../core/custody-markers.js";
import { resolveCliMasterKey, withCliMasterKeySession } from "../core/master-custody.js";
import {
  LocalOperatorStores,
  neutralizeControlText,
  OPERATOR_LOG_PAGE_ROWS,
} from "../local-recompile/operator-surface.js";
import type { LocalResultObject } from "../local-recompile/results-store.js";
import { deriveLocalStoreKeys } from "../local-recompile/store-keys.js";
import { LocalStoreError } from "../local-recompile/store-record.js";
import { OPLOG_MAX_ROWS } from "../local-recompile/oplog.js";
import { resolveCustodyLockRoot } from "../storage/cross-process-lock.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  argvTokenForDisplay,
  consumeFlagValue,
  flagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";

export interface LocalResultsCommandArgs {
  argv: string[];
  out?: Writable;
  err?: Writable;
  env?: NodeJS.ProcessEnv;
  /** Confirmation input for `delete --all`; defaults to stdin. */
  input?: Readable;
}

/** The typed word `results delete --all` asks for; must match RESULTS_USAGE below. */
export const DELETE_ALL_CONFIRMATION = "delete";

/** Owner read and write only (0o600): an export holds model output from stored records. */
const EXPORT_FILE_MODE = 0o600;

const USAGE_EXIT_CODE = 2;

export const RESULTS_USAGE = `Usage: sanctuary results <command> [options]

Results written by the local model on this machine. Only you see them;
no agent can read them.

Commands:
  list                          List results, newest first.
  show <request_id>             Print one result's summary and its sources.
  export <request_id> --out <path>
                                Write one result as JSON (file mode 600).
                                Refuses an existing path.
  delete <request_id>           Delete one result.
  delete --all [--yes]          Delete every result. Asks you to type
                                "${DELETE_ALL_CONFIRMATION}" unless --yes is given.

Options:
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.

Every show, export and delete is written to the local operator log first.
`;

export const LOCAL_USAGE = `Usage: sanctuary local log <command> [options]

The local operator log: every local task, model call and operator action,
with no record or model text.

Commands:
  log show [--since <seq>] [--limit <n>]
                                Verify the log, then print rows from <seq>.
  log export --out <path>       Verify the log, then write every row as JSON
                                lines (file mode 600). Refuses an existing path.

Options:
  --fortress <path>   Override the storage path.
  --passphrase <val>  Passphrase for master-key derivation.
  --help, -h          Show this help.

A broken log chain is printed and the command exits non-zero.
`;

function write(stream: Writable, text: string): void {
  stream.write(text);
}

function wantsHelp(argv: string[]): boolean {
  return argv.length === 0 || argv.includes("--help") || argv.includes("-h");
}

function positional(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--passphrase" || arg === "--out" || arg === "--since" || arg === "--limit") {
      i++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    out.push(arg);
  }
  return out;
}

function describeStoreFailure(error: unknown): string {
  return error instanceof LocalStoreError ? `local stores unavailable (${error.kind})` : "local stores unavailable";
}

/**
 * Unlock the fortress, open both local stores under the same custody lock
 * root the server and the worker use, run `operation`, and close everything.
 */
async function withOperatorStores(
  argv: string[],
  err: Writable,
  env: NodeJS.ProcessEnv,
  operation: (stores: LocalOperatorStores) => Promise<number>,
): Promise<number> {
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress value refuses, never the default fortress.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    write(err, `${fortressFlagRefusalText(consumedFortress.error)}\n`);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  if (consumedFortress.value !== undefined) process.env.SANCTUARY_STORAGE_PATH = consumedFortress.value;

  const passphrase = flagValue(argv, "--passphrase") ?? env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    write(err, "Error: this command requires SANCTUARY_PASSPHRASE, --passphrase, or SANCTUARY_RECOVERY_KEY.\n");
    return 1;
  }
  if (typeof process.getuid !== "function") {
    write(err, "Error: local stores are not available on this platform.\n");
    return 1;
  }
  // The same root the server resolves and hands the worker, so all three take one lock.
  const runtimeRoot = resolveCustodyLockRoot(process.getuid(), { env: process.env, platform: platform() });

  const config = await loadConfig();
  const storage = new FilesystemStorage(join(config.storage_path, FORTRESS_STATE_DIRECTORY));
  const session = await resolveCliMasterKey(storage, {
    ...(passphrase !== undefined ? { passphrase } : {}),
    ...(recoveryKey !== undefined ? { recoveryKey } : {}),
    storagePathHint: config.storage_path,
  });
  return withCliMasterKeySession(session, async () => {
    const keys = deriveLocalStoreKeys(session.masterKey);
    let stores: LocalOperatorStores;
    try {
      stores = new LocalOperatorStores(storage, keys, { runtimeRoot });
    } finally {
      // The stores hold their own copies.
      keys.oplogKey.fill(0);
      keys.resultsKey.fill(0);
    }
    try {
      return await operation(stores);
    } catch (error) {
      write(err, `Error: ${describeStoreFailure(error)}.\n`);
      return 1;
    } finally {
      stores.close();
    }
  });
}

/** Create a new file with mode 600; an existing path is refused, never overwritten. */
async function createExclusive(path: string): Promise<FileHandle> {
  // O_EXCL: the open fails when anything already exists at the path, including a symlink.
  return open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, EXPORT_FILE_MODE);
}

async function refuseExisting(path: string, err: Writable): Promise<FileHandle | null> {
  try {
    return await createExclusive(path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    write(err, code === "EEXIST" ? `Error: ${argvTokenForDisplay(path)} already exists.\n` : `Error: cannot create ${argvTokenForDisplay(path)}.\n`);
    return null;
  }
}

function renderResult(object: LocalResultObject): string {
  const body = object.body ?? {};
  const refs = Array.isArray(body.refs) ? body.refs : [];
  const summary = typeof body.summary === "string" ? body.summary : "";
  const lines = [
    `request_id: ${object.request_id}`,
    `kind: ${object.kind}`,
    `state: ${object.state}`,
    `created_at: ${new Date(object.created_at).toISOString()}`,
    ...(body.truncated === "true" ? ["truncated: true"] : []),
    "sources:",
    ...refs.map((ref) => `  ${neutralizeControlText(ref)}`),
    "summary:",
    // Model text is printed with terminal control characters replaced, so it cannot drive the terminal.
    neutralizeControlText(summary),
  ];
  return `${lines.join("\n")}\n`;
}

async function confirmDeleteAll(input: Readable, err: Writable): Promise<boolean> {
  const rl = createInterface({ input, output: err, terminal: false });
  try {
    const answer = await rl.question(`Type "${DELETE_ALL_CONFIRMATION}" to delete every local result: `);
    return answer.trim() === DELETE_ALL_CONFIRMATION;
  } finally {
    rl.close();
  }
}

export async function runResultsCommand(args: LocalResultsCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  const argv = args.argv;
  if (wantsHelp(argv)) {
    write(out, RESULTS_USAGE);
    return 0;
  }
  const command = argv[0]!;
  const rest = argv.slice(1);
  const params = positional(rest);
  switch (command) {
    case "list":
      return withOperatorStores(rest, err, env, async (stores) => {
        const results = await stores.listResults();
        if (results.length === 0) write(out, "No local results.\n");
        for (const result of results) {
          write(out, `${result.request_id}  ${result.kind}  ${result.state}  ${new Date(result.created_at).toISOString()}  ${result.summary_bytes} bytes\n`);
        }
        return 0;
      });
    case "show": {
      const id = params[0];
      if (id === undefined) return usage(err, RESULTS_USAGE);
      return withOperatorStores(rest, err, env, async (stores) => {
        const object = await stores.viewResult(id);
        if (object === null) return notFound(err, id);
        write(out, renderResult(object));
        return 0;
      });
    }
    case "export": {
      const id = params[0];
      const path = flagValue(rest, "--out");
      if (id === undefined || path === undefined) return usage(err, RESULTS_USAGE);
      return withOperatorStores(rest, err, env, async (stores) => {
        const handle = await refuseExisting(path, err);
        if (handle === null) return 1;
        let written = false;
        try {
          const object = await stores.exportResult(id);
          if (object === null) return notFound(err, id);
          await handle.writeFile(`${JSON.stringify(object, null, 2)}\n`, "utf8");
          written = true;
          write(out, `Exported ${id} to ${argvTokenForDisplay(path)}.\n`);
          return 0;
        } finally {
          await handle.close();
          if (!written) await removeQuietly(path);
        }
      });
    }
    case "delete": {
      if (rest.includes("--all")) {
        return withOperatorStores(rest, err, env, async (stores) => {
          if (!rest.includes("--yes") && !(await confirmDeleteAll(args.input ?? process.stdin, err))) {
            write(err, "Nothing deleted.\n");
            return 1;
          }
          const deleted = await stores.deleteAllResults();
          write(out, `Deleted ${deleted} local results.\n`);
          return 0;
        });
      }
      const id = params[0];
      if (id === undefined) return usage(err, RESULTS_USAGE);
      return withOperatorStores(rest, err, env, async (stores) => {
        if (!(await stores.deleteResult(id))) return notFound(err, id);
        write(out, `Deleted ${id}.\n`);
        return 0;
      });
    }
    default:
      write(err, `Unknown results command: ${argvTokenForDisplay(command)}\n`);
      return usage(err, RESULTS_USAGE);
  }
}

export async function runLocalCommand(args: LocalResultsCommandArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  const argv = args.argv;
  if (wantsHelp(argv)) {
    write(out, LOCAL_USAGE);
    return 0;
  }
  if (argv[0] !== "log" || argv.length < 2) {
    write(err, `Unknown local command: ${argvTokenForDisplay(argv[0])}\n`);
    return usage(err, LOCAL_USAGE);
  }
  const command = argv[1]!;
  const rest = argv.slice(2);
  switch (command) {
    case "show": {
      const since = parseCount(flagValue(rest, "--since") ?? "0", Number.MAX_SAFE_INTEGER);
      const limit = parseCount(flagValue(rest, "--limit") ?? String(OPERATOR_LOG_PAGE_ROWS), OPLOG_MAX_ROWS);
      if (since === null || limit === null || limit === 0) return usage(err, LOCAL_USAGE);
      return withOperatorStores(rest, err, env, async (stores) => {
        const read = await stores.readLog(since, limit);
        if (!read.ok) return chainBroken(err, read.break);
        for (const row of read.rows) write(out, `${JSON.stringify(row)}\n`);
        return 0;
      });
    }
    case "export": {
      const path = flagValue(rest, "--out");
      if (path === undefined) return usage(err, LOCAL_USAGE);
      return withOperatorStores(rest, err, env, async (stores) => {
        const handle = await refuseExisting(path, err);
        if (handle === null) return 1;
        let written = false;
        try {
          const verification = await stores.exportLog(async (rows) => {
            await handle.write(rows.map((row) => `${JSON.stringify(row)}\n`).join(""));
          });
          if (!verification.ok) return chainBroken(err, verification);
          written = true;
          write(out, `Exported log rows ${verification.base_seq} to ${verification.head_seq} to ${argvTokenForDisplay(path)}.\n`);
          return 0;
        } finally {
          await handle.close();
          if (!written) await removeQuietly(path);
        }
      });
    }
    default:
      write(err, `Unknown local log command: ${argvTokenForDisplay(command)}\n`);
      return usage(err, LOCAL_USAGE);
  }
}

function usage(err: Writable, text: string): number {
  write(err, text);
  return USAGE_EXIT_CODE;
}

function notFound(err: Writable, id: string): number {
  write(err, `No local result ${argvTokenForDisplay(id)}.\n`);
  return 1;
}

function chainBroken(err: Writable, broken: { seq: number; reason: string }): number {
  write(err, `Error: the local operator log chain is broken at row ${broken.seq} (${broken.reason}).\n`);
  return 1;
}

function parseCount(text: string, max: number): number | null {
  if (!/^\d{1,16}$/.test(text)) return null;
  const value = Number(text);
  return Number.isSafeInteger(value) && value <= max ? value : null;
}

async function removeQuietly(path: string): Promise<void> {
  await rm(path, { force: true }).catch(() => undefined);
}
