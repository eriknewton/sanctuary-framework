/**
 * `sanctuary memory_ingest` / `sanctuary memory_emit` CLI wrappers.
 *
 * These are manual transcode commands. They use the same SDW memory backend as
 * the MCP tools and deliberately do not watch, sync, or modify harness-owned
 * source files.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Writable } from "node:stream";

import { loadConfig } from "../config.js";
import { resolveCliMasterKey } from "../core/master-custody.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { AuditLog } from "../operational/audit-log.js";
import {
  CLAUDE_CODE_MEMORY_HARNESS,
  emitClaudeCodeMemoryDirectory,
  ingestClaudeCodeMemorySnapshot,
  readClaudeCodeMemoryDirectory,
} from "../sdw/adapters/claude-code-file-adapter.js";
import { SdwMemoryBackendAdapter } from "../sdw/adapters/sdw-memory-backend.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { flagValue, hasFlag } from "./argv.js";

export interface MemoryFileCommandArgs {
  readonly argv: string[];
  readonly out?: Writable;
  readonly err?: Writable;
  readonly env?: NodeJS.ProcessEnv;
  /** Stdin source for `--passphrase-stdin` (tests inject a Readable). */
  readonly stdin?: NodeJS.ReadableStream;
}

const DEFAULT_OWNER_REF = "fleet-self";
/**
 * Bound on the `--passphrase-stdin` read so a pipe that is opened and never
 * written does not hang the command forever. An empty read falls through to the
 * normal "no credential supplied" refusal.
 */
const STDIN_READ_DEADLINE_MS = 30_000;
export const PASSPHRASE_ARGV_WARNING =
  "Warning: --passphrase puts the fortress passphrase in this process's argv, " +
  "where any local user can read it from the process list. Use " +
  "SANCTUARY_PASSPHRASE or --passphrase-stdin instead.\n";

function write(stream: Writable, text: string): void {
  stream.write(text);
}

export async function runMemoryIngestCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printIngestHelp(out);
    return 0;
  }

  const parsed = parseCommonArgs(args.argv, "memory_ingest", err);
  if (!parsed) return 2;

  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin);
  if (!boot) return 1;

  try {
    const snapshot = await readClaudeCodeMemoryDirectory(parsed.dir);
    // Write-ahead INTENT, durable before any vault write. If appendCritical
    // throws, the command aborts with no ingested memory files. It is labelled
    // `_started` because nothing is committed yet and the count is only what
    // was read; the outcome record below carries what actually landed.
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_ingest_started",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        source_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        source_file_count: snapshot.entries.length,
      },
    });
    const result = await ingestClaudeCodeMemorySnapshot(boot.adapter, snapshot);
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_ingest",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        source_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        source_file_count: result.source_file_count,
        committed_file_count: result.ingested.length,
        skipped_file_count: result.skipped.length,
        complete: result.complete,
        skipped: result.skipped.map((skip) => ({
          source_path: skip.source_path,
          reason: skip.reason,
        })),
      },
    });
    write(
      out,
      `memory_ingest: ingested ${String(result.ingested.length)} of ${String(result.source_file_count)} Claude Code memory files into owner_ref ${parsed.ownerRef}\n`,
    );
    if (!result.complete) {
      // Loud, on stderr, and named per file: a partial mirror that reports only
      // a count reads exactly like a complete one.
      write(
        err,
        `memory_ingest: WARNING - the mirror is INCOMPLETE. ${String(result.skipped.length)} file(s) were refused by the secret classifier and are NOT in the vault:\n`,
      );
      for (const skip of result.skipped) {
        write(err, `  - ${skip.source_path} (${skip.reason})\n`);
      }
      write(
        err,
        "memory_ingest: remove the sensitive material from those files or keep them outside the mirrored directory, then re-run.\n",
      );
    }
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_ingest", {
      harness: parsed.harness,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
    });
    write(err, `memory_ingest failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    await boot.auditLog.flush();
  }
}

export async function runMemoryEmitCommand(
  args: MemoryFileCommandArgs,
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const env = args.env ?? process.env;
  if (hasFlag(args.argv, "--help") || hasFlag(args.argv, "-h")) {
    printEmitHelp(out);
    return 0;
  }

  const parsed = parseCommonArgs(args.argv, "memory_emit", err);
  if (!parsed) return 2;

  const boot = await bootstrap(parsed, env, err, args.stdin ?? process.stdin);
  if (!boot) return 1;

  try {
    // Write-ahead INTENT, durable before any plaintext file is materialized
    // from the vault. If appendCritical throws, emit aborts without writes.
    // Labelled `_started`: at this point no file exists on disk yet.
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_emit_started",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
      },
    });
    const result = await emitClaudeCodeMemoryDirectory(boot.adapter, parsed.dir);
    await boot.auditLog.appendCritical({
      layer: "l1",
      operation: "memory_emit",
      identity_id: "principal",
      result: "success",
      details: {
        harness: parsed.harness,
        output_dir: parsed.dir,
        owner_ref: parsed.ownerRef,
        emitted_file_count: result.emitted.length,
      },
    });
    write(
      out,
      `memory_emit: emitted ${String(result.emitted.length)} Claude Code memory files to ${parsed.dir}\n`,
    );
    return 0;
  } catch (error) {
    await appendFailure(boot.auditLog, "memory_emit", {
      harness: parsed.harness,
      owner_ref: parsed.ownerRef,
      error_class: errorName(error),
    });
    write(err, `memory_emit failed: ${errorMessage(error)}\n`);
    return 1;
  } finally {
    await boot.auditLog.flush();
  }
}

interface ParsedCommonArgs {
  readonly harness: typeof CLAUDE_CODE_MEMORY_HARNESS;
  readonly dir: string;
  readonly ownerRef: string;
  readonly fortress?: string;
  readonly passphrase?: string;
  readonly passphraseFromStdin: boolean;
}

function parseCommonArgs(
  argv: readonly string[],
  command: "memory_ingest" | "memory_emit",
  err: Writable,
): ParsedCommonArgs | null {
  const harness = flagValue([...argv], "--harness");
  const dir = flagValue([...argv], "--dir");
  if (harness !== CLAUDE_CODE_MEMORY_HARNESS) {
    write(err, `${command}: --harness must be "claude-code"\n`);
    return null;
  }
  if (dir === undefined || dir.trim().length === 0) {
    write(err, `${command}: --dir is required\n`);
    return null;
  }
  const passphrase = flagValue([...argv], "--passphrase");
  if (passphrase !== undefined) {
    // The secret is already in argv by the time this runs; the warning exists so
    // the operator learns to stop, not to pretend the leak was prevented.
    write(err, PASSPHRASE_ARGV_WARNING);
  }
  return {
    harness,
    dir,
    ownerRef: flagValue([...argv], "--owner-ref") ?? DEFAULT_OWNER_REF,
    fortress: flagValue([...argv], "--fortress"),
    passphrase,
    passphraseFromStdin: hasFlag([...argv], "--passphrase-stdin"),
  };
}

/**
 * Read one line from stdin as the fortress passphrase.
 *
 * Failure mode to watch for: a caller that passes `--passphrase-stdin` and then
 * never writes to the pipe. That looks like a wedged command rather than a
 * credential problem, so the read is deadline-bounded and an empty result falls
 * through to the normal refusal.
 */
async function readPassphraseFromStdin(stdin: NodeJS.ReadableStream): Promise<string> {
  return new Promise((resolvePassphrase) => {
    const rl = createInterface({ input: stdin });
    let settled = false;
    const finish = (value: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      try {
        rl.close();
      } catch {
        // Already closed; the value is what matters.
      }
      resolvePassphrase(value);
    };
    const deadline = setTimeout(() => finish(""), STDIN_READ_DEADLINE_MS);
    rl.once("line", (line) => finish(line));
    rl.once("close", () => finish(""));
    rl.once("error", () => finish(""));
  });
}

interface BootstrappedMemoryFileCommand {
  readonly adapter: SdwMemoryBackendAdapter;
  readonly auditLog: AuditLog;
}

async function bootstrap(
  args: ParsedCommonArgs,
  env: NodeJS.ProcessEnv,
  err: Writable,
  stdin: NodeJS.ReadableStream,
): Promise<BootstrappedMemoryFileCommand | null> {
  if (args.fortress !== undefined) {
    process.env.SANCTUARY_STORAGE_PATH = args.fortress;
  }

  const stdinPassphrase = args.passphraseFromStdin
    ? await readPassphraseFromStdin(stdin)
    : "";
  const passphrase =
    (stdinPassphrase.length > 0 ? stdinPassphrase : undefined) ??
    args.passphrase ??
    env.SANCTUARY_PASSPHRASE;
  const recoveryKey = env.SANCTUARY_RECOVERY_KEY;
  if (!passphrase && !recoveryKey) {
    write(
      err,
      "Error: memory file commands require SANCTUARY_PASSPHRASE, --passphrase-stdin, --passphrase, or SANCTUARY_RECOVERY_KEY.\n",
    );
    return null;
  }

  const config = await loadConfig();
  await mkdir(config.storage_path, { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(config.storage_path, "state"));
  let masterKey: Uint8Array;
  try {
    masterKey = await resolveCliMasterKey(storage, {
      ...(passphrase !== undefined ? { passphrase } : {}),
      ...(recoveryKey !== undefined ? { recoveryKey } : {}),
      storagePathHint: config.storage_path,
    });
  } catch (error) {
    // Fail closed AND diagnosable. Failure mode this guards: an unlock error
    // thrown out of the command surfaces as an unhandled rejection, which reads
    // as a crashed CLI rather than "this fortress is not unlocked".
    write(err, `Error: could not unlock the fortress: ${errorMessage(error)}\n`);
    return null;
  }
  const auditLog = new AuditLog(storage, masterKey);
  const adapter = new SdwMemoryBackendAdapter({
    storage,
    masterKey,
    fortressId: fortressIdFromStoragePath(config.storage_path),
    ownerRef: args.ownerRef,
  });
  return { adapter, auditLog };
}

async function appendFailure(
  auditLog: AuditLog,
  operation: "memory_ingest" | "memory_emit",
  details: Record<string, unknown>,
): Promise<void> {
  try {
    await auditLog.appendCritical({
      layer: "l1",
      operation: `${operation}_denied`,
      identity_id: "system",
      result: "failure",
      details,
    });
  } catch {
    // Preserve the original operator-visible error. The command still returns
    // non-zero and flushes whatever audit state is available in finally.
  }
}

function printIngestHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_ingest --harness=claude-code --dir <path> [options]

Manually mirror Claude Code memory files into the encrypted SDW vault. Source
files remain plaintext and untouched; this command does not sync or watch.

Options:
  --harness=claude-code  Required harness format.
  --dir <path>           Claude Code memory directory to read.
  --owner-ref <id>       SDW owner_ref scope (default: fleet-self).
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Fortress passphrase. Visible in the process list to
                         any local user; prefer SANCTUARY_PASSPHRASE or
                         --passphrase-stdin.
  --help, -h             Show this help.
`,
  );
}

function printEmitHelp(out: Writable): void {
  write(
    out,
    `Usage: sanctuary memory_emit --harness=claude-code --dir <path> [options]

Manually emit Claude Code memory files from the encrypted SDW vault into an
operator-named output directory. Existing memory files are never overwritten.

Options:
  --harness=claude-code  Required harness format.
  --dir <path>           Output directory for emitted plaintext files.
  --owner-ref <id>       SDW owner_ref scope (default: fleet-self).
  --fortress <path>      Override the fortress path.
  --passphrase-stdin     Read the fortress passphrase from stdin (preferred).
  --passphrase <value>   Fortress passphrase. Visible in the process list to
                         any local user; prefer SANCTUARY_PASSPHRASE or
                         --passphrase-stdin.
  --help, -h             Show this help.
`,
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "Error";
}
