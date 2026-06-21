/**
 * Sanctuary MCP Server — `sanctuary rotate-master` CLI subcommand
 *
 * Interactive-only front end for the master-rotation engine
 * (core/master-rotation.ts). Master rotation is an irreversible Tier-1
 * operation class (CLAUDE.md #3): the human gate here is a typed
 * confirmation ("ROTATE" + the fortress name) AFTER a preflight summary of
 * exactly what will be re-encrypted. There is deliberately NO `--no-confirm`
 * and NO headless path in this round — unattended rotation is part of the
 * headless-daemon custody model (Erik's D3) and stays deferred.
 *
 * Crash recovery: `--resume` drives a journaled rotation forward to
 * completion (idempotent; requires only the fortress passphrase). While the
 * journal exists every other entry point refuses to boot the fortress.
 */

import { createInterface, Interface as ReadlineInterface } from "node:readline";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { access } from "node:fs/promises";

import { resolveStoragePath } from "../paths.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  rotateMaster,
  resumeRotation,
  RotationPreflightError,
  RotationResumeError,
  type RotationPlanSummary,
} from "../core/master-rotation.js";
import { getOrCreateKeychainCustodyKey } from "../wrap/keychain-custody.js";
import { readCustodyEnvelope } from "../core/master-custody.js";
import {
  discloseRecoveryKey,
  preflightRecoveryKeyOutputFile,
  resolveRecoveryKeyOutputPath,
  verifyRecoveryKeyReentry,
  type DisclosureIo,
} from "../wrap/recovery-key-disclosure.js";

export interface RotateMasterCliArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  stdin?: NodeJS.ReadableStream & { isTTY?: boolean };
  storagePath?: string;
  home?: string;
  /** Test seam: passphrase without the interactive prompt. */
  passphraseOverride?: string;
}

interface ParsedArgs {
  storage?: string;
  recoveryOut?: string;
  resume: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { resume: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--resume") out.resume = true;
    else if ((a === "--fortress" || a === "--storage") && argv[i + 1]) {
      out.storage = argv[++i];
    } else if (a === "--recovery-out") {
      out.recoveryOut = readRequiredPathArg(argv, i, "--recovery-out");
      i++;
    } else if (a && a.startsWith("--")) {
      throw new Error(`Unknown flag: ${a}`);
    }
  }
  return out;
}

function readRequiredPathArg(
  argv: string[],
  index: number,
  flag: string
): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new Error(`${flag} requires a path value`);
  }
  return value;
}

function printUsage(out: NodeJS.WritableStream): void {
  out.write(`
Usage: sanctuary rotate-master [options]

Rotate the fortress master key: a fresh random master is minted, every piece
of fortress data is re-encrypted under it, custody is re-wrapped (your
passphrase, a NEW recovery key you must capture and re-enter, and the OS
keyring where available), and the old master is retired. The audit chain is
NOT rewritten — it stays verifiable across the rotation; the retiring audit
key is wrapped under the new master instead.

This is an irreversible, interactively confirmed operation. Use it when the
old master or a credential for it may have been exposed.

Options:
  --fortress <path>   Override the fortress storage path.
  --storage <path>    Alias for --fortress.
  --recovery-out <path>
                      Write the NEW plaintext recovery key to this exact
                      path instead of <fortress>/recovery-key.txt. The path
                      must be outside the fortress directory.
  --resume            Resume a rotation interrupted by a crash or power loss.
                      Idempotent; requires the fortress passphrase.
  --help, -h          Show this help.

The fortress passphrase is read from SANCTUARY_PASSPHRASE when set, otherwise
prompted. Stop the dashboard and all wrapped agents first; the command
refuses to run while runtime.json exists under the storage path.

After completion the PREVIOUS recovery key, passphrase-derived legacy
markers, and any leaked copy of the old master no longer unlock anything.
`);
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function captureRotatedRecoveryKey(opts: {
  recoveryKey: string;
  verify: (entered: string) => Promise<boolean>;
  storagePath: string;
  fortressId: string;
  recoveryKeyFilePath?: string;
  io: DisclosureIo;
  err: NodeJS.WritableStream;
}): Promise<boolean> {
  const disclosureOptions: Parameters<typeof discloseRecoveryKey>[0] = {
    recoveryKey: opts.recoveryKey,
    storagePath: opts.storagePath,
    fortressId: opts.fortressId,
    mode: "no-confirm", // re-entry verification below replaces the Y/N
    io: opts.io,
  };
  if (opts.recoveryKeyFilePath) {
    disclosureOptions.recoveryKeyFilePath = opts.recoveryKeyFilePath;
  }
  await discloseRecoveryKey(disclosureOptions);
  opts.err.write(
    "\n  NOTE: this NEW recovery key becomes active only when the rotation\n" +
      "  completes. Your previous recovery key stops working at that point.\n\n"
  );
  try {
    await verifyRecoveryKeyReentry({ check: opts.verify, io: opts.io });
    return true;
  } catch {
    return false;
  }
}

class LineReader {
  private readonly rl: ReadlineInterface;
  private readonly queue: string[] = [];
  private readonly waiters: Array<(line: string) => void> = [];
  private closed = false;

  constructor(stdin: NodeJS.ReadableStream) {
    this.rl = createInterface({ input: stdin });
    this.rl.on("line", (line) => {
      const w = this.waiters.shift();
      if (w) w(line);
      else this.queue.push(line);
    });
    this.rl.on("close", () => {
      this.closed = true;
      while (this.waiters.length > 0) this.waiters.shift()!("");
    });
  }

  next(): Promise<string> {
    if (this.queue.length > 0) return Promise.resolve(this.queue.shift()!);
    if (this.closed) return Promise.resolve("");
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.rl.close();
    } catch {
      // already closed
    }
  }
}

function renderSummary(summary: RotationPlanSummary): string {
  const lines = [
    "",
    "Master rotation plan:",
    `  rotation id:        ${summary.rotation_id}`,
    `  entries to re-key:  ${summary.total_entries}`,
    `  audit entries:      ${summary.audit_entries_epoch_scoped} (chain preserved; old epoch key re-wrapped)`,
    `  castle pin:         ${summary.castle_pin}`,
    `  keychain wrap:      ${summary.keychain_wrap}`,
    "  namespaces:",
    ...summary.namespaces.map(
      (n) => `    ${n.namespace}  (${n.entries} entries, ${n.kind})`
    ),
  ];
  if (summary.warnings.length > 0) {
    lines.push("  WARNINGS:");
    for (const w of summary.warnings) lines.push(`    - ${w}`);
  }
  lines.push("");
  return lines.join("\n") + "\n";
}

export async function runRotateMasterCommand(
  args: RotateMasterCliArgs
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  const stdin =
    args.stdin ?? (process.stdin as NodeJS.ReadableStream & { isTTY?: boolean });
  const home = args.home ?? homedir();

  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(args.argv);
  } catch (e) {
    err.write(`${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  }
  if (parsed.help) {
    printUsage(out);
    return 0;
  }

  const storagePath =
    parsed.storage ?? args.storagePath ?? resolveStoragePath(process.env, home);
  let recoveryKeyFilePath: string | undefined;
  try {
    recoveryKeyFilePath = resolveRecoveryKeyOutputPath({
      recoveryOut: parsed.recoveryOut,
      storagePath,
      env: process.env,
    });
    if (recoveryKeyFilePath) {
      await preflightRecoveryKeyOutputFile(recoveryKeyFilePath);
    }
  } catch (e) {
    err.write(`${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  }
  const statePath = join(storagePath, "state");
  const fortressId = fortressIdFromStoragePath(storagePath);
  const fortressName = basename(storagePath) || "sanctuary";

  out.write(`\nSanctuary rotate-master\nStorage: ${storagePath}\n\n`);

  // Refuse-if-running guard (mirrors reset-passphrase).
  const runtimeFile = join(storagePath, "runtime.json");
  if (await fileExists(runtimeFile)) {
    err.write(
      `Refusing to rotate: ${runtimeFile} exists, indicating a Sanctuary process may be running.\n` +
        "Close the dashboard and stop all wrapped agents first. If everything is\n" +
        `stopped and the file is stale, remove it manually: rm ${runtimeFile}\n`
    );
    return 1;
  }

  // Interactive-only gate. The io test seam (args.stdin) is the same pattern
  // reset-passphrase uses; production requires a TTY.
  if (!args.stdin && process.stdin.isTTY !== true) {
    err.write(
      "rotate-master is interactive-only: it requires a TTY for the typed\n" +
        "confirmation and recovery-key re-entry. There is no --no-confirm.\n"
    );
    return 1;
  }

  const lines = new LineReader(stdin);
  const io: DisclosureIo = { input: stdin, output: err };
  const prompt = async (q: string): Promise<string> => {
    err.write(q);
    return lines.next();
  };

  try {
    const storage = new FilesystemStorage(statePath);

    // Passphrase: env first, then prompt.
    let passphrase =
      args.passphraseOverride ?? process.env.SANCTUARY_PASSPHRASE ?? "";
    if (!passphrase) {
      passphrase = (await prompt("Fortress passphrase: ")).trim();
    }
    if (!passphrase) {
      err.write("Aborted: no passphrase provided.\n");
      return 1;
    }

    if (parsed.resume) {
      const result = await resumeRotation({
        storage,
        fortressPath: storagePath,
        fortressId,
        passphrase,
        log: (line) => err.write(`${line}\n`),
      });
      out.write(
        `\nRotation ${result.rotation_id} resumed to completion.\n` +
          `Converted ${result.converted_entries} remaining entries.\n` +
          "The fortress is fully under the new master.\n"
      );
      return 0;
    }

    // Keychain custody key (re-creates the keychain wrap where the OS
    // keyring is available; null elsewhere — surfaced in the plan summary).
    let keychainKey: Uint8Array | null = null;
    const envelope = await readCustodyEnvelope(storage);
    if (envelope?.wraps.some((w) => w.type === "keychain")) {
      keychainKey = await getOrCreateKeychainCustodyKey(storagePath, { home });
    }

    const result = await rotateMaster({
      storage,
      fortressPath: storagePath,
      fortressId,
      passphrase,
      ...(keychainKey ? { keychainKey } : {}),
      log: (line) => err.write(`${line}\n`),
      approve: async (summary) => {
        out.write(renderSummary(summary));
        out.write(
          "This operation is IRREVERSIBLE once conversion starts (a crash can\n" +
            "always be resumed forward with --resume + your passphrase). The OLD\n" +
            "recovery key and any leaked copy of the old master stop working.\n\n"
        );
        const name = await prompt(
          `Type the fortress name (${fortressName}) to continue: `
        );
        if (name.trim() !== fortressName) {
          err.write("Aborted: fortress name did not match.\n");
          return false;
        }
        const word = await prompt("Type the word ROTATE (uppercase) to continue: ");
        if (word.trim() !== "ROTATE") {
          err.write("Aborted: confirmation word did not match.\n");
          return false;
        }
        return true;
      },
      captureRecoveryKey: async (recoveryKey, verify) => {
        const captureOptions: Parameters<typeof captureRotatedRecoveryKey>[0] = {
          recoveryKey,
          verify,
          storagePath,
          fortressId,
          io,
          err,
        };
        if (recoveryKeyFilePath) {
          captureOptions.recoveryKeyFilePath = recoveryKeyFilePath;
        }
        return captureRotatedRecoveryKey(captureOptions);
      },
    });

    out.write(
      `\nRotation ${result.rotation_id} complete.\n` +
        `  re-keyed entries:  ${result.converted_entries}\n` +
        `  retired wraps:     ${result.old_wrap_ids.length}\n` +
        `  new wraps:         ${result.new_wrap_ids.length}\n` +
        "The old master, old recovery key, and legacy key markers are retired.\n" +
        "Save the NEW recovery key you just verified.\n"
    );
    if (keychainKey) keychainKey.fill(0);
    return 0;
  } catch (e) {
    if (e instanceof RotationPreflightError || e instanceof RotationResumeError) {
      err.write(`${e.message}\n`);
      return 1;
    }
    err.write(
      `rotate-master failed: ${e instanceof Error ? e.message : String(e)}\n`
    );
    return 1;
  } finally {
    lines.close();
  }
}
