/**
 * Sanctuary MCP Server - `sanctuary rotate-master` CLI subcommand
 *
 * Interactive-only front end for the master-rotation engine
 * (core/master-rotation.ts). Master rotation is an irreversible Tier-1
 * operation class (CLAUDE.md #3): the human gate here is a typed
 * confirmation ("ROTATE" + the fortress name) AFTER a preflight summary of
 * exactly what will be re-encrypted. There is deliberately NO `--no-confirm`
 * and NO headless path in this round - unattended rotation is part of the
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
  PENDING_RECOVERY_KEY,
  type RotationPendingRecoveryAuthority,
  type RotationPlanSummary,
} from "../core/master-rotation.js";
import {
  getOrCreateKeychainCustodyKey,
  adoptRecoveryKeyRotationInKeychain,
  reconcilePendingRecoveryKeyRotationInKeychain,
  stageRecoveryKeyRotationInKeychain,
  RecoveryKeyKeychainStoreError,
  type KeychainCustodyOptions,
  type RecoveryKeyRotationMutation,
} from "../wrap/keychain-custody.js";
import {
  readCustodyEnvelope,
  STAGED_CUSTODY_ENVELOPE_KEY,
} from "../core/master-custody.js";
import {
  preflightRecoveryKeyOutputFile,
  reconcileRotationRecoveryKeyFile,
  resolveRecoveryKeyOutputPath,
  verifyRecoveryKeyReentry,
  writeRotationRecoveryKeyFileTransactional,
  type DisclosureIo,
  type RotationRecoveryFileMutation,
} from "../wrap/recovery-key-disclosure.js";
import { consumeFlagValue } from "./argv.js";

export interface RotateMasterCliArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
  stdin?: NodeJS.ReadableStream & { isTTY?: boolean };
  storagePath?: string;
  home?: string;
  /** Test seam: passphrase without the interactive prompt. */
  passphraseOverride?: string;
  /** Test seam: observe ownership of a keychain key without touching the real keyring. */
  getKeychainCustodyKey?: typeof getOrCreateKeychainCustodyKey;
  /** Test seam: inject a failure after custody-key acquisition. */
  rotateMasterImpl?: typeof rotateMaster;
  /** Test seam: isolate recovery escrow and resume adoption from real keyrings. */
  recoveryKeychain?: KeychainCustodyOptions;
}

interface ParsedArgs {
  storage?: string;
  recoveryOut?: string;
  resume: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { resume: false, help: false };
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress/--storage value must refuse, never silently resolve the default fortress; wrong-fortress custody operations are a constraint-5 violation.
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error !== undefined) throw new Error(fortress.error);
  const storage = consumeFlagValue(fortress.argv, "--storage");
  if (storage.error !== undefined) throw new Error(storage.error);
  const storageValue = storage.value ?? fortress.value;
  if (storageValue !== undefined) out.storage = storageValue;

  for (let i = 0; i < storage.argv.length; i++) {
    const a = storage.argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--resume") out.resume = true;
    else if (a === "--recovery-out") {
      out.recoveryOut = readRequiredPathArg(storage.argv, i, "--recovery-out");
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
NOT rewritten - it stays verifiable across the rotation; the retiring audit
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

/**
 * An interrupted pre-journal file handoff must reach authenticated engine
 * reconciliation before ordinary single-issuance preflight rejects its exact
 * output path. This probe is intentionally only a deferral hint: it trusts no
 * bytes and authorizes no deletion or overwrite. The old-master MAC and staged
 * envelope binding are verified inside rotateMaster before cleanup.
 */
async function mayBePendingRecoveryFileRetry(
  statePath: string,
  recoveryKeyFilePath: string,
): Promise<boolean> {
  try {
    const storage = new FilesystemStorage(statePath);
    const [raw, staged] = await Promise.all([
      storage.read("_meta", PENDING_RECOVERY_KEY),
      storage.read("_meta", STAGED_CUSTODY_ENVELOPE_KEY),
    ]);
    if (!raw || !staged || raw.byteLength > 64 * 1024) return false;
    const parsed = JSON.parse(Buffer.from(raw).toString("utf8")) as {
      data?: { authorities?: Array<{ kind?: unknown; path?: unknown }> };
    };
    return parsed.data?.authorities?.some((authority) =>
      authority.kind === "recovery-file"
      && authority.path === recoveryKeyFilePath,
    ) === true;
  } catch {
    return false;
  }
}

/**
 * Capture the NEW recovery key minted by a rotation. Anti-strand (element 4):
 * a rotation must never strand the operator with a key that exists only inside
 * the fortress directory, so confirmed OFF-HOST capture is a HARD precondition
 * of returning true (the rotation engine aborts, mutating nothing, on false).
 *
 * Durable-fix posture: the NEW recovery key is NEVER written inside the fortress
 * directory. It is escrowed to an explicit off-host target (--recovery-out file
 * and/or the OS-keyring recovery escrow), shown on the controlling terminal for
 * the operator to store in their password manager, and re-entry verified. If no
 * off-host escrow target was reachable (no --recovery-out AND the OS keyring is
 * unavailable), capture FAILS so the rotation aborts before any data is touched.
 */
export async function captureRotatedRecoveryKey(opts: {
  recoveryKey: string;
  verify: (entered: string) => Promise<boolean>;
  storagePath: string;
  fortressId: string;
  rotationId: string;
  recoveryKeyFilePath?: string;
  registerPendingAuthority: (
    authority: RotationPendingRecoveryAuthority,
  ) => Promise<void>;
  io: DisclosureIo;
  err: NodeJS.WritableStream;
  /** Test seam: inject a mock OS-keyring backend for recovery escrow. */
  recoveryKeychain?: KeychainCustodyOptions;
}): Promise<
  | boolean
  | {
      captured: true;
      commit(): Promise<void>;
      rollback(): Promise<void>;
    }
> {
  let recoveryOutPath: string | undefined;
  let fileMutation: RotationRecoveryFileMutation | undefined;
  let keychainMutation: RecoveryKeyRotationMutation | undefined;

  const rollbackMutations = async (): Promise<void> => {
    const failures: unknown[] = [];
    for (const rollback of [
      () => fileMutation?.rollback(),
      () => keychainMutation?.rollback(),
    ]) {
      try {
        await rollback();
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) {
      throw new AggregateError(failures, "recovery escrow rollbacks failed");
    }
  };

  // Bind the engine's pending authority to the exact staged envelope bytes
  // before any external location is published. This proves the generated
  // string unwraps the staged master; the independent human re-entry below is
  // still mandatory and a refusal rolls every external mutation back.
  if (!(await opts.verify(opts.recoveryKey))) {
    throw new Error("generated rotation recovery key did not verify its staged envelope");
  }

  // 1. Off-host plaintext copy (outside the fortress), when --recovery-out was
  //    supplied. Register the intended parent-bound authority BEFORE publish;
  //    then upgrade it to the exact file inode after the atomic link.
  if (opts.recoveryKeyFilePath) {
    fileMutation = await writeRotationRecoveryKeyFileTransactional({
      storagePath: opts.storagePath,
      recoveryKeyFilePath: opts.recoveryKeyFilePath,
      recoveryKey: opts.recoveryKey,
      fortressId: opts.fortressId,
      registerPendingAuthority: opts.registerPendingAuthority,
    });
    recoveryOutPath = fileMutation.authority.path;
  }

  // 2. OS-keyring recovery escrow (a recoverable second factor). Best-effort:
  //    a locked / absent keyring does not by itself satisfy the precondition.
  try {
    keychainMutation = await stageRecoveryKeyRotationInKeychain(
      opts.storagePath,
      opts.recoveryKey,
      opts.rotationId,
      opts.recoveryKeychain ?? {},
      opts.registerPendingAuthority,
    );
  } catch (err) {
    if (!(err instanceof RecoveryKeyKeychainStoreError)) {
      await rollbackMutations();
      throw err;
    }
    // keyring not usable here - fall through to the off-host file requirement
  }

  let mutationTransferred = false;
  try {
    // 3. HARD anti-strand precondition: there MUST be a durable off-host copy
    //    of the new key. With neither, refuse before touching fortress data.
    if (!fileMutation && !keychainMutation) {
      opts.err.write(
        "\n  Refusing to rotate: the NEW recovery key has no durable off-host\n" +
          "  escrow target on this run. Sanctuary will NOT write it inside the\n" +
          "  fortress directory (that copy gets wiped and strands you). Re-run with\n" +
          "  --recovery-out <path outside the fortress>, or from a session where the\n" +
          "  OS keyring is unlocked, so the new key is captured before rotation.\n\n"
      );
      return false;
    }

    // 4. Disclose on the controlling terminal and prove re-entry. Until the
    //    mutation handle is returned to the engine, every exit rolls it back.
    const escrowNote =
      (recoveryOutPath
        ? `\n  Off-host plaintext copy written to:\n    ${recoveryOutPath}\n`
        : "") +
      (keychainMutation
        ? `  Staged in the OS keyring pending rotation commit (service ${keychainMutation.stagingService}).\n`
        : "");
    opts.io.output.write(
      "\n  ================ NEW RECOVERY KEY (rotation) ================\n" +
        "  This is shown only on this terminal. Store it in your password\n" +
        "  manager. It is NOT written inside the fortress directory.\n\n" +
        `  Recovery key:\n    ${opts.recoveryKey}\n` +
        escrowNote +
        "  ============================================================\n"
    );
    opts.err.write(
      "\n  NOTE: this NEW recovery key becomes active only when the rotation\n" +
        "  completes. Your previous recovery key stops working at that point.\n\n"
    );
    try {
      await verifyRecoveryKeyReentry({ check: opts.verify, io: opts.io });
    } catch {
      return false;
    }
    mutationTransferred = true;
    return {
      captured: true,
      commit: async () => {
        await keychainMutation?.commit();
        fileMutation?.commit();
      },
      rollback: rollbackMutations,
    };
  } finally {
    if (!mutationTransferred) await rollbackMutations();
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
  const statePath = join(storagePath, "state");
  let recoveryKeyFilePath: string | undefined;
  try {
    recoveryKeyFilePath = resolveRecoveryKeyOutputPath({
      recoveryOut: parsed.recoveryOut,
      storagePath,
      env: process.env,
    });
    if (recoveryKeyFilePath) {
      try {
        await preflightRecoveryKeyOutputFile(recoveryKeyFilePath);
      } catch (error) {
        if (!(await mayBePendingRecoveryFileRetry(statePath, recoveryKeyFilePath))) {
          throw error;
        }
      }
    }
  } catch (e) {
    err.write(`${e instanceof Error ? e.message : String(e)}\n`);
    return 1;
  }
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
  let keychainKey: Uint8Array | null = null;

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
        adoptRecoveryEscrow: (authority, verify, rotationId) =>
          adoptRecoveryKeyRotationInKeychain(
            storagePath,
            rotationId,
            authority,
            verify,
            args.recoveryKeychain ?? { home },
          ),
      });
      out.write(
        `\nRotation ${result.rotation_id} resumed to completion.\n` +
          `Converted ${result.converted_entries} remaining entries.\n` +
          "The fortress is fully under the new master.\n"
      );
      return 0;
    }

    // Keychain custody key (re-creates the keychain wrap where the OS
    // keyring is available; null elsewhere - surfaced in the plan summary).
    const envelope = await readCustodyEnvelope(storage);
    if (envelope?.wraps.some((w) => w.type === "keychain")) {
      const getKeychainKey =
        args.getKeychainCustodyKey ?? getOrCreateKeychainCustodyKey;
      keychainKey = await getKeychainKey(storagePath, { home });
    }

    const rotate = args.rotateMasterImpl ?? rotateMaster;
    const result = await rotate({
      storage,
      fortressPath: storagePath,
      fortressId,
      passphrase,
      ...(keychainKey ? { keychainKey } : {}),
      log: (line) => err.write(`${line}\n`),
      reconcilePendingRecoveryEscrow: async (pending, verify) => {
        for (const authority of pending.authorities) {
          if (authority.kind === "os-keyring") {
            await reconcilePendingRecoveryKeyRotationInKeychain(
              storagePath,
              pending.rotation_id,
              authority,
              verify,
              args.recoveryKeychain ?? { home },
            );
          } else {
            await reconcileRotationRecoveryKeyFile(authority, verify);
          }
        }
      },
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
      captureRecoveryKey: async (
        recoveryKey,
        verify,
        rotationId,
        registerPendingAuthority,
      ) => {
        const captureOptions: Parameters<typeof captureRotatedRecoveryKey>[0] = {
          recoveryKey,
          verify,
          storagePath,
          fortressId,
          rotationId,
          registerPendingAuthority,
          io,
          err,
          recoveryKeychain: args.recoveryKeychain ?? { home },
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
    keychainKey?.fill(0);
    lines.close();
  }
}
