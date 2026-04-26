/**
 * Recovery Key Disclosure (Finding U / v1.1.1 hotfix)
 *
 * The recovery key is the operator's only path to fortress recovery on
 * principal loss. v1.1.0 truncated it on display with a literal "..." and
 * never persisted the plaintext anywhere, so any operator who followed the
 * documented init flow ended up with an unrecoverable fortress.
 *
 * This module owns the disclosure surface across every code path that
 * generates a fresh recovery key:
 *   - server/src/index.ts (MCP server stdio first-run)
 *   - server/src/dashboard-standalone.ts (standalone dashboard first-run)
 *   - server/src/cocoon/init.ts (sanctuary init subcommand)
 *
 * Disclosure is three-pronged:
 *   1. Print the FULL key in a bordered banner on stderr (no truncation).
 *   2. Write the plaintext to <storage>/recovery-key.txt mode 0600 with
 *      explicit "move off-host immediately" instructions. Single-issuance:
 *      we never overwrite an existing file.
 *   3. Optionally prompt the operator to confirm they have saved the key
 *      before init completes. Skippable via the noConfirm flag for CI.
 */

import { writeFile, access, constants, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";

export const RECOVERY_KEY_FILENAME = "recovery-key.txt";

export interface DiscloseRecoveryKeyOptions {
  /** Full base64url-encoded recovery key (do NOT pre-truncate). */
  recoveryKey: string;
  /** Resolved fortress storage path; recovery-key.txt lands here. */
  storagePath: string;
  /** Optional fortress identifier; embedded in the file content. */
  fortressId?: string;
  /**
   * Confirmation policy:
   *   - "interactive": prompt at TTY; on non-TTY without bypass, throw.
   *   - "no-confirm": skip prompt entirely (CI / scripted callers).
   *   - "stdio-server": skip prompt; intended for the MCP server stdio
   *     boot path where stdin is owned by the host harness. The file +
   *     banner are the durable disclosure for that path.
   */
  mode?: "interactive" | "no-confirm" | "stdio-server";
  /** Test seam: clock injection for the file timestamp. */
  now?: () => Date;
  /** Test seam: stdin/stdout streams. */
  io?: {
    input: NodeJS.ReadableStream;
    output: NodeJS.WritableStream;
  };
}

export interface DiscloseRecoveryKeyResult {
  /** Absolute path to the written recovery-key.txt (or existing one). */
  filePath: string;
  /** True if a file was written this call; false if it already existed. */
  fileWritten: boolean;
  /** True if the operator confirmed; false if confirmation was skipped. */
  confirmed: boolean;
}

/**
 * Aborted by the operator answering "n" to the confirmation prompt.
 *
 * Callers should treat this as a hard refusal: the fortress state should
 * be rolled back and the process should exit non-zero.
 */
export class RecoveryKeyConfirmationDeclinedError extends Error {
  constructor() {
    super(
      "Recovery key confirmation declined. " +
        "Save the recovery key (printed above and written to recovery-key.txt) " +
        "before re-running init."
    );
    this.name = "RecoveryKeyConfirmationDeclinedError";
  }
}

/**
 * Aborted because the operator is on a non-TTY stdin and did not pass the
 * --no-confirm bypass. Callers exit non-zero with operator guidance.
 */
export class RecoveryKeyConfirmationNonInteractiveError extends Error {
  constructor() {
    super(
      "Recovery key confirmation requires an interactive terminal. " +
        "Re-run with --no-confirm for CI/scripted use, or run from a TTY."
    );
    this.name = "RecoveryKeyConfirmationNonInteractiveError";
  }
}

/**
 * Print the bordered first-run recovery-key banner on stderr.
 *
 * Box width is sized to the key length so the right border lines up. The
 * older banner truncated to a fixed visual width — the fix is to size the
 * box dynamically and never touch the key.
 */
export function printRecoveryKeyBanner(
  recoveryKey: string,
  filePath: string,
  output: NodeJS.WritableStream = process.stderr
): void {
  const lines = [
    "SANCTUARY: First Run, Recovery Key Generated",
    "",
    `Recovery Key: ${recoveryKey}`,
    "",
    "SAVE THIS KEY. It will not be shown again.",
    "Without it, your encrypted state is unrecoverable.",
    "",
    "Plaintext copy written to:",
    `  ${filePath}`,
    "Move it off-host (password manager, encrypted backup),",
    "then delete the file from the fortress directory.",
  ];
  const inner = Math.max(...lines.map((l) => l.length));
  const horizontal = "═".repeat(inner + 2);
  const top = `╔${horizontal}╗`;
  const bottom = `╚${horizontal}╝`;
  const body = lines.map((l) => `║ ${l.padEnd(inner)} ║`).join("\n");
  output.write(`\n${top}\n${body}\n${bottom}\n\n`);
}

/**
 * Write the one-time recovery-key.txt file with mode 0600.
 *
 * Single-issuance semantics: if the file already exists, return its path
 * without overwriting. The fortress is the authoritative state and we
 * must never regenerate or replace a recovery key that an operator may
 * have already saved.
 */
export async function writeRecoveryKeyFile(opts: {
  storagePath: string;
  recoveryKey: string;
  fortressId?: string;
  now?: () => Date;
}): Promise<{ filePath: string; written: boolean }> {
  const filePath = join(opts.storagePath, RECOVERY_KEY_FILENAME);

  try {
    await access(filePath, constants.F_OK);
    return { filePath, written: false };
  } catch {
    // File does not exist — proceed to write.
  }

  await mkdir(opts.storagePath, { recursive: true, mode: 0o700 });

  const now = (opts.now ?? (() => new Date()))().toISOString();
  const fortressLine = opts.fortressId
    ? `Fortress: ${opts.fortressId}\n`
    : "";

  const content =
    "SANCTUARY RECOVERY KEY — DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.\n" +
    `Generated: ${now}\n` +
    fortressLine +
    "\n" +
    "Recovery key:\n" +
    `${opts.recoveryKey}\n` +
    "\n" +
    "This file was created on first init. Sanctuary will NOT regenerate this file on\n" +
    "subsequent runs and will NOT display the key again. After moving this file off\n" +
    "the host (encrypted backup, password manager, paper safe), delete it from the\n" +
    "fortress directory. Do NOT keep it in the fortress; the recovery key bypasses\n" +
    "the cocoon passphrase by design.\n";

  await writeFile(filePath, content, { mode: 0o600 });
  return { filePath, written: true };
}

/**
 * Prompt the operator to confirm they have saved the recovery key.
 *
 * Returns when the operator answers "y" or "yes" (case-insensitive).
 * Throws RecoveryKeyConfirmationDeclinedError on "n" or any other answer.
 * Throws RecoveryKeyConfirmationNonInteractiveError when stdin is not a
 * TTY (caller should bypass with mode "no-confirm" instead).
 */
export async function confirmRecoveryKeySaved(
  io?: {
    input: NodeJS.ReadableStream;
    output: NodeJS.WritableStream;
  }
): Promise<void> {
  const input = io?.input ?? process.stdin;
  const output = io?.output ?? process.stderr;

  // tty detection: real stdin exposes isTTY; injected streams in tests do not
  // and are treated as TTY-like (the test owns the stream).
  const realStdin = !io && process.stdin.isTTY !== true;
  if (realStdin) {
    throw new RecoveryKeyConfirmationNonInteractiveError();
  }

  const rl = createInterface({ input, output });
  try {
    const answer = await rl.question(
      "Have you saved the recovery key? [y/N] "
    );
    const normalized = answer.trim().toLowerCase();
    if (normalized !== "y" && normalized !== "yes") {
      throw new RecoveryKeyConfirmationDeclinedError();
    }
  } finally {
    rl.close();
  }
}

/**
 * Disclose a freshly generated recovery key end-to-end: write the file,
 * print the banner, and (in interactive mode) prompt for confirmation.
 *
 * Order matters: file write happens first so the operator can recover the
 * key even if banner output is lost (terminal scrollback, redirected stderr).
 * Banner print is second so the operator sees the key live. Confirmation
 * is last so the operator has the file path on screen before deciding.
 */
export async function discloseRecoveryKey(
  opts: DiscloseRecoveryKeyOptions
): Promise<DiscloseRecoveryKeyResult> {
  const mode = opts.mode ?? "interactive";

  const fileResult = await writeRecoveryKeyFile({
    storagePath: opts.storagePath,
    recoveryKey: opts.recoveryKey,
    ...(opts.fortressId !== undefined ? { fortressId: opts.fortressId } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
  });

  printRecoveryKeyBanner(
    opts.recoveryKey,
    fileResult.filePath,
    opts.io?.output
  );

  if (mode === "no-confirm" || mode === "stdio-server") {
    return {
      filePath: fileResult.filePath,
      fileWritten: fileResult.written,
      confirmed: false,
    };
  }

  await confirmRecoveryKeySaved(opts.io);
  return {
    filePath: fileResult.filePath,
    fileWritten: fileResult.written,
    confirmed: true,
  };
}
