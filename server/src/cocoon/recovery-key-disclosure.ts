/**
 * Secret disclosure (Finding U + Finding X / v1.1.1 + v1.1.3 hotfixes)
 *
 * Two operator-trust surfaces share this module:
 *   1. Recovery key disclosure (Finding U, v1.1.1) on `sanctuary init`. The
 *      master key on init is random; the operator's only path to fortress
 *      recovery on principal loss is the recovery key generated at first run.
 *   2. Passphrase disclosure (Finding X, v1.1.3) on `sanctuary wrap` when
 *      Sanctuary generated the passphrase itself. The wrap path derives the
 *      master key purely from the passphrase via Argon2id, so the generated
 *      passphrase is the secret-of-last-resort. User-supplied passphrase
 *      (`--passphrase` flag, `SANCTUARY_PASSPHRASE` env) skips disclosure;
 *      the operator already holds the secret.
 *
 * Both surfaces are three-pronged:
 *   1. Print the FULL secret in a bordered banner on stderr (no truncation).
 *   2. Write the plaintext to <storage>/<filename> mode 0600 with explicit
 *      "move off-host immediately" instructions. Single-issuance: never
 *      overwrite an existing file.
 *   3. Optionally prompt the operator to confirm they have saved the secret.
 *      Skippable via mode "no-confirm" / "stdio-server" for CI / scripted use.
 *
 * Common code paths that reach disclosure:
 *   - server/src/index.ts (MCP server stdio first-run, recovery key)
 *   - server/src/dashboard-standalone.ts (standalone dashboard first-run, recovery key)
 *   - server/src/cocoon/init.ts (sanctuary init subcommand, recovery key)
 *   - server/src/cocoon/cli.ts (sanctuary wrap, generated passphrase only)
 */

import { writeFile, access, constants, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";

export const RECOVERY_KEY_FILENAME = "recovery-key.txt";
export const PASSPHRASE_BACKUP_FILENAME = "passphrase-backup.txt";

/**
 * Confirmation policy:
 *   - "interactive": prompt at TTY; on non-TTY without bypass, throw.
 *   - "no-confirm": skip prompt entirely (CI / scripted callers).
 *   - "stdio-server": skip prompt; intended for the MCP server stdio
 *     boot path where stdin is owned by the host harness. The file +
 *     banner are the durable disclosure for that path.
 */
export type DisclosureMode = "interactive" | "no-confirm" | "stdio-server";

export interface DisclosureIo {
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream;
}

interface SecretDisclosureCopy {
  /** Filename for the on-disk plaintext copy. */
  fileName: string;
  /** Banner header line, e.g. "SANCTUARY: First Run, Recovery Key Generated". */
  bannerHeader: string;
  /** Banner display label for the secret value, e.g. "Recovery Key" or "Passphrase". */
  bannerSecretLabel: string;
  /** Banner save-imperative line, e.g. "SAVE THIS KEY. It will not be shown again.". */
  bannerSaveLine: string;
  /** Banner consequence-of-loss line. */
  bannerLossLine: string;
  /** File-level all-caps warning header. */
  fileWarningHeader: string;
  /** File-body label preceding the secret value, e.g. "Recovery key:" or "Passphrase:". */
  fileSecretLabel: string;
  /** File-body paragraph after the secret value. */
  fileBody: string;
  /** Inline phrasing for the confirm prompt, e.g. "recovery key" or "passphrase". */
  promptLabel: string;
}

const RECOVERY_KEY_COPY: SecretDisclosureCopy = {
  fileName: RECOVERY_KEY_FILENAME,
  bannerHeader: "SANCTUARY: First Run, Recovery Key Generated",
  bannerSecretLabel: "Recovery Key",
  bannerSaveLine: "SAVE THIS KEY. It will not be shown again.",
  bannerLossLine: "Without it, your encrypted state is unrecoverable.",
  fileWarningHeader:
    "SANCTUARY RECOVERY KEY, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.",
  fileSecretLabel: "Recovery key:",
  fileBody:
    "This file was created on first init. Sanctuary will NOT regenerate this file on\n" +
    "subsequent runs and will NOT display the key again. After moving this file off\n" +
    "the host (encrypted backup, password manager, paper safe), delete it from the\n" +
    "fortress directory. Do NOT keep it in the fortress; the recovery key bypasses\n" +
    "the cocoon passphrase by design.\n",
  promptLabel: "recovery key",
};

const PASSPHRASE_BACKUP_COPY: SecretDisclosureCopy = {
  fileName: PASSPHRASE_BACKUP_FILENAME,
  bannerHeader: "SANCTUARY: First Run, Passphrase Generated",
  bannerSecretLabel: "Passphrase",
  bannerSaveLine:
    "SAVE THIS PASSPHRASE. It will not be shown again.",
  bannerLossLine: "Without it, your encrypted state is unrecoverable.",
  fileWarningHeader:
    "SANCTUARY PASSPHRASE, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY.",
  fileSecretLabel: "Passphrase:",
  fileBody:
    "This file was created on first wrap when Sanctuary generated the passphrase.\n" +
    "Sanctuary will NOT regenerate this file on subsequent runs and will NOT display\n" +
    "the passphrase again. After moving this file off the host (encrypted backup,\n" +
    "password manager, paper safe), delete it from the fortress directory. Do NOT\n" +
    "keep it in the fortress; the keychain copy is recoverable only while the host\n" +
    "and its OS keyring are intact.\n",
  promptLabel: "passphrase",
};

/**
 * v1.1.1 (Finding U) error: operator answered "n" to the recovery-key
 * confirmation prompt. Callers should treat this as a hard refusal: the
 * fortress state should be rolled back and the process should exit non-zero.
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
 * v1.1.1 (Finding U) error: non-TTY stdin without --no-confirm bypass.
 * Callers exit non-zero with operator guidance.
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
 * v1.1.3 (Finding X) error: operator answered "n" to the passphrase
 * confirmation prompt. Mirrors the recovery-key declined error shape so
 * callers can roll back fortress state and exit non-zero.
 */
export class PassphraseConfirmationDeclinedError extends Error {
  constructor() {
    super(
      "Passphrase confirmation declined. " +
        "Save the passphrase (printed above and written to passphrase-backup.txt) " +
        "before re-running wrap."
    );
    this.name = "PassphraseConfirmationDeclinedError";
  }
}

/**
 * v1.1.3 (Finding X) error: non-TTY stdin without bypass on the wrap path.
 * Callers exit non-zero with operator guidance.
 */
export class PassphraseConfirmationNonInteractiveError extends Error {
  constructor() {
    super(
      "Passphrase confirmation requires an interactive terminal. " +
        "Re-run with --no-open for scripted use, or run from a TTY."
    );
    this.name = "PassphraseConfirmationNonInteractiveError";
  }
}

/**
 * Print a bordered first-run secret-disclosure banner on stderr. Box width
 * is sized to the secret length so the right border lines up. The original
 * v1.1.0 banner truncated to a fixed visual width; the fix is to size the
 * box dynamically and never touch the secret value.
 */
function printSecretBanner(
  secret: string,
  filePath: string,
  copy: SecretDisclosureCopy,
  output: NodeJS.WritableStream = process.stderr
): void {
  const lines = [
    copy.bannerHeader,
    "",
    `${copy.bannerSecretLabel}: ${secret}`,
    "",
    copy.bannerSaveLine,
    copy.bannerLossLine,
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
 * Public banner for recovery-key disclosure (Finding U). Kept exported for
 * any caller that wants to print without the file-write side effect.
 */
export function printRecoveryKeyBanner(
  recoveryKey: string,
  filePath: string,
  output: NodeJS.WritableStream = process.stderr
): void {
  printSecretBanner(recoveryKey, filePath, RECOVERY_KEY_COPY, output);
}

/**
 * Public banner for passphrase disclosure (Finding X).
 */
export function printPassphraseBanner(
  passphrase: string,
  filePath: string,
  output: NodeJS.WritableStream = process.stderr
): void {
  printSecretBanner(passphrase, filePath, PASSPHRASE_BACKUP_COPY, output);
}

/**
 * Write the one-time secret-backup file with mode 0600. Single-issuance
 * semantics: if the file already exists, return its path without overwriting.
 * The fortress is the authoritative state and we must never regenerate or
 * replace a secret that an operator may have already saved.
 */
async function writeSecretFile(opts: {
  storagePath: string;
  secret: string;
  copy: SecretDisclosureCopy;
  fortressId?: string;
  now?: () => Date;
}): Promise<{ filePath: string; written: boolean }> {
  const filePath = join(opts.storagePath, opts.copy.fileName);

  try {
    await access(filePath, constants.F_OK);
    return { filePath, written: false };
  } catch {
    // File does not exist, proceed to write.
  }

  await mkdir(opts.storagePath, { recursive: true, mode: 0o700 });

  const now = (opts.now ?? (() => new Date()))().toISOString();
  const fortressLine = opts.fortressId
    ? `Fortress: ${opts.fortressId}\n`
    : "";

  const content =
    `${opts.copy.fileWarningHeader}\n` +
    `Generated: ${now}\n` +
    fortressLine +
    "\n" +
    `${opts.copy.fileSecretLabel}\n` +
    `${opts.secret}\n` +
    "\n" +
    opts.copy.fileBody;

  await writeFile(filePath, content, { mode: 0o600 });
  return { filePath, written: true };
}

/**
 * Public entry point for recovery-key file write (Finding U).
 */
export async function writeRecoveryKeyFile(opts: {
  storagePath: string;
  recoveryKey: string;
  fortressId?: string;
  now?: () => Date;
}): Promise<{ filePath: string; written: boolean }> {
  const writeOpts: Parameters<typeof writeSecretFile>[0] = {
    storagePath: opts.storagePath,
    secret: opts.recoveryKey,
    copy: RECOVERY_KEY_COPY,
  };
  if (opts.fortressId !== undefined) writeOpts.fortressId = opts.fortressId;
  if (opts.now !== undefined) writeOpts.now = opts.now;
  return writeSecretFile(writeOpts);
}

/**
 * Public entry point for passphrase backup file write (Finding X).
 */
export async function writePassphraseBackupFile(opts: {
  storagePath: string;
  passphrase: string;
  fortressId?: string;
  now?: () => Date;
}): Promise<{ filePath: string; written: boolean }> {
  const writeOpts: Parameters<typeof writeSecretFile>[0] = {
    storagePath: opts.storagePath,
    secret: opts.passphrase,
    copy: PASSPHRASE_BACKUP_COPY,
  };
  if (opts.fortressId !== undefined) writeOpts.fortressId = opts.fortressId;
  if (opts.now !== undefined) writeOpts.now = opts.now;
  return writeSecretFile(writeOpts);
}

/**
 * Prompt the operator to confirm they have saved the secret. Returns when
 * the operator answers "y" or "yes" (case-insensitive). Throws the supplied
 * declined-error class on "n" or any other answer; throws the non-interactive
 * error class when stdin is not a TTY (caller should bypass with mode
 * "no-confirm" instead).
 */
async function confirmSecretSaved(
  copy: SecretDisclosureCopy,
  declinedError: new () => Error,
  nonInteractiveError: new () => Error,
  io?: DisclosureIo
): Promise<void> {
  const input = io?.input ?? process.stdin;
  const output = io?.output ?? process.stderr;

  // tty detection: real stdin exposes isTTY; injected streams in tests do not
  // and are treated as TTY-like (the test owns the stream).
  const realStdin = !io && process.stdin.isTTY !== true;
  if (realStdin) {
    throw new nonInteractiveError();
  }

  const rl = createInterface({ input, output });
  try {
    const answer = await rl.question(
      `Have you saved the ${copy.promptLabel}? [y/N] `
    );
    const normalized = answer.trim().toLowerCase();
    if (normalized !== "y" && normalized !== "yes") {
      throw new declinedError();
    }
  } finally {
    rl.close();
  }
}

/**
 * Public confirmation prompt for the recovery-key path (Finding U).
 */
export async function confirmRecoveryKeySaved(
  io?: DisclosureIo
): Promise<void> {
  await confirmSecretSaved(
    RECOVERY_KEY_COPY,
    RecoveryKeyConfirmationDeclinedError,
    RecoveryKeyConfirmationNonInteractiveError,
    io
  );
}

/**
 * Public confirmation prompt for the passphrase path (Finding X).
 */
export async function confirmPassphraseSaved(
  io?: DisclosureIo
): Promise<void> {
  await confirmSecretSaved(
    PASSPHRASE_BACKUP_COPY,
    PassphraseConfirmationDeclinedError,
    PassphraseConfirmationNonInteractiveError,
    io
  );
}

interface DiscloseSecretInternalOptions {
  /** Full secret value (do NOT pre-truncate). */
  secret: string;
  /** Resolved fortress storage path; backup file lands here. */
  storagePath: string;
  /** Optional fortress identifier; embedded in the file content. */
  fortressId?: string;
  /** Confirmation policy. */
  mode?: DisclosureMode;
  /** Test seam: clock injection for the file timestamp. */
  now?: () => Date;
  /** Test seam: stdin/stdout streams. */
  io?: DisclosureIo;
}

interface DiscloseSecretInternalResult {
  filePath: string;
  fileWritten: boolean;
  confirmed: boolean;
}

/**
 * Disclose a freshly generated secret end-to-end: write the file, print the
 * banner, and (in interactive mode) prompt for confirmation.
 *
 * Order matters: file write happens first so the operator can recover the
 * secret even if banner output is lost (terminal scrollback, redirected
 * stderr). Banner print is second so the operator sees the value live.
 * Confirmation is last so the operator has the file path on screen before
 * deciding.
 */
async function discloseSecret(
  opts: DiscloseSecretInternalOptions,
  copy: SecretDisclosureCopy,
  declinedError: new () => Error,
  nonInteractiveError: new () => Error
): Promise<DiscloseSecretInternalResult> {
  const mode = opts.mode ?? "interactive";

  const writeOpts: Parameters<typeof writeSecretFile>[0] = {
    storagePath: opts.storagePath,
    secret: opts.secret,
    copy,
  };
  if (opts.fortressId !== undefined) writeOpts.fortressId = opts.fortressId;
  if (opts.now !== undefined) writeOpts.now = opts.now;
  const fileResult = await writeSecretFile(writeOpts);

  printSecretBanner(opts.secret, fileResult.filePath, copy, opts.io?.output);

  if (mode === "no-confirm" || mode === "stdio-server") {
    return {
      filePath: fileResult.filePath,
      fileWritten: fileResult.written,
      confirmed: false,
    };
  }

  await confirmSecretSaved(copy, declinedError, nonInteractiveError, opts.io);
  return {
    filePath: fileResult.filePath,
    fileWritten: fileResult.written,
    confirmed: true,
  };
}

export interface DiscloseRecoveryKeyOptions {
  /** Full base64url-encoded recovery key (do NOT pre-truncate). */
  recoveryKey: string;
  /** Resolved fortress storage path; recovery-key.txt lands here. */
  storagePath: string;
  /** Optional fortress identifier; embedded in the file content. */
  fortressId?: string;
  /** Confirmation policy. */
  mode?: DisclosureMode;
  /** Test seam: clock injection for the file timestamp. */
  now?: () => Date;
  /** Test seam: stdin/stdout streams. */
  io?: DisclosureIo;
}

export interface DiscloseRecoveryKeyResult {
  /** Absolute path to the written recovery-key.txt (or existing one). */
  filePath: string;
  /** True if a file was written this call; false if it already existed. */
  fileWritten: boolean;
  /** True if the operator confirmed; false if confirmation was skipped. */
  confirmed: boolean;
}

export interface DisclosePassphraseOptions {
  /** Full passphrase (do NOT pre-truncate). */
  passphrase: string;
  /** Resolved fortress storage path; passphrase-backup.txt lands here. */
  storagePath: string;
  /** Optional fortress identifier; embedded in the file content. */
  fortressId?: string;
  /** Confirmation policy. */
  mode?: DisclosureMode;
  /** Test seam: clock injection for the file timestamp. */
  now?: () => Date;
  /** Test seam: stdin/stdout streams. */
  io?: DisclosureIo;
}

export interface DisclosePassphraseResult {
  /** Absolute path to the written passphrase-backup.txt (or existing one). */
  filePath: string;
  /** True if a file was written this call; false if it already existed. */
  fileWritten: boolean;
  /** True if the operator confirmed; false if confirmation was skipped. */
  confirmed: boolean;
}

/**
 * Public entry point for recovery-key disclosure (Finding U / v1.1.1).
 */
export async function discloseRecoveryKey(
  opts: DiscloseRecoveryKeyOptions
): Promise<DiscloseRecoveryKeyResult> {
  const internalOpts: DiscloseSecretInternalOptions = {
    secret: opts.recoveryKey,
    storagePath: opts.storagePath,
  };
  if (opts.fortressId !== undefined) internalOpts.fortressId = opts.fortressId;
  if (opts.mode !== undefined) internalOpts.mode = opts.mode;
  if (opts.now !== undefined) internalOpts.now = opts.now;
  if (opts.io !== undefined) internalOpts.io = opts.io;

  return discloseSecret(
    internalOpts,
    RECOVERY_KEY_COPY,
    RecoveryKeyConfirmationDeclinedError,
    RecoveryKeyConfirmationNonInteractiveError
  );
}

/**
 * Public entry point for passphrase disclosure (Finding X / v1.1.3).
 */
export async function disclosePassphrase(
  opts: DisclosePassphraseOptions
): Promise<DisclosePassphraseResult> {
  const internalOpts: DiscloseSecretInternalOptions = {
    secret: opts.passphrase,
    storagePath: opts.storagePath,
  };
  if (opts.fortressId !== undefined) internalOpts.fortressId = opts.fortressId;
  if (opts.mode !== undefined) internalOpts.mode = opts.mode;
  if (opts.now !== undefined) internalOpts.now = opts.now;
  if (opts.io !== undefined) internalOpts.io = opts.io;

  return discloseSecret(
    internalOpts,
    PASSPHRASE_BACKUP_COPY,
    PassphraseConfirmationDeclinedError,
    PassphraseConfirmationNonInteractiveError
  );
}
