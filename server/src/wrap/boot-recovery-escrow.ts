/**
 * Sanctuary wrap - boot-path recovery-key escrow (the durable fix)
 *
 * The MCP stdio server (server/src/index.ts) and the standalone dashboard
 * (server/src/dashboard-standalone.ts) both MINT a fresh recovery key on a
 * real-host first run. PR #661 built the durable off-fortress escrow
 * machinery (`--recovery-out` / `SANCTUARY_RECOVERY_OUT`,
 * `storeRecoveryKeyInKeychain`, read-back-verified, fail-closed) but wired it
 * ONLY into `sanctuary init` + `rotate-master`. The two boot paths still wrote
 * `recovery-key.txt` INSIDE the fortress directory and never escrowed - so the
 * only durable copy lived in the one place that gets scratch-cleared. That is
 * exactly why fortress keys kept getting orphaned (Erik, 2026-06-22).
 *
 * This module is the boot-path escrow that closes that gap. Its contract:
 *
 *  1. NEVER writes `recovery-key.txt` (or any plaintext recovery copy) into
 *     the fortress directory. The co-located file IS the orphaning bug.
 *
 *  2. Surfaces the freshly minted recovery key to the HUMAN over a channel the
 *     LLM/coordinator and logs CANNOT see or capture: it is written ONLY to
 *     the interactive controlling terminal (`/dev/tty`). It is NEVER written
 *     to stdout/stderr (which get piped/redirected/captured by the host
 *     harness), NEVER to a file in the fortress, NEVER through a logger. The
 *     operator is told to store it in their password manager.
 *
 *  3. Optional explicit off-host escrow targets (the #661 machinery, now
 *     reachable from the boot paths): an operator-chosen off-fortress file via
 *     `--recovery-out` / `SANCTUARY_RECOVERY_OUT`, and the OS-keyring
 *     recovery-key second factor via `storeRecoveryKeyInKeychain`.
 *
 *  4. A HARD provisioning gate: the boot does not finish a usable fortress
 *     until the human confirms (interactively, at the tty) they stored the key
 *     off-host - OR an explicit escrow target was supplied. With NEITHER a tty
 *     NOR an escrow target, the boot FAILS CLOSED (it does not silently leave
 *     the key on disk; there is no disk copy to leave).
 *
 * NO-disk-fallback (Erik-ratified): the recovery key is human-held. There is
 * no automatic on-disk copy and the unlock path never auto-reads one.
 */

import { closeSync, createReadStream, openSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import { Readable } from "node:stream";

import {
  preflightRecoveryKeyOutputFile,
  resolveRecoveryKeyOutputPath,
  writeRecoveryKeyFile,
} from "./recovery-key-disclosure.js";
import {
  storeRecoveryKeyInKeychain,
  RecoveryKeyKeychainStoreError,
  type KeychainCustodyOptions,
} from "./keychain-custody.js";

/**
 * The escrow attempt could not satisfy the provisioning gate: the recovery key
 * was minted but there was no interactive terminal to disclose it on AND no
 * explicit off-host escrow target was provided, so the key would be lost the
 * moment this process exits. Boot must fail closed (the fortress holds nothing
 * trust-bearing yet - the two-factor floor guarantees it - so re-provisioning
 * with an escrow target is safe).
 */
export class BootRecoveryKeyEscrowRequiredError extends Error {
  constructor() {
    super(
      "Sanctuary: a fresh recovery key was generated for this new fortress, but\n" +
        "there is no way to hand it to you safely on this run.\n" +
        "  - No interactive terminal is attached (so it cannot be shown for you to\n" +
        "    copy into your password manager), AND\n" +
        "  - No off-host escrow target was provided.\n\n" +
        "The recovery key is the ONLY thing that can recover this fortress if its\n" +
        "other factors are lost. Sanctuary will NOT write it inside the fortress\n" +
        "directory (that copy gets wiped and is how keys get orphaned), and will\n" +
        "NOT print it to a log/pipe. Re-run with ONE of:\n" +
        "  - an interactive terminal (run it yourself, not through a wrapper), or\n" +
        "  - --recovery-out <path outside the fortress> / SANCTUARY_RECOVERY_OUT, or\n" +
        "  - SANCTUARY_PASSPHRASE set, so the recovery key is escrowed in the OS\n" +
        "    keyring as a recoverable second factor.\n" +
        "Nothing precious has been stored yet, so re-provisioning is safe."
    );
    this.name = "BootRecoveryKeyEscrowRequiredError";
  }
}

/**
 * The operator declined the off-host-capture confirmation at the tty. Treated
 * as a hard refusal: boot must not finish (same posture as init's declined
 * confirmation).
 */
export class BootRecoveryKeyCaptureDeclinedError extends Error {
  constructor() {
    super(
      "Sanctuary: recovery-key off-host capture not confirmed. The fortress was\n" +
        "NOT finished. Store the recovery key shown on your terminal in your\n" +
        "password manager, then re-run."
    );
    this.name = "BootRecoveryKeyCaptureDeclinedError";
  }
}

export interface BootRecoveryEscrowOptions {
  /** The freshly minted base64url recovery key (do NOT pre-truncate). */
  recoveryKey: string;
  /** Resolved fortress storage path (used for escrow targeting + keychain service). */
  storagePath: string;
  /** A short fortress identifier embedded in the off-host file, when written. */
  fortressId?: string;
  /**
   * Operator-chosen off-fortress plaintext path (the `--recovery-out` flag).
   * `SANCTUARY_RECOVERY_OUT` is honored when this is absent. Must be OUTSIDE
   * the fortress directory (enforced by resolveRecoveryKeyOutputPath).
   */
  recoveryOut?: string;
  /**
   * Skip the interactive off-host-capture confirmation. Required for non-TTY
   * (CI / launchd / systemd) callers. When set, an explicit escrow target
   * (recoveryOut OR a passphrase-enabled keychain escrow) MUST exist or boot
   * fails closed via {@link BootRecoveryKeyEscrowRequiredError}.
   */
  noConfirm?: boolean;
  /**
   * Whether a passphrase is in play. When true, the recovery key is also
   * escrowed into the OS keyring (a recoverable second factor), exactly as
   * `sanctuary init` does. Keychain escrow is best-effort: a keyring that is
   * absent/locked does NOT by itself satisfy the provisioning gate (the tty
   * disclosure or --recovery-out does).
   */
  attemptKeychainEscrow?: boolean;
  /** Test seam: inject a mock OS-keyring backend. */
  recoveryKeychain?: KeychainCustodyOptions;
  /** Test seam: override env (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /**
   * Test seam: a non-tty disclosure/confirmation channel. When provided, this
   * stands in for `/dev/tty` (production opens the real controlling terminal).
   * The disclosure is written here; the confirmation is read from `input`.
   */
  ttyChannel?: {
    /** Write the recovery key + instructions here (stands in for /dev/tty). */
    write: (text: string) => void;
    /** Confirmation input (stands in for reading /dev/tty). */
    input?: NodeJS.ReadableStream;
    /** Force the "no interactive terminal" branch even with a channel. */
    nonInteractive?: boolean;
  };
}

export interface BootRecoveryEscrowResult {
  /** Off-host plaintext file path, when --recovery-out / env was used. */
  recoveryOutPath?: string;
  /** OS-keyring recovery-key service name, when keychain escrow succeeded. */
  keychainService?: string;
  /** True when the key was disclosed on the interactive terminal. */
  disclosedOnTty: boolean;
  /** True when the operator confirmed off-host capture at the tty. */
  confirmed: boolean;
}

/**
 * Build the tty-only disclosure text. The recovery key appears ONLY here - in
 * the string handed to the controlling terminal - never in a return value, a
 * log line, or an exception message.
 */
function buildTtyDisclosure(recoveryKey: string, escrowedNote: string): string {
  return (
    "\n" +
    "================ SANCTUARY: SAVE YOUR RECOVERY KEY ================\n" +
    "This is shown ONCE, only on this terminal. It is NOT written to any\n" +
    "log, file, or pipe. Store it in your password manager NOW.\n\n" +
    "Recovery key:\n" +
    `  ${recoveryKey}\n\n` +
    "This key is the ONLY way to recover this fortress if its other factors\n" +
    "are lost. Do not paste it into chat, a ticket, or a shared terminal.\n" +
    escrowedNote +
    "==================================================================\n\n"
  );
}

/**
 * Open the controlling terminal (`/dev/tty`) for write + read. Returns null
 * when there is no controlling terminal (CI / launchd / piped stdin). The
 * recovery key is written here and ONLY here - never to process.stdout /
 * process.stderr, which the host harness captures.
 */
function openTty():
  | { write: (text: string) => void; input: NodeJS.ReadableStream; close: () => void }
  | null {
  let fd: number;
  try {
    // ONE read+write fd for the controlling terminal. A single open (not a
    // write-open plus a separate read-open of the same path) avoids both the
    // js/file-system-race heuristic and the fd leak the two-fd shape had (the
    // write fd was never closed). `/dev/tty` resolves to THIS process's
    // controlling terminal at open time; it is a per-process device, not a
    // path-swappable file, so there is no real TOCTOU here.
    fd = openSync("/dev/tty", "r+");
  } catch {
    return null;
  }
  let input: NodeJS.ReadableStream;
  try {
    // The path arg is ignored when `fd` is supplied; the stream reads from fd.
    // autoClose:true makes the stream own the single fd's close on destroy().
    input = createReadStream("/dev/tty", {
      fd,
      autoClose: true,
      encoding: "utf8",
    });
  } catch {
    try {
      closeSync(fd);
    } catch {
      // ignore
    }
    return null;
  }
  return {
    write: (text: string) => {
      writeSync(fd, text);
    },
    input,
    close: () => {
      try {
        (input as Readable).destroy(); // closes the single fd (autoClose)
      } catch {
        // ignore
      }
    },
  };
}

/**
 * Prompt for off-host-capture confirmation on the supplied tty channel.
 * Returns true on "y"/"yes", false otherwise. Reads ONLY from the tty input
 * (never process.stdin, which the harness owns).
 */
async function confirmCaptureAtTty(
  write: (text: string) => void,
  input: NodeJS.ReadableStream
): Promise<boolean> {
  const readline = await import("node:readline/promises");
  const sink = { write } as unknown as NodeJS.WritableStream;
  const rl = readline.createInterface({
    input: input as Readable,
    output: sink,
  });
  let answer: string;
  try {
    answer = await rl.question(
      "Have you stored the recovery key in your password manager? [y/N] "
    );
  } catch {
    return false;
  } finally {
    rl.close();
  }
  const normalized = answer.trim().toLowerCase();
  return normalized === "y" || normalized === "yes";
}

/**
 * Escrow + disclose a freshly minted boot-path recovery key. See module doc
 * for the full contract. Throws {@link BootRecoveryKeyEscrowRequiredError} or
 * {@link BootRecoveryKeyCaptureDeclinedError} when the provisioning gate is not
 * satisfied - the caller should surface the message and exit non-zero.
 */
export async function escrowBootRecoveryKey(
  opts: BootRecoveryEscrowOptions
): Promise<BootRecoveryEscrowResult> {
  const env = opts.env ?? process.env;
  const result: BootRecoveryEscrowResult = {
    disclosedOnTty: false,
    confirmed: false,
  };

  // 1. Resolve + preflight the operator-chosen off-host path BEFORE minting
  //    any state on disk fails are surfaced here. The resolver enforces
  //    "outside the fortress" and throws on an in-fortress path.
  const recoveryOutPath = resolveRecoveryKeyOutputPath({
    ...(opts.recoveryOut !== undefined ? { recoveryOut: opts.recoveryOut } : {}),
    storagePath: opts.storagePath,
    env,
  });
  if (recoveryOutPath) {
    await preflightRecoveryKeyOutputFile(recoveryOutPath);
  }

  // 2. Best-effort OS-keyring recovery-key escrow (the recoverable second
  //    factor) when a passphrase is in play, exactly as init does. A locked /
  //    absent keyring does NOT satisfy the gate; only an explicit, durable
  //    target (the off-host file) or the human confirming the tty disclosure
  //    does. So a keychain failure here is non-fatal.
  if (opts.attemptKeychainEscrow) {
    try {
      const { service } = await storeRecoveryKeyInKeychain(
        opts.storagePath,
        opts.recoveryKey,
        opts.recoveryKeychain ?? {}
      );
      result.keychainService = service;
    } catch (err) {
      if (!(err instanceof RecoveryKeyKeychainStoreError)) throw err;
      // Keyring not usable here (locked / no GUI / not installed). Fall through:
      // the tty disclosure or --recovery-out carries durability instead.
    }
  }

  // 3. Write the operator-chosen off-host plaintext copy when requested. This
  //    is OUTSIDE the fortress (enforced above), single-issuance + O_EXCL +
  //    O_NOFOLLOW (the #661 machinery).
  if (recoveryOutPath) {
    const writeOpts: Parameters<typeof writeRecoveryKeyFile>[0] = {
      storagePath: opts.storagePath,
      recoveryKeyFilePath: recoveryOutPath,
      recoveryKey: opts.recoveryKey,
    };
    if (opts.fortressId !== undefined) writeOpts.fortressId = opts.fortressId;
    await writeRecoveryKeyFile(writeOpts);
    result.recoveryOutPath = resolve(recoveryOutPath);
  }

  const hasDurableTarget =
    result.recoveryOutPath !== undefined || result.keychainService !== undefined;

  // 4. Disclose on the controlling terminal (NEVER stdout/stderr/file/log) and
  //    gate on the human confirming off-host capture - UNLESS noConfirm and a
  //    durable target already exists.
  const escrowedNote = buildEscrowedNote(result);

  // Test seam: an injected channel stands in for /dev/tty.
  if (opts.ttyChannel) {
    if (opts.ttyChannel.nonInteractive) {
      return finishWithoutTty(opts, hasDurableTarget, result);
    }
    opts.ttyChannel.write(buildTtyDisclosure(opts.recoveryKey, escrowedNote));
    result.disclosedOnTty = true;
    if (opts.noConfirm) {
      // noConfirm suppresses the interactive capture prompt, so an UNCONFIRMED
      // one-shot tty flash is NOT proof of capture. The gate is satisfied only
      // by a durable off-host target; otherwise fail closed. (Else a stdio
      // first-run with a controlling terminal but no escrow target would
      // reintroduce the exact orphaning this fix exists to close.)
      return finishWithoutTty(opts, hasDurableTarget, result, /*disclosed*/ true);
    }
    const input = opts.ttyChannel.input;
    if (!input) {
      // A channel with no input cannot confirm: fall back to the gate.
      return finishWithoutTty(opts, hasDurableTarget, result, /*disclosed*/ true);
    }
    const ok = await confirmCaptureAtTty(opts.ttyChannel.write, input);
    if (!ok) throw new BootRecoveryKeyCaptureDeclinedError();
    result.confirmed = true;
    return result;
  }

  // Production: open the real controlling terminal.
  const tty = openTty();
  if (!tty) {
    return finishWithoutTty(opts, hasDurableTarget, result);
  }
  try {
    tty.write(buildTtyDisclosure(opts.recoveryKey, escrowedNote));
    result.disclosedOnTty = true;
    if (opts.noConfirm) {
      // See the ttyChannel branch: noConfirm requires a durable target; an
      // unconfirmed tty disclosure alone does not satisfy the gate.
      return finishWithoutTty(opts, hasDurableTarget, result, /*disclosed*/ true);
    }
    const ok = await confirmCaptureAtTty(tty.write, tty.input);
    if (!ok) throw new BootRecoveryKeyCaptureDeclinedError();
    result.confirmed = true;
    return result;
  } finally {
    tty.close();
  }
}

/**
 * No interactive terminal was available. The provisioning gate is satisfied
 * ONLY if a durable off-host target was already written; otherwise fail closed.
 * The recovery key is NOT disclosed anywhere in this branch (nowhere safe to
 * put it) and NOT written to disk inside the fortress.
 */
function finishWithoutTty(
  _opts: BootRecoveryEscrowOptions,
  hasDurableTarget: boolean,
  result: BootRecoveryEscrowResult,
  disclosed = false
): BootRecoveryEscrowResult {
  if (!hasDurableTarget) {
    throw new BootRecoveryKeyEscrowRequiredError();
  }
  result.disclosedOnTty = disclosed;
  result.confirmed = false;
  return result;
}

function buildEscrowedNote(result: BootRecoveryEscrowResult): string {
  const lines: string[] = [];
  if (result.recoveryOutPath) {
    lines.push(
      `An off-host plaintext copy was written to:\n  ${result.recoveryOutPath}\n` +
        "Move it to durable encrypted storage and remove the plaintext.\n"
    );
  }
  if (result.keychainService) {
    lines.push(
      `Also escrowed in the OS keyring (service ${result.keychainService}) as a\n` +
        "recoverable second factor on this machine.\n"
    );
  }
  return lines.length > 0 ? "\n" + lines.join("") + "\n" : "";
}
