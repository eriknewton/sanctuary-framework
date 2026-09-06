/**
 * Sanctuary MCP Server — `sanctuary reset-passphrase` CLI subcommand
 *
 * Recovery flow for passphrase loss. Three mutually exclusive paths:
 *
 *   (a) Recovery shares   — reconstruct the master key from M-of-N shares.
 *                           Operationally available only when the operator has
 *                           previously persisted shares to this fortress. v1.0.x
 *                           does not yet ship share persistence; this path
 *                           degrades gracefully today.
 *
 *   (b) Guardian quorum   — initiate a federation v0.1
 *                           `guardian_recovery_request` and wait for the
 *                           configured guardian threshold. Requires an
 *                           unlocked local fortress to talk to the federation,
 *                           which the lost-passphrase scenario does not have.
 *                           Path ships with v1.1 federation full mesh.
 *
 *   (c) Nuke and rebind   — destroy the fortress entirely and re-initialize.
 *                           ALL state (identities, broker tokens, audit log,
 *                           federation membership) is permanently lost. The
 *                           operator types the fortress name and the literal
 *                           word DESTROY before the wipe runs.
 *
 *   (d) Recovery-key rekey — TTY-only, hidden-prompt-only. The operator enters
 *                           their HUMAN-HELD recovery key; it unlocks the
 *                           master via the existing recovery wrap, a fresh
 *                           random passphrase is enrolled (new passphrase wrap +
 *                           exact-fortress stored credential) and VERIFIED, and
 *                           only then are the old passphrase wraps atomically
 *                           removed. Master, fortress data, and the recovery
 *                           wrap are all preserved; a wrong key mutates nothing.
 *                           This is the fresh-host / lost-passphrase path: the
 *                           operator keeps their fortress instead of nuking it.
 *
 * Deliberately ABSENT path (ratified posture 2026-07-22,
 * docs/custody-recovery-posture.md): "unlock with the OS-keyring custody key
 * and enroll a new passphrase." The keyring key is released to any process in
 * the logged-in session, so that path would let anyone at an unlocked machine
 * take over custody without holding a human credential. Machine-resident
 * factors never bootstrap human-held custody; do not add that mode without
 * superseding the posture doc. The recovery-key mode (d) is NOT that path: it
 * requires a human-held recovery key the operator types at an interactive
 * terminal, exactly the human credential the posture requires.
 *
 * Refuse-if-unlocked guard: if `<storage>/runtime.json` exists, refuse with a
 * clear hint to stop the dashboard and any wrapped agents first. Operators on
 * a stale runtime file can remove it manually after confirming nothing is
 * running.
 *
 * Multi-principal note: v1.0.x fortresses are single-principal. When a future
 * v1.x ships multi-principal fortresses (Federation Protocol §10 reservation,
 * Architecture Walk Q4), this command MUST branch on principal selection so a
 * single principal's lost passphrase does not silently nuke the whole
 * fortress. The hook point is `selectMode()` below; the survey logic at
 * `surveyAvailableModes()` is the right place to enumerate per-principal
 * mode availability when that lands.
 *
 * No Concordia or Verascore imports (non-dependency principle).
 */

import { createInterface, Interface as ReadlineInterface } from "node:readline";
import { spawn } from "node:child_process";
import {
  readdir,
  stat,
  access,
  rename,
  lstat,
  realpath,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";

import { randomBytes, timingSafeEqual } from "node:crypto";

import { resolveStoragePath } from "../paths.js";
import { execKeychain } from "../wrap/keychain-exec.js";
import {
  generatePassphrase,
  capturePassphraseCredentialIdentity,
  deleteRetiredMatchingPassphraseServices,
  persistAndConfirmUserProvidedPassphrase,
  readStoredPassphrase,
  observeStoredPassphrase,
  PassphrasePathIdentityError,
  type PassphraseOptions,
} from "../wrap/passphrase.js";
import {
  classifyDarwinFailure,
  classifyLinuxFailure,
} from "../wrap/keychain-custody.js";
import { allFortressKeychainCredentialServices } from "../wrap/credential-registry.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import {
  readCustodyEnvelope,
  unwrapMaster,
  verifyEnvelopeMac,
  wrapMasterWithPassphrase,
  writeCustodyEnvelope,
  withCustodyWriteLock,
  CustodyUnlockError,
  CUSTODY_ENVELOPE_KEY,
  CUSTODY_WRITE_LOCK_FILE,
  type CustodyEnvelope,
} from "../core/master-custody.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hmacSha256 } from "../core/hashing.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  CrossProcessLockError,
  type CrossProcessLockLease,
} from "../storage/cross-process-lock.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import {
  aliasConflictMessage,
  consumeFlagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";
import { promptHiddenLine, type RawModeStdin } from "./hidden-prompt.js";
import { readFileCustody, writeFileCustody } from "../storage/custody-fs.js";
import type { ResetHistoryRecoveryMode } from "../audit/reset-history.js";
import { AuditLog } from "../operational/audit-log.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";

// ── Types ───────────────────────────────────────────────────────────

// The writer's mode set IS the boot reader's mode set: any value written into
// `.reset-history.log` must parse on the next boot, so this type is the reader's
// enum, not a parallel literal union. Must match RESET_HISTORY_RECOVERY_MODES in
// server/src/audit/reset-history.ts (AGENTS rule 11: writer and reader share one
// schema; a split here bricks server boot after a rekey writes the marker).
export type RecoveryMode = ResetHistoryRecoveryMode;

export interface ResetPassphraseArgs {
  argv: string[];
  /** Output stream (stdout in prod; captured in tests). */
  out?: NodeJS.WritableStream;
  /** Error stream (stderr in prod; captured in tests). */
  err?: NodeJS.WritableStream;
  /**
   * Stdin source for prompts (tests inject a Readable; prod uses process.stdin).
   * Typed as {@link RawModeStdin} — the exact shape the hidden-prompt raw-mode
   * reader needs — so the stream flows to `promptHiddenLine` with no cast.
   */
  stdin?: RawModeStdin;
  /** Override storage path (tests; prod resolves from env). */
  storagePath?: string;
  /** Override home directory (tests). */
  home?: string;
  /** Override platform detection (tests). */
  platformOverride?: NodeJS.Platform;
  /**
   * Test seam for `--mode recovery-key`: supplies the recovery key without a
   * real TTY hidden prompt. Mirrors restore-attest's `recoveryKeyOverride`; when
   * set, the interactive-terminal requirement and hidden prompt are bypassed.
   * Production leaves this undefined so the key is only ever read from a hidden
   * interactive prompt.
   */
  recoveryKeyOverride?: string;
  /**
   * Override `security` exec for Keychain cleanup (tests). Production uses a
   * default that spawns `/usr/bin/security`.
   */
  exec?: (
    cmd: string,
    args: string[],
    input?: string
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
  /**
   * Optional buffers holding key material the caller wants zeroed before this
   * command returns. Each entry has `.fill(0)` applied in a `finally` block,
   * including on early aborts. Production v1.x reset paths hold no key
   * material in this CLI module; the hook exists so future recovery-share
   * reconstruction (path (a)) and any caller that constructs the command
   * with a pre-decoded passphrase Buffer cannot forget to zeroize.
   *
   * JS strings are immutable in V8 and cannot be zeroed; route key material
   * through Buffer / Uint8Array, place it on this list, and the buffer will
   * be cleared post-use. See `runNukePath` doc block for the full threat
   * model.
   */
  keyMaterialToZeroize?: Array<Buffer | Uint8Array>;
  /**
   * Test seam: bound the recovery-key rekey's cross-process lock wait. Omitted
   * in production (the library default applies). A concurrency test injects a
   * small value so the loser fails closed fast instead of waiting the full
   * production budget.
   */
  lockTimeoutMs?: number;
  /** Test only: mutate the fortress path after the kernel lock is acquired. */
  __testAfterKernelHolderAcquired?: (pid: number) => void;
  /**
   * Test seam: a fault injected AFTER a named durability stage of the
   * recovery-key rekey, to simulate an exceptional unwind at each write
   * boundary. Production leaves it undefined. Real process death is distinct
   * (no JavaScript finally runs) and is covered by a SIGKILL subprocess test;
   * both cases leave the durable journal for idempotent recovery.
   */
  faultAfterRekeyStage?: (stage: RekeyStage) => void | Promise<void>;
  /** Test only: runs after the final root-identity check and before the
   * cwd-bound wipe worker is spawned. Used to prove a pathname replacement is
   * refused without deleting through the replacement. */
  beforeIdentityBoundWipe?: () => void | Promise<void>;
  /** Test seam: bound the identity-bound wipe worker (round-2 deadline test). */
  wipeDeadlineMs?: number;
  /**
   * Test seam: receives a REFERENCE to each live secret buffer (the decoded
   * recovery key, the unlocked master) at the moment it is created, so a test
   * can assert the OUTER `finally` zeroed it on every exit path — success,
   * wrong-key throw, lock contention, and injected crash — without ever printing
   * the bytes. Production leaves it undefined.
   */
  observeSecretBuffer?: (label: "recovery-key" | "master", buf: Uint8Array) => void;
  /**
   * Override for `process.exit`. The `--exit-on-completion` flag calls this
   * with code 0 after a successful nuke to limit the post-nuke window an
   * attacker-on-host with heap-dump access could exploit. Tests inject a
   * spy so the test process does not actually exit; production passes
   * `process.exit`.
   */
  exitProcess?: (code: number) => void;
}

interface ModeAvailability {
  recoveryKey: { available: boolean; reason: string };
  shares: { available: boolean; reason: string };
  guardian: { available: boolean; reason: string };
  nuke: { available: boolean; reason: string };
}

interface ParsedArgs {
  mode?: RecoveryMode;
  storage?: string;
  fortress?: string;
  exitOnCompletion: boolean;
  help: boolean;
  /**
   * Opt-in for the recovery-key rekey to store its freshly minted passphrase in
   * the machine-local fallback file when NO OS keyring is available (S3). Default
   * false: fail closed rather than land a secret the operator never sees in a
   * machine-bound file with no operator-held copy.
   */
  allowMachineLocalPassphrase: boolean;
}

function isStorageTargetFlagParseError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.startsWith("--fortress requires ") ||
    message.startsWith("--fortress may ") ||
    message.startsWith("--storage requires ") ||
    message.startsWith("--storage may ") ||
    message === aliasConflictMessage("--fortress", "--storage")
  );
}

// ── Public entry ────────────────────────────────────────────────────

export async function runResetPassphraseCommand(
  args: ResetPassphraseArgs
): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;
  // `process.stdin` (tty.ReadStream) structurally satisfies RawModeStdin
  // (setRawMode/resume/pause all return `this`), so no cast is needed.
  const stdin: RawModeStdin = args.stdin ?? process.stdin;
  const home = args.home ?? homedir();
  const plat = args.platformOverride ?? process.platform;

  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(args.argv);
  } catch (error) {
    if (isStorageTargetFlagParseError(error)) {
      err.write(
        `${fortressFlagRefusalText(error instanceof Error ? error.message : String(error))}\n`,
      );
      return FORTRESS_FLAG_USAGE_EXIT_CODE;
    }
    throw error;
  }
  if (parsed.help) {
    printUsage(out);
    return 0;
  }

  const storagePath =
    parsed.storage ??
    parsed.fortress ??
    args.storagePath ??
    resolveStoragePath(process.env, home);

  out.write(banner(storagePath));

  // Refuse-if-unlocked guard.
  const runtimeFile = join(storagePath, "runtime.json");
  if (await fileExists(runtimeFile)) {
    err.write(
      `Refusing to reset: ${runtimeFile} exists, indicating a Sanctuary process may be running.\n` +
        `Close the dashboard and stop all wrapped agents before running reset-passphrase.\n` +
        `If you have already stopped everything and the file is stale, remove it manually:\n` +
        `  rm ${runtimeFile}\n` +
        `Then re-run this command.\n`
    );
    return 1;
  }

  // Single readline interface shared across all prompts in this command run.
  // Tests pass a pre-loaded Readable; production hands process.stdin which
  // stays open for the duration of the command.
  const lines = new LineReader(stdin);
  let code: number;
  let nukeSucceeded = false;
  try {
    const availability = await surveyAvailableModes(storagePath);
    const mode = parsed.mode ?? (await selectMode(lines, out, err, availability));
    if (!mode) {
      err.write("Aborted: no recovery mode selected.\n");
      code = 1;
    } else if (mode === "shares") {
      code = await runSharesPath(out, err, availability);
    } else if (mode === "guardian") {
      code = await runGuardianPath(out, err, availability);
    } else if (mode === "recovery-key") {
      code = await runRecoveryKeyPath({
        out,
        err,
        stdin,
        // Free stdin from the shared line reader so the hidden raw-mode prompt
        // can own it; the outer `finally` closes it again idempotently.
        closeSharedReader: () => lines.close(),
        storagePath,
        home,
        plat,
        allowMachineLocalPassphrase: parsed.allowMachineLocalPassphrase,
        exec: args.exec ?? defaultExec,
        ...(args.recoveryKeyOverride !== undefined
          ? { recoveryKeyOverride: args.recoveryKeyOverride }
          : {}),
        ...(args.lockTimeoutMs !== undefined
          ? { lockTimeoutMs: args.lockTimeoutMs }
          : {}),
        ...(args.__testAfterKernelHolderAcquired !== undefined
          ? {
              __testAfterKernelHolderAcquired:
                args.__testAfterKernelHolderAcquired,
            }
          : {}),
        ...(args.faultAfterRekeyStage !== undefined
          ? { faultAfter: args.faultAfterRekeyStage }
          : {}),
        ...(args.observeSecretBuffer !== undefined
          ? { observeSecretBuffer: args.observeSecretBuffer }
          : {}),
      });
    } else {
      code = await runNukePath({
        out,
        err,
        lines,
        storagePath,
        home,
        plat,
        exec: args.exec ?? defaultExec,
        ...(args.beforeIdentityBoundWipe !== undefined
          ? { beforeIdentityBoundWipe: args.beforeIdentityBoundWipe }
          : {}),
        ...(args.wipeDeadlineMs !== undefined
          ? { wipeDeadlineMs: args.wipeDeadlineMs }
          : {}),
      });
      nukeSucceeded = mode === "nuke" && code === 0;
    }
  } finally {
    // Zeroize any caller-supplied key-material buffers regardless of which
    // path we took or whether it succeeded. JS strings on the heap remain
    // immutable and cannot be cleared; callers MUST pass key material as
    // Buffer / Uint8Array on `keyMaterialToZeroize` for this hook to do
    // anything. Order matters: run AFTER the recovery path returns, BEFORE
    // the readline interface closes (so a buffer that was decrypted
    // mid-prompt and not yet consumed still gets zeroed on early abort),
    // and BEFORE any --exit-on-completion process.exit() so the heap is
    // wiped before the kernel reaps the address space.
    zeroizeBuffers(args.keyMaterialToZeroize);
    lines.close();
  }

  // --exit-on-completion: bound the heap-dump window for extreme threat
  // models. Only fires after a successful nuke; aborts and degraded-shares
  // / degraded-guardian returns leave the shell intact for re-run. The
  // `finally` block above has already zeroed any caller-supplied buffers;
  // process.exit reaps everything else.
  if (parsed.exitOnCompletion && nukeSucceeded) {
    const doExit = args.exitProcess ?? ((c: number) => process.exit(c));
    doExit(0);
  }
  return code;
}

// ── Argument parsing ────────────────────────────────────────────────

function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = {
    exitOnCompletion: false,
    help: false,
    allowMachineLocalPassphrase: false,
  };
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress/--storage value must refuse, never silently resolve the default fortress; wrong-fortress custody operations are a constraint-5 violation.
  const fortress = consumeFlagValue(argv, "--fortress");
  if (fortress.error !== undefined) throw new Error(fortress.error);
  const storage = consumeFlagValue(fortress.argv, "--storage");
  if (storage.error !== undefined) throw new Error(storage.error);
  if (fortress.value !== undefined && storage.value !== undefined) {
    throw new Error(aliasConflictMessage("--fortress", "--storage"));
  }
  if (fortress.value !== undefined) out.fortress = fortress.value;
  if (storage.value !== undefined) out.storage = storage.value;

  for (let i = 0; i < storage.argv.length; i++) {
    const a = storage.argv[i];
    if (a === "--help" || a === "-h") {
      out.help = true;
    } else if (a === "--mode" && storage.argv[i + 1]) {
      const v = storage.argv[++i] as RecoveryMode;
      if (
        v !== "shares" &&
        v !== "guardian" &&
        v !== "nuke" &&
        v !== "recovery-key"
      ) {
        throw new Error(
          `--mode must be one of: shares, guardian, nuke, recovery-key (got ${v})`
        );
      }
      out.mode = v;
    } else if (a === "--exit-on-completion") {
      out.exitOnCompletion = true;
    } else if (a === "--allow-machine-local-passphrase") {
      out.allowMachineLocalPassphrase = true;
    } else if (a && a.startsWith("--")) {
      throw new Error(`Unknown flag: ${a}`);
    }
  }
  return out;
}

function printUsage(out: NodeJS.WritableStream): void {
  out.write(`
Usage: sanctuary reset-passphrase [options]

Recover a fortress whose passphrase has been lost or corrupted. Modes:

  recovery-key  Use your human-held RECOVERY KEY to enroll a fresh passphrase
                WITHOUT losing any data. Interactive terminal only: the recovery
                key is read from a hidden prompt (never argv/env/pipe). Unlocks
                the master via the existing recovery wrap, enrolls and verifies a
                new passphrase (custody wrap + stored credential), then removes
                the old passphrase. Your recovery key keeps working. This is the
                lost-passphrase / fresh-host path; prefer it over nuke.

  shares     Reconstruct the master key from M-of-N recovery shares.
             Available only when shares were previously persisted to this
             fortress. Not yet configured by default in v1.0.x.

  guardian   Initiate a guardian-quorum recovery via the federation. Ships
             with v1.1 federation full mesh; not operational on a single
             unreachable local fortress today.

  nuke       Destroy the fortress entirely and re-initialize. ALL identities,
             broker tokens, audit log entries, and federation membership are
             permanently lost. Operator types the fortress name and the
             literal word DESTROY before the wipe runs. Use this only when
             the recovery-key path and any configured shares/guardian path
             cannot recover this fortress and you accept starting over.

Options:
  --mode <recovery-key|shares|guardian|nuke>
                                  Pick a path non-interactively. recovery-key is
                                  interactive-terminal-only (hidden prompt).
  --fortress <path>               Override the fortress storage path.
                                  Consistent with "sanctuary wrap --fortress".
  --storage <path>                Alias for --fortress.
  --exit-on-completion            After a successful nuke, call process.exit(0)
                                  immediately so the post-wipe heap is reaped
                                  by the OS without re-entering the shell. Use
                                  on extreme-threat-model deployments where an
                                  attacker-on-host with heap-dump access could
                                  recover residual passphrase or key bytes
                                  between the wipe and the next operator
                                  command. JS strings cannot be explicitly
                                  zeroed; this flag is the supported way to
                                  bound the heap-dump window.
  --allow-machine-local-passphrase
                                  recovery-key mode only: permit the freshly
                                  enrolled passphrase to be stored in the
                                  machine-local encrypted fallback file when this
                                  host has no OS keyring. Off by default: the
                                  rekey fails closed rather than land a passphrase
                                  you never see in a machine-bound file with no
                                  operator-held copy. Opting in prints a loud
                                  downgrade warning; your recovery key remains the
                                  durable custody factor.
  --help, -h                      Show this help.

Without --mode, the command surveys which paths are operationally available
on this fortress and presents an interactive menu.

Refuse-if-unlocked: this command refuses to run while runtime.json exists
under the storage path, since that signals a live Sanctuary process. Close
the dashboard and stop all wrapped agents first.

After a successful nuke, run:
  sanctuary wrap

to re-initialize a fresh fortress.
`);
}

// ── Mode survey ─────────────────────────────────────────────────────

async function surveyAvailableModes(
  storagePath: string
): Promise<ModeAvailability> {
  const sharesFile = join(storagePath, "recovery-shares.json");
  const guardianFile = join(storagePath, "guardian-roster.json");

  const sharesPresent = await fileExists(sharesFile);
  const guardianPresent = await fileExists(guardianFile);

  return {
    recoveryKey: {
      // The menu has no credential with which to authenticate the envelope, so
      // it makes NO statement about whether a recovery wrap exists. The
      // selectable operation itself supplies the authentication: a human-held
      // recovery key either opens the current MAC-verified envelope or changes
      // nothing. This label is therefore custody-neutral and attacker-invariant.
      available: false,
      reason:
        "availability is not claimed until your key authenticates the fortress; choose this nondestructive path only if you hold its recovery key",
    },
    shares: {
      available: sharesPresent,
      reason: sharesPresent
        ? "recovery shares persisted on this fortress"
        : "not yet configured on this fortress (M-of-N share persistence ships with v1.1)",
    },
    guardian: {
      available: false,
      reason: guardianPresent
        ? "guardian roster present, but the guardian recovery transport ships with v1.1 federation full mesh"
        : "not-yet-supported: guardian path ships with federation v0.1 full mesh, expected v1.1; use your recovery key first, then shares when configured; nuke only if recovery is impossible",
    },
    nuke: {
      available: true,
      reason: "destroys all state and re-initializes a fresh fortress",
    },
  };
}

// ── Mode selection (interactive) ────────────────────────────────────

async function selectMode(
  lines: LineReader,
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  availability: ModeAvailability
): Promise<RecoveryMode | undefined> {
  // Recovery is the primary operator path. Destruction is deliberately last;
  // interactive numeric choices are not an automation contract.
  out.write(`
Pick a recovery path (if you saved a recovery key, choose 1 - it keeps all data):

  1) recovery-key (human-held key required; keeps all data)
     ${availability.recoveryKey.reason}
     Interactive terminal only: the recovery key is read from a hidden prompt.

  2) shares       ${availability.shares.available ? "(available)" : "(unavailable)"}
     ${availability.shares.reason}

  3) guardian     ${availability.guardian.available ? "(available)" : "(unavailable)"}
     ${availability.guardian.reason}

  4) nuke         (available, DESTRUCTIVE LAST RESORT)
     ${availability.nuke.reason}

`);
  const answer = await prompt(
    lines,
    err,
    "Choose 1, 2, 3, or 4 (or q to abort): "
  );
  const trimmed = answer.trim().toLowerCase();
  if (trimmed === "1" || trimmed === "recovery-key") return "recovery-key";
  if (trimmed === "2" || trimmed === "shares") return "shares";
  if (trimmed === "3" || trimmed === "guardian") return "guardian";
  if (trimmed === "4" || trimmed === "nuke") return "nuke";
  return undefined;
}

// ── Path (a) shares ─────────────────────────────────────────────────

async function runSharesPath(
  _out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  availability: ModeAvailability
): Promise<number> {
  if (!availability.shares.available) {
    err.write(
      `Recovery shares: ${availability.shares.reason}.\n` +
        `Falling through. Re-run with --mode recovery-key if you hold the recovery key,\n` +
        `or use --mode guardian; use --mode nuke only when recovery is impossible,\n` +
        `or omit --mode for the interactive menu.\n`
    );
    return 2;
  }
  // Reserved for v1.1 implementation. When share persistence lands, this
  // branch prompts for M shares, reconstructs the master, asks for the new
  // passphrase, derives a new Argon2id key via core/key-derivation, re-wraps,
  // and writes a passphrase_reset audit entry signed by the preserved
  // identity.
  err.write(
    "Recovery-share reconstruction is reserved for v1.1. The detection branch\n" +
      "is in place, but the reconstruction primitive has not yet shipped.\n"
  );
  return 2;
}

// ── Path (b) guardian ───────────────────────────────────────────────

async function runGuardianPath(
  _out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  availability: ModeAvailability
): Promise<number> {
  err.write(
    `Guardian recovery: ${availability.guardian.reason}.\n` +
      `The federation v0.1 \`guardian_recovery_request\` message class lands with v1.1\n` +
      `full-mesh transport. Use --mode recovery-key if you hold the recovery key,\n` +
      `or --mode shares when configured. Use --mode nuke only when recovery is impossible.\n`
  );
  return 2;
}

// ── Path (c) nuke ───────────────────────────────────────────────────

interface NukeContext {
  out: NodeJS.WritableStream;
  err: NodeJS.WritableStream;
  lines: LineReader;
  storagePath: string;
  home: string;
  plat: NodeJS.Platform;
  exec: (
    cmd: string,
    args: string[]
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
  /** Test only: adversarial root swap immediately before the bound wipe. */
  beforeIdentityBoundWipe?: () => void | Promise<void>;
  /**
   * Bound the identity-bound wipe worker's runtime (round-2). Omitted uses
   * {@link IDENTITY_BOUND_WIPE_DEADLINE_MS}. A worker that wedges (a stuck
   * secure-overwrite, a hung filesystem) must not hold the custody lock forever;
   * on the deadline it is SIGKILLed and the reset fails closed with a re-run
   * remedy. Tests set a small value to exercise the deadline.
   */
  wipeDeadlineMs?: number;
}

// Generous default: a large fortress under a 3-pass secure overwrite can take a
// while, but an unbounded wait that pins the custody lock is worse than a
// bounded refusal the operator can re-run. 10 minutes.
const IDENTITY_BOUND_WIPE_DEADLINE_MS = 10 * 60 * 1000;

/**
 * Nuke-path memory-hygiene threat model
 * --------------------------------------
 *
 * Adversary: an attacker-on-host with the ability to capture a heap dump of
 * this Node.js process between the moment `wipeStorage()` returns and the
 * moment the process exits or is reaped. Such an adversary could potentially
 * recover residual passphrase or key bytes that lived in the V8 heap before
 * the wipe ran.
 *
 * Defenses in this path:
 *
 *   1. Buffers and Uint8Arrays holding key material are zeroed via
 *      `Buffer.fill(0)` / `Uint8Array.fill(0)` AFTER their last legitimate
 *      use and BEFORE this function returns. The current v1.x nuke flow
 *      holds NO such buffers itself: keychain entries are deleted via
 *      `security delete-generic-password` (which never reads the value),
 *      and the encrypted `passphrase.enc` file is explicitly unlinked and
 *      verified absent before the remaining storage is wiped, without ever
 *      being decrypted. The `zeroizeBuffers` helper at the bottom
 *      of this module is the structural hook for any future code path that
 *      DOES decrypt or fetch key material in the nuke flow.
 *
 *   2. JS strings (UTF-16 in V8) cannot be explicitly zeroed in user-space:
 *      they are immutable, GC-managed, and may be string-interned or copied
 *      by the runtime. Any passphrase that flows through this command as a
 *      `string` will linger on the heap until V8 reclaims its slot. Callers
 *      that require mem-hygiene MUST route key material through Buffer or
 *      Uint8Array (and put those on `args.keyMaterialToZeroize`) rather than
 *      as `string`.
 *
 *   3. The `--exit-on-completion` flag, when set, calls `process.exit(0)`
 *      immediately after the wipe summary prints. This is the supported
 *      mitigation for the string-immutability gap: the kernel reclaims the
 *      whole address space, so any residual heap bytes (string or otherwise)
 *      become unreachable to a heap-dump attacker who races the OS reaper.
 *      It is opt-in because operators on standard threat models prefer the
 *      shell to return normally so they can immediately run `sanctuary wrap`.
 *
 * Out of scope (longer-term hardening):
 *
 *   - WASM-backed zeroizer that mlock()s a page, holds key material there,
 *     and sodium_memzero()s on drop. Tracked for v1.x security hardening.
 *   - End-to-end heap-dump test that captures the process heap mid-flight
 *     and asserts no key material is present. Documented in PR body as
 *     verified by code review and unit test of the buffer-zero path; full
 *     heap-dump test deferred.
 */
async function runNukePath(ctx: NukeContext): Promise<number> {
  const fortressName = basename(ctx.storagePath) || "sanctuary";

  // Bind the human confirmations to the exact directory entry that was shown.
  // A path swap while the operator is reading the prompt must never redirect a
  // destructive reset onto a different fortress.
  const initialIdentity = await captureDestructionIdentity(ctx.storagePath);
  if (initialIdentity === null) {
    ctx.err.write(
      "Refusing: the fortress root must be an existing, non-symlink directory.\n"
    );
    return 1;
  }
  const credentialServices =
    ctx.plat === "darwin" || ctx.plat === "linux"
      ? allFortressKeychainCredentialServices(ctx.storagePath, ctx.home)
      : [];

  // 1. Enumerate what is about to die.
  const inventory = await inventoryStorage(ctx.storagePath);
  ctx.out.write(`
About to permanently destroy the fortress at:
  ${ctx.storagePath}

Contents (${inventory.entries.length} entries, ${formatBytes(inventory.totalBytes)} total):
`);
  for (const e of inventory.entries) {
    ctx.out.write(`  ${e.kind === "dir" ? "d" : "f"} ${e.name}  (${formatBytes(e.bytes)})\n`);
  }
  if (inventory.entries.length === 0) {
    ctx.out.write(`  (storage path is empty, nothing to destroy)\n`);
  }

  ctx.out.write(`
This action is IRREVERSIBLE. You will lose:
  - All wrapped agent identities (Ed25519 private keys)
  - All Secret Broker tokens and grants
  - The encrypted audit log and policy configuration
  - Federation membership and guardian roster
  - All L1 cognitive state, L3 commitments, L4 reputation attestations

If you have the human-held recovery key, abort now and run
  sanctuary reset-passphrase --mode recovery-key --fortress ${ctx.storagePath}
to preserve every identity and record. Backups, recovery shares, and guardian
quorum are also safer than destruction. Closing this prompt with anything other than the
exact confirmations below aborts the wipe.

`);

  // 2. Type the fortress name.
  const nameAnswer = await prompt(
    ctx.lines,
    ctx.err,
    `Type the fortress name (${fortressName}) to continue: `
  );
  if (nameAnswer.trim() !== fortressName) {
    ctx.err.write(
      `Aborted: fortress name did not match (expected "${fortressName}", got "${nameAnswer.trim()}").\n`
    );
    return 1;
  }

  // 3. Type the literal word DESTROY.
  const destroyAnswer = await prompt(
    ctx.lines,
    ctx.err,
    `Type the word DESTROY (uppercase) to continue: `
  );
  if (destroyAnswer.trim() !== "DESTROY") {
    ctx.err.write(`Aborted: confirmation word did not match.\n`);
    return 1;
  }

  // 4. Final yes/no.
  const finalAnswer = await prompt(
    ctx.lines,
    ctx.err,
    `Final confirmation. Wipe ${ctx.storagePath} now? [y/N] `
  );
  if (!/^y(es)?$/i.test(finalAnswer.trim())) {
    ctx.err.write(`Aborted: final confirmation declined.\n`);
    return 1;
  }

  // 5. Perform the wipe under the exact custody/master lock. Re-stat the root
  // inside the lock so a prompt-time rename/symlink swap fails closed.
  const startedAt = new Date().toISOString();
  if (
    !sameDestructionIdentity(
      initialIdentity,
      await captureDestructionIdentity(ctx.storagePath),
    )
  ) {
    ctx.err.write(
      "Refusing: the fortress root changed while confirmation was pending. Nothing was destroyed.\n"
    );
    return 1;
  }
  if (!(await destructionLockAncestorsAreSafe(ctx.storagePath))) {
    ctx.err.write(
      "Refusing: the fortress custody-lock path contains a symlink or non-directory component. Nothing was destroyed.\n"
    );
    return 1;
  }
  const storage = new FilesystemStorage(join(ctx.storagePath, "state"));
  let cleanup: { ok: boolean; keychain: KeychainClearStatus };
  let wipeStarted = false;
  try {
    cleanup = await withCustodyWriteLock(
      storage,
      async (lease) => {
      lease.assertHeld();
      const currentIdentity = await captureDestructionIdentity(ctx.storagePath);
      lease.assertHeld();
      if (!sameDestructionIdentity(initialIdentity, currentIdentity)) {
        ctx.err.write(
          "Refusing: the fortress root changed while confirmation was pending. Nothing was destroyed.\n"
        );
        return { ok: false as const, keychain: "unsupported" as const };
      }
      if (!(await liveCustodyLockScaffoldIsSafe(ctx.storagePath))) {
        ctx.err.write(
          "Refusing: the live custody-lock scaffold is not one zero-byte, single-link regular file. Nothing was destroyed.\n"
        );
        return { ok: false as const, keychain: "unsupported" as const };
      }

      // Clear every external credential BEFORE destroying disk state. An
      // indeterminate keyring result aborts the reset: claiming success while a
      // reusable credential may survive would violate destructive-reset truth.
      let keychain: KeychainClearStatus = "unsupported";
      if (ctx.plat === "darwin" || ctx.plat === "linux") {
        keychain = await clearKeychainEntries(ctx, lease, credentialServices);
        if (keychain === "indeterminate") {
          ctx.err.write(
            "Refusing: the OS credential store is locked or unreachable, so Sanctuary cannot prove every stored credential was removed. Unlock it and retry. Fortress data and the encrypted fallback were preserved; some keyring aliases may already have been cleared.\n"
          );
          return { ok: false as const, keychain };
        }
      }
      lease.assertHeld();
      if (
        !sameDestructionIdentity(
          initialIdentity,
          await captureDestructionIdentity(ctx.storagePath),
        )
      ) {
        ctx.err.write(
          "Refusing: the fortress root changed during credential cleanup. Fortress data and the encrypted fallback were preserved.\n"
        );
        return { ok: false as const, keychain };
      }

      // A final pathname check cannot bind later path-based readdir/rm calls:
      // an attacker can rename this root after the check and install a
      // replacement while the kernel custody lock remains attached to the
      // renamed original tree. Spawn a tiny worker with cwd set to the root.
      // chdir(2) binds the worker to one directory inode; the worker validates
      // that inode before deleting and then uses only relative paths. A swap
      // before chdir is a mismatch/refusal, while a swap after chdir cannot
      // redirect any deletion through the replacement pathname.
      await ctx.beforeIdentityBoundWipe?.();
      wipeStarted = true;
      await wipeStorageIdentityBound(
        ctx.storagePath,
        initialIdentity,
        lease,
        ctx.wipeDeadlineMs ?? IDENTITY_BOUND_WIPE_DEADLINE_MS,
      );
      lease.assertHeld();
      if (!sameDestructionIdentity(
        initialIdentity,
        await captureDestructionIdentity(ctx.storagePath),
      )) {
        throw new DestructiveResetRefusedError(
          "the fortress root changed during the identity-bound wipe; the original " +
            "fortress may be partially reset, but no replacement path was traversed",
        );
      }
      return { ok: true as const, keychain };
      },
      { metadata: { operation: "destructive_reset" } },
    );
  } catch (error) {
    if (wipeStarted) {
      ctx.err.write(
        `Destructive reset failed after the wipe began (${error instanceof Error ? error.message : String(error)}). ` +
          "The fortress is partially destroyed; do not reuse it. Recover from backup or complete re-initialization.\n",
      );
      return 1;
    }
    if (error instanceof CrossProcessLockError) {
      ctx.err.write(
        `Refusing: destructive reset requires the custody kernel lock, but it could not be held. ${error.message}\n` +
          "No successful reset was recorded. If cleanup had already begun, treat the fortress as partially reset and recover or reinitialize it before use.\n"
      );
      return 1;
    }
    if (error instanceof DestructiveResetRefusedError) {
      ctx.err.write(
        `Destructive reset stopped: ${error.message}. The fortress is partially destroyed; ` +
          "do not reuse it. Recover from backup or complete re-initialization. No successful reset was recorded.\n",
      );
      return 1;
    }
    throw error;
  }
  if (!cleanup.ok) return 1;
  const keychainCleared = cleanup.keychain === "cleared";

  // 7. Write a plaintext reset marker so a future fortress at the same
  //    storage path can show this history on first boot. Audit-log
  //    continuity is impossible by definition (the audit log was just
  //    destroyed), so this marker is the best-effort substitute.
  const completedAt = new Date().toISOString();
  const markerRecorded = await recordResetMarkerBestEffort(ctx.storagePath, {
    started_at: startedAt,
    completed_at: completedAt,
    recovery_mode: "nuke",
    fortress_name: fortressName,
    storage_path: ctx.storagePath,
    keychain_cleared: keychainCleared,
  }, ctx.err);

  ctx.out.write(`
Reset complete.
  recovery_mode: nuke
  started_at:    ${startedAt}
  completed_at:  ${completedAt}
  storage_path:  ${ctx.storagePath}
  stored credential: ${cleanup.keychain === "cleared" ? "cleared" : cleanup.keychain === "absent" ? "no keyring entry existed" : "keyring unsupported; encrypted fallback removed"}

Reset history: ${markerRecorded ? join(ctx.storagePath, ".reset-history.log") : "not recorded (see warning above)"}
Next step:    sanctuary wrap
`);
  return 0;
}

// ── Recovery-key rekey (mode d) ─────────────────────────────────────
//
// A DURABLE, cross-process-exclusive transaction. The rekey publishes a NEW
// passphrase factor (a custody wrap AND the exact-fortress stored credential),
// then removes the OLD passphrase wraps — but a crash or a concurrent writer
// between those steps could otherwise leave the on-disk envelope inconsistent
// with the stored credential (publish envelope A, credential B). Two mechanisms
// prevent that:
//
//  1. Kernel-backed cross-process exclusive lock: the WHOLE
//     reread→append→persist→readback→replace→audit critical section runs under
//     the SAME `withCustodyWriteLock` domain used by establishment, wrap writes,
//     and master rotation. The kernel never grants it to two live holders and
//     releases it automatically on SIGKILL, so recovery needs no unsafe stale
//     lockfile theft and cannot overlap another custody/master writer.
//  2. Durable journal + DISK-TRUTH recovery: before the first mutation a journal
//     records the exact prior envelope bytes and the new wrap id; on entry, any
//     journal left by a crashed prior run is healed FIRST. The heal decision
//     reads the ACTUAL on-disk envelope + stored credential (never just the
//     state label), so it always converges to a consistent fortress: it rolls
//     FORWARD when the stored credential unlocks the new-wrap-only envelope,
//     rolls BACK a pre-final state to the exact prior envelope, or safely
//     supersedes an authenticated final state on a copied host without replaying
//     its retired passphrase wraps.
//
// Invariants that hold at EVERY interruption point: the recovery key is never
// removed (always a valid factor); the on-disk envelope always contains a wrap
// the surviving stored credential can open; a pre-commit failure restores the
// EXACT prior envelope (so repeated failed attempts never accrete unusable
// wraps); after custody-commit at least one valid factor survives and recovery
// is deterministic. No secret is printed or written to the audit marker
// (CLAUDE.md #6).

/** The 256-bit recovery key width; a decoded key of any other length is refused. */
const RECOVERY_KEY_BYTES = 32;

/** `_meta` key of the durable rekey journal (removed once the rekey completes). */
const REKEY_JOURNAL_KEY = "custody-rekey-journal";
/**
 * Named durability stages, in order. The journal records how far a run got (for
 * the CLI's own pre-commit-vs-committed reporting); recovery does NOT trust the
 * label — it reads disk truth. `faultAfter(stage)` (test-only) fires after each.
 */
export type RekeyStage =
  | "journal-prepared"
  | "augmented-written"
  | "stored-persisted"
  | "custody-committed"
  | "final-written"
  | "journal-clear-before-unlink"
  | "journal-cleared"
  | "marker-written";

interface RekeyJournal {
  v: 1;
  /** The furthest stage reached; advisory only (recovery reads disk truth). */
  state: RekeyStage;
  started_at: string;
  /** id of the NEW passphrase wrap this rekey is enrolling. */
  new_wrap_id: string;
  /** base64url of the EXACT prior envelope bytes, for a byte-identical restore. */
  prior_envelope: string;
  /** Master-keyed authentication over every recovery-bearing field above. */
  mac: string;
}

type UnsignedRekeyJournal = Omit<RekeyJournal, "mac">;

class RekeyJournalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RekeyJournalError";
  }
}

class RekeyJournalPostCommitError extends Error {
  constructor(cause: unknown) {
    super(
      "custody is already committed, but its recovery journal could not be removed; " +
        "the journal was preserved. Restart this process and rerun the same recovery-key " +
        "command; replay is authenticated and safe",
      { cause },
    );
    this.name = "RekeyJournalPostCommitError";
  }
}

const REKEY_JOURNAL_DOMAIN = "sanctuary-custody-rekey-journal-v1";
const REKEY_JOURNAL_STATES = new Set<RekeyStage>([
  "journal-prepared",
  "augmented-written",
  "stored-persisted",
  "custody-committed",
  "final-written",
  "journal-clear-before-unlink",
  "journal-cleared",
  "marker-written",
]);

function unsignedRekeyJournalBytes(journal: UnsignedRekeyJournal): Uint8Array {
  return Buffer.from(
    JSON.stringify({
      domain: REKEY_JOURNAL_DOMAIN,
      v: journal.v,
      state: journal.state,
      started_at: journal.started_at,
      new_wrap_id: journal.new_wrap_id,
      prior_envelope: journal.prior_envelope,
    }),
    "utf8",
  );
}

function rekeyJournalMac(
  journal: UnsignedRekeyJournal,
  master: Uint8Array,
): string {
  const key = derivePurposeKey(master, REKEY_JOURNAL_DOMAIN);
  try {
    return toBase64url(hmacSha256(key, unsignedRekeyJournalBytes(journal)));
  } finally {
    key.fill(0);
  }
}

function authenticatePriorEnvelope(
  journal: RekeyJournal,
  master: Uint8Array,
): { bytes: Uint8Array; envelope: CustodyEnvelope } {
  let bytes: Uint8Array;
  let envelope: CustodyEnvelope;
  try {
    bytes = fromBase64url(journal.prior_envelope);
    envelope = JSON.parse(Buffer.from(bytes).toString("utf8")) as CustodyEnvelope;
    verifyEnvelopeMac(envelope, master);
  } catch {
    throw new RekeyJournalError(
      "the recovery journal's prior custody snapshot is not authentic for this fortress",
    );
  }
  return { bytes, envelope };
}

function sameEnvelopeHeader(a: CustodyEnvelope, b: CustodyEnvelope): boolean {
  return (
    a.v === b.v &&
    a.install_mode === b.install_mode &&
    a.created_at === b.created_at &&
    a.epoch === b.epoch &&
    a.epoch_id === b.epoch_id
  );
}

function sameWraps(a: CustodyEnvelope["wraps"], b: CustodyEnvelope["wraps"]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Bind a journal not merely to this master, but to the exact transaction state
 * currently on disk. This defeats replay of an old, still-authentic journal.
 */
function journalEnvelopePhase(
  current: CustodyEnvelope,
  prior: CustodyEnvelope,
  newWrapId: string,
): "prior" | "augmented" | "final" | null {
  if (!sameEnvelopeHeader(current, prior)) return null;
  if (sameWraps(current.wraps, prior.wraps)) return "prior";
  const newWraps = current.wraps.filter(
    (wrap) => wrap.id === newWrapId && wrap.type === "passphrase",
  );
  if (newWraps.length !== 1) return null;
  const newWrap = newWraps[0]!;
  const augmented = [...prior.wraps, newWrap];
  if (sameWraps(current.wraps, augmented)) return "augmented";
  const final = [
    ...prior.wraps.filter((wrap) => wrap.type !== "passphrase"),
    newWrap,
  ];
  return sameWraps(current.wraps, final) ? "final" : null;
}

interface RecoveryKeyPathContext {
  out: NodeJS.WritableStream;
  err: NodeJS.WritableStream;
  // The exact raw-mode stdin shape the hidden-prompt reader needs; reused from
  // hidden-prompt.ts so this context carries no divergent re-declaration.
  stdin: RawModeStdin;
  /** Closes the shared line reader so the hidden raw-mode prompt owns stdin. */
  closeSharedReader: () => void;
  storagePath: string;
  home: string;
  plat: NodeJS.Platform;
  /**
   * S3: when false (default), the rekey refuses to store its generated
   * passphrase in the machine-local fallback file with no OS keyring (fail
   * closed). When true (operator opt-in via `--allow-machine-local-passphrase`),
   * it is permitted and a loud SEC-063-style downgrade warning is emitted.
   */
  allowMachineLocalPassphrase?: boolean;
  exec: (
    cmd: string,
    args: string[],
    input?: string
  ) => Promise<{ stdout: string; stderr: string; code: number | null }>;
  /** Test seam: recovery key without a real TTY hidden prompt. */
  recoveryKeyOverride?: string;
  /** Test seam: bound the cross-process lock wait (production uses the default). */
  lockTimeoutMs?: number;
  __testAfterKernelHolderAcquired?: (pid: number) => void;
  /** Test seam: inject a crash after a named durability stage. */
  faultAfter?: (stage: RekeyStage) => void | Promise<void>;
  /** Test seam: observe a live secret buffer at creation (see ResetPassphraseArgs). */
  observeSecretBuffer?: (label: "recovery-key" | "master", buf: Uint8Array) => void;
}

async function readRekeyJournal(
  storage: StorageBackend,
  master: Uint8Array,
): Promise<RekeyJournal | null> {
  const raw = await storage.read("_meta", REKEY_JOURNAL_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw).toString("utf8")) as RekeyJournal;
    if (
      parsed?.v === 1 &&
      REKEY_JOURNAL_STATES.has(parsed.state) &&
      typeof parsed.started_at === "string" &&
      parsed.started_at.length > 0 &&
      typeof parsed.new_wrap_id === "string" &&
      parsed.new_wrap_id.length > 0 &&
      typeof parsed.prior_envelope === "string" &&
      typeof parsed.mac === "string"
    ) {
      const unsigned: UnsignedRekeyJournal = {
        v: parsed.v,
        state: parsed.state,
        started_at: parsed.started_at,
        new_wrap_id: parsed.new_wrap_id,
        prior_envelope: parsed.prior_envelope,
      };
      const expected = fromBase64url(rekeyJournalMac(unsigned, master));
      let supplied: Uint8Array;
      try {
        supplied = fromBase64url(parsed.mac);
      } catch {
        throw new RekeyJournalError("the recovery journal authentication tag is malformed");
      }
      if (
        supplied.length !== expected.length ||
        !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))
      ) {
        throw new RekeyJournalError("the recovery journal authentication tag does not verify");
      }
      // A valid journal tag binds the snapshot bytes, but independently validate
      // the snapshot as a custody envelope under this same recovered master too.
      authenticatePriorEnvelope(parsed, master);
      return parsed;
    }
  } catch (error) {
    if (error instanceof RekeyJournalError) throw error;
    throw new RekeyJournalError("the recovery journal is malformed or unauthenticated");
  }
  throw new RekeyJournalError("the recovery journal is malformed or unauthenticated");
}

async function writeRekeyJournal(
  storage: StorageBackend,
  journal: UnsignedRekeyJournal,
  master: Uint8Array,
): Promise<void> {
  const authenticated: RekeyJournal = {
    ...journal,
    mac: rekeyJournalMac(journal, master),
  };
  await storage.write(
    "_meta",
    REKEY_JOURNAL_KEY,
    Buffer.from(JSON.stringify(authenticated), "utf8")
  );
}

async function clearRekeyJournal(storage: StorageBackend): Promise<void> {
  // This journal contains authenticated ciphertext metadata, not plaintext key
  // material. Never secure-overwrite it: overwrite+fsync+unlink creates a fatal
  // SIGKILL window in which random bytes can survive as a malformed journal.
  // Plain unlink is atomic (old valid journal or absent); FilesystemStorage also
  // fsyncs the namespace directory before resolving.
  await storage.delete("_meta", REKEY_JOURNAL_KEY, false);
}

async function clearCommittedRekeyJournal(storage: StorageBackend): Promise<void> {
  try {
    await clearRekeyJournal(storage);
  } catch (error) {
    throw new RekeyJournalPostCommitError(error);
  }
}

type StoredFinalCredentialProbe =
  | "opens-final"
  | "absent"
  | "mismatch"
  | "indeterminate";

type LockedCredentialOptions = Pick<
  PassphraseOptions,
  "credentialIdentity" | "fallbackCapability"
>;

async function probeStoredCredentialAgainstFinal(
  ctx: RecoveryKeyPathContext,
  candidateFinal: CustodyEnvelope,
  master: Uint8Array,
  lockedCredentialOptions: LockedCredentialOptions,
): Promise<StoredFinalCredentialProbe> {
  let observed: Awaited<ReturnType<typeof observeStoredPassphrase>>;
  try {
    observed = await observeStoredPassphrase({
      storagePath: ctx.storagePath,
      home: ctx.home,
      platformOverride: ctx.plat,
      exec: ctx.exec,
      readOnly: true,
      ...lockedCredentialOptions,
    });
  } catch {
    return "indeterminate";
  }
  if (observed.status === "fallback-unreadable") {
    // An unreadable fallback is a definite negative only when every keyring
    // identity was reachable. If the keyring is unavailable, it may contain the
    // just-committed credential; preserve the journal rather than guess.
    return observed.keyringUnreachable ? "indeterminate" : "mismatch";
  }
  if (observed.status === "absent") {
    return observed.keyringUnreachable ? "indeterminate" : "absent";
  }
  const stored = observed.result.value;
  let unlocked: Uint8Array | undefined;
  try {
    unlocked = await unwrapMaster(candidateFinal, { passphrase: stored });
    const matches =
      unlocked.length === master.length &&
      timingSafeEqual(Buffer.from(unlocked), Buffer.from(master));
    // A positive fallback authentication is conclusive even while the keyring
    // is down. A stale fallback is not: the unavailable keyring may hold the
    // committed final credential, so retain the journal as indeterminate.
    return matches
      ? "opens-final"
      : observed.keyringUnreachable
        ? "indeterminate"
        : "mismatch";
  } catch {
    return observed.keyringUnreachable ? "indeterminate" : "mismatch";
  } finally {
    unlocked?.fill(0);
  }
}

/**
 * Heal a journal left by a crashed prior rekey. DISK-TRUTH: roll FORWARD only
 * when the stored credential already unlocks the new-wrap-only envelope (the
 * fresh passphrase was durably committed), otherwise roll BACK to the exact
 * prior envelope (the fresh passphrase was never durably stored, so the
 * untouched old credential / recovery key still open the restored envelope).
 * An authenticated final state with no usable local credential is superseded
 * by a fresh enrollment, never restored from retired wraps. In every case,
 * `master` (already unlocked from the entered recovery key) authenticates the
 * decision and writes.
 */
async function healInterruptedRekey(
  storage: StorageBackend,
  ctx: RecoveryKeyPathContext,
  currentEnv: Awaited<ReturnType<typeof readCustodyEnvelope>>,
  master: Uint8Array,
  journal: RekeyJournal,
  lease: CrossProcessLockLease,
  lockedCredentialOptions: LockedCredentialOptions,
): Promise<"rolled-forward" | "rolled-back" | "superseded-final"> {
  if (currentEnv === null) {
    throw new RekeyJournalError(
      "the recovery journal cannot be bound because current custody is absent",
    );
  }
  const authenticatedPrior = authenticatePriorEnvelope(journal, master);
  const phase = journalEnvelopePhase(
    currentEnv,
    authenticatedPrior.envelope,
    journal.new_wrap_id,
  );
  if (phase === null) {
    throw new RekeyJournalError(
      "the recovery journal does not describe the current custody transaction",
    );
  }
  const newWrapId = journal.new_wrap_id;
  const hasNewWrap =
    currentEnv !== null &&
    currentEnv.wraps.some((w) => w.id === newWrapId && w.type === "passphrase");

  // The new-wrap-only envelope: every non-passphrase wrap plus ONLY the new
  // passphrase wrap. This is what a completed rekey leaves on disk.
  const candidateFinal =
    currentEnv === null
      ? null
      : {
          ...currentEnv,
          wraps: currentEnv.wraps.filter(
            (w) => w.type !== "passphrase" || w.id === newWrapId
          ),
        };

  // Does the stored credential open the new-wrap-only envelope? If so the fresh
  // passphrase was durably committed and removing the old wraps keeps it valid.
  const storedProbe =
    hasNewWrap && candidateFinal
      ? await probeStoredCredentialAgainstFinal(
          ctx,
          candidateFinal,
          master,
          lockedCredentialOptions,
        )
      : "mismatch";
  const storedUnlocksFinal = storedProbe === "opens-final";

  if (storedUnlocksFinal && candidateFinal) {
    if (!lockedCredentialOptions.credentialIdentity) {
      throw new RekeyJournalError(
        "rekey healing is missing its inode-bound credential identity",
      );
    }
    const committedReadback = await readStoredPassphrase({
      storagePath: ctx.storagePath,
      home: ctx.home,
      platformOverride: ctx.plat,
      exec: ctx.exec,
      readOnly: true,
      ...lockedCredentialOptions,
    });
    if (committedReadback === null) {
      throw new RekeyJournalError(
        "the committed stored credential vanished during retired-service cleanup",
      );
    }
    await deleteRetiredMatchingPassphraseServices({
      value: committedReadback.value,
      credentialIdentity: lockedCredentialOptions.credentialIdentity,
      platformOverride: ctx.plat,
      exec: ctx.exec,
    });
    // ROLL FORWARD: finalize idempotently (removing old wraps keeps the stored
    // credential valid), then clear the authoritative journal BEFORE touching
    // non-authoritative operator history. History failure cannot wedge healing.
    lease.assertHeld();
    await writeCustodyEnvelope(storage, candidateFinal, master);
    lease.assertHeld();
    await clearCommittedRekeyJournal(storage);
    lease.assertHeld();
    await recordResetMarkerBestEffort(ctx.storagePath, {
      started_at: journal.started_at,
      completed_at: new Date().toISOString(),
      recovery_mode: "recovery-key",
      fortress_name: basename(ctx.storagePath),
      storage_path: ctx.storagePath,
      keychain_cleared: false,
    }, ctx.err);
    return "rolled-forward";
  }

  if (storedProbe === "indeterminate") {
    throw new RekeyJournalError(
      "the stored credential is locked, unreachable, or otherwise indeterminate; " +
        "the augmented custody and authenticated recovery journal were preserved. " +
        "Unlock the OS keyring and rerun " +
        "`sanctuary reset-passphrase --mode recovery-key --fortress <path>`",
    );
  }

  if (phase === "final") {
    // Final custody intentionally removed the old passphrase factors. The
    // operator has authenticated the CURRENT envelope and journal with the
    // human-held recovery key, but may supersede only after the local credential
    // is known definitely absent or mismatched. A locked/indeterminate keyring
    // preserves both committed custody and journal above; guessing here could
    // overwrite a valid credential on a temporarily unavailable keyring.
    lease.assertHeld();
    await clearCommittedRekeyJournal(storage);
    lease.assertHeld();
    return "superseded-final";
  }

  // ROLL BACK: restore the EXACT prior envelope bytes. The old credential /
  // recovery key still open it, and the orphaned new wrap is gone (no accretion).
  lease.assertHeld();
  await storage.write("_meta", CUSTODY_ENVELOPE_KEY, authenticatedPrior.bytes);
  lease.assertHeld();
  await clearRekeyJournal(storage);
  lease.assertHeld();
  return "rolled-back";
}

/**
 * Recovery-key rekey. TTY-only, hidden-prompt-only: the operator types their
 * human-held recovery key, it unlocks the master through the existing recovery
 * wrap, and a fresh random passphrase is enrolled as a NEW passphrase wrap plus
 * the exact-fortress stored credential. The whole custody mutation runs under a
 * cross-process exclusive lock and a durable journal (see the section header),
 * so every interruption is idempotently recoverable and the envelope is never
 * published inconsistent with the stored credential. Master key, fortress data,
 * and the recovery wrap are preserved. A wrong key mutates nothing. No secret is
 * ever printed or written to the audit marker (CLAUDE.md #6).
 *
 * F4: recoveryKeyBytes and master are owned by the OUTER `finally`, so both are
 * zeroed on EVERY exit — the wrong-key throw, a lock-contention throw, an
 * injected crash, and the success path alike.
 */
async function runRecoveryKeyPath(
  ctx: RecoveryKeyPathContext
): Promise<number> {
  // Private + interactive only: the recovery key is read from a hidden prompt,
  // never from argv, env, or a piped stdin — so it cannot be scraped from a
  // process list, a shell history, or a CI log. The test-only override bypasses
  // the terminal requirement (production leaves it undefined).
  if (ctx.recoveryKeyOverride === undefined && !ctx.stdin.isTTY) {
    ctx.err.write(
      "Refusing: --mode recovery-key requires an interactive terminal.\n" +
        "The recovery key is read from a hidden prompt only; it is never accepted\n" +
        "from argv, an environment variable, or a piped stdin.\n"
    );
    return 2;
  }
  // Hand stdin to the hidden raw-mode reader.
  ctx.closeSharedReader();

  const entered = (
    ctx.recoveryKeyOverride ??
    (await promptHiddenLine(ctx.stdin, "Recovery key", {
      err: ctx.err,
    }))
  ).trim();
  if (!entered) {
    ctx.err.write("Aborted: no recovery key entered. No changes were made.\n");
    return 1;
  }

  // F4: both secret buffers are function-scoped and zeroed in the OUTER finally,
  // so they are scrubbed even when unwrapMaster throws for a wrong key, when the
  // lock is contended, or when an injected fault unwinds mid-transaction.
  let recoveryKeyBytes: Uint8Array | null = null;
  // `master` is assigned inside the cross-process-lock closure; a holder object
  // keeps it visible (as Uint8Array | null) to the outer `finally` for zeroing,
  // which a closure-assigned `let` would not be under control-flow analysis.
  const held: { master: Uint8Array | null } = { master: null };
  try {
    try {
      recoveryKeyBytes = fromBase64url(entered);
    } catch {
      ctx.err.write(
        "Aborted: the recovery key is not valid base64url. No changes were made.\n"
      );
      return 1;
    }
    if (recoveryKeyBytes.length !== RECOVERY_KEY_BYTES) {
      ctx.err.write(
        "Aborted: the recovery key has the wrong length. No changes were made.\n"
      );
      return 1;
    }
    ctx.observeSecretBuffer?.("recovery-key", recoveryKeyBytes);
    const rkBytes = recoveryKeyBytes;

    let canonicalFortressPath: string;
    // Capture the operator-supplied path identity before canonicalizing the
    // filesystem root. The canonical service remains authoritative, while the
    // read-service set intentionally retains pre-realpath lexical aliases so a
    // committed rekey can retire the exact legacy credential that opened this
    // fortress through an alias. Deletion later still requires an exact value
    // match and an authenticated canonical readback.
    const credentialIdentity = capturePassphraseCredentialIdentity(
      ctx.storagePath,
      ctx.home,
    );
    try {
      canonicalFortressPath = await realpath(ctx.storagePath);
    } catch (error) {
      throw new PassphrasePathIdentityError(ctx.storagePath, error);
    }
    const storage = new FilesystemStorage(join(canonicalFortressPath, "state"));

    // The ENTIRE reread→mutate→verify→finalize critical section runs under the
    // cross-process exclusive lock, so no concurrent process can race the stored
    // credential against the envelope. A contended acquire fails closed
    // (CrossProcessLockError) with nothing mutated.
    return await withCustodyWriteLock(
      storage,
      async (lease) => {
        lease.assertHeld();
        const fortressFiles = lease.stableFortressFiles;
        if (!fortressFiles) {
          throw new Error(
            "recovery rekey requires an inode-bound fortress file capability",
          );
        }
        const lockedCredentialOptions: LockedCredentialOptions = {
          credentialIdentity,
          fallbackCapability: {
            read: () => fortressFiles.read("passphrase.enc"),
            write: (data) => fortressFiles.write("passphrase.enc", data, 0o600),
            delete: () => fortressFiles.delete("passphrase.enc"),
          },
        };
        let envelope = await readCustodyEnvelope(storage);
        if (!envelope) {
          ctx.err.write(
            "Refusing: this fortress has no envelope-format custody to rekey.\n" +
              "The recovery-key rekey path applies only to envelope custody. Nothing was changed.\n"
          );
          return 1;
        }

        // Prove the operator holds the recovery key against the CURRENT envelope
        // BEFORE any mutation (heal or rekey). A wrong key throws
        // CustodyUnlockError here → the outer catch reports it and NOTHING is
        // mutated (the zero-mutation guarantee for a wrong key).
        held.master = await unwrapMaster(envelope, { recoveryKey: rkBytes });
        // Local non-null alias for readability within the closure; the outer
        // `finally` zeroes the SAME buffer via `held.master`.
        const master = held.master;
        ctx.observeSecretBuffer?.("master", master);
        // Authenticate the envelope's wrap list under the recovered master
        // before trusting it (never honor an unauthenticated envelope).
        verifyEnvelopeMac(envelope, master);
        // Validate a pending journal before ANY secondary custody/keyring
        // mutation. A corrupt or foreign journal therefore preserves both the
        // current authenticated envelope and every stored-credential namespace.
        const pending = await readRekeyJournal(storage, master);

        // Heal any journal a crashed prior rekey left, FIRST. Disk-truth heal
        // always converges the fortress to a consistent state.
        if (pending) {
          const outcome = await healInterruptedRekey(
            storage,
            ctx,
            envelope,
            master,
            pending,
            lease,
            lockedCredentialOptions,
          );
          if (outcome === "rolled-forward") {
            // This invocation owns a freshly requested rekey. Finalizing the
            // prior transaction is one-shot recovery work, not authorization to
            // suppress the new request (a replayed completed journal must never
            // make reset-passphrase silently do nothing).
            ctx.out.write(
              "\nRecovered an interrupted recovery-key rekey: the previously enrolled\n" +
                "passphrase was finalized; proceeding with the freshly requested rekey.\n"
            );
          }
          if (outcome === "superseded-final") {
            ctx.out.write(
              "\nRecovered an interrupted final-written rekey on this host without " +
                "replaying retired passphrase wraps; proceeding to enroll a fresh " +
                "exact-fortress stored credential.\n",
            );
          } else if (outcome === "rolled-back") {
            // rolled-back: the prior attempt's fresh passphrase was never durably
            // stored; the exact prior custody was restored. Fall through and rekey
            // now with the key the operator just entered.
            ctx.out.write(
              "\nRecovered an interrupted recovery-key rekey by restoring the prior custody;\n" +
                "proceeding with a fresh rekey.\n"
            );
          }
          const healedEnvelope = await readCustodyEnvelope(storage);
          if (!healedEnvelope) {
            throw new RekeyJournalError(
              "custody vanished after authenticated rekey recovery",
            );
          }
          verifyEnvelopeMac(healedEnvelope, master);
          envelope = healedEnvelope;
        }

        const startedAt = new Date().toISOString();
        // The fresh passphrase is random and never surfaced to the operator; it
        // lives only in the stored credential and as a custody wrap. JS strings
        // cannot be zeroed, so it is kept out of argv/logs.
        const freshPassphrase = generatePassphrase();
        const newWrap = await wrapMasterWithPassphrase(master, freshPassphrase, {
          verified: true,
        });
        const augmented = {
          ...envelope,
          wraps: [...envelope.wraps, newWrap],
        };

        // The EXACT prior envelope bytes, for a byte-identical restore on a
        // pre-commit failure (so repeated failures never accrete new wraps).
        const priorRaw = await storage.read("_meta", CUSTODY_ENVELOPE_KEY);
        if (!priorRaw) {
          ctx.err.write(
            "Refusing: the custody envelope vanished mid-operation. Nothing was changed.\n"
          );
          return 1;
        }

        // JOURNAL: prepared (nothing mutated yet but the journal + snapshot).
        lease.assertHeld();
        await writeRekeyJournal(storage, {
          v: 1,
          state: "journal-prepared",
          started_at: startedAt,
          new_wrap_id: newWrap.id,
          prior_envelope: toBase64url(priorRaw),
        }, master);
        lease.assertHeld();
        await ctx.faultAfter?.("journal-prepared");

        // Append the new wrap. The envelope now holds old + new + recovery; the
        // OLD passphrase and the recovery key both still unlock it (consistent).
        lease.assertHeld();
        await writeCustodyEnvelope(storage, augmented, master);
        lease.assertHeld();
        await ctx.faultAfter?.("augmented-written");

        // PRE-COMMIT verify: the new wrap unlocks the same master.
        const reread = await readCustodyEnvelope(storage);
        let wrapOk = false;
        if (reread) {
          try {
            const check = await unwrapMaster(reread, {
              passphrase: freshPassphrase,
            });
            wrapOk =
              check.length === master.length &&
              timingSafeEqual(Buffer.from(check), Buffer.from(master));
            check.fill(0);
          } catch {
            wrapOk = false;
          }
        }
        if (!wrapOk) {
          // PRE-COMMIT failure: restore the EXACT prior envelope (removes the new
          // wrap → no accretion). The stored credential was never touched, so the
          // fortress stays consistent.
          lease.assertHeld();
          await storage.write("_meta", CUSTODY_ENVELOPE_KEY, priorRaw);
          lease.assertHeld();
          await clearRekeyJournal(storage);
          lease.assertHeld();
          ctx.err.write(
            "Refusing to finalize: the new passphrase wrap did not verify.\n" +
              "The exact prior custody was restored; nothing was removed and no unusable\n" +
              "wrap was left behind. Your recovery key and the OLD passphrase still work.\n"
          );
          return 1;
        }

        // COMMIT custody: persist the fresh passphrase to the EXACT-fortress
        // stored credential. The envelope already holds the new wrap, so once the
        // credential is stored the pair is consistent.
        let storedLocation: string;
        try {
          lease.assertHeld();
          const persisted = await persistAndConfirmUserProvidedPassphrase(freshPassphrase, {
            storagePath: ctx.storagePath,
            home: ctx.home,
            platformOverride: ctx.plat,
            exec: ctx.exec,
            // S3: the rekey mints a passphrase the operator never sees, so it must
            // not silently land in a machine-local fallback file with no keyring
            // and no operator-held copy. Fail closed unless the operator opted in.
            refuseFallbackFile: !ctx.allowMachineLocalPassphrase,
            ...lockedCredentialOptions,
          });
          lease.assertHeld();
          storedLocation = persisted.location;
          if (
            ctx.allowMachineLocalPassphrase &&
            persisted.source === "fallback-file"
          ) {
            // Opt-in downgrade: emit the loud SEC-063-style warning so the
            // operator knows the generated passphrase is protected only against
            // off-machine access and has no operator-held copy to migrate with.
            ctx.err.write(
              "\n  ⚠  The freshly enrolled passphrase was stored in the machine-local\n" +
                "     encrypted fallback file (no OS keyring on this host). It is protected\n" +
                "     ONLY against off-machine access, is bound to this host/user, and was\n" +
                "     NEVER shown to you, so there is no operator-held copy. If this fortress\n" +
                "     directory is copied off the host, only four public host facts stand\n" +
                "     between an attacker and the vault. Prefer a host with an OS keyring, or\n" +
                "     keep your RECOVERY KEY as the durable custody factor.\n",
            );
          }
        } catch (error) {
          lease.assertHeld();
          // An external credential-store error can be ambiguous: the write may
          // have committed before its result was lost. Read disk/keychain truth
          // before deciding, and never remove the new wrap on an indeterminate
          // read.
          const candidateFinal = {
            ...augmented,
            wraps: augmented.wraps.filter(
              (w) => w.type !== "passphrase" || w.id === newWrap.id,
            ),
          };
          const persisted = await probeStoredCredentialAgainstFinal(
            ctx,
            candidateFinal,
            master,
            lockedCredentialOptions,
          );
          if (persisted === "opens-final") {
            storedLocation =
              "exact-fortress stored credential (readback confirmed)";
          } else if (persisted === "indeterminate") {
            ctx.err.write(
              "Credential persistence returned an indeterminate result. The augmented custody and authenticated recovery journal were preserved; unlock the local credential store and rerun this command to recover deterministically.\n",
            );
            return 1;
          } else {
            // Confirmed pre-commit: no stored credential opens the new wrap.
            lease.assertHeld();
            await storage.write("_meta", CUSTODY_ENVELOPE_KEY, priorRaw);
            lease.assertHeld();
            await clearRekeyJournal(storage);
            lease.assertHeld();
            const refusedMachineLocal =
              error instanceof Error &&
              error.message.includes("machine-local fallback storage was refused");
            ctx.err.write(
              "Refusing to finalize: the new passphrase could not be stored " +
                `(${error instanceof Error ? error.message : String(error)}).\n` +
                "The exact prior custody was restored; your recovery key and the OLD passphrase\n" +
                "still work; nothing was removed.\n" +
                (refusedMachineLocal
                  ? "This host has no OS keyring, so the fresh passphrase had nowhere safe to\n" +
                    "live. Run this on a host with a keyring (macOS Keychain / Linux Secret\n" +
                    "Service), or re-run with --allow-machine-local-passphrase to accept the\n" +
                    "machine-local fallback (protected only against off-machine access; the\n" +
                    "recovery key remains your durable custody factor).\n"
                  : ""),
            );
            return 1;
          }
        }
        await ctx.faultAfter?.("stored-persisted");

        // JOURNAL: custody-committed. From here the fresh passphrase is durably
        // held, so recovery rolls FORWARD, never back.
        lease.assertHeld();
        await writeRekeyJournal(storage, {
          v: 1,
          state: "custody-committed",
          started_at: startedAt,
          new_wrap_id: newWrap.id,
          prior_envelope: toBase64url(priorRaw),
        }, master);
        lease.assertHeld();
        await ctx.faultAfter?.("custody-committed");

        // Post-commit readback of the stored credential (belt-and-suspenders).
        let storedOk: boolean;
        try {
          const readback = await readStoredPassphrase({
            storagePath: ctx.storagePath,
            home: ctx.home,
            platformOverride: ctx.plat,
            exec: ctx.exec,
            readOnly: true,
            ...lockedCredentialOptions,
          });
          storedOk = readback !== null && readback.value === freshPassphrase;
        } catch {
          storedOk = false;
        }
        if (!storedOk) {
          // Custody is COMMITTED (the fresh passphrase is enrolled and the
          // envelope holds its wrap) but finalization did not confirm the stored
          // readback. Do NOT roll back — that would strand the stored credential
          // against a restored envelope. Leave the journal so a rerun rolls
          // FORWARD deterministically. Distinguished from a pre-commit failure by
          // this message and the on-disk journal state.
          ctx.err.write(
            "Custody committed but the stored-credential readback did not confirm.\n" +
              "The fresh passphrase is enrolled and your recovery key still works; the OLD\n" +
              "passphrase has NOT yet been removed. Rerun `sanctuary reset-passphrase --mode\n" +
              "recovery-key` to finish; it will complete without changing anything else.\n"
          );
          return 1;
        }

        // The canonical/inode-bound credential is now committed and has read
        // back exactly. Delete only retired alias services carrying the same
        // fresh value; distinct credentials are never guessed away. A cleanup
        // failure leaves the authenticated journal and augmented envelope for
        // deterministic roll-forward on the next invocation.
        await deleteRetiredMatchingPassphraseServices({
          value: freshPassphrase,
          credentialIdentity,
          platformOverride: ctx.plat,
          exec: ctx.exec,
        });

        // AUDIT/FINALIZE: remove the OLD passphrase wraps (keep the new wrap and
        // every non-passphrase wrap). The stored credential (= fresh) still opens
        // the result; the master and recovery wrap are unchanged.
        const finalEnvelope = {
          ...augmented,
          wraps: augmented.wraps.filter(
            (w) => w.type !== "passphrase" || w.id === newWrap.id
          ),
        };
        lease.assertHeld();
        await writeCustodyEnvelope(storage, finalEnvelope, master);
        lease.assertHeld();
        await ctx.faultAfter?.("final-written");

        const completedAt = new Date().toISOString();
        // COMPLETE: final custody + stored credential are authoritative. Clear
        // their journal before touching non-authoritative reset history, so a
        // corrupt history path can never wedge or resurrect committed custody.
        await ctx.faultAfter?.("journal-clear-before-unlink");
        lease.assertHeld();
        await clearCommittedRekeyJournal(storage);
        lease.assertHeld();
        await ctx.faultAfter?.("journal-cleared");

        // M2: record the passphrase rekey in the fortress audit log so a custody
        // change is not a silent, unaudited mutation (and so the audit-write
        // inventory sees an emit on this path). Custody is already committed and
        // its journal cleared, so an append failure WARNS but never fails the
        // completed transaction — the master is unchanged, and rolling back a
        // committed custody swap over a lost audit line would be worse. The entry
        // carries no secret (no passphrase, key, or wrap bytes).
        try {
          const auditLog = new AuditLog(storage, master);
          await auditLog.appendCritical({
            layer: "l2",
            operation: "custody_passphrase_rekeyed",
            identity_id: fortressIdFromStoragePath(ctx.storagePath),
            result: "success",
            details: {
              recovery_mode: "recovery-key",
              started_at: startedAt,
              completed_at: completedAt,
              new_wrap_id: newWrap.id,
              stored_location: storedLocation,
            },
          });
          await auditLog.flush();
        } catch (auditError) {
          ctx.err.write(
            "Warning: custody was rekeyed successfully but the audit entry could not be " +
              `recorded (${auditError instanceof Error ? auditError.message : String(auditError)}). ` +
              "The rekey stands; corroborate via the reset-history marker below.\n",
          );
        }

        // Best-effort operator history, never an authorization/recovery input.
        // keychain_cleared is false — the credential was REWRITTEN.
        const markerRecorded = await recordResetMarkerBestEffort(ctx.storagePath, {
          started_at: startedAt,
          completed_at: completedAt,
          recovery_mode: "recovery-key",
          fortress_name: basename(ctx.storagePath),
          storage_path: ctx.storagePath,
          keychain_cleared: false,
        }, ctx.err);
        await ctx.faultAfter?.("marker-written");

        ctx.out.write(`
Recovery-key rekey complete.
  recovery_mode:      recovery-key
  started_at:         ${startedAt}
  completed_at:       ${completedAt}
  storage_path:       ${ctx.storagePath}
  stored credential:  ${storedLocation}

Your recovery key is UNCHANGED and still works. A fresh passphrase was enrolled
and stored on this host; the OLD passphrase no longer unlocks this fortress.
No secret was printed.

Reset history: ${markerRecorded ? join(ctx.storagePath, ".reset-history.log") : "not recorded (see warning above)"}
`);
        return 0;
      },
      {
        metadata: { owner: "reset-passphrase", mode: "recovery-key" },
        ...(ctx.lockTimeoutMs !== undefined
          ? { timeoutMs: ctx.lockTimeoutMs }
          : {}),
        ...(ctx.__testAfterKernelHolderAcquired !== undefined
          ? {
              __testAfterKernelHolderAcquired:
                ctx.__testAfterKernelHolderAcquired,
            }
          : {}),
      }
    );
  } catch (error) {
    if (error instanceof PassphrasePathIdentityError) {
      ctx.err.write(`Refusing: ${error.message}\n`);
      return 1;
    }
    if (error instanceof CustodyUnlockError) {
      ctx.err.write(
        "The recovery key does not unlock this fortress. No changes were made.\n"
      );
      return 1;
    }
    if (error instanceof CrossProcessLockError) {
      if (error.kind === "contention") {
        ctx.err.write(
          "Refusing: another custody operation is in progress for this fortress. " +
            "Nothing was changed; retry after the active operation finishes.\n",
        );
      } else if (error.kind === "capability") {
        ctx.err.write(`Refusing: ${error.message}\n`);
      } else {
        // Holder loss can occur after a journaled mutation. Never claim that
        // nothing changed; the durable journal is the authority for the retry.
        ctx.err.write(
          `Custody operation stopped fail-closed: ${error.message}. ` +
            "Do not start another custody mutation in this process; restart it and rerun " +
            "the same recovery command so the durable journal can heal or complete.\n",
        );
      }
      return 1;
    }
    if (error instanceof RekeyJournalError) {
      ctx.err.write(
        `Refusing recovery: ${error.message}. The current custody envelope and journal ` +
          "were preserved for inspection; no rollback or rekey was attempted.\n",
      );
      return 1;
    }
    if (error instanceof RekeyJournalPostCommitError) {
      ctx.err.write(`Recovery needs completion: ${error.message}.\n`);
      return 1;
    }
    throw error;
  } finally {
    // F4: zero both secret buffers on EVERY path — wrong key, lock contention,
    // injected crash, and success alike.
    if (recoveryKeyBytes) recoveryKeyBytes.fill(0);
    if (held.master) held.master.fill(0);
  }
}

// ── Storage helpers ─────────────────────────────────────────────────

interface InventoryEntry {
  name: string;
  kind: "file" | "dir";
  bytes: number;
}

interface Inventory {
  entries: InventoryEntry[];
  totalBytes: number;
}

async function inventoryStorage(storagePath: string): Promise<Inventory> {
  if (!(await fileExists(storagePath))) {
    return { entries: [], totalBytes: 0 };
  }
  const names = await readdir(storagePath);
  const entries: InventoryEntry[] = [];
  let totalBytes = 0;
  for (const name of names) {
    const full = join(storagePath, name);
    try {
      const s = await stat(full);
      const bytes = s.isDirectory() ? await dirSize(full) : s.size;
      entries.push({
        name,
        kind: s.isDirectory() ? "dir" : "file",
        bytes,
      });
      totalBytes += bytes;
    } catch {
      // Permission denied or vanished mid-scan; skip.
    }
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  return { entries, totalBytes };
}

async function dirSize(path: string): Promise<number> {
  let total = 0;
  try {
    const names = await readdir(path);
    for (const name of names) {
      const full = join(path, name);
      try {
        const s = await stat(full);
        total += s.isDirectory() ? await dirSize(full) : s.size;
      } catch {
        // Skip unreadable.
      }
    }
  } catch {
    // Skip unreadable directory.
  }
  return total;
}

class DestructiveResetRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DestructiveResetRefusedError";
  }
}

// This worker deliberately runs in a separate process whose cwd is established
// by the kernel before JavaScript starts. Unlike a path string, cwd remains
// attached to the same directory inode after rename. Each directory that must
// be traversed (`state`, then `_meta`) is entered and identity-validated before
// any deletion inside it; no operation resolves the operator-supplied root
// pathname again. The fallback artifact is explicitly removed and verified
// before the remaining entries so destructive-reset completeness stays visible.
const IDENTITY_BOUND_WIPE_WORKER = String.raw`
const { lstat, readdir, rm } = require("node:fs/promises");

const expectedDev = BigInt(process.argv[1]);
const expectedIno = BigInt(process.argv[2]);
const lockName = process.argv[3];

function sameIdentity(stats, dev, ino) {
  return stats.isDirectory() && !stats.isSymbolicLink() && stats.dev === dev && stats.ino === ino;
}

async function enterBoundDirectory(name) {
  const before = await lstat(name, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw new Error(name + " is not a non-symlink directory");
  }
  process.chdir(name);
  const after = await lstat(".", { bigint: true });
  if (!sameIdentity(after, before.dev, before.ino)) {
    throw new Error(name + " changed before its directory identity was bound");
  }
}

(async () => {
  const root = await lstat(".", { bigint: true });
  if (!sameIdentity(root, expectedDev, expectedIno)) {
    process.stderr.write("fortress root identity changed before wipe\n");
    process.exitCode = 73;
    return;
  }

  await rm("passphrase.enc", { force: true });
  try {
    await lstat("passphrase.enc");
    throw new Error("encrypted fallback credential survived removal");
  } catch (error) {
    if (error && error.code !== "ENOENT") throw error;
  }

  for (const name of await readdir(".")) {
    if (name === ".reset-history.log" || name === "state" || name === "passphrase.enc") continue;
    await rm(name, { recursive: true, force: true });
  }

  await enterBoundDirectory("state");
  for (const name of await readdir(".")) {
    if (name === "_meta") continue;
    await rm(name, { recursive: true, force: true });
  }

  await enterBoundDirectory("_meta");
  const lock = await lstat(lockName, { bigint: true });
  if (!lock.isFile() || lock.isSymbolicLink() || lock.nlink !== 1n || lock.size !== 0n) {
    throw new Error("live custody lock scaffold changed before wipe");
  }
  for (const name of await readdir(".")) {
    if (name === lockName) continue;
    await rm(name, { recursive: true, force: true });
  }
})().catch((error) => {
  process.stderr.write("identity-bound wipe refused: " +
    (error instanceof Error ? error.message : String(error)) + "\n");
  process.exitCode = 74;
});
`;

async function wipeStorageIdentityBound(
  storagePath: string,
  identity: DestructionIdentity,
  lease: CrossProcessLockLease,
  deadlineMs: number,
): Promise<void> {
  lease.assertHeld();
  if (process.release.name !== "node" || process.execPath.length === 0) {
    throw new DestructiveResetRefusedError(
      "identity-bound destructive reset requires the supported Node runtime",
    );
  }

  const child = spawn(
    process.execPath,
    [
      "-e",
      IDENTITY_BOUND_WIPE_WORKER,
      identity.dev.toString(),
      identity.ino.toString(),
      CUSTODY_WRITE_LOCK_FILE,
    ],
    {
      cwd: storagePath,
      stdio: ["ignore", "ignore", "pipe"],
      // Own process group so a deadline/abort kill reaps the whole worker tree,
      // never orphaning a process that keeps deleting files after we gave up.
      detached: true,
    },
  );
  const killWorkerGroup = (): void => {
    const pid = child.pid;
    if (pid === undefined) return;
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already exited.
      }
    }
  };
  let diagnostics = "";
  let overflow = false;
  let timedOut = false;
  child.stderr.on("data", (chunk: Buffer) => {
    if (diagnostics.length >= 4096) {
      overflow = true;
      killWorkerGroup();
      return;
    }
    diagnostics += chunk.toString("utf8").slice(0, 4096 - diagnostics.length);
  });
  const onLeaseAbort = (): void => {
    killWorkerGroup();
  };
  lease.signal.addEventListener("abort", onLeaseAbort, { once: true });
  // Round-2: bound the worker. A wedged secure-overwrite or hung filesystem must
  // not pin the custody lock forever; on the deadline SIGKILL the worker group
  // and fail closed with a re-run remedy (a partial wipe is safe to resume).
  const deadline = setTimeout(() => {
    timedOut = true;
    killWorkerGroup();
  }, deadlineMs);
  try {
    const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolve({ code, signal }));
      },
    );
    lease.assertHeld();
    if (timedOut) {
      throw new DestructiveResetRefusedError(
        `the identity-bound wipe worker exceeded its ${deadlineMs}ms deadline and was ` +
          "terminated. A partial wipe is safe to resume: re-run the same reset command.",
      );
    }
    if (overflow || result.code !== 0 || result.signal !== null) {
      const detail = diagnostics.trim();
      throw new DestructiveResetRefusedError(
        detail.length > 0
          ? detail
          : `identity-bound wipe worker failed (code=${String(result.code)}, signal=${String(result.signal)})`,
      );
    }
  } finally {
    clearTimeout(deadline);
    lease.signal.removeEventListener("abort", onLeaseAbort);
  }
}

interface DestructionIdentity {
  dev: bigint;
  ino: bigint;
}

async function destructionLockAncestorsAreSafe(
  storagePath: string
): Promise<boolean> {
  for (const path of [
    join(storagePath, "state"),
    join(storagePath, "state", "_meta"),
  ]) {
    try {
      const stats = await lstat(path);
      if (stats.isSymbolicLink() || !stats.isDirectory()) return false;
    } catch (error) {
      if (errorCode(error) === "ENOENT") continue;
      return false;
    }
  }
  return true;
}

async function liveCustodyLockScaffoldIsSafe(
  storagePath: string
): Promise<boolean> {
  if (!(await destructionLockAncestorsAreSafe(storagePath))) return false;
  try {
    const stats = await lstat(
      join(storagePath, "state", "_meta", CUSTODY_WRITE_LOCK_FILE),
    );
    return (
      stats.isFile() &&
      !stats.isSymbolicLink() &&
      stats.nlink === 1 &&
      stats.size === 0
    );
  } catch {
    return false;
  }
}

async function captureDestructionIdentity(
  storagePath: string
): Promise<DestructionIdentity | null> {
  try {
    const stats = await lstat(storagePath, { bigint: true });
    if (stats.isSymbolicLink() || !stats.isDirectory()) return null;
    return { dev: stats.dev, ino: stats.ino };
  } catch {
    return null;
  }
}

function sameDestructionIdentity(
  expected: DestructionIdentity,
  observed: DestructionIdentity | null
): boolean {
  return (
    observed !== null &&
    expected.dev === observed.dev &&
    expected.ino === observed.ino
  );
}

type KeychainClearStatus =
  | "cleared"
  | "absent"
  | "indeterminate"
  | "unsupported";

async function clearKeychainEntries(
  ctx: NukeContext,
  lease: CrossProcessLockLease,
  services: readonly string[],
): Promise<KeychainClearStatus> {
  // Clear EVERY identity a stored credential could live under for this fortress:
  // the canonical (realpath) service where writes now land, plus the legacy
  // lexical and 12-hex names (finding 5). On a normal canonical path these
  // collapse to one name; on a symlink-reached fortress the canonical name is
  // where the real credential is, so clearing only the lexical name would leave
  // it behind for a fresh `sanctuary wrap` to pick up.
  // Use the exact same complete identity registry as the read path. Keeping a
  // second hand-written list here previously missed canonical-realpath/12-hex,
  // leaving a valid destructive-reset credential behind when the fortress was
  // reached through a symlink alias.
  let clearedAny = false;
  for (const service of services) {
    lease.assertHeld();
    try {
      const result = ctx.plat === "linux"
        ? await ctx.exec("secret-tool", [
            "clear",
            "service",
            service,
            "account",
            "sanctuary",
          ])
        : await ctx.exec("security", [
            "delete-generic-password",
            "-a",
            "sanctuary",
            "-s",
            service,
          ]);
      lease.assertHeld();
      if (result.code === 0) {
        clearedAny = true;
        continue;
      }
      const classified = ctx.plat === "linux"
        ? classifyLinuxFailure(result)
        : classifyDarwinFailure(result);
      if (classified.status !== "not-found") return "indeterminate";
    } catch {
      // A thrown subprocess failure cannot prove absence. Preserve fortress data
      // and the fallback instead of reporting a complete destructive reset.
      return "indeterminate";
    }
  }
  return clearedAny ? "cleared" : "absent";
}

export interface ResetMarker {
  started_at: string;
  completed_at: string;
  recovery_mode: RecoveryMode;
  fortress_name: string;
  storage_path: string;
  keychain_cleared: boolean;
}

interface PersistedResetMarker extends ResetMarker {
  schema: "sanctuary.reset-marker.v1";
  /** Operator history only: never authorization, custody proof, or recovery input. */
  authoritative: false;
}

const RESET_MARKER_MAX_BYTES = 1024 * 1024;

function errorCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException).code;
}

async function quarantineResetHistory(path: string): Promise<string | null> {
  const quarantinePath =
    `${path}.quarantine.${Date.now()}.` + randomBytes(8).toString("hex");
  try {
    // rename(2) moves the directory entry itself. A symlink is quarantined as
    // a symlink; its target is never followed, read, truncated, or overwritten.
    await rename(path, quarantinePath);
    return quarantinePath;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  }
}

// Exported for the S0 writer/reader boot-parity test: it feeds this real
// writer's on-disk output to the real boot parser in server/src/audit/reset-history.ts.
export async function writeResetMarker(
  storagePath: string,
  marker: ResetMarker
): Promise<string | null> {
  const path = join(storagePath, ".reset-history.log");
  let prior: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  let next: Buffer<ArrayBufferLike> | null = null;
  let quarantineReason: string | null = null;
  let quarantinedPath: string | null = null;
  try {
    try {
      const pathStats = await lstat(path);
      if (pathStats.isSymbolicLink() || !pathStats.isFile()) {
        quarantineReason = "unsafe non-regular path";
      } else if (pathStats.size > RESET_MARKER_MAX_BYTES) {
        // Bound memory before reading an attacker-controlled history file.
        quarantineReason = "oversize history";
      }
    } catch (error) {
      if (errorCode(error) !== "ENOENT") {
        quarantineReason = "unsafe or unreadable path";
      }
    }
    if (quarantineReason === null) {
      try {
        prior = await readFileCustody(path, {
          mode: { rejectGroupOrOther: true },
          verifyPathIdentity: true,
        });
      } catch (error) {
        if (errorCode(error) !== "ENOENT") {
          quarantineReason = "unsafe or unreadable path";
        }
      }
    }
    if (prior.length > RESET_MARKER_MAX_BYTES) {
      quarantineReason = "oversize history changed during read";
    }
    if (quarantineReason === null && prior.length > 0) {
      try {
        const text = prior.toString("utf8");
        if (!text.endsWith("\n")) {
          throw new Error("incomplete crash frame");
        }
        for (const line of text.slice(0, -1).split("\n")) JSON.parse(line);
      } catch {
        quarantineReason = "malformed or incomplete history";
      }
    }
    if (quarantineReason !== null) {
      prior.fill(0);
      prior = Buffer.alloc(0);
      quarantinedPath = await quarantineResetHistory(path);
    }
    const persisted: PersistedResetMarker = {
      schema: "sanctuary.reset-marker.v1",
      authoritative: false,
      ...marker,
    };
    const line = Buffer.from(`${JSON.stringify(persisted)}\n`, "utf8");
    next = Buffer.concat([prior, line]);
    line.fill(0);
    if (next.length > RESET_MARKER_MAX_BYTES) {
      throw new Error("reset history would exceed the 1 MiB safety bound");
    }
    // Custody writes refuse symlinks/non-regular files, use an exclusive
    // same-directory temp, fsync it, rename atomically, and fsync the parent.
    // A crash therefore exposes the complete old or complete new log.
    await writeFileCustody(path, next, { mode: 0o600, parentMode: 0o700 });
    return quarantinedPath;
  } finally {
    prior.fill(0);
    next?.fill(0);
  }
}

async function recordResetMarkerBestEffort(
  storagePath: string,
  marker: ResetMarker,
  err: NodeJS.WritableStream,
): Promise<boolean> {
  const warn = (message: string): void => {
    try {
      err.write(message);
    } catch {
      // A broken diagnostic stream cannot promote history into authority.
    }
  };
  try {
    const quarantined = await writeResetMarker(storagePath, marker);
    if (quarantined !== null) {
      warn(
        `Warning: unsafe or malformed reset history was quarantined as ${quarantined}; a fresh non-authoritative history was recorded.\n`,
      );
    }
    return true;
  } catch (error) {
    // History is explicitly non-authoritative. A failure here must never turn a
    // completed custody transaction into a failure or resurrect its journal.
    warn(
      "Warning: custody committed successfully, but non-authoritative reset history " +
        `could not be recorded (${error instanceof Error ? error.message : String(error)}).\n`,
    );
    return false;
  }
}

// ── Misc helpers ────────────────────────────────────────────────────

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function banner(storagePath: string): string {
  return `
Sanctuary reset-passphrase
Storage: ${storagePath}

`;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

async function prompt(
  lines: LineReader,
  err: NodeJS.WritableStream,
  question: string
): Promise<string> {
  err.write(question);
  return await lines.next();
}

/**
 * Single-readline-interface-per-command wrapper. Buffers `line` events and
 * serves them on demand so multiple `prompt()` calls in the same command can
 * share one underlying interface (a fresh readline.Interface per prompt
 * stops working when the source stdin is a one-shot Readable, like the test
 * harness uses).
 */
class LineReader {
  private readonly rl: ReadlineInterface;
  private readonly queue: string[] = [];
  private readonly waiters: Array<(line: string) => void> = [];
  private closed = false;

  constructor(stdin: NodeJS.ReadableStream) {
    this.rl = createInterface({ input: stdin });
    this.rl.on("line", (line) => {
      const w = this.waiters.shift();
      if (w) {
        w(line);
      } else {
        this.queue.push(line);
      }
    });
    this.rl.on("close", () => {
      this.closed = true;
      while (this.waiters.length > 0) {
        const w = this.waiters.shift();
        if (w) w("");
      }
    });
  }

  next(): Promise<string> {
    if (this.queue.length > 0) {
      return Promise.resolve(this.queue.shift() as string);
    }
    if (this.closed) return Promise.resolve("");
    return new Promise((resolve) => {
      this.waiters.push(resolve);
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.rl.close();
    } catch {
      // Already closed.
    }
  }
}

/**
 * Zero each Buffer / Uint8Array in `buffers`. Safe on `undefined`, an empty
 * list, and individual `undefined` entries: callers can pass a sparse list
 * without checking. Errors during `.fill(0)` (e.g., a detached / shared
 * buffer view) are swallowed: best-effort hygiene must not throw and abort
 * a command's `finally` cleanup. See the `runNukePath` threat-model block
 * for the full motivation and limitations (V8 string immutability is out
 * of reach of this helper).
 *
 * Exported so tests can verify the zeroize semantics directly without
 * driving a full nuke flow.
 */
export function zeroizeBuffers(
  buffers: ReadonlyArray<Buffer | Uint8Array | undefined> | undefined
): void {
  if (!buffers) return;
  for (const b of buffers) {
    if (!b) continue;
    try {
      b.fill(0);
    } catch {
      // Detached / shared / read-only view; best-effort.
    }
  }
}

/**
 * Default credential-CLI runner. Routed through the single chokepoint
 * (`wrap/keychain-exec`) rather than spawning `security` here: this module is
 * the FOURTH call site, and the chokepoint exists precisely because per-site
 * spawns are whack-a-mole. Under test the chokepoint refuses the real binary,
 * so a reset path can never delete from the operator's real login keychain.
 */
async function defaultExec(
  cmd: string,
  args: string[],
  input?: string
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  // `input` must be threaded through: the recovery-key mode's keychain WRITE
  // (persistUserProvidedPassphrase) delivers the passphrase on stdin via
  // `security -i`, never in argv, so dropping it would break the write.
  const result = await execKeychain(cmd, args, input);
  return { stdout: result.stdout, stderr: result.stderr, code: result.code };
}
