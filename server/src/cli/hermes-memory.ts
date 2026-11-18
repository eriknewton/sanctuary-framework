import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { consumeFlagValue } from "./argv.js";
import { CUSTODY_RELEASE_FAILURE_MESSAGE } from "./custody-release-message.js";
import { promptHiddenLine, type RawModeStdin } from "./hidden-prompt.js";
import { isSshSession } from "./ssh-session.js";
import { IdentityManager } from "../cognitive/tools.js";
import {
  CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME,
  unlockExistingMasterReadOnly,
} from "../core/master-custody.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import {
  ID_GRAMMAR, MEMORY_CORPUS_SCAN_CAP,
  canonicalHermesFortressPath, composeHermesMemoryAdapterOptions, hermesBridgeAuditPrincipal,
} from "../hermes-memory-bridge/index.js";
import { createSdwMemoryAdapter } from "../index.js";
import { AuditLog, auditChainVerdictClaimsClean, type AuditEntry } from "../operational/audit-log.js";
import {
  HERMES_INSERT_INTENT_KEY, HERMES_INSERT_INTENT_NAMESPACE, MEMORY_BATCH_LOCK_NAMESPACE,
  hermesBridgePassageTextDigest, sdwMemoryCorpusBatchLockFile,
  type SdwMemoryBackendAdapter, type SdwMemoryOwnerInspection, type SdwMemoryPassageRawSnapshot, type SdwMemoryOwnerRecordMetadata,
} from "../sdw/adapters/sdw-memory-backend.js";
import { SdwValidationError } from "../sdw/errors.js";
import { isSdwIdentifier } from "../sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../sdw/records.js";
import { parseIsoInstantWithOffset } from "../core/time.js";
import { CrossProcessLockError, withExclusiveMasterRotationBarrier } from "../storage/cross-process-lock.js";
import { hasInterruptedExitImport } from "../storage/exit-import-journal.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { StorageBackend } from "../storage/interface.js";
import { ReadOnlyStorageGuard } from "../storage/read-only-guard.js";
import { resolveHostLocalBootCredential } from "../wrap/custody-credential.js";

/** The owner verbs this module serves; the `sanctuary hermes` router in cli.ts dispatches these names here. */
export const HERMES_MEMORY_OWNER_VERBS = Object.freeze(["memory-report", "memory-show", "memory-delete"] as const);
export type HermesMemoryOwnerVerb = typeof HERMES_MEMORY_OWNER_VERBS[number];

/** Audit operation for an owner delete; rows carry `outcome: "intent"` first, then one terminal outcome. */
export const HERMES_MEMORY_OWNER_DELETE_OPERATION = "hermes_memory_owner_delete";
// Must match the AuditForwarder operation in hermes-memory-bridge/process-shell.ts, which writes every bridge row.
const HERMES_BRIDGE_AUDIT_OPERATION = "hermes_memory_bridge";
// Must match the hermes_save_recovered row in cli/hermes-recover-save.ts.
const HERMES_SAVE_RECOVERED_OPERATION = "hermes_save_recovered";

// Must match the relay LaunchAgent label installed by the Hermes kit (outside this repository).
const HERMES_MEMORY_RELAY_LAUNCHD_LABEL = "ai.sanctuaryprotocol.hermes-memory-relay";

/** 120 s = two minutes for any interactive prompt; after it the verb exits having changed nothing. */
export const OWNER_PROMPT_TIMEOUT_MS = 120_000;
// 24 h of milliseconds: the report's default window when --since is not given.
const DEFAULT_REPORT_WINDOW_MS = 24 * 60 * 60 * 1000;
/** `--recent` accepts 1 to 20 passages; more would scroll Erik's own prompt out of view. */
export const MAX_RECENT_PASSAGES = 20;
/** The delete preview shows this many characters (code points) of the passage. */
export const DELETE_PREVIEW_CHARS = 80;
// 64 characters is far longer than DELETE plus any typing slip; a longer line is a mismatch, never buffered further.
const MAX_CONFIRMATION_CHARS = 64;
const CONFIRMATION_WORD = "DELETE";
const OWNER_DIRECTORY_MODE = 0o700;
const OWNER_FILE_MODE = 0o600;
const PERMISSION_BITS = 0o777;

/** Signals ignored from an accepted DELETE until the delete returns. SIGKILL cannot be caught; an intent row without an outcome records it. */
export const DELETE_IGNORED_SIGNALS = Object.freeze(["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGTSTP"] as const);
type IgnoredSignal = typeof DELETE_IGNORED_SIGNALS[number];

export type OwnerDeleteOutcome =
  | "intent" | "deleted" | "not_found" | "not_attempted" | "failed_restored" | "failed_unrestored" | "indeterminate";

const NOTHING_CHANGED = "Nothing was changed.";
const NOTHING_DELETED = "Nothing was deleted.";
const BARRIER_REFUSAL =
  "Stop the Hermes memory relay first: a live bridge, recover-save, key rotation or import holds this fortress, " +
  "or its custody barrier is unavailable. " + NOTHING_CHANGED;
const CORPUS_LOCK_PROCEDURE =
  "stop every fortress writer, verify none remain, then remove only this exact lock file; never remove it while anything may still run. " +
  "Ask the coordinator before removing it.";
const UNCLASSIFIED = "The command could not finish and nothing was changed.";

const HELP_COMMON = `
Run these at the Mac's own keyboard with the Hermes memory relay stopped, as the account that owns the fortress:
  1. launchctl kill SIGTERM gui/$(id -u)/${HERMES_MEMORY_RELAY_LAUNCHD_LABEL}
  2. Wait until launchctl print shows no pid and no bridge process remains for your account.
     Running too early refuses with "Stop the Hermes memory relay first"; nothing is changed.
  3. Run the command with the kit's private runtime (B_RUNTIME/bin/node B_RUNTIME/pkg/dist/cli.js hermes ...),
     never npx or a global install, which may be a different version.
  4. Run the kit's helper check. If a keychain dialog is still open, click Deny.
  5. launchctl kickstart gui/$(id -u)/${HERMES_MEMORY_RELAY_LAUNCHD_LABEL}
  6. Run the kit's verify.

Custody: the fortress opens with this Mac's keychain item or stored passphrase. --recovery-key-prompt
is for when neither is available; it asks for the recovery key without echo and refuses if a keychain
item or stored passphrase would also open the fortress. A recovery key in SANCTUARY_RECOVERY_KEY is
refused. Key bytes are zeroed when the command ends; passphrase and recovery-key strings cannot be
zeroed inside a JavaScript process.

Refusals change nothing: root, an SSH session (the keychain prompt cannot be answered there), a
fortress your account does not own, a missing fortress (nothing is created), or a prompt left
unanswered for 120 seconds. The last line says how to start the Hermes memory relay only after the audit record
has been checked and no unresolved delete remains. After a delete that may have left the passage half-removed
or unconfirmed, that run and every later run that reads the audit log says to leave the relay stopped until
the coordinator has read a memory-report, and
steps 5 and 6 wait until then. A usage error or a refusal that stops before the audit log can be checked also
says to leave the relay stopped.
`;

const HELP_REPORT = `Usage: sanctuary hermes memory-report --fortress <dir> --agent-id <id> [--since <ISO time>] [--out <file>] [--recovery-key-prompt]
List what the memory bridge recorded: saves, refusals and recalls, with fingerprints and ids, never saved words.
Default window: the last 24 hours. Output: JSON on stdout, or --out writes a new file with mode 0600.
--out refuses an existing file, any symlink in the path, a parent folder that is not yours with mode 0700,
and any place inside the fortress or the kit folder. Create ~/hermes-memory-reports once with mode 0700.
A report with truncated: true, an unverified chain, or absence_claims_supported: false is not a witness.
Anyone who can read a report and guess a message can confirm it was saved; keep reports on this Mac.
The command reads only; the fortress is left byte-identical.
${HELP_COMMON}`;

const HELP_SHOW = `Usage: sanctuary hermes memory-show --fortress <dir> --agent-id <id> (--passage <id> | --recent <n>) [--recovery-key-prompt]
Print saved passages on this terminal: one by id, or the newest n (1 to ${MAX_RECENT_PASSAGES}) by saved time.
Both input and output must be a terminal, so text is not sent to a pipe or file by accident. That check
is not a security boundary. Text is labelled "Saved from the conversation, unverified" because the
agent chose what to save. Control and direction characters are shown escaped. A passage that cannot be
verified is listed without its text. Terminal scrollback and window restoration can keep what was shown.
${HELP_COMMON}`;

const HELP_DELETE = `Usage: sanctuary hermes memory-delete --fortress <dir> --agent-id <id> --passage <id> [--recovery-key-prompt]
Remove one saved passage after you type DELETE within 120 seconds; anything else leaves it in place.
Refuses, naming the next step, when a save is unfinished (run recover-save), a corpus lock was left
behind or an earlier delete was interrupted (ask the coordinator, with a memory-report), an exit import
is unfinished, or no passage with that id exists. Ctrl-C and similar signals are ignored from DELETE
until the delete returns; a force kill leaves an intent row that the next report and delete call interrupted.
What delete means: the passage leaves Sanctuary memory and no later recall returns it. These remain:
  - The audit log keeps its fingerprint, byte length and timestamps under the audit log's retention limits.
  - Hermes's session store keeps the original turn, and every prompt that recall fed it into.
  - Secure overwrite on APFS is not physical erasure; snapshots and backups can keep old blocks, and
    confidentiality rests on encryption.
  - The agent can save the same words again, even under the same id, as a new passage.
${HELP_COMMON}`;

const HELP_HERMES = `Usage:
  sanctuary hermes recover-save --fortress <dir> [--apply]
      Recover an unfinished save.
  sanctuary hermes memory-report --fortress <dir> --agent-id <id>
      List what the memory bridge recorded, without saved words.
  sanctuary hermes memory-show --fortress <dir> --agent-id <id> (--passage <id> | --recent <n>)
      Show saved passages on this terminal.
  sanctuary hermes memory-delete --fortress <dir> --agent-id <id> --passage <id>
      Remove one saved passage.
Run "sanctuary hermes <command> --help" for each command's rules.
`;

/** Help text per owner verb, exported so the help copy can be checked as operator-facing product text. */
export const HERMES_MEMORY_HELP: Readonly<Record<HermesMemoryOwnerVerb | "hermes", string>> = Object.freeze({
  "memory-report": HELP_REPORT,
  "memory-show": HELP_SHOW,
  "memory-delete": HELP_DELETE,
  hermes: HELP_HERMES,
});

type Writer = Pick<NodeJS.WriteStream, "write">;
type TerminalWriter = Writer & { isTTY?: boolean };

export interface SignalPort {
  on(signal: IgnoredSignal, listener: () => void): unknown;
  off(signal: IgnoredSignal, listener: () => void): unknown;
}

export interface HermesMemoryOptions {
  readonly argv: string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly uid?: number;
  readonly stdin?: RawModeStdin;
  readonly stdout?: TerminalWriter;
  readonly stderr?: Writer;
  readonly now?: () => Date;
  /** Test seam only; production prompts always use OWNER_PROMPT_TIMEOUT_MS. */
  readonly promptTimeoutMs?: number;
  readonly signals?: SignalPort;
  /** The running package's version, passed by cli.ts from its own package.json; the report header carries it exactly. */
  readonly packageVersion: string;
  /**
   * The running package's root folder, passed by cli.ts. --out refuses the kit folder two levels above it
   * (B in the kit's B/B_RUNTIME/pkg layout); tests pass a fixture layout here.
   */
  readonly packageRoot: string;
  /**
   * The entry path exactly as invoked (process.argv[1]), passed by cli.ts. Node runs the entry from its real
   * path, so a symlinked pkg or B_RUNTIME moves packageRoot; the invoked path still names the kit folder. It
   * counts only in the package layout (dist/cli.js or src/cli.ts); a bin link path is ignored.
   */
  readonly invokedEntry: string | undefined;
}

class OwnerRefusal extends Error {
  constructor(message: string, readonly exitCode = 1) {
    super(message);
    this.name = "HermesOwnerRefusal";
  }
}

interface ParsedArgs {
  readonly verb: HermesMemoryOwnerVerb;
  readonly fortress: string;
  readonly agentId: string;
  readonly recoveryKeyPrompt: boolean;
  /** --since as epoch milliseconds, from the one offset-strict parse in parseArgs. */
  readonly sinceMs?: number;
  readonly out?: string;
  readonly passage?: string;
  readonly recent?: number;
}

interface OwnerContext {
  readonly storage: FilesystemStorage;
  readonly readonlyStorage: ReadOnlyStorageGuard;
  readonly masterKey: Uint8Array;
  readonly storagePath: string;
  readonly fortressId: string;
  readonly identities: IdentityManager;
  readonly reader: SdwMemoryBackendAdapter;
}

/** Entry point for `sanctuary hermes memory-report | memory-show | memory-delete`. */
export async function runHermesMemory(options: HermesMemoryOptions): Promise<number> {
  const out = options.stdout ?? process.stdout;
  const err = options.stderr ?? process.stderr;
  const verb = options.argv[0];
  if (verb === undefined || verb === "--help" || verb === "-h") {
    out.write(HELP_HERMES);
    return 0;
  }
  // A usage error has no checked audit evidence, so its closing line keeps the relay stopped.
  if (!isOwnerVerb(verb)) { err.write(HELP_HERMES + CLOSING_LINE_RECORD_UNCHECKED); return 2; }
  if (options.argv.includes("--help") || options.argv.includes("-h")) {
    out.write(HERMES_MEMORY_HELP[verb]);
    return 0;
  }
  const parsed = parseArgs(verb, options.argv.slice(1));
  if (typeof parsed === "string") {
    err.write(`Error: ${parsed}\n${HERMES_MEMORY_HELP[verb].split("\n")[0]}\n` + CLOSING_LINE_RECORD_UNCHECKED);
    return 2;
  }
  const uid = options.uid ?? process.getuid?.();
  const relay: RelayClosing = { auditViewRead: false, auditRecordUnchecked: false, thisDeleteUnsafe: false, unconfirmedPassages: new Set(), reportWritten: false };
  const code = await runOwnerVerb(parsed, options, uid, relay);
  // A start command requires checked audit evidence and no unresolved delete in any document scope.
  err.write(relay.auditRecordUnchecked ? CLOSING_LINE_RECORD_UNCHECKED
    : relay.thisDeleteUnsafe ? CLOSING_LINE_KEEP_STOPPED
      : relay.unconfirmedPassages.size > 0 ? closingLineAfterUnconfirmedDelete(relay.reportWritten)
        : relay.auditViewRead ? closingLine(uid) : CLOSING_LINE_RECORD_UNCHECKED);
  return code;
}

/**
 * What a run's closing line may say, from what the run itself read. The start command is given outright only
 * by a run that read the audit view and found no passage whose latest delete is still unconfirmed; bridge
 * startup never reads delete outcomes, so this line is the only place an unconfirmed delete can stop a restart.
 */
interface RelayClosing {
  auditViewRead: boolean;
  auditRecordUnchecked: boolean;
  /** This run's own delete has an unsafe outcome or lacks a confirmed audit append. */
  thisDeleteUnsafe: boolean;
  /** Passages whose latest owner-delete attempt is unconfirmed and that no later attempt removed. */
  unconfirmedPassages: Set<string>;
  /** A memory-report run produced its report, so its closing line can point at this report. */
  reportWritten: boolean;
}

function isOwnerVerb(value: string): value is HermesMemoryOwnerVerb {
  return (HERMES_MEMORY_OWNER_VERBS as readonly string[]).includes(value);
}

// After a delete that may have left the passage half-removed or unconfirmed, bridge startup would serve
// recall over that state without looking at the outcome, so this line gives no start command.
const CLOSING_LINE_KEEP_STOPPED = "The Hermes memory relay is still stopped. Leave it stopped until the coordinator has " +
  "read the memory-report.\n";

const CLOSING_LINE_RECORD_UNCHECKED = "The Hermes memory relay is still stopped. The audit record could not be checked. " +
  "Leave it stopped until the coordinator has read a memory-report.\n";

// Every later run that reads the audit view keeps the relay stopped too, until an unconfirmed delete is cleared.
function closingLineAfterUnconfirmedDelete(reportWritten: boolean): string {
  return "The Hermes memory relay is still stopped. An earlier memory-delete was not confirmed, so leave it stopped " +
    `until the coordinator has read ${reportWritten ? "this report" : "a memory-report"}.\n`;
}

function closingLine(uid: number | undefined): string {
  return `The Hermes memory relay is still stopped. Start it with: ${startCommand(uid)}.\n`;
}

function startCommand(uid: number | undefined): string {
  const domain = uid === undefined ? "gui/$(id -u)" : `gui/${uid}`;
  return `launchctl kickstart ${domain}/${HERMES_MEMORY_RELAY_LAUNCHD_LABEL} then run the kit's verify`;
}

function parseArgs(verb: HermesMemoryOwnerVerb, argv: string[]): ParsedArgs | string {
  let rest = argv;
  const take = (name: string): string | undefined | { error: string } => {
    const consumed = consumeFlagValue(rest, name);
    if (consumed.error) return { error: consumed.error };
    rest = consumed.argv;
    return consumed.value;
  };
  const values: Record<string, string | undefined> = {};
  const allowed = verb === "memory-report" ? ["--fortress", "--agent-id", "--since", "--out"]
    : verb === "memory-show" ? ["--fortress", "--agent-id", "--passage", "--recent"]
      : ["--fortress", "--agent-id", "--passage"];
  for (const name of allowed) {
    const value = take(name);
    if (typeof value === "object") return value.error;
    values[name] = value;
  }
  const flags = rest.filter(arg => arg === "--recovery-key-prompt");
  if (flags.length > 1 || rest.length !== flags.length) {
    return `only ${allowed.join(", ")} and --recovery-key-prompt are accepted, each once`;
  }
  const fortress = values["--fortress"];
  const agentId = values["--agent-id"];
  if (!fortress) return "--fortress is required";
  if (!agentId) return "--agent-id is required";
  // One grammar for the bridge environment and the owner scope; a copy could drift and match the wrong scope.
  if (!ID_GRAMMAR.test(agentId)) return "--agent-id must be the bridge's agent id (lowercase letters, digits and hyphens)";
  const parsed = { verb, fortress, agentId, recoveryKeyPrompt: flags.length === 1 };
  if (verb === "memory-report") {
    const since = values["--since"];
    // An explicit offset is required: a zone-less time would shift the window by the host's local offset.
    const sinceMs = since === undefined ? undefined : parseIsoInstantWithOffset(since);
    if (since !== undefined && sinceMs === undefined) {
      return "--since must be an ISO time such as 2026-11-16T09:00:00Z";
    }
    return { ...parsed, sinceMs, out: values["--out"] };
  }
  const passage = values["--passage"];
  if (passage !== undefined && !isSdwIdentifier(passage)) return "--passage is not a valid passage id";
  if (verb === "memory-delete") {
    if (passage === undefined) return "--passage is required";
    return { ...parsed, passage };
  }
  const recentRaw = values["--recent"];
  if ((passage === undefined) === (recentRaw === undefined)) return "give exactly one of --passage or --recent";
  if (recentRaw !== undefined) {
    const recent = Number(recentRaw);
    if (!/^\d+$/u.test(recentRaw) || recent < 1 || recent > MAX_RECENT_PASSAGES) {
      return `--recent must be a whole number from 1 to ${MAX_RECENT_PASSAGES}`;
    }
    return { ...parsed, recent };
  }
  return { ...parsed, passage };
}

/**
 * Shared prologue and continuing-path table for all three verbs.
 *
 * Path                                   | Exit | Message
 * Root, SSH, wrong owner, missing _meta  | 1    | refusal; nothing created or changed
 * Barrier held or no kernel admission    | 1    | stop the Hermes memory relay first
 * Custody virgin or fail-closed          | 1    | refusal; nothing changed
 * Host-local plus recovery key           | 1    | refusal before any unlock
 * Prompt timeout                         | 1    | nothing changed
 * Verb finished, release failed          | 1    | output or action stands; release-failure text
 */
async function runOwnerVerb(args: ParsedArgs, options: HermesMemoryOptions, uid: number | undefined,
  relay: RelayClosing): Promise<number> {
  const out = options.stdout ?? process.stdout;
  const err = options.stderr ?? process.stderr;
  const env = options.env ?? process.env;
  const stdin = options.stdin ?? (process.stdin as RawModeStdin);
  let admitted = false;
  let callbackReturned = false;
  // Set once a verb has produced its output or performed its action; a later failure never reverses it.
  let finished = false;
  try {
    if (uid === undefined) throw new OwnerRefusal("This command needs a Unix account identity. " + NOTHING_CHANGED);
    // Root would bypass the per-account ownership that keeps the agent out; refusing keeps root out too.
    if (uid === 0) throw new OwnerRefusal("Run this as the account that owns the fortress, not root. " + NOTHING_CHANGED);
    // An accident guard, not a boundary: over SSH the keychain prompt hangs with no one to answer it.
    if (isSshSession(env)) {
      throw new OwnerRefusal("This command runs only at the Mac's own keyboard, not over SSH. " + NOTHING_CHANGED);
    }
    if (args.verb !== "memory-report") {
      // An accident guard, not a confidentiality boundary: it keeps passage text off pipes and files.
      if (stdin.isTTY !== true || (out as TerminalWriter).isTTY !== true) {
        throw new OwnerRefusal("This command needs a terminal for both input and output. " + NOTHING_CHANGED);
      }
    }
    let storagePath: string;
    try {
      // Same canonical identity as bridge startup, so the owner verbs open exactly the bridge's fortress.
      storagePath = await canonicalHermesFortressPath({ home: env.HOME, fortressDir: resolve(args.fortress), uid });
      const owner = await lstat(storagePath);
      // The fortress owner's uid is what keeps the agent account out; any other owner is refused.
      if (owner.uid !== uid) throw new Error("owner mismatch");
    } catch {
      throw new OwnerRefusal("The fortress path is missing, not owned by this account, or unsafe. " + NOTHING_CHANGED);
    }
    const storage = new FilesystemStorage(join(storagePath, "state"));
    // A mistyped --fortress must refuse before lock resolution can create any directory.
    const meta = await lstat(storage.namespacePath(CUSTODY_WRITE_LOCK_NAMESPACE)).catch(() => null);
    if (meta === null || !meta.isDirectory() || meta.isSymbolicLink()) {
      throw new OwnerRefusal("This is not an existing Sanctuary fortress. Nothing was created or changed.");
    }
    const outPlan = args.out === undefined ? undefined
      : await validateOutPath(args.out, uid, storagePath, await hermesKitFolders(options.packageRoot, options.invokedEntry, env.HOME));
    // The exclusive side is the only proof that no bridge can admit a save, serve a recall or hold a
    // stale corpus view while an owner verb reads or deletes; without kernel coordinates it proves nothing.
    return await withExclusiveMasterRotationBarrier(storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME,
      async () => {
        admitted = true;
        const result = await withOwnerCustody({ args, env, err, stdin, storage, storagePath, promptTimeoutMs: options.promptTimeoutMs },
          async (context) => {
            const noteAuditView = (view: AuditView): void => {
              // Restart advice relies on a verified owner audit chain with known retention state.
              relay.auditViewRead = view.chainVerified && typeof view.everPruned === "boolean";
              relay.auditRecordUnchecked = !relay.auditViewRead;
              for (const passageId of unconfirmedDeletePassages(ownerDeleteAttempts(view.entries))) relay.unconfirmedPassages.add(passageId);
            };
            switch (args.verb) {
              case "memory-report": {
                const report = await buildMemoryReport(context, args, options.now?.() ?? new Date(), options.packageVersion, noteAuditView);
                const body = JSON.stringify(report, null, 2) + "\n";
                if (outPlan === undefined) out.write(body);
                else {
                  await writeReportFile(outPlan, body);
                  out.write(`Report written to ${displayPath(outPlan)}\n`);
                }
                relay.reportWritten = true;
                finished = true;
                return 0;
              }
              case "memory-show": {
                // Show itself needs no audit rows; it reads them only so its closing line can keep the relay stopped.
                noteAuditView(await readAuditView(context));
                const code = await showPassages(context, args, out);
                finished = true;
                return code;
              }
              case "memory-delete":
                return deletePassage(context, args, { out, err, stdin, signals: options.signals ?? process,
                  promptTimeoutMs: options.promptTimeoutMs ?? OWNER_PROMPT_TIMEOUT_MS, markFinished: () => { finished = true; },
                  noteAuditView, keepRelayStopped: () => { relay.thisDeleteUnsafe = true; },
                  removed: (documentId, passageId) => { relay.unconfirmedPassages.delete(ownerDeleteIdentity(documentId, passageId)); } });
            }
          });
        // Only a resolved callback separates custody finalization from operation failures, including refusals.
        callbackReturned = true;
        return result;
      }, { timeoutMs: 0, requireKernelAdmission: true }); // Zero wait: a live holder is an immediate refusal.
  } catch (cause) {
    const refusal = cause instanceof OwnerRefusal ? cause
      : cause instanceof AggregateError ? cause.errors.find((error): error is OwnerRefusal => error instanceof OwnerRefusal) : undefined;
    // After admission, a typed custody error beside a returned callback, finished work or a refusal is the barrier's release.
    if (admitted && (callbackReturned || finished || refusal !== undefined) && containsCustodyError(cause)) {
      if (refusal !== undefined) err.write(refusal.message + "\n");
      // Must match CUSTODY_RELEASE_FAILURE_MESSAGE in cli/custody-release-message.ts, shared with recover-save.
      err.write(CUSTODY_RELEASE_FAILURE_MESSAGE + "\n");
      return 1;
    }
    if (refusal !== undefined) {
      err.write(refusal.message + "\n");
      return refusal.exitCode;
    }
    // A lock error before admission is the barrier refusing: a live holder or no kernel coordinates.
    if (!admitted && cause instanceof CrossProcessLockError) {
      err.write(BARRIER_REFUSAL + "\n");
      return 1;
    }
    err.write((finished ? "The command finished, but custody did not close cleanly; what it reported stands." : UNCLASSIFIED) + "\n");
    return 1;
  }
}

function containsCustodyError(error: unknown): boolean {
  const seen = new Set<unknown>();
  const matches = (value: unknown): boolean => {
    // Aggregate members can share references or cycles, so each member is examined only once.
    if (seen.has(value)) return false;
    seen.add(value);
    if (value instanceof AggregateError) return value.errors.some(matches);
    return value instanceof CrossProcessLockError;
  };
  return matches(error);
}

/**
 * Custody inside the admitted callback only. Host-local sources first, never a
 * mint. The recovery key is the break-glass credential, the same for report,
 * show and delete: it opens the fortress only when host-local custody resolves
 * fail-closed, --recovery-key-prompt is given, the key is read from the no-echo
 * prompt within its bound, custody is not virgin, and no host-local credential
 * resolved. Without the flag, fail-closed refuses. Unlock is read-only and never
 * establishes or degrades custody. Every key buffer is zeroed on every exit.
 */
async function withOwnerCustody<T>(input: {
  readonly args: ParsedArgs;
  readonly env: NodeJS.ProcessEnv;
  readonly err: Writer;
  readonly stdin: RawModeStdin;
  readonly storage: FilesystemStorage;
  readonly storagePath: string;
  readonly promptTimeoutMs?: number;
}, operation: (context: OwnerContext) => Promise<T>): Promise<T> {
  const { env, storage, storagePath } = input;
  const readonlyStorage = new ReadOnlyStorageGuard(storage);
  if (env.SANCTUARY_RECOVERY_KEY !== undefined) {
    // The environment copy is removed before anything else so no later step or child can read it.
    delete env.SANCTUARY_RECOVERY_KEY;
    throw new OwnerRefusal("A recovery key is read only from the no-echo prompt (--recovery-key-prompt), never from " +
      "SANCTUARY_RECOVERY_KEY. " + NOTHING_CHANGED);
  }
  // Like the bridge, no owner verb opens a fortress with an unfinished exit import: its view would be half-applied,
  // and recovery belongs to the operator exit-recover path. Must match the allowlist entry in fortress-open-recovery-wiring.test.ts.
  if (await hasInterruptedExitImport(readonlyStorage)) {
    throw new OwnerRefusal("An exit import did not finish; recover it with `sanctuary exit recover` first. " + NOTHING_CHANGED);
  }
  const resolved = await resolveHostLocalBootCredential({ storage: readonlyStorage, storagePath, home: env.HOME });
  let keychainKey: Uint8Array | undefined;
  let passphrase: string | undefined;
  let recoveryKey: string | undefined;
  let masterKey: Uint8Array | undefined;
  try {
    if (resolved.kind === "keychain-key") keychainKey = resolved.key;
    else if (resolved.kind === "passphrase") passphrase = resolved.value;
    // A virgin fortress has no custody to open; minting here would create a parallel master.
    if (resolved.kind === "virgin") throw new OwnerRefusal("This fortress has no custody to open. " + NOTHING_CHANGED);
    if (input.args.recoveryKeyPrompt) {
      // Two sources offered is ambiguous custody; the verb refuses rather than choosing one.
      if (resolved.kind !== "fail-closed") {
        throw new OwnerRefusal("A keychain item or stored passphrase already opens this fortress; run without " +
          "--recovery-key-prompt. " + NOTHING_CHANGED);
      }
      recoveryKey = await promptRecoveryKey(input.stdin, input.err, input.promptTimeoutMs ?? OWNER_PROMPT_TIMEOUT_MS);
    } else if (resolved.kind === "fail-closed") {
      throw new OwnerRefusal("The fortress could not be opened from this Mac's keychain or stored passphrase " +
        "(it may be locked, or the helper timed out). " + NOTHING_CHANGED);
    }
    masterKey = await unlockExistingMasterReadOnly(readonlyStorage, {
      ...(keychainKey !== undefined ? { keychainKey } : passphrase !== undefined ? { passphrase } : { recoveryKey: recoveryKey! }),
      storagePathHint: storagePath,
    });
    const identities = new IdentityManager(readonlyStorage, masterKey);
    const loaded = await identities.load();
    if (loaded.failed > 0 || loaded.loaded < 1) throw new OwnerRefusal("The fortress identity could not be read. " + NOTHING_CHANGED);
    const fortressId = fortressIdFromStoragePath(storagePath);
    const reader = await composeOwnerAdapter(readonlyStorage, masterKey, fortressId, input.args.agentId, identities);
    return await operation({ storage, readonlyStorage, masterKey, storagePath, fortressId, identities, reader });
  } finally {
    keychainKey?.fill(0);
    masterKey?.fill(0);
  }
}

async function promptRecoveryKey(stdin: RawModeStdin, err: Writer, timeoutMs: number): Promise<string> {
  if (stdin.isTTY !== true) throw new OwnerRefusal("The recovery key prompt needs a terminal. " + NOTHING_CHANGED);
  let timer: NodeJS.Timeout | undefined;
  let timedOut = false;
  try {
    const value = await Promise.race([
      promptHiddenLine(stdin, "Recovery key (not shown)", { err: err as NodeJS.WritableStream, onSigint: () => undefined }),
      new Promise<string>(resolvePrompt => {
        timer = setTimeout(() => {
          timedOut = true;
          // Ending input settles the hidden reader, which restores the terminal and zeroes its buffer.
          stdin.emit("end");
          resolvePrompt("");
        }, timeoutMs);
      }),
    ]);
    if (timedOut) throw new OwnerRefusal("The recovery key prompt timed out. " + NOTHING_CHANGED);
    if (value.trim() === "") throw new OwnerRefusal("No recovery key was entered. " + NOTHING_CHANGED);
    return value.trim();
  } finally {
    clearTimeout(timer);
  }
}

async function composeOwnerAdapter(
  storage: StorageBackend, masterKey: Uint8Array, fortressId: string, ownerRef: string, identities: IdentityManager,
): Promise<SdwMemoryBackendAdapter> {
  let adapter: SdwMemoryBackendAdapter | undefined = undefined;
  // Same composition as the bridge; only the standard mode differs, so verification uses the bridge's signer set.
  const composed = await composeHermesMemoryAdapterOptions({
    storage, masterKey, fortressId, ownerRef, identityManager: identities,
    scanForeignDependencies: async (did, fingerprint) => {
      if (adapter === undefined) throw new Error("owner adapter is not bound");
      return adapter.scanForeignSignerDependencies(did, fingerprint);
    },
  });
  adapter = createSdwMemoryAdapter({ mode: "standard", ...composed.options });
  return adapter;
}

/** Build the declared read-only audit reader every report, show and delete pre-check uses. */
export function createOwnerAuditReader(storage: ReadOnlyStorageGuard, masterKey: Uint8Array): AuditLog {
  // readOnly suppresses the load path's recovery batch and refuses the write lock; lenient keeps findings reportable.
  return new AuditLog(storage, masterKey, { readOnly: true, integrityMode: "lenient" });
}

interface AuditView {
  readonly entries: readonly AuditEntry[];
  readonly chainVerified: boolean;
  readonly chainStatus: string;
  readonly headSequence: number;
  readonly everPruned: boolean | null;
  readonly earliestRetainedAt: string | null;
}

async function readAuditView(context: OwnerContext): Promise<AuditView> {
  const reader = createOwnerAuditReader(context.readonlyStorage, context.masterKey);
  // The whole surviving chain is reloaded: the same work class as `sanctuary audit search`; output is capped later.
  const { entries } = await reader.runAllowingIntegrityFindings(() => reader.query({ limit: Number.MAX_SAFE_INTEGER }));
  const verdict = await reader.runAllowingIntegrityFindings(() => reader.getAuditChainVerdict());
  const head = await reader.runAllowingIntegrityFindings(() => reader.getChainHead());
  const usage = await reader.getRetentionUsage();
  return {
    entries,
    chainVerified: auditChainVerdictClaimsClean(verdict),
    chainStatus: verdict.status,
    headSequence: head.sequence,
    everPruned: usage.everPruned,
    earliestRetainedAt: entries[0]?.timestamp ?? null,
  };
}

interface OwnerDeleteAttempt {
  readonly passage_id: string;
  readonly document_id: string | null;
  readonly intent_at: string;
  readonly outcome: Exclude<OwnerDeleteOutcome, "intent"> | "interrupted";
  readonly outcome_at: string | null;
  readonly error_category?: string;
}

/**
 * Pair each owner-delete intent with the next owner-delete row in chain order.
 * Deletes run one at a time under the exclusive barrier, so an intent whose next
 * row is not its own outcome, or that has no next row, was killed: `interrupted`.
 */
function ownerDeleteAttempts(entries: readonly AuditEntry[]): OwnerDeleteAttempt[] {
  const rows = entries.filter(entry => entry.operation === HERMES_MEMORY_OWNER_DELETE_OPERATION);
  const attempts: OwnerDeleteAttempt[] = [];
  for (let index = 0; index < rows.length; index++) {
    const details = rows[index]!.details ?? {};
    if (details.outcome !== "intent") continue;
    const next = rows[index + 1];
    const nextDetails = next?.details ?? {};
    // An outcome settles only the intent for the same document and passage in the owner audit chain.
    const paired = next !== undefined && nextDetails.outcome !== "intent" && nextDetails.passage_id === details.passage_id &&
      typeof details.document_id === "string" && nextDetails.document_id === details.document_id;
    attempts.push({
      passage_id: String(details.passage_id),
      document_id: typeof details.document_id === "string" ? details.document_id : null,
      intent_at: rows[index]!.timestamp,
      outcome: paired ? nextDetails.outcome as OwnerDeleteAttempt["outcome"] : "interrupted",
      outcome_at: paired ? next.timestamp : null,
      ...(paired && typeof nextDetails.error_category === "string" ? { error_category: nextDetails.error_category } : {}),
    });
  }
  return attempts;
}

/**
 * Scoped passages with an interrupted, failed_unrestored or indeterminate delete that no later attempt
 * removed. Only a later "deleted" settles one: not_attempted and failed_restored leave the same uncertain
 * records in place, and a failed_unrestored passage has no document left for a later delete to find.
 */
function unconfirmedDeletePassages(attempts: readonly OwnerDeleteAttempt[]): Set<string> {
  const unconfirmed = new Set<string>();
  for (const attempt of attempts) {
    const identity = ownerDeleteIdentity(attempt.document_id, attempt.passage_id);
    // Every unresolved intent holds its full owner scope until a recorded delete settles that same identity.
    if (attempt.outcome === "interrupted" || attempt.outcome === "failed_unrestored" || attempt.outcome === "indeterminate") unconfirmed.add(identity);
    else if (attempt.outcome === "deleted") unconfirmed.delete(identity);
  }
  return unconfirmed;
}

function ownerDeleteIdentity(documentId: string | null, passageId: string): string {
  return JSON.stringify([documentId, passageId]);
}

type TriState = boolean | "indeterminate";

interface ReportRow {
  readonly timestamp: string;
  readonly kind: string;
  readonly entryId?: string;
  readonly passage_id?: string;
  readonly document_id?: string;
  readonly agent_id?: string;
  readonly text_sha256?: string;
  readonly bytes?: number;
  readonly passage_ids?: readonly string[];
  readonly truncated?: boolean;
  readonly reason?: string;
  readonly later_failure?: TriState;
  readonly present?: "present" | "absent" | "indeterminate";
  readonly digest_matches?: boolean | null;
  readonly tags?: readonly string[] | null;
  readonly resaved?: TriState;
}

// Only these bridge fields leave the fortress; query_sha256 and every other digest stay out of the report.
const REPORT_ROW_FIELDS = ["entryId", "passage_id", "document_id", "agent_id", "text_sha256", "bytes", "passage_ids", "truncated", "reason"] as const;

async function buildMemoryReport(context: OwnerContext, args: ParsedArgs, runAt: Date, packageVersion: string,
  noteAuditView: (view: AuditView) => void) {
  // The instant parseArgs validated is the one used; a second parser could disagree with it.
  const since = new Date(args.sinceMs ?? runAt.getTime() - DEFAULT_REPORT_WINDOW_MS);
  const view = await readAuditView(context);
  noteAuditView(view);
  const principal = hermesBridgeAuditPrincipal(args.agentId);
  const windowRows = view.entries.filter(entry => entry.operation === HERMES_BRIDGE_AUDIT_OPERATION &&
    new Date(entry.timestamp).getTime() >= since.getTime());
  // The scope check uses the bridge's own row shape: a mistyped --agent-id refuses instead of reading everything as absent.
  for (const entry of windowRows) {
    const details = entry.details ?? {};
    if (details.agent_id !== undefined && details.agent_id !== principal) {
      throw new OwnerRefusal("The window holds rows for a different agent id than --agent-id; the report was refused. " + NOTHING_CHANGED);
    }
    if (details.kind === "insert_admitted") {
      let expected: string | undefined;
      try { expected = context.reader.ownerDocumentId(String(details.passage_id)); } catch { expected = undefined; }
      if (details.agent_id !== principal || expected === undefined || details.document_id !== expected) {
        throw new OwnerRefusal("An admitted row does not match the --agent-id owner scope; the report was refused. " + NOTHING_CHANGED);
      }
    }
  }
  const admittedCount = windowRows.filter(entry => entry.details?.kind === "insert_admitted").length;
  const fullyRetained = view.earliestRetainedAt !== null && new Date(view.earliestRetainedAt).getTime() <= since.getTime();
  const truncated = windowRows.length > MEMORY_CORPUS_SCAN_CAP;
  // An absence claim needs a verified chain whose retention reaches back past the window start (and is known),
  // and every window row in the output: a truncated report dropped its oldest rows, so it supports no absence.
  const absenceSupported = view.chainVerified && fullyRetained && view.everPruned !== null && admittedCount > 0 && !truncated;
  const inspections = new Map<string, SdwMemoryOwnerInspection>();
  const firstKept = truncated ? windowRows.length - MEMORY_CORPUS_SCAN_CAP : 0;
  const rows: ReportRow[] = [];
  for (let index = firstKept; index < windowRows.length; index++) {
    const entry = windowRows[index]!;
    const details = entry.details ?? {};
    const row: Record<string, unknown> = { timestamp: entry.timestamp, kind: details.kind };
    for (const field of REPORT_ROW_FIELDS) if (details[field] !== undefined) row[field] = details[field];
    if (details.kind === "insert_admitted") {
      const later = windowRows.slice(index + 1).map(next => next.details ?? {});
      const laterFailure = later.some(next => next.kind === "latch" ||
        ((next.kind === "insert_refused" || next.kind === "insert_unconfirmed") && next.entryId === details.entryId));
      const resaved = later.some(next => next.kind === "insert_admitted" && next.passage_id === details.passage_id);
      const passageId = String(details.passage_id);
      // At most one inspect per admitted passage in the output; a repeated id reuses the first result.
      let inspection = inspections.get(passageId);
      if (inspection === undefined) {
        inspection = await context.reader.inspectPassageReadOnly(passageId).catch((): SdwMemoryOwnerInspection =>
          ({ state: "indeterminate", reason: "read_failed", metadata: null }));
        inspections.set(passageId, inspection);
      }
      const present = inspection.state === "absent" && !absenceSupported ? "indeterminate" : inspection.state;
      row.later_failure = laterFailure ? true : absenceSupported ? false : "indeterminate";
      row.present = present;
      // Compared in memory only; the stored text never leaves this function.
      row.digest_matches = inspection.state === "present"
        ? hermesBridgePassageTextDigest(inspection.text) === details.text_sha256 : null;
      row.tags = inspection.state === "absent" ? null : inspection.metadata?.tags ?? null;
      row.resaved = resaved ? true : absenceSupported ? false : "indeterminate";
    }
    rows.push(row as unknown as ReportRow);
  }
  const attempts = ownerDeleteAttempts(view.entries);
  const recoveries = view.entries.filter(entry => entry.operation === HERMES_SAVE_RECOVERED_OPERATION &&
    new Date(entry.timestamp).getTime() >= since.getTime());
  const lock = await corpusLockState(context.storage);
  const intentPresent = await context.readonlyStorage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY) !== null;
  return {
    report: "sanctuary hermes memory-report",
    provenance: {
      fortress_id: context.fortressId,
      package_version: packageVersion,
      run_at: runAt.toISOString(),
      chain_head_sequence: view.headSequence,
      agent_id: args.agentId,
      signed: false,
    },
    window: {
      since: since.toISOString(),
      chain_verified: view.chainVerified,
      chain_status: view.chainStatus,
      earliest_retained_row_at: view.earliestRetainedAt,
      ever_pruned: view.everPruned,
      fully_retained: fullyRetained,
      absence_claims_supported: absenceSupported,
      ...(absenceSupported ? {} : { note: truncated
        ? "The report is truncated: its oldest window rows are not listed, so it supports no absence claim."
        : admittedCount === 0
          ? "No insert_admitted rows in this window; the report makes no absence claim."
          : "The chain is not verified, the window is not fully retained, or pruning is unknown; this report supports no absence claim." }),
    },
    truncated,
    row_cap: MEMORY_CORPUS_SCAN_CAP,
    ...(truncated ? { truncated_note: "Only the newest rows are listed; a truncated report is not a witness for any criterion." } : {}),
    admitted_rows: admittedCount,
    rows,
    owner_scope_passage_count: await context.reader.countPassages(),
    owner_deletes: groupAttempts(attempts.slice(-MEMORY_CORPUS_SCAN_CAP)),
    owner_deletes_truncated: attempts.length > MEMORY_CORPUS_SCAN_CAP,
    save_recoveries: recoveries.slice(-MEMORY_CORPUS_SCAN_CAP)
      .map(entry => ({ timestamp: entry.timestamp, outcome: entry.details?.outcome, records_removed: entry.details?.records_removed })),
    save_recoveries_truncated: recoveries.length > MEMORY_CORPUS_SCAN_CAP,
    unfinished_save_intent: intentPresent,
    corpus_batch_lock: lock === null ? { present: false } : { present: true, path: lock, next_step: CORPUS_LOCK_PROCEDURE },
  };
}

function groupAttempts(attempts: readonly OwnerDeleteAttempt[]) {
  const groups = new Map<string, { passage_id: string; document_id: string | null; attempts: Omit<OwnerDeleteAttempt, "passage_id" | "document_id">[] }>();
  for (const { passage_id, document_id, ...attempt } of attempts) {
    const identity = ownerDeleteIdentity(document_id, passage_id);
    const group = groups.get(identity) ?? { passage_id, document_id, attempts: [] };
    group.attempts.push(attempt);
    groups.set(identity, group);
  }
  return [...groups.values()];
}

async function corpusLockState(storage: FilesystemStorage): Promise<string | null> {
  const lockPath = join(storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE), sdwMemoryCorpusBatchLockFile());
  return lstat(lockPath).then(() => lockPath, (cause: NodeJS.ErrnoException) => {
    if (cause.code === "ENOENT") return null;
    throw cause;
  });
}

/**
 * The package root for an entry module one folder below it: src/cli.ts in the source tree, dist/cli.js in the
 * bundle. cli.ts passes its own module URL; this module never resolves paths from its own location, because
 * the bundle inlines it into dist/cli.js and a module-relative path would point somewhere else there.
 */
export function hermesPackageRootFromEntry(entryModuleUrl: string): string {
  // Must match the "../package.json" that cli.ts reads PKG_VERSION from: the same folder above the entry module.
  return dirname(dirname(fileURLToPath(entryModuleUrl)));
}

/** The kit folder B: the parent of the runtime folder B_RUNTIME, which is the parent of the package root. */
export function hermesKitFolder(packageRoot: string): string {
  return dirname(dirname(resolve(packageRoot)));
}

// Must match the layouts hermesPackageRootFromEntry reads: the entry file directly inside one folder of the package root.
const ENTRY_FILE_NAMES: readonly string[] = ["cli.js", "cli.ts"];
const ENTRY_FOLDER_NAMES: readonly string[] = ["dist", "src"];

/**
 * The package root an invoked entry names, or undefined when the entry does not have the package layout.
 * Through a bin link (npm's global bin, node_modules/.bin, a kit's bin folder) argv[1] is the link path, and
 * two folders above it is an unrelated folder such as /opt/homebrew or the owner's home, never the package root.
 */
function packageRootFromInvokedEntry(invokedEntry: string | undefined): string | undefined {
  if (invokedEntry === undefined || invokedEntry === "") return undefined;
  const entry = resolve(invokedEntry);
  if (!ENTRY_FILE_NAMES.includes(basename(entry)) || !ENTRY_FOLDER_NAMES.includes(basename(dirname(entry)))) return undefined;
  return dirname(dirname(entry));
}

/**
 * Every kit folder --out refuses: from the package root as given, from its real path, and from the entry
 * path as invoked, each one both as derived and after realpath. A symlink anywhere in the kit layout can
 * make these differ, and each one may hold the runtime the relay executes, so all of them are refused
 * rather than trusting one resolution. The filesystem root and the owner's home are never a kit folder:
 * refusing either would refuse every --out, including the folder the help tells the owner to create.
 */
async function hermesKitFolders(packageRoot: string, invokedEntry: string | undefined, home: string | undefined): Promise<string[]> {
  const roots = [packageRoot, await realpath(packageRoot).catch(() => packageRoot)];
  const invokedRoot = packageRootFromInvokedEntry(invokedEntry);
  if (invokedRoot !== undefined) roots.push(invokedRoot);
  const kits: string[] = [];
  for (const root of roots) {
    // Narrower runtime and package folders remain protected when the kit ancestor is the owner's home.
    for (const folder of [resolve(root), dirname(resolve(root)), hermesKitFolder(root)]) {
      kits.push(folder, await realpath(folder).catch(() => folder));
    }
  }
  const neverKit: string[] = [sep];
  if (home !== undefined && home !== "") neverKit.push(resolve(home), await realpath(home).catch(() => resolve(home)));
  return [...new Set(kits)].filter(kit => !neverKit.includes(kit));
}

function isInsideOrEqual(path: string, parent: string): boolean {
  const rel = relative(parent, path);
  // Only a complete parent segment leaves the protected tree; names inside it remain protected.
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/** Validate --out before custody: a new file in a private, caller-owned folder outside the fortress and the kit folder. */
async function validateOutPath(out: string, uid: number, fortress: string, kitFolders: readonly string[]): Promise<string> {
  const refuse = (why: string): never => { throw new OwnerRefusal(`--out refused: ${why}. ` + NOTHING_CHANGED); };
  if (!isAbsolute(out)) refuse("give an absolute path");
  const target = resolve(out);
  const parent = dirname(target);
  // Walking every component with lstat refuses a symlink anywhere, so the file lands exactly where named.
  let current: string = sep;
  for (const part of parent.split(sep).filter(Boolean)) {
    current = join(current, part);
    const stats = await lstat(current).catch(() => null);
    if (stats === null) refuse(`the folder ${displayPath(current)} does not exist`);
    if (stats!.isSymbolicLink()) refuse(`${displayPath(current)} is a symlink`);
  }
  const parentStats = await lstat(parent);
  if (!parentStats.isDirectory()) refuse("the parent is not a folder");
  if (parentStats.uid !== uid || (parentStats.mode & PERMISSION_BITS) !== OWNER_DIRECTORY_MODE) {
    refuse("the parent folder must be yours with mode 0700");
  }
  const existing = await lstat(target).catch(() => null);
  if (existing !== null) refuse("the file already exists");
  const realParent = await realpath(parent);
  // hermesKitFolders already holds each kit folder both as derived and after realpath.
  const refused = [fortress, ...kitFolders];
  // The kit folder holds the runtime the relay executes; a report written there could shadow or alter it.
  if (refused.some(area => isInsideOrEqual(realParent, area))) {
    refuse("it is inside the fortress or the kit folder");
  }
  return target;
}

async function writeReportFile(target: string, body: string): Promise<void> {
  // Exclusive create without following links: a file or link that appeared since validation refuses the write.
  const handle = await open(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, OWNER_FILE_MODE)
    .catch(() => { throw new OwnerRefusal(`--out refused: ${displayPath(target)} could not be created as a new file. ` + NOTHING_CHANGED); });
  try {
    await handle.writeFile(body, "utf8");
    await handle.sync();
  } catch {
    await handle.close().catch(() => undefined);
    // A partial report must never be read as a whole one: remove it, or name it when it cannot be removed.
    const removed = await unlink(target).then(() => true, () => false);
    throw new OwnerRefusal(removed
      ? `--out: the report could not be written in full and the partial file was removed. ${NOTHING_CHANGED}`
      : `--out: the report could not be written in full and a partial file remains at ${displayPath(target)}; delete it before ` +
        "reading or sharing anything there. Nothing in the fortress was changed.");
  }
  // After a completed write and sync the file holds the whole report, so a close failure says so instead of
  // falling through to the generic "nothing was changed".
  await handle.close().catch(() => {
    throw new OwnerRefusal(`--out: the whole report was written and synced to ${displayPath(target)}, but the file did not ` +
      "close cleanly. Nothing in the fortress was changed.");
  });
}

/**
 * A path from argv or derived from it, shown on the terminal: JSON quoting escapes line breaks and C0
 * controls, and escapeForTerminal escapes the C1, direction and invisible characters JSON leaves as-is.
 */
function displayPath(path: string): string {
  return escapeForTerminal(JSON.stringify(path));
}

// Bidi embeddings, overrides, isolates and marks, the Unicode line and paragraph separators, and the
// zero-width and invisible format characters (soft hyphen, combining grapheme joiner, Hangul fillers,
// Mongolian vowel separator, zero-width space and joiners, word joiner, invisible operators, byte order
// mark) that could hide or disguise text on the owner's screen.
const ESCAPED_FORMAT_CODE_POINTS = new Set([0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x180e, 0x200b, 0x200c, 0x200d,
  0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
  0x2066, 0x2067, 0x2068, 0x2069, 0x3164, 0xfeff]);
// Unicode tag characters U+E0000 to U+E007F render as nothing and can carry hidden text.
const TAG_START = 0xe0000;
const TAG_END = 0xe007f;
// Variation selectors render as nothing on their own and can also carry hidden bytes.
const VARIATION_SELECTOR_START = 0xfe00;
const VARIATION_SELECTOR_END = 0xfe0f;
const VARIATION_SELECTOR_SUPPLEMENT_START = 0xe0100;
const VARIATION_SELECTOR_SUPPLEMENT_END = 0xe01ef;
const LINE_FEED = 0x0a;
const C0_END = 0x20;
const DEL_CODE_POINT = 0x7f;
const C1_END = 0x9f;
const SURROGATE_START = 0xd800;
const SURROGATE_END = 0xdfff;
const ESCAPE_HEX_DIGITS = 4;

/**
 * Escape text for the owner's terminal: C0 and C1 controls (0x9B included),
 * DEL, bidi, separator, zero-width and invisible format characters, tag
 * characters, variation selectors, lone surrogates and the backslash
 * itself, so stored text can neither drive the terminal nor pass for this tool's
 * own output. Line feeds are kept; each line is framed by the caller.
 */
export function escapeForTerminal(text: string): string {
  let escaped = "";
  for (const character of text) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint === LINE_FEED) escaped += "\n";
    else if (character === "\\") escaped += "\\\\";
    else if (codePoint < C0_END || (codePoint >= DEL_CODE_POINT && codePoint <= C1_END) ||
      ESCAPED_FORMAT_CODE_POINTS.has(codePoint) || (codePoint >= SURROGATE_START && codePoint <= SURROGATE_END) ||
      (codePoint >= TAG_START && codePoint <= TAG_END) ||
      (codePoint >= VARIATION_SELECTOR_START && codePoint <= VARIATION_SELECTOR_END) ||
      (codePoint >= VARIATION_SELECTOR_SUPPLEMENT_START && codePoint <= VARIATION_SELECTOR_SUPPLEMENT_END)) {
      escaped += `\\u{${codePoint.toString(16).toUpperCase().padStart(ESCAPE_HEX_DIGITS, "0")}}`;
    } else escaped += character;
  }
  return escaped;
}

/** First `count` code points; iterating by code point never splits a surrogate pair. */
export function truncateCodePoints(text: string, count: number): { readonly text: string; readonly cut: boolean } {
  const points = Array.from(text);
  return { text: points.slice(0, count).join(""), cut: points.length > count };
}

const FRAME_TOP = "+---- Saved from the conversation, unverified ----";
const FRAME_LINE = "| ";
const FRAME_BOTTOM = "+---- end of saved passage ----";
const CANNOT_VERIFY = "cannot be verified; text not shown";

/** Frame one passage so no stored line starts at column zero, where this tool's own prompts appear. */
export function framePassage(passageId: string, metadata: SdwMemoryOwnerRecordMetadata | null, text: string | null, cut = false): string {
  const lines = [
    FRAME_TOP,
    `${FRAME_LINE}passage_id: ${passageId}`,
    `${FRAME_LINE}created_at: ${metadata === null ? "unknown" : escapeForTerminal(metadata.created_at)}`,
    `${FRAME_LINE}tags: ${metadata === null ? "unknown" : metadata.tags.length === 0 ? "none" : metadata.tags.map(escapeForTerminal).join(", ")}`,
    `${FRAME_LINE}bytes: ${metadata?.byte_length ?? "unknown"}`,
    FRAME_LINE.trimEnd(),
  ];
  if (text === null) lines.push(`${FRAME_LINE}${CANNOT_VERIFY}`);
  else {
    for (const line of escapeForTerminal(text).split("\n")) lines.push(`${FRAME_LINE}${line}`);
    if (cut) lines.push(`${FRAME_LINE}[preview ends here]`);
  }
  lines.push(FRAME_BOTTOM);
  return lines.join("\n") + "\n";
}

async function showPassages(context: OwnerContext, args: ParsedArgs, out: Writer): Promise<number> {
  const renderInspection = (passageId: string, inspection: SdwMemoryOwnerInspection): string =>
    inspection.state === "present" ? framePassage(passageId, inspection.metadata, inspection.text)
      : inspection.state === "indeterminate" ? framePassage(passageId, inspection.metadata, null)
        : "";
  if (args.passage !== undefined) {
    const inspection = await context.reader.inspectPassageReadOnly(args.passage);
    if (inspection.state === "absent") {
      out.write("No saved passage with that id in this owner scope.\n");
      return 1;
    }
    out.write(renderInspection(args.passage, inspection));
    return 0;
  }
  const listed = await context.reader.listOwnerRecordMetadata();
  // Newest first by record metadata, passage_id as the tie-break; only the top n are ever decrypted.
  const newest = [...listed.records].sort((a, b) => b.created_at.localeCompare(a.created_at) ||
    a.passage_id.localeCompare(b.passage_id)).slice(0, args.recent);
  if (listed.truncated) out.write(`The owner scope has more than ${MEMORY_CORPUS_SCAN_CAP} records; this list may not be the newest overall.\n`);
  if (listed.unreadable > 0) out.write(`${listed.unreadable} saved record(s) could not be read and are not listed.\n`);
  if (newest.length === 0) out.write("No saved passages in this owner scope.\n");
  for (const record of newest) {
    const inspection = await context.reader.inspectPassageReadOnly(record.passage_id);
    out.write(renderInspection(record.passage_id, inspection.state === "absent"
      ? { state: "indeterminate", reason: "document_changed", metadata: record } : inspection));
  }
  return 0;
}

async function readConfirmationLine(stdin: RawModeStdin, timeoutMs: number): Promise<string | null> {
  return new Promise(resolveLine => {
    let buffered = "";
    let settled = false;
    const finish = (value: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onEnd);
      stdin.pause();
      resolveLine(value);
    };
    const onData = (chunk: unknown) => {
      buffered += String(chunk);
      const [line, ...rest] = buffered.split("\n");
      if (rest.length > 0) finish(line!.replace(/\r$/u, ""));
      else if (buffered.length > MAX_CONFIRMATION_CHARS) finish(buffered);
    };
    const onEnd = () => finish(null);
    const timer = setTimeout(() => finish(null), timeoutMs);
    stdin.on("data", onData);
    stdin.on("end", onEnd);
    stdin.on("error", onEnd);
    stdin.resume();
  });
}

function errorCategory(error: unknown): string {
  if (error instanceof SdwValidationError) return error.category;
  if (error instanceof CrossProcessLockError) return `lock_${error.kind}`;
  return "error";
}

/** Exit code and operator message per terminal delete outcome; the row is already written when these print. */
const OUTCOME_REPORT: Readonly<Record<Exclude<OwnerDeleteOutcome, "intent">, (category: string) => { code: number; message: string }>> = {
  deleted: () => ({ code: 0, message: "deleted" }),
  not_found: () => ({ code: 1, message: "The passage was already gone when the delete ran." }),
  not_attempted: category => ({ code: 1, message: `The delete could not start (${category}). ${NOTHING_DELETED} You may run it again.` }),
  failed_restored: category => ({ code: 1, message: `The delete failed (${category}) and was rolled back. ${NOTHING_DELETED} You may run it again.` }),
  failed_unrestored: category => ({ code: 1, message: `The delete failed (${category}): removed from memory, cleanup incomplete. ` +
    "Next step: the coordinator, with a memory-report. Leftover encrypted chunks are invisible to recall and to the passage count." }),
  indeterminate: category => ({ code: 1, message: `The delete failed (${category}) and its result could not be confirmed: treat ` +
    "the passage as still listed, and it may still be recalled. Do not restart the Hermes memory relay or run the delete " +
    "again; stop here and bring a memory-report to the coordinator." }),
};

/**
 * Classify a delete that threw, from a re-read of the fortress only, never from a partial read. After a
 * mutation began, the passage's raw records are compared with the snapshot taken before the intent row:
 * all equal is rolled back, a missing document record is removed, and anything else, or a re-read that
 * throws, is indeterminate. A passage that could not be verified before the delete compares equal after
 * a clean rollback, so it is never reported as removed.
 */
async function outcomeAfterThrow(reader: SdwMemoryBackendAdapter, passageId: string, mutationBegan: boolean,
  snapshot: SdwMemoryPassageRawSnapshot): Promise<"not_attempted" | "failed_restored" | "failed_unrestored" | "indeterminate"> {
  if (!mutationBegan) {
    const present = await reader.hasRawDocumentRecord(passageId).catch(() => undefined);
    return present === undefined ? "indeterminate" : present ? "not_attempted" : "failed_unrestored";
  }
  const comparison = await reader.compareWithPassageRawSnapshot(snapshot).catch(() => undefined);
  return comparison === "equal" ? "failed_restored" : comparison === "document_absent" ? "failed_unrestored" : "indeterminate";
}

/**
 * An intent append that throws may still have committed its row, so the chain is read back before the
 * operator is told anything. The pre-checks refused any earlier interrupted delete, so an interrupted
 * attempt for this passage in the re-read can only be the row this run just wrote.
 */
async function intentAppendFailureMessage(context: OwnerContext, passageId: string): Promise<string> {
  let landed: boolean;
  try {
    const view = await readAuditView(context);
    landed = ownerDeleteAttempts(view.entries).some(attempt => attempt.outcome === "interrupted" && attempt.passage_id === passageId);
  } catch {
    return "The delete could not confirm its audit row, and the audit log could not be read back, so the intent may be " +
      `recorded. ${NOTHING_DELETED} If the next memory-delete refuses as interrupted, stop and bring a memory-report to the coordinator.`;
  }
  if (landed) {
    return "The delete could not confirm its audit row, but the intent row is recorded, so this delete is recorded as " +
      `interrupted. ${NOTHING_DELETED} Next step: stop here and bring a memory-report to the coordinator.`;
  }
  return "The delete could not be recorded in the audit log. " + NOTHING_DELETED;
}

/** Wrap storage so the delete can tell whether any corpus mutation was attempted before a throw. */
function trackCorpusMutations(storage: FilesystemStorage, onMutation: () => void): FilesystemStorage {
  return new Proxy(storage, {
    get(target, property) {
      const value = Reflect.get(target, property, target) as unknown;
      if (typeof value !== "function") return value;
      if (property === "delete" || property === "write" || property === "writeDurable") {
        return (...callArgs: unknown[]) => {
          // Marked before the call: a call that throws partway may already have removed a record.
          if (callArgs[0] === SDW_DOCUMENT_CORPUS_NAMESPACE) onMutation();
          return (value as (...inner: unknown[]) => unknown).apply(target, callArgs);
        };
      }
      return (value as (...inner: unknown[]) => unknown).bind(target);
    },
  });
}

/**
 * memory-delete continuing paths. The outcome after any throw is decided by
 * re-reading the fortress, never from the error type alone.
 *
 * Arm                                   | Outcome row        | Exit and message
 * Writer composition or the raw-record  | none (no intent)   | 1, could not be prepared; nothing was deleted
 *   snapshot throws                     |                    |
 * Intent append throws, re-read finds   | none               | 1, nothing was deleted
 *   no intent row                       |                    |
 * Intent append throws, re-read finds   | intent only        | 1, recorded as interrupted; stop, coordinator
 *   the intent row                      |                    |
 * Intent append throws, re-read fails   | unknown            | 1, intent may be recorded; coordinator if refused
 * Throw after the intent, before any    | not_attempted      | 1, nothing was deleted
 *   corpus mutation, record present     |                    |
 * deletePassage returns true            | deleted            | 0, deleted (row first)
 * deletePassage returns false           | not_found          | 1, already gone
 * Throw after mutation, every raw record | failed_restored    | 1, nothing was deleted; may run again
 *   equals the snapshot                 |                    |
 * Throw after mutation, raw document     | failed_unrestored  | 1, removed, cleanup incomplete; coordinator;
 *   record absent; or no mutation and   |                    |   closing line: keep the relay stopped
 *   the record absent                   |                    |
 * Throw after mutation, any other        | indeterminate      | 1, still listed, unconfirmed; do not restart
 *   difference; or the re-read throws   |                    |   the relay; coordinator with a report;
 *                                       |                    |   closing line: keep the relay stopped
 * Throw before mutation, re-read throws | indeterminate      | same as above
 * Outcome append throws                 | (stderr names it)  | 1
 * Killed before an outcome              | intent only        | next report and delete say interrupted
 */
async function deletePassage(context: OwnerContext, args: ParsedArgs, io: {
  readonly out: Writer;
  readonly err: Writer;
  readonly stdin: RawModeStdin;
  readonly signals: SignalPort;
  readonly promptTimeoutMs: number;
  readonly markFinished: () => void;
  readonly noteAuditView: (view: AuditView) => void;
  readonly keepRelayStopped: () => void;
  /** This passage's delete was confirmed, so an earlier unconfirmed attempt on it no longer holds the relay. */
  readonly removed: (documentId: string, passageId: string) => void;
}): Promise<number> {
  const passageId = args.passage!;
  if (await context.readonlyStorage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY) !== null) {
    throw new OwnerRefusal("An earlier save did not finish. Run `sanctuary hermes recover-save --fortress <dir>` first. " + NOTHING_DELETED);
  }
  const lock = await corpusLockState(context.storage);
  if (lock !== null) {
    throw new OwnerRefusal(`A corpus lock was left behind at ${displayPath(lock)}. Next step: ${CORPUS_LOCK_PROCEDURE} ` + NOTHING_DELETED);
  }
  const view = await readAuditView(context);
  io.noteAuditView(view);
  if (ownerDeleteAttempts(view.entries).some(attempt => attempt.outcome === "interrupted")) {
    throw new OwnerRefusal("An earlier memory-delete was interrupted before it recorded an outcome. Next step: the " +
      "coordinator, with a memory-report. " + NOTHING_DELETED);
  }
  let documentId: string;
  try { documentId = context.reader.ownerDocumentId(passageId); }
  catch { throw new OwnerRefusal("That passage id is not valid for this owner scope. " + NOTHING_DELETED); }
  // Existence comes from the raw record, so a passage that cannot be verified can still be deleted.
  if (!await context.reader.hasRawDocumentRecord(passageId)) {
    throw new OwnerRefusal("No saved passage with that id in this owner scope. " + NOTHING_DELETED);
  }
  const inspection = await context.reader.inspectPassageReadOnly(passageId);
  const preview = inspection.state === "present" ? truncateCodePoints(inspection.text, DELETE_PREVIEW_CHARS) : null;
  io.out.write(framePassage(passageId, inspection.state === "absent" ? null : inspection.metadata, preview?.text ?? null, preview?.cut ?? false));
  io.out.write(`Type ${CONFIRMATION_WORD} and press Return within ${Math.round(io.promptTimeoutMs / 1000)} seconds to remove this passage. Anything else keeps it.\n> `);
  const answer = await readConfirmationLine(io.stdin, io.promptTimeoutMs);
  if (answer === null) throw new OwnerRefusal("No answer within the time limit. " + NOTHING_DELETED);
  if (answer !== CONFIRMATION_WORD) throw new OwnerRefusal("The confirmation did not match. " + NOTHING_DELETED);

  let mutationBegan = false;
  // Every fallible step that does not mutate runs before the intent row, so nothing between that row
  // and the delete can fail without its own outcome row and leave a permanent interrupted block.
  let writer: SdwMemoryBackendAdapter;
  let snapshot: SdwMemoryPassageRawSnapshot;
  try {
    writer = await composeOwnerAdapter(trackCorpusMutations(context.storage, () => { mutationBegan = true; }),
      context.masterKey, context.fortressId, args.agentId, context.identities);
    // Read-only, through the reader: the evidence a failed delete is later compared against.
    snapshot = await context.reader.snapshotPassageRawRecords(passageId);
  } catch (error) {
    throw new OwnerRefusal(`The delete could not be prepared (${errorCategory(error)}). ` + NOTHING_DELETED);
  }
  const textSha256 = inspection.state === "present" ? hermesBridgePassageTextDigest(inspection.text) : null;
  const audit = new AuditLog(context.storage, context.masterKey);

  const ignore = () => undefined;
  // From an accepted DELETE until the delete returns, a stray signal cannot cut the delete between its writes.
  for (const signal of DELETE_IGNORED_SIGNALS) io.signals.on(signal, ignore);
  try {
    const row = (outcome: OwnerDeleteOutcome, extra: Record<string, unknown> = {}) => audit.appendCritical({
      layer: "l3",
      operation: HERMES_MEMORY_OWNER_DELETE_OPERATION,
      identity_id: "operator",
      result: outcome === "intent" || outcome === "deleted" ? "success" : "failure",
      details: { passage_id: passageId, document_id: documentId, text_sha256: textSha256, outcome, ...extra },
    });
    try {
      // Audit first: if the intent cannot be recorded, nothing is deleted.
      await row("intent");
    } catch {
      // An unconfirmed intent append keeps this run stopped even when read-back is unavailable.
      io.keepRelayStopped();
      io.err.write(await intentAppendFailureMessage(context, passageId) + "\n");
      return 1;
    }
    let outcome: Exclude<OwnerDeleteOutcome, "intent">;
    let category: string | undefined;
    try {
      // Any throw from here to the first corpus mutation is not_attempted with its category, never an exit without a row.
      outcome = await writer.deletePassage(passageId) ? "deleted" : "not_found";
    } catch (error) {
      category = errorCategory(error);
      outcome = await outcomeAfterThrow(context.reader, passageId, mutationBegan, snapshot);
    }
    // Decided before the outcome row, so the closing line holds even if that row cannot be written.
    if (outcome === "failed_unrestored" || outcome === "indeterminate") io.keepRelayStopped();
    io.markFinished();
    try {
      // The outcome row is appended before success is reported, so a printed "deleted" always has its row.
      await row(outcome, category === undefined ? {} : { error_category: category });
    } catch {
      // A delete without a recorded outcome remains unresolved even if the corpus mutation completed.
      io.keepRelayStopped();
      io.err.write(`The delete outcome "${outcome}" could not be written to the audit log; it is not retried.\n`);
      return 1;
    }
    // Only a durable deleted outcome releases the hold for this document and passage.
    if (outcome === "deleted") io.removed(documentId, passageId);
    const result = OUTCOME_REPORT[outcome](category ?? "error");
    (result.code === 0 ? io.out : io.err).write(result.message + "\n");
    return result.code;
  } finally {
    for (const signal of DELETE_IGNORED_SIGNALS) io.signals.off(signal, ignore);
  }
}
