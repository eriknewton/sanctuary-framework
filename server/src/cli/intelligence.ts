/**
 * Sanctuary MCP Server -- `sanctuary intelligence` CLI subcommand
 *
 * v1.2.1 (Finding III): minimal `sanctuary intelligence diagnose` that prints
 * the substrate config and last error from the audit log. Helps operators
 * debug why the intelligence layer failed at boot.
 *
 * Q5E residual 2: `sanctuary intelligence config-reset` is the ONE recovery
 * verb for an unreadable durable config record (corrupt or version-too-new).
 * It unlocks the fortress master (write intent, so it holds the shared
 * rotation barrier), classifies the record, prints the plan, requires a typed
 * confirmation on an interactive terminal (no flag bypasses it), and then
 * asks the store to quarantine the bytes to a sidecar and remove the record.
 * Readable records and Q5 integrity refusals are refused, so the verb cannot
 * disarm a working armed record; a fortress armed on the UNREADABLE record it
 * quarantines is left in the default legacy-unarmed state until re-provisioned.
 */

import { join, resolve } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { BACKEND_FALLBACK_STRINGS } from "../intelligence/templates.js";
import { INTEL_OPS } from "../intelligence/audit-events.js";
import {
  INTELLIGENCE_CONFIG_RESET_VERB,
  IntelligenceConfigStore,
  type LoadOutcome,
} from "../intelligence/policy-store.js";
import { AuditLog } from "../operational/audit-log.js";
import { recoverInterruptedExitImportsOrThrow } from "../exit/bundle.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import type { MasterWriteBarrierLease } from "../storage/cross-process-lock.js";
import { fortressIdFromStoragePath } from "../dashboard/v1_1/wiring.js";
import { unlockLocalFortress } from "./local-fortress-unlock.js";
import {
  aliasConflictMessage,
  consumeFlagValue,
  FORTRESS_FLAG_USAGE_EXIT_CODE,
  fortressFlagRefusalText,
} from "./argv.js";

/**
 * Print the model-choice privacy tradeoff to the operator-facing CLI channel.
 * The copy is REUSED verbatim from the canonical badge strings in
 * `intelligence/templates.ts` (the same strings the dashboard Intelligence
 * picker shows); it is not re-authored here. Leads with what the operator
 * controls about their own data so a fresh operator sees the tradeoff in the
 * CLI setup path, not only in the dashboard.
 */
function printSubstratePrivacyNote(): void {
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("");
  console.error("Choosing a model: your privacy tradeoff");
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(
    `  Local (default): ${BACKEND_FALLBACK_STRINGS["intelligence.badge.local.tradeoff"]}`,
  );
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(
    `  Venice.ai: ${BACKEND_FALLBACK_STRINGS["intelligence.badge.venice.tradeoff"]}`,
  );
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(
    `  Frontier (Anthropic/OpenAI/Google): ${BACKEND_FALLBACK_STRINGS["intelligence.badge.frontier.tradeoff"]}`,
  );
}

interface IntelligenceCommandOpts {
  argv: string[];
  /** Test seams for `config-reset`; production leaves this undefined. */
  configResetDeps?: ConfigResetDeps;
}

function hasFlag(argv: string[], name: string): boolean {
  return argv.includes(name);
}

export async function runIntelligenceCommand(
  opts: IntelligenceCommandOpts,
): Promise<number> {
  const subcommand = opts.argv[0];

  if (subcommand === "diagnose" || subcommand === undefined) {
    const rest = opts.argv.slice(subcommand === "diagnose" ? 1 : 0);
    if (subcommand === "diagnose" && wantsHelp(rest)) {
      printIntelligenceDiagnoseHelp();
      return 0;
    }
    return runDiagnose(rest);
  }

  if (subcommand === "config-reset") {
    return runIntelligenceConfigReset(opts.argv.slice(1), opts.configResetDeps);
  }

  if (subcommand === "--help" || subcommand === "-h") {
    printHelp();
    return 0;
  }

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`Unknown intelligence subcommand: ${subcommand}`);
  printHelp();
  return 2;
}

function wantsHelp(argv: string[]): boolean {
  return argv.includes("--help") || argv.includes("-h");
}

function printHelp(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`
Usage: sanctuary intelligence <subcommand>

Subcommands:
  diagnose      Print intelligence substrate config and last error.
  config-reset  Quarantine an unreadable local-intelligence config record and reinitialize.
  --help        Show this help.
`);
}

export function printIntelligenceDiagnoseHelp(): void {
  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`
sanctuary intelligence diagnose. Print local intelligence substrate diagnostics.

Usage:
  sanctuary intelligence diagnose [--fortress <path>]
  sanctuary intelligence diagnose [--fortress-path <path>]

Description:
  Checks the local fortress intelligence config directory, recent audit
  filenames, and relevant substrate environment variables. This command does
  not require a passphrase.

Options:
  --fortress <path>       Override the fortress path.
  --fortress-path <path>  Alias for --fortress.
  --help, -h              Show this help.

Examples:
  sanctuary intelligence diagnose
  sanctuary intelligence diagnose --fortress ~/.sanctuary-work
`);
}

/**
 * Resolve the fortress path from a trailing `--fortress`/`--fortress-path`
 * flag, then the environment, then the default. Shared by `diagnose` and
 * `config-reset` so both verbs refuse the same malformed forms identically.
 */
function resolveFortressStoragePath(
  argv: string[],
  env: NodeJS.ProcessEnv,
): { storagePath: string; argv: string[] } | { error: string } {
  // Must match consumeFlagValue in ./argv.ts: a dropped --fortress/
  // --fortress-path value must refuse, never silently resolve the default
  // fortress; acting on the wrong fortress's intelligence config is a
  // constraint-5 violation.
  const consumedFortress = consumeFlagValue(argv, "--fortress");
  if (consumedFortress.error !== undefined) {
    return { error: fortressFlagRefusalText(consumedFortress.error) };
  }
  const consumedFortressPath = consumeFlagValue(
    consumedFortress.argv,
    "--fortress-path",
  );
  if (consumedFortressPath.error !== undefined) {
    return { error: fortressFlagRefusalText(consumedFortressPath.error) };
  }
  // IC-30 fix-round finding #3: --fortress and --fortress-path are ALIASES
  // for the same value; giving both must refuse rather than let `??` below
  // silently pick --fortress over --fortress-path regardless of which one
  // the operator meant.
  if (consumedFortress.value !== undefined && consumedFortressPath.value !== undefined) {
    return {
      error: fortressFlagRefusalText(
        aliasConflictMessage("--fortress", "--fortress-path"),
      ),
    };
  }
  const fortressFlag = consumedFortress.value ?? consumedFortressPath.value;
  return {
    storagePath: resolve(
      fortressFlag ??
        env.SANCTUARY_STORAGE_PATH ??
        env.SANCTUARY_FORTRESS_PATH ??
        `${env.HOME}/.sanctuary`,
    ),
    argv: consumedFortressPath.argv,
  };
}

async function runDiagnose(argv: string[] = []): Promise<number> {
  const json = hasFlag(argv, "--json");
  const resolved = resolveFortressStoragePath(argv, process.env);
  if ("error" in resolved) {
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(resolved.error);
    return FORTRESS_FLAG_USAGE_EXIT_CODE;
  }
  const storagePath = resolved.storagePath;

  const intelligenceDir = resolve(storagePath, "state", "_intelligence");
  const auditDir = resolve(storagePath, "state", "_audit");
  const environment = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "VENICE_API_KEY",
    "OLLAMA_HOST",
  ].map((key) => {
    const value = process.env[key];
    return {
      key,
      set: Boolean(value),
      prefix: value ? `${value.slice(0, 4)}...` : null,
    };
  });

  if (json) {
    let intelligenceEntries: string[] = [];
    let intelligenceReadError: string | null = null;
    let auditFiles: string[] = [];
    let auditTotal = 0;
    let auditReadError: string | null = null;

    if (existsSync(intelligenceDir)) {
      try {
        intelligenceEntries = readdirSync(intelligenceDir);
      } catch (error) {
        intelligenceReadError =
          error instanceof Error ? error.message : String(error);
      }
    }

    if (existsSync(auditDir)) {
      try {
        const files = readdirSync(auditDir).sort().reverse();
        auditTotal = files.length;
        auditFiles = files.slice(0, 20);
      } catch (error) {
        auditReadError = error instanceof Error ? error.message : String(error);
      }
    }

    const initialized = existsSync(intelligenceDir);
    // SAFETY: stdout is the requested machine-readable CLI channel for --json.
    console.log(
      JSON.stringify(
        {
          ok: initialized && intelligenceReadError === null,
          fortress: storagePath,
          intelligence: {
            directory: intelligenceDir,
            exists: initialized,
            entries: intelligenceEntries,
            read_error: intelligenceReadError,
          },
          audit: {
            directory: auditDir,
            exists: existsSync(auditDir),
            recent_entries: auditFiles,
            total_entries: auditTotal,
            read_error: auditReadError,
          },
          environment,
        },
        null,
        2,
      ),
    );
    return initialized ? 0 : 1;
  }

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`Intelligence substrate diagnostics`);
  console.error(`Fortress: ${storagePath}`);
  console.error("");

  // Check for intelligence config in the state directory
  if (!existsSync(intelligenceDir)) {
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `No intelligence config directory found at ${intelligenceDir}.`,
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      "Intelligence substrate may not have been initialized yet.",
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      "Ensure at least one substrate API key is set in your environment:",
    );
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      "  ANTHROPIC_API_KEY, OPENAI_API_KEY, VENICE_API_KEY, or OLLAMA_HOST",
    );
    printSubstratePrivacyNote();
    return 1;
  }

  // List intelligence config files
  try {
    const entries = readdirSync(intelligenceDir);
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`Intelligence config entries: ${entries.length}`);
    for (const entry of entries) {
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error(`  ${entry}`);
    }
  } catch {
    console.error(`Could not read intelligence config directory.`);
  }

  // Check audit log for intelligence failures
  if (existsSync(auditDir)) {
    try {
      const auditFiles = readdirSync(auditDir).sort().reverse();
      const recentFiles = auditFiles.slice(0, 20);
      // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
      console.error("");
      console.error(`Recent audit entries (${recentFiles.length} of ${auditFiles.length}):`);
      for (const file of recentFiles) {
        // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
        console.error(`  ${file}`);
      }
    } catch {
      console.error(`Could not read audit directory.`);
    }
  }

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("");
  console.error("Substrate environment check:");
  const keys = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "VENICE_API_KEY",
    "OLLAMA_HOST",
  ];
  for (const key of keys) {
    const val = process.env[key];
    // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  ${key}: ${val ? `set (${val.slice(0, 4)}...)` : "not set"}`,
    );
  }

  printSubstratePrivacyNote();

  return 0;
}

// ---------------------------------------------------------------------------
// `sanctuary intelligence config-reset`
// ---------------------------------------------------------------------------

/** Named exit codes so a runbook can branch on them. */
export const CONFIG_RESET_EXIT = {
  /** Quarantined, or nothing to do (no durable record). */
  OK: 0,
  /** Refused: non-interactive, declined, unlock failed, or record not unreadable. */
  REFUSED: 1,
  /** Malformed flags; shares the fortress-flag usage code. */
  USAGE: FORTRESS_FLAG_USAGE_EXIT_CODE,
} as const;

/**
 * The literal the operator must type. A bare "y" is too easy to give to the
 * wrong prompt; the word names the action being confirmed.
 */
export const CONFIG_RESET_CONFIRMATION_WORD = "reset";

export interface ConfigResetDeps {
  /** Master unlock chokepoint; tests inject a keyring-free wrapper. */
  unlock?: typeof unlockLocalFortress;
  /** Returns the operator's typed answer to the confirmation prompt. */
  ask?: (prompt: string) => Promise<string>;
  /** Whether stdin is an interactive terminal (defaults to the real check). */
  isTty?: boolean;
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
  /** Operator-facing line sink (stderr by default). */
  print?: (line: string) => void;
  /** Test seam for the store's catalog key pin; production uses the compiled key. */
  modelManifestV2PublicKey?: Uint8Array;
}

export function printIntelligenceConfigResetHelp(print: (line: string) => void = defaultPrint): void {
  // Must match INTELLIGENCE_CONFIG_RESET_VERB in `intelligence/policy-store.ts`,
  // which the typed refusal quotes as the remedy; the verb name must not drift.
  print(`
${INTELLIGENCE_CONFIG_RESET_VERB}. Quarantine an unreadable local-intelligence config record and reinitialize.

Usage:
  ${INTELLIGENCE_CONFIG_RESET_VERB} [--fortress <path>]
  ${INTELLIGENCE_CONFIG_RESET_VERB} [--fortress-path <path>]

Description:
  Use this only when local-intelligence config writes fail with
  "durable config is corrupt" or "durable config is version-too-new".
  The verb unlocks the fortress (SANCTUARY_PASSPHRASE, SANCTUARY_RECOVERY_KEY,
  or the exact-fortress stored credential), classifies the durable record,
  prints what it will do, and asks you to type "${CONFIG_RESET_CONFIRMATION_WORD}".
  It then copies the record's raw bytes to a timestamped sidecar file in the
  fortress's _intelligence state directory and removes the record. The next
  load returns the default legacy-unarmed configuration; operator substrate
  choices and API keys held inside the unreadable record are not recovered.
  A fortress that was Q5-armed on the quarantined record is unarmed afterward,
  and local load-integrity verification does not apply until it is
  re-provisioned.

  A readable record is refused, armed or not. An armed record that fails Q5
  integrity validation is refused too: that is an integrity refusal, not an
  unreadable record. Because of both refusals this verb cannot disarm a
  working armed record; it only clears a record nothing can read.

  Requires an interactive terminal. There is no flag that skips the prompt.

Options:
  --fortress <path>       Override the fortress path.
  --fortress-path <path>  Alias for --fortress.
  --help, -h              Show this help.

Exit codes:
  0  quarantined, or no durable record existed
  1  refused (non-interactive, declined, unlock failed, record not unreadable)
  2  malformed flags
`);
}

function defaultPrint(line: string): void {
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(line);
}

function describeOutcome(outcome: LoadOutcome): string {
  switch (outcome.kind) {
    case "default":
      return "no durable record";
    case "loaded":
      return `readable record, version ${outcome.config.version}`;
    case "integrity-state-invalid":
      return `armed record failed Q5 integrity validation (${outcome.reason})`;
    case "corrupt":
      return "unreadable record: does not decrypt or parse (corrupt)";
    case "version-too-new":
      return `unreadable record: version ${outcome.persistedVersion} is newer than this build supports`;
  }
}

export async function runIntelligenceConfigReset(
  argv: string[],
  deps: ConfigResetDeps = {},
): Promise<number> {
  const print = deps.print ?? defaultPrint;
  const env = deps.env ?? process.env;
  if (wantsHelp(argv)) {
    printIntelligenceConfigResetHelp(print);
    return CONFIG_RESET_EXIT.OK;
  }
  const resolved = resolveFortressStoragePath(argv, env);
  if ("error" in resolved) {
    print(resolved.error);
    return CONFIG_RESET_EXIT.USAGE;
  }
  const unknown = resolved.argv.filter((arg) => arg.startsWith("-"));
  if (unknown.length > 0) {
    print(`Unknown option(s) for config-reset: ${unknown.join(" ")}`);
    printIntelligenceConfigResetHelp(print);
    return CONFIG_RESET_EXIT.USAGE;
  }
  const storagePath = resolved.storagePath;

  // The consent gate is a human at a terminal; a piped or headless run refuses
  // before the fortress is even unlocked, so nothing is read or changed.
  const isTty = deps.isTty ?? process.stdin.isTTY === true;
  if (!isTty) {
    print(
      `${INTELLIGENCE_CONFIG_RESET_VERB} requires an interactive terminal; nothing was changed.`,
    );
    return CONFIG_RESET_EXIT.REFUSED;
  }

  const storage = new FilesystemStorage(join(storagePath, "state"));
  const unlock = deps.unlock ?? unlockLocalFortress;
  // Write intent: the quarantine deletes a fortress record, so this verb holds
  // the shared master-rotation barrier until its last write or fails closed
  // (S1 / AGENTS rule 12), the same as every other master-derived write verb.
  const unlocked = await unlock({ storage, storagePath, env, writeIntent: true });
  if (!unlocked.ok) {
    print(`Error: could not unlock the fortress: ${unlocked.message}`);
    return CONFIG_RESET_EXIT.REFUSED;
  }
  const masterKey = unlocked.masterKey;
  const barrier: MasterWriteBarrierLease | undefined = unlocked.barrier;
  try {
    const auditLog = new AuditLog(storage, masterKey);
    // Every fortress-open call site that can mutate state routes through the
    // exit-import recovery chokepoint first: an interrupted Exit import leaves
    // a journal whose snapshots this fortress's state is bound to, and opening
    // around it would mutate a half-applied target as if it were legitimate.
    // The wrapper throws on a partial or unparseable rollback (never proceeds).
    try {
      await recoverInterruptedExitImportsOrThrow(storage, auditLog);
    } catch (error) {
      print(
        `Refused: interrupted exit-import recovery did not complete; nothing was changed. ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return CONFIG_RESET_EXIT.REFUSED;
    }
    const store = new IntelligenceConfigStore(
      storage,
      masterKey,
      deps.modelManifestV2PublicKey === undefined
        ? {}
        : { modelManifestV2PublicKey: deps.modelManifestV2PublicKey },
    );
    const outcome = await store.load();
    print(`Fortress: ${storagePath}`);
    print(`Local-intelligence config record: ${describeOutcome(outcome)}`);
    if (outcome.kind === "default") {
      print("Nothing to reset.");
      return CONFIG_RESET_EXIT.OK;
    }
    if (outcome.kind === "loaded") {
      print(
        "Refused: config-reset only quarantines an unreadable record; a readable record is never discarded here.",
      );
      return CONFIG_RESET_EXIT.REFUSED;
    }
    if (outcome.kind === "integrity-state-invalid") {
      print(
        "Refused: an armed record that fails Q5 integrity validation is not an unreadable record, and there is no in-product disarm.",
      );
      return CONFIG_RESET_EXIT.REFUSED;
    }

    const intelligenceDir = storage.namespacePath("_intelligence");
    print("");
    print("Plan (no changes have been made):");
    print(`- Copy the record's raw bytes to a timestamped sidecar file in ${intelligenceDir}`);
    print("- Remove the unreadable record; the next load returns the default legacy-unarmed configuration.");
    print("- If this fortress was Q5-armed on that record it is unarmed afterward; load-integrity verification does not apply until you re-provision.");
    print("- Operator substrate choices and API keys inside the unreadable record are NOT recovered.");
    print("");
    const ask = deps.ask ?? defaultAsk;
    const answer = (await ask(
      `Type "${CONFIG_RESET_CONFIRMATION_WORD}" to continue, anything else to abort: `,
    )).trim();
    if (answer !== CONFIG_RESET_CONFIRMATION_WORD) {
      print("Aborted; nothing was changed.");
      return CONFIG_RESET_EXIT.REFUSED;
    }

    // Consent gates satisfied above (TTY, typed word, write-intent unlock);
    // this is the ONE production call site the structure test pins.
    const result = await store.quarantineUnreadable(
      deps.now === undefined ? {} : { now: deps.now },
    );
    if (result.kind === "absent") {
      // Another process removed it between the plan and the lock; honest no-op.
      print("The record was no longer present; nothing to reset.");
      return CONFIG_RESET_EXIT.OK;
    }
    if (result.kind === "refused") {
      print(`Refused: ${result.detail}; nothing was changed.`);
      return CONFIG_RESET_EXIT.REFUSED;
    }

    print(`Quarantined ${result.bytes} bytes to ${result.quarantinePath}`);
    print("The record was removed; the next load returns the default legacy-unarmed configuration.");
    print("If this fortress was Q5-armed on that record it is now unarmed; re-provision local intelligence before relying on load-integrity verification.");
    try {
      await auditLog.append(
        "l2",
        INTEL_OPS.CONFIG_QUARANTINED,
        `fortress:${fortressIdFromStoragePath(storagePath)}`,
        {
          persisted: result.persisted,
          persisted_version: result.persistedVersion,
          quarantine_file: result.quarantineFile,
          bytes: result.bytes,
        },
        "success",
      );
    } catch (error) {
      // The mutation is already durable; say so rather than imply a rollback.
      print(
        `Warning: the quarantine completed but its audit record could not be written: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return CONFIG_RESET_EXIT.REFUSED;
    }
    return CONFIG_RESET_EXIT.OK;
  } finally {
    masterKey.fill(0);
    await barrier?.release().catch(() => undefined);
  }
}

async function defaultAsk(prompt: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return await rl.question(prompt);
  } finally {
    rl.close();
  }
}
