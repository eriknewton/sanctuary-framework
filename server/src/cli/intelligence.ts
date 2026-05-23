/**
 * Sanctuary MCP Server -- `sanctuary intelligence` CLI subcommand
 *
 * v1.2.1 (Finding III): minimal `sanctuary intelligence diagnose` that prints
 * the substrate config and last error from the audit log. Helps operators
 * debug why the intelligence layer failed at boot.
 */

import { resolve } from "node:path";
import { existsSync, readdirSync } from "node:fs";

interface IntelligenceCommandOpts {
  argv: string[];
}

function flagValue(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
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
  diagnose    Print intelligence substrate config and last error.
  --help      Show this help.
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

async function runDiagnose(argv: string[] = []): Promise<number> {
  const fortressFlag = flagValue(argv, "--fortress") ?? flagValue(argv, "--fortress-path");
  const storagePath = resolve(
    fortressFlag ??
      process.env.SANCTUARY_STORAGE_PATH ??
      process.env.SANCTUARY_FORTRESS_PATH ??
      `${process.env.HOME}/.sanctuary`,
  );

  // SAFETY: stderr / stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(`Intelligence substrate diagnostics`);
  console.error(`Fortress: ${storagePath}`);
  console.error("");

  // Check for intelligence config in the state directory
  const intelligenceDir = resolve(storagePath, "state", "_intelligence");
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
  const auditDir = resolve(storagePath, "state", "_audit");
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

  return 0;
}
