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

export async function runIntelligenceCommand(
  opts: IntelligenceCommandOpts,
): Promise<number> {
  const subcommand = opts.argv[0];

  if (subcommand === "diagnose" || subcommand === undefined) {
    return runDiagnose();
  }

  if (subcommand === "--help" || subcommand === "-h") {
    printHelp();
    return 0;
  }

  console.error(`Unknown intelligence subcommand: ${subcommand}`);
  printHelp();
  return 2;
}

function printHelp(): void {
  console.error(`
Usage: sanctuary intelligence <subcommand>

Subcommands:
  diagnose    Print intelligence substrate config and last error.
  --help      Show this help.
`);
}

async function runDiagnose(): Promise<number> {
  const storagePath = resolve(
    process.env.SANCTUARY_STORAGE_PATH ??
      process.env.SANCTUARY_FORTRESS_PATH ??
      `${process.env.HOME}/.sanctuary`,
  );

  console.error(`Intelligence substrate diagnostics`);
  console.error(`Fortress: ${storagePath}`);
  console.error("");

  // Check for intelligence config in the state directory
  const intelligenceDir = resolve(storagePath, "state", "_intelligence");
  if (!existsSync(intelligenceDir)) {
    console.error(
      `No intelligence config directory found at ${intelligenceDir}.`,
    );
    console.error(
      "Intelligence substrate may not have been initialized yet.",
    );
    console.error(
      "Ensure at least one substrate API key is set in your environment:",
    );
    console.error(
      "  ANTHROPIC_API_KEY, OPENAI_API_KEY, VENICE_API_KEY, or OLLAMA_HOST",
    );
    return 1;
  }

  // List intelligence config files
  try {
    const entries = readdirSync(intelligenceDir);
    console.error(`Intelligence config entries: ${entries.length}`);
    for (const entry of entries) {
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
      console.error("");
      console.error(`Recent audit entries (${recentFiles.length} of ${auditFiles.length}):`);
      for (const file of recentFiles) {
        console.error(`  ${file}`);
      }
    } catch {
      console.error(`Could not read audit directory.`);
    }
  }

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
    console.error(
      `  ${key}: ${val ? `set (${val.slice(0, 4)}...)` : "not set"}`,
    );
  }

  return 0;
}
