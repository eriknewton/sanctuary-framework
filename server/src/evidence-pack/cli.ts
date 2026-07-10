/**
 * Sanctuary MCP Server - Law-firm Evidence Pack CLI
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Usage:
 *   sanctuary evidence-pack generate --quarter 2026-Q3 --firm "Acme Law"
 *
 * Spins up a Sanctuary server instance, pulls the retained audit history,
 * aggregates the requested calendar quarter, and writes a signed evidence
 * pack (a human-readable PDF + a signed Markdown report + a signed manifest)
 * to the output directory.
 *
 * NOT LEGAL ADVICE. The generated pack is a technical artifact.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createSanctuaryServer } from "../index.js";
import type { AuditEntry } from "../operational/audit-log.js";
import type {
  CustodyFacts,
  EvidencePackInput,
  RetentionFacts,
} from "./types.js";
import {
  buildEvidencePack,
  MANIFEST_FILENAME,
  PDF_FILENAME,
  PRODUCT_NAME,
  REPORT_FILENAME,
} from "./generate.js";
import { currentQuarter, parseQuarterLabel, quarterLabel } from "./quarter.js";

interface EvidencePackCliOptions {
  subcommand: "generate" | "help";
  firmName: string;
  quarterLabel?: string;
  output?: string;
  passphrase?: string;
}

function parseArgs(args: string[]): EvidencePackCliOptions {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return { subcommand: "help", firmName: "" };
  }
  if (args[0] !== "generate") {
    throw new Error(
      `Unknown evidence-pack subcommand: "${args[0]}". Supported: "generate".`
    );
  }

  const opts: EvidencePackCliOptions = { subcommand: "generate", firmName: "" };
  const flags = args.slice(1);
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    const next = flags[i + 1];
    switch (flag) {
      case "--quarter":
        opts.quarterLabel = next;
        i++;
        break;
      case "--firm":
        opts.firmName = next ?? "";
        i++;
        break;
      case "--output":
        opts.output = next;
        i++;
        break;
      case "--passphrase":
        opts.passphrase = next;
        i++;
        break;
      default:
        throw new Error(`Unknown flag: "${flag}"`);
    }
  }

  if (opts.firmName.trim().length === 0) {
    throw new Error(
      'Missing required --firm "<name>". ' +
        'Usage: sanctuary evidence-pack generate --quarter 2026-Q3 --firm "Acme Law"'
    );
  }
  return opts;
}

function printHelp(): void {
  const help = `
Sanctuary - Law-firm Evidence Pack (walking skeleton, slice 1)

USAGE
  sanctuary evidence-pack generate --firm "<name>" [flags]

FLAGS
  --firm <name>       Firm name printed on the cover (required)
  --quarter <YYYY-Qn> Reporting quarter, e.g. 2026-Q3 (default: current quarter)
  --output <dir>      Output directory (default: ./evidence-pack-<quarter>-<ts>)
  --passphrase <pass> Master key passphrase (or SANCTUARY_PASSPHRASE env)
  --help              Print this help text

OUTPUT
  ${MANIFEST_FILENAME}  - signed manifest (per-file SHA-256 + Ed25519)
  ${REPORT_FILENAME}    - signed human-readable Markdown report
  ${PDF_FILENAME}       - rendered PDF (a copy of the report; NOT signed)

  The Markdown report is SHA-256 hashed and Ed25519-signed with the fortress
  primary identity; the manifest signs over those hashes. The PDF is a
  human-readable render and is intentionally not signed - verify integrity
  against the Markdown report and the manifest.

NOT LEGAL ADVICE
  This tool produces a technical evidence artifact. It is not legal advice.
`.trim();
  // SAFETY: stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(help);
}

function defaultOutputDir(label: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, "-").replace(/Z$/, "");
  return `./evidence-pack-${label}-${ts}`;
}

/**
 * Run the evidence-pack CLI subcommand. Called from the main CLI dispatcher
 * in `src/cli.ts` when `args[0] === "evidence-pack"`.
 */
export async function runEvidencePack(args: string[]): Promise<void> {
  let opts: EvidencePackCliOptions;
  try {
    opts = parseArgs(args);
  } catch (e) {
    // SAFETY: stderr is the operator-facing CLI error channel for this subcommand; no logger module is in scope yet.
    console.error(`Error: ${(e as Error).message}\n`);
    printHelp();
    process.exit(2);
  }

  if (opts.subcommand === "help") {
    printHelp();
    process.exit(0);
  }

  const quarter = opts.quarterLabel
    ? parseQuarterLabel(opts.quarterLabel)
    : currentQuarter();
  const label = quarterLabel(quarter);
  const outputDir = opts.output ?? defaultOutputDir(label);

  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error("[sanctuary evidence-pack] Starting Sanctuary server instance...");
  const { identityManager, masterKey, auditLog } = await createSanctuaryServer({
    passphrase: opts.passphrase ?? process.env.SANCTUARY_PASSPHRASE,
  });

  const signer = identityManager.getDefault();
  if (!signer) {
    throw new Error(
      "No primary identity configured. Run identity_create and " +
        "identity_set_primary before generating an evidence pack."
    );
  }

  // Pull the full retained audit history (oldest first). The aggregation layer
  // filters to the quarter window; the earliest retained entry drives the
  // covered-window shortfall disclosure.
  const { entries, total } = await auditLog.query({ limit: 1_000_000 });
  const retentionConfig = auditLog.getRetentionConfig();
  const earliest: string | null =
    entries.length > 0 ? (entries[0] as AuditEntry).timestamp : null;
  const retention: RetentionFacts = {
    max_entries: retentionConfig.maxEntries,
    retained_total: total,
    earliest_retained_at: earliest,
  };

  // Custody facts: no-outbound-by-default is true by architecture. The precise
  // master-key custody mode is not yet surfaced by the server API, so slice 1
  // reports it as unknown rather than guessing.
  const custody: CustodyFacts = {
    custody_mode: "unknown",
    no_outbound_by_default: true,
  };

  const input: EvidencePackInput = {
    firm_name: opts.firmName,
    quarter,
    custody,
  };

  const pack = buildEvidencePack(input, {
    entries,
    retention,
    signer,
    masterKey,
  });

  await mkdir(outputDir, { recursive: true });
  await writeFile(
    join(outputDir, MANIFEST_FILENAME),
    JSON.stringify(pack.manifest, null, 2),
    "utf-8"
  );
  for (const file of pack.files) {
    await writeFile(join(outputDir, file.filename), file.content, "utf-8");
  }
  await writeFile(join(outputDir, PDF_FILENAME), pack.pdf);

  const shortfallLine = pack.shortfall.shortfall
    ? "YES - disclosed in the report"
    : "no";
  const summary = [
    "",
    `[sanctuary evidence-pack] ${PRODUCT_NAME} generation complete.`,
    "",
    `  Output directory: ${outputDir}`,
    `  Firm:             ${opts.firmName}`,
    `  Quarter:          ${label}`,
    `  Covered window:   ${pack.shortfall.covered_from} to ${pack.shortfall.covered_to_exclusive}`,
    `  Covered-window shortfall: ${shortfallLine}`,
    `  Control-point decisions in quarter: ${pack.aggregation.total_in_window}`,
    `  Signer:           ${pack.manifest.signer.did}`,
    "",
    "  NOT LEGAL ADVICE. Have the policy/attestation content reviewed by a",
    "  licensed attorney before first use.",
    "",
  ].join("\n");
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(summary);

  // Stdout: just the output directory path (for scripting).
  // SAFETY: stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(outputDir);
}
