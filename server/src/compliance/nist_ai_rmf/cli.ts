/**
 * Sanctuary MCP Server, NIST AI RMF Crosswalk CLI Subcommand
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Usage:
 *   sanctuary-mcp-server compliance nist-ai-rmf [flags]
 *
 * Flags:
 *   --output <path>   Write the crosswalk Markdown to this file path.
 *                     If omitted, the crosswalk is printed to stdout.
 *   --help            Print this help text.
 *
 * The crosswalk is a static, pre-reviewed data structure rendered to
 * Markdown. Unlike the EU AI Act bundle generator, it does NOT spin up
 * a Sanctuary server instance, read identities, or touch the operator's
 * keychain, it is a pure data -> document transform.
 *
 * NOT LEGAL ADVICE and NOT a NIST conformity assessment. The crosswalk
 * is a tooling-coverage map: it states which NIST AI RMF subcategories
 * a shipped Sanctuary mechanism bears on.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { NIST_CROSSWALK_V1, coverageStats } from "./crosswalk.js";
import { renderNistCrosswalk } from "./generator.js";

interface NistCliOptions {
  help: boolean;
  output?: string;
}

function parseArgs(args: string[]): NistCliOptions {
  const opts: NistCliOptions = { help: false };
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    const next = args[i + 1];
    switch (flag) {
      case "--help":
      case "-h":
        opts.help = true;
        break;
      case "--output":
        opts.output = next;
        i++;
        break;
      default:
        throw new Error(`Unknown flag: "${flag}"`);
    }
  }
  return opts;
}

function printHelp(): void {
  const help = `
Sanctuary, NIST AI RMF 1.0 Crosswalk

USAGE
  sanctuary-mcp-server compliance nist-ai-rmf [flags]

FLAGS
  --output <path>   Write the crosswalk Markdown to this file path.
                    If omitted, prints to stdout.
  --help            Print this help text.

OUTPUT
  A single Markdown document: a preamble (tooling-coverage-map
  disclaimer), a coverage summary, and one table per AI RMF function
  (GOVERN, MAP, MEASURE, MANAGE). Every "Sanctuary control" cell names
  the MCP tool(s) whose output is the evidence; these are the same tool
  names used by the EU AI Act coverage matrix (one shared control
  catalog), so the EU AI Act <-> NIST AI RMF overlap is visible.

NOT LEGAL ADVICE
  This crosswalk is a tooling-coverage map, not a NIST conformity
  assessment. It marks "covered" only where a shipped Sanctuary
  mechanism backs the subcategory; organizational subcategories are
  marked not-applicable.
`.trim();
  // SAFETY: stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(help);
}

/**
 * Run the `compliance nist-ai-rmf` subcommand. Called from
 * runCompliance() when the first compliance arg is "nist-ai-rmf".
 */
export async function runNistAiRmf(args: string[]): Promise<void> {
  let opts: NistCliOptions;
  try {
    opts = parseArgs(args);
  } catch (e) {
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(`Error: ${(e as Error).message}`);
    console.error("");
    printHelp();
    process.exit(2);
  }

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  const markdown = renderNistCrosswalk(NIST_CROSSWALK_V1);

  if (opts.output) {
    await mkdir(dirname(opts.output), { recursive: true });
    await writeFile(opts.output, markdown, "utf-8");
    const s = coverageStats(NIST_CROSSWALK_V1);
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `[sanctuary compliance] NIST AI RMF crosswalk written to ${opts.output}`
    );
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      `  covered: ${s.covered}  partial: ${s.partial}  ` +
        `not-applicable: ${s.not_applicable}  gap: ${s.gap}  ` +
        `(total ${s.total})`
    );
    // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.error(
      "  Tooling-coverage map, NOT a certification. NOT LEGAL ADVICE."
    );
  } else {
    // SAFETY: stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
    console.log(markdown);
  }
}
