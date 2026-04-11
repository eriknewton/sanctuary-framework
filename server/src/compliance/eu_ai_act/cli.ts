/**
 * Sanctuary MCP Server — EU AI Act Compliance CLI Subcommand
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Usage:
 *   sanctuary-mcp-server compliance eu-ai-act <agent-did> [flags]
 *
 * Flags:
 *   --output <dir>             Output directory (default: ./eu-ai-act-bundle-<ts>)
 *   --period-start <iso>       Reporting period start (default: 30 days ago)
 *   --period-end <iso>         Reporting period end (default: now)
 *   --provider-name <name>     Legal provider name (enterprise legal entity)
 *   --provider-contact <email> Provider contact email
 *   --annex-iii-class <label>  Annex III risk classification label
 *   --intended-purpose <text>  One-sentence description of the agent
 *   --vertical <name>          Vertical industry (finance, healthcare, hr, ...)
 *   --passphrase <pass>        Master key passphrase (or SANCTUARY_PASSPHRASE env)
 *   --help                     Print this help text
 *
 * The CLI spins up a Sanctuary server instance, generates the bundle
 * using the primary identity as signer, writes all 7 files to the
 * output directory, and prints a summary with the manual-input
 * marker count for enterprise completion tracking.
 *
 * NOT LEGAL ADVICE. The generated bundle is a technical artifact;
 * consult qualified legal counsel before regulatory submission.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createSanctuaryServer } from "../../index.js";
import { generateEuAiActBundle } from "./generator.js";
import { countManualInputMarkers } from "./templates/render.js";
import type {
  ComplianceBundleInput,
  DeploymentContext,
  AnnexIIIRiskClass,
} from "./types.js";

// ── Arg parsing ──────────────────────────────────────────────────────

interface ComplianceCliOptions {
  subcommand: "eu-ai-act" | "help";
  agentDid: string;
  output?: string;
  periodStart?: string;
  periodEnd?: string;
  deploymentContext: DeploymentContext;
  passphrase?: string;
  deltaFrom?: string;
  publishToVerascore?: boolean;
  verascoreUrl?: string;
}

function parseArgs(args: string[]): ComplianceCliOptions {
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    return {
      subcommand: "help",
      agentDid: "",
      deploymentContext: {},
    };
  }

  if (args[0] !== "eu-ai-act") {
    throw new Error(
      `Unknown compliance subcommand: "${args[0]}". Only "eu-ai-act" is supported in v1.`
    );
  }

  const rest = args.slice(1);
  if (rest.length === 0 || rest[0]!.startsWith("--")) {
    throw new Error(
      "Missing required <agent-did> positional argument. " +
        "Usage: sanctuary-mcp-server compliance eu-ai-act <agent-did> [flags]"
    );
  }

  const agentDid = rest[0]!;
  const flags = rest.slice(1);

  const opts: ComplianceCliOptions = {
    subcommand: "eu-ai-act",
    agentDid,
    deploymentContext: {},
  };

  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    const next = flags[i + 1];
    switch (flag) {
      case "--output":
        opts.output = next;
        i++;
        break;
      case "--period-start":
        opts.periodStart = next;
        i++;
        break;
      case "--period-end":
        opts.periodEnd = next;
        i++;
        break;
      case "--provider-name":
        opts.deploymentContext.provider_legal_name = next;
        i++;
        break;
      case "--provider-contact":
        opts.deploymentContext.provider_contact = next;
        i++;
        break;
      case "--annex-iii-class":
        opts.deploymentContext.annex_iii_class = next as AnnexIIIRiskClass;
        i++;
        break;
      case "--intended-purpose":
        opts.deploymentContext.intended_purpose = next;
        i++;
        break;
      case "--vertical":
        opts.deploymentContext.vertical = next;
        i++;
        break;
      case "--passphrase":
        opts.passphrase = next;
        i++;
        break;
      case "--delta-from":
        opts.deltaFrom = next;
        i++;
        break;
      case "--publish-to-verascore":
        opts.publishToVerascore = true;
        // no argument — this is a boolean flag
        break;
      case "--verascore-url":
        opts.verascoreUrl = next;
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
Sanctuary — EU AI Act Compliance Bundle Generator

USAGE
  sanctuary-mcp-server compliance eu-ai-act <agent-did> [flags]

POSITIONAL
  <agent-did>              DID of the agent the bundle is for

FLAGS
  --output <dir>           Output directory (default: ./eu-ai-act-bundle-<ts>)
  --period-start <iso>     Reporting period start (default: 30 days ago)
  --period-end <iso>       Reporting period end (default: now)
  --provider-name <name>   Legal provider name (enterprise legal entity)
  --provider-contact <em>  Provider contact email
  --annex-iii-class <lbl>  Annex III risk classification label
  --intended-purpose <s>   One-sentence description of the agent
  --vertical <name>        Vertical industry (finance, healthcare, hr, ...)
  --passphrase <pass>      Master key passphrase (or SANCTUARY_PASSPHRASE env)
  --delta-from <path>      Prior bundle directory to diff against; adds
                           08_delta.md to the output
  --publish-to-verascore   POST the signed manifest (not the document
                           bodies) to Verascore as a post-generation
                           side effect. Publish failure never fails the
                           local bundle generation.
  --verascore-url <url>    Override the Verascore base URL (HTTPS, must
                           point to an allow-listed Verascore host).
                           Defaults to https://verascore.ai.
  --help                   Print this help text

OUTPUT
  The bundle is written to the output directory as 7 files:

    00_bundle_manifest.json              — signed index
    01_annex_iv_technical_documentation.md
    02_article_26_deployer_log.md
    03_article_12_automatic_logs.md
    04_risk_management_summary.md
    05_human_oversight_statement.md
    06_cryptographic_attestations.md

  Every file is SHA-256 hashed and Ed25519-signed with the provider's
  primary identity. The manifest carries the full coverage matrix
  and per-row evidence attribution.

NOT LEGAL ADVICE
  This tool produces a technical compliance artifact. It is not
  legal advice and does not constitute a legal interpretation of
  Regulation (EU) 2024/1689. Consult qualified legal counsel before
  filing or relying on the bundle for regulatory submission.
`.trim();
  console.log(help);
}

// ── Defaults ─────────────────────────────────────────────────────────

function defaultPeriod(): { start: string; end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

function defaultOutputDir(): string {
  const ts = new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .replace(/Z$/, "");
  return `./eu-ai-act-bundle-${ts}`;
}

// ── Main entry point ─────────────────────────────────────────────────

/**
 * Run the compliance CLI subcommand. Called from the main CLI
 * dispatcher in `src/cli.ts` when `args[0] === "compliance"`.
 */
export async function runCompliance(args: string[]): Promise<void> {
  let opts: ComplianceCliOptions;
  try {
    opts = parseArgs(args);
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    console.error("");
    printHelp();
    process.exit(2);
  }

  if (opts.subcommand === "help") {
    printHelp();
    process.exit(0);
  }

  const period = defaultPeriod();
  const periodStart = opts.periodStart ?? period.start;
  const periodEnd = opts.periodEnd ?? period.end;
  const outputDir = opts.output ?? defaultOutputDir();

  console.error(
    "[sanctuary compliance] Starting Sanctuary server instance..."
  );
  const { config, identityManager, masterKey, auditLog, policy } =
    await createSanctuaryServer({
      passphrase: opts.passphrase ?? process.env.SANCTUARY_PASSPHRASE,
    });

  console.error(
    `[sanctuary compliance] Generating EU AI Act bundle for ${opts.agentDid}...`
  );

  const input: ComplianceBundleInput = {
    agent_did: opts.agentDid,
    deployment_context: opts.deploymentContext,
    period_start: periodStart,
    period_end: periodEnd,
    delta_from_bundle_path: opts.deltaFrom,
    publish_to_verascore: opts.publishToVerascore,
    verascore_url: opts.verascoreUrl,
  };

  const bundle = await generateEuAiActBundle(input, {
    config,
    identityManager,
    masterKey,
    auditLog,
    policy,
  });

  // Write the bundle to disk.
  await mkdir(outputDir, { recursive: true });

  const manifestPath = join(outputDir, "00_bundle_manifest.json");
  await writeFile(
    manifestPath,
    JSON.stringify(bundle.manifest, null, 2),
    "utf-8"
  );

  let totalManualMarkers = 0;
  for (const file of bundle.files) {
    const path = join(outputDir, file.filename);
    await writeFile(path, file.content, "utf-8");
    totalManualMarkers += countManualInputMarkers(file.content);
  }

  // Print summary to stderr so downstream pipelines can capture the
  // output directory path from stdout if desired.
  console.error("");
  console.error(
    "[sanctuary compliance] Bundle generation complete."
  );
  console.error("");
  console.error(`  Output directory: ${outputDir}`);
  console.error(`  Bundle version:   ${bundle.manifest.bundle_version}`);
  console.error(
    `  Matrix version:   ${bundle.manifest.matrix_version}`
  );
  console.error(
    `  Regulation:       ${bundle.manifest.regulation_version}`
  );
  console.error(
    `  Agent DID:        ${bundle.manifest.agent_did}`
  );
  console.error(
    `  Reporting period: ${bundle.manifest.period_start} → ${bundle.manifest.period_end}`
  );
  console.error(
    `  Signer DID:       ${bundle.manifest.signer.did}`
  );
  console.error(
    `  Files generated:  ${bundle.files.length + 1} (6 Markdown + 1 manifest)`
  );
  console.error("");
  console.error("  Coverage summary:");
  console.error(
    `    full:        ${bundle.manifest.coverage_summary.full} rows (${bundle.manifest.coverage_summary.full_pct}%)`
  );
  console.error(
    `    partial:     ${bundle.manifest.coverage_summary.partial} rows (${bundle.manifest.coverage_summary.partial_pct}%)`
  );
  console.error(
    `    manual_only: ${bundle.manifest.coverage_summary.manual_only} rows (${bundle.manifest.coverage_summary.manual_only_pct}%)`
  );
  console.error("");
  console.error(
    `  Unfilled [MANUAL INPUT REQUIRED] markers: ${totalManualMarkers}`
  );
  console.error(
    "  Review each marker and replace with the relevant enterprise fact."
  );
  console.error("");
  if (bundle.publish_result) {
    console.error("");
    console.error("  Verascore publish:");
    if (bundle.publish_result.published) {
      console.error(
        `    ✓ published to ${bundle.publish_result.verascore_url} as ${bundle.publish_result.verascore_agent_id}`
      );
    } else {
      console.error(`    ✗ publish failed: ${bundle.publish_result.error}`);
      console.error(
        `    (bundle has been written to disk regardless — this is a pure side effect)`
      );
    }
  }

  console.error("");
  console.error(
    "  NOT LEGAL ADVICE. Consult qualified legal counsel before filing."
  );
  console.error("");

  // Stdout: just the output directory path (for scripting).
  console.log(outputDir);
}
