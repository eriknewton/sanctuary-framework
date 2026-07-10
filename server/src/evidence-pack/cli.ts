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
import { Writable } from "node:stream";
import { createSanctuaryServer } from "../index.js";
import type { SanctuaryConfig } from "../config.js";
import type { StoredIdentity } from "../core/identity.js";
import type { AuditEntry } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import { FilesystemStorage } from "../storage/filesystem.js";
import { StateStore } from "../cognitive/state-store.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { ObserveStore } from "../castle-wall/observe/index.js";
import { readPersistedLocalAgents } from "../hub/agent-registry-persistence.js";
import { SovereigntyProfileStore } from "../sovereignty-profile.js";
import { readPersistedCheckpoints } from "../transparency/emitter.js";
import {
  TRANSPARENCY_BUNDLE_FORMAT,
  type TransparencyBundle,
} from "../transparency/checkpoint.js";
import { exportAuditChain } from "../cli/audit-chain-export.js";
import type {
  CustodyFacts,
  EvidencePackDiscreteExports,
  EvidencePackInput,
  InventorySnapshot,
  RetentionFacts,
} from "./types.js";
import { buildInventorySnapshot, type ProxyServerView } from "./inventory.js";
import {
  buildEvidencePack,
  MANIFEST_FILENAME,
  PDF_FILENAME,
  PRODUCT_NAME,
  REPORT_FILENAME,
} from "./generate.js";
import { currentQuarter, parseQuarterLabel, quarterLabel } from "./quarter.js";

/**
 * Enumerate the AI-tool inventory from the fortress's persisted state,
 * READ-ONLY and with NO live upstream connections or network: wrapped-harness
 * records from the plaintext hub registry file, configured MCP tool servers
 * from the sovereignty profile, and observed egress destinations from the
 * encrypted observe store. Each source is best-effort: a read failure yields an
 * empty source, and the section renderer then prints its honest coverage-basis
 * note and placeholder. Never establishes a live connection during pack
 * generation.
 */
async function gatherInventory(
  config: SanctuaryConfig,
  storage: StorageBackend,
  masterKey: Uint8Array,
  signer: StoredIdentity
): Promise<InventorySnapshot> {
  const agentRecords = (() => {
    try {
      return readPersistedLocalAgents(config.storage_path);
    } catch {
      return [];
    }
  })();

  const proxyServers: ProxyServerView[] = await (async () => {
    try {
      const profileStore = new SovereigntyProfileStore(storage, masterKey);
      await profileStore.load();
      return (profileStore.get().upstream_servers ?? []).map((u) => ({
        name: u.name,
        transport: u.transport.type,
        enabled: u.enabled,
      }));
    } catch {
      return [];
    }
  })();

  const observedDestinations = await (async () => {
    try {
      const stateStore = new StateStore(storage, masterKey);
      const observeStore = new ObserveStore(stateStore, {
        identityId: signer.identity_id,
        encryptedPrivateKey: signer.encrypted_private_key,
        identityEncryptionKey: derivePurposeKey(masterKey, "identity-encryption"),
      });
      return [...(await observeStore.listCandidates()).values()];
    } catch {
      return [];
    }
  })();

  return buildInventorySnapshot({
    agentRecords,
    proxyServers,
    observedDestinations,
  });
}

/**
 * Gather the discrete third-party verification exports from persisted state,
 * offline: the signed transparency-checkpoint bundle (assembled from the
 * shipped `readPersistedCheckpoints`; requires a single signing key across the
 * checkpoints), and the audit-chain JSONL export (from the shipped
 * `exportAuditChain`). Public-anchor evidence is opt-in / default-off and is
 * reported absent unless a later slice wires it. Each absent export carries an
 * honest reason string. Never contacts the network.
 */
async function gatherDiscreteExports(
  storage: StorageBackend,
  generatedAt: string
): Promise<EvidencePackDiscreteExports> {
  const out: EvidencePackDiscreteExports = {};

  try {
    const checkpoints = await readPersistedCheckpoints(storage);
    if (checkpoints.length === 0) {
      out.transparency_absent_reason =
        "no signed transparency checkpoints have been emitted on this fortress yet.";
    } else {
      const keys = new Set(checkpoints.map((c) => c.public_key));
      if (keys.size !== 1) {
        out.transparency_absent_reason =
          "the checkpoints carry more than one signing key; a single-key bundle could not be assembled. Investigate the key history before publishing.";
      } else {
        const bundle: TransparencyBundle = {
          format: TRANSPARENCY_BUNDLE_FORMAT,
          exported_at: generatedAt,
          public_key: [...keys][0]!,
          checkpoints,
        };
        out.transparency_bundle_json = JSON.stringify(bundle, null, 2);
      }
    }
  } catch (e) {
    out.transparency_absent_reason = `the transparency bundle could not be gathered: ${(e as Error).message}`;
  }

  try {
    const chunks: Buffer[] = [];
    const sink = new Writable({
      write(chunk, _enc, cb) {
        chunks.push(Buffer.from(chunk));
        cb();
      },
    });
    await exportAuditChain(storage, sink);
    out.audit_chain_jsonl = Buffer.concat(chunks).toString("utf8");
  } catch (e) {
    out.audit_chain_absent_reason = `the audit-chain export could not be gathered: ${(e as Error).message}`;
  }

  out.anchor_absent_reason =
    "public transparency anchoring (Sigstore/Rekor) is opt-in and is not enabled on this install.";

  return out;
}

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
  const { config, identityManager, masterKey, auditLog } =
    await createSanctuaryServer({
      passphrase: opts.passphrase ?? process.env.SANCTUARY_PASSPHRASE,
    });

  const signer = identityManager.getDefault();
  if (!signer) {
    throw new Error(
      "No primary identity configured. Run identity_create and " +
        "identity_set_primary before generating an evidence pack."
    );
  }

  // Read-only storage handle onto the same fortress state dir, for the
  // inventory + discrete-export enumeration (no live connections, no network).
  const storage: StorageBackend = new FilesystemStorage(
    `${config.storage_path}/state`
  );

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

  // Slice 2: enumerate the real AI-tool inventory and gather the discrete
  // third-party verification exports, both READ-ONLY from persisted state.
  const generatedAt = new Date().toISOString();
  const inventory = await gatherInventory(config, storage, masterKey, signer);
  const discreteExports = await gatherDiscreteExports(storage, generatedAt);

  const input: EvidencePackInput = {
    firm_name: opts.firmName,
    quarter,
    generated_at_override: generatedAt,
    custody,
    inventory,
    discrete_exports: discreteExports,
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
  const summaryLines = [
    "",
    `[sanctuary evidence-pack] ${PRODUCT_NAME} generation complete.`,
    "",
  ];
  if (pack.shortfall.in_progress_quarter) {
    summaryLines.push(
      `  WARNING: ${label} is still IN PROGRESS. This pack covers only through`,
      `  ${pack.shortfall.covered_to_exclusive} (the generation time), NOT the full`,
      "  quarter. Do not present it to an insurer or client as a complete-quarter",
      "  report; regenerate after the quarter closes. The report is stamped PARTIAL.",
      ""
    );
  }
  summaryLines.push(
    `  Output directory: ${outputDir}`,
    `  Firm:             ${opts.firmName}`,
    `  Quarter:          ${label}${pack.shortfall.in_progress_quarter ? " (PARTIAL - in progress)" : ""}`,
    `  Covered window:   ${pack.shortfall.covered_from} to ${pack.shortfall.covered_to_exclusive} (exclusive)`,
    `  Covered-window shortfall: ${shortfallLine}`,
    `  Control-point decisions in quarter: ${pack.aggregation.total_in_window}`,
    `  Signer:           ${pack.manifest.signer.did}`,
    "",
    "  NOT LEGAL ADVICE. Have the policy/attestation content reviewed by a",
    "  licensed attorney before first use.",
    ""
  );
  // SAFETY: stderr is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.error(summaryLines.join("\n"));

  // Stdout: just the output directory path (for scripting).
  // SAFETY: stdout is the operator-facing CLI channel for this subcommand; no logger module is in scope yet.
  console.log(outputDir);
}
