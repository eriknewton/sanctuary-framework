/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: generator
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Assembles the quarterly evidence pack from already-resolved inputs, each of
 * which arrives as a typed {@link ReadOutcome} so a failed or absent read can
 * never render as a definitive claim (see `read-outcome.ts`). This function is
 * pure over its deps (no I/O, no server boot), so tests drive the real
 * aggregation, shortfall, rendering, PDF, and signing paths with synthetic
 * fixtures and never touch a real fortress. The CLI (`cli.ts`) resolves the
 * deps from a running server and writes the result to disk.
 */

import type { AuditEntry } from "../operational/audit-log.js";
import type { StoredIdentity } from "../core/identity.js";
import { renderMarkdownDocumentsToPdf } from "../compliance/eu_ai_act/pdf.js";
import type {
  CustodyFacts,
  EvidencePack,
  EvidencePackFile,
  EvidencePackInput,
  EvidencePackManifest,
  QuarterAggregation,
  RetentionFacts,
  ShortfallReport,
} from "./types.js";
import {
  emptyVerified,
  foldOutcome,
  populated,
  readFailed,
  type ReadOutcome,
} from "./read-outcome.js";
import { isInWindow, quarterWindow } from "./quarter.js";
import { aggregateQuarter, detectShortfall } from "./aggregate.js";
import { renderSections } from "./sections.js";
import { buildPackManifest, makePackSigner, signFile } from "./signer.js";

/** Working product name shown on the cover and in the manifest. */
export const PRODUCT_NAME = "Sanctuary Evidence Pack";

/** Basename of the single human-readable Markdown report. */
export const REPORT_FILENAME = "01_evidence_pack.md";
/** Basename of the signed manifest. */
export const MANIFEST_FILENAME = "00_pack_manifest.json";
/** Basename of the rendered PDF. */
export const PDF_FILENAME = "evidence-pack.pdf";
/** Basename of the gathered transparency-checkpoint bundle (slice 2). */
export const TRANSPARENCY_BUNDLE_FILENAME = "transparency-bundle.json";
/** Basename of the gathered audit-chain JSONL export (slice 2). */
export const AUDIT_CHAIN_FILENAME = "audit-chain.jsonl";
/** Basename of the gathered public-anchor evidence (slice 2). */
export const ANCHOR_EVIDENCE_FILENAME = "anchor-evidence.json";

/** The result of reading the audit log for the pack (one read: entries + retention). */
export interface AuditReadData {
  entries: readonly AuditEntry[];
  retention: RetentionFacts;
  /**
   * G-2: when the F2 daemon store was merged (`included`), the daemon entries on
   * their own (a subset of `entries`), so the generator -- which owns the quarter
   * window -- can count how many fall INSIDE the window and render that windowed
   * figure in the §7 daemon note instead of the all-time total. Absent for a
   * non-split / unreadable / absent daemon store.
   */
  daemon_entries?: readonly AuditEntry[];
}

/** Already-resolved inputs the generator needs (see module doc-comment). */
export interface BuildEvidencePackDeps {
  /**
   * The audit-log read as a {@link ReadOutcome}: `populated` with the entries +
   * retention when the log was read, or `read_failed` with a reason. On
   * `read_failed`, the decision-count and coverage sections render
   * incomplete-with-reason and the manifest coverage is marked non-determinable
   * - never a false "no denials" or "full quarter covered".
   */
  audit: ReadOutcome<AuditReadData>;
  /** The fortress primary identity used to sign every emitted file. */
  signer: StoredIdentity;
  /** The fortress master key (used transiently for signing only). */
  masterKey: Uint8Array;
}

/** Default (not-collected) discrete exports: all verified-empty. */
function defaultDiscreteExports(): {
  transparency: ReadOutcome<string>;
  audit_chain: ReadOutcome<string>;
  anchor: ReadOutcome<string>;
} {
  return {
    transparency: emptyVerified(),
    audit_chain: emptyVerified(),
    anchor: emptyVerified(),
  };
}

/**
 * Build the complete in-memory evidence pack. Every read-dependent claim flows
 * through a {@link ReadOutcome}, so a `read_failed` source renders incomplete
 * language and NEVER a definitive negative.
 */
export function buildEvidencePack(
  input: EvidencePackInput,
  deps: BuildEvidencePackDeps
): EvidencePack {
  const window = quarterWindow(input.quarter);
  const generatedAt = input.generated_at_override ?? new Date().toISOString();

  // Derive the aggregation + shortfall from the audit read. Both are
  // read_failed exactly when the audit read is - a failed read can never
  // produce a zero-count aggregation or a "full quarter covered" bound.
  const aggregation = foldOutcome<AuditReadData, ReadOutcome<QuarterAggregation>>(
    deps.audit,
    {
      populated: (data) => populated(aggregateQuarter(data.entries, window)),
      emptyVerified: () =>
        readFailed("the audit log read returned no verifiable result."),
      readFailed: (reason) => readFailed(reason),
    }
  );
  const shortfall = foldOutcome<AuditReadData, ReadOutcome<ShortfallReport>>(
    deps.audit,
    {
      populated: (data) => {
        const lastEntryAt =
          aggregation.status === "populated"
            ? aggregation.value.last_entry_at
            : null;
        const report = detectShortfall(window, data.retention, {
          generatedAt,
          lastEntryAt,
        });
        // G-2: the §7 daemon note renders "N merged into the counts above". The
        // counts above are quarter-windowed, so N must be the daemon entries
        // that fall INSIDE the window, not the all-time total the read layer
        // recorded. Compute it here, where the window is known.
        if (
          report.daemon_store?.status === "included" &&
          data.daemon_entries !== undefined
        ) {
          const windowed = data.daemon_entries.reduce(
            (n, e) => (isInWindow(e.timestamp, window) ? n + 1 : n),
            0
          );
          report.daemon_store = {
            ...report.daemon_store,
            windowed_entry_count: windowed,
          };
        }
        return populated(report);
      },
      emptyVerified: () =>
        readFailed("the audit log read returned no verifiable result."),
      readFailed: (reason) => readFailed(reason),
    }
  );

  const custody: ReadOutcome<CustodyFacts> =
    input.custody ?? readFailed("custody facts were not supplied for this pack.");
  const inventory = input.inventory;
  const discrete = input.discrete_exports ?? defaultDiscreteExports();

  const sections = renderSections({
    input,
    window,
    generatedAt,
    signerDid: deps.signer.did,
    productName: PRODUCT_NAME,
    aggregation,
    shortfall,
    custody,
    inventory,
    discreteExports: {
      transparency: { outcome: discrete.transparency, filename: TRANSPARENCY_BUNDLE_FILENAME },
      audit_chain: { outcome: discrete.audit_chain, filename: AUDIT_CHAIN_FILENAME },
      anchor: { outcome: discrete.anchor, filename: ANCHOR_EVIDENCE_FILENAME },
    },
  });

  // The signed Markdown report concatenates every section with a horizontal
  // rule between them. This is the artifact the manifest signs; the PDF is a
  // human-readable render of the same sections.
  const reportMarkdown =
    sections.map((s) => s.markdown).join("\n\n---\n\n") + "\n";

  const ds = makePackSigner(deps.signer, deps.masterKey);
  const reportFile: EvidencePackFile = signFile(
    REPORT_FILENAME,
    reportMarkdown,
    "text/markdown",
    ds
  );
  const files: EvidencePackFile[] = [reportFile];

  // Sign each gathered discrete export into the manifest (only the populated
  // ones) so the whole output directory is tamper-evident under one manifest.
  // The transparency bundle ALSO carries its own Castle Wall signatures.
  if (discrete.transparency.status === "populated") {
    files.push(
      signFile(TRANSPARENCY_BUNDLE_FILENAME, discrete.transparency.value, "application/json", ds)
    );
  }
  if (discrete.audit_chain.status === "populated") {
    files.push(
      signFile(AUDIT_CHAIN_FILENAME, discrete.audit_chain.value, "application/jsonl", ds)
    );
  }
  if (discrete.anchor.status === "populated") {
    files.push(
      signFile(ANCHOR_EVIDENCE_FILENAME, discrete.anchor.value, "application/json", ds)
    );
  }

  // Manifest coverage: a machine-readable UNION so a failed audit read cannot
  // serialize a false "shortfall: false" - it serializes determinable:false.
  const coverage = foldOutcome<ShortfallReport, EvidencePackManifest["coverage"]>(
    shortfall,
    {
      populated: (s) => ({
        determinable: true,
        covered_from: s.covered_from,
        covered_to_exclusive: s.covered_to_exclusive,
        shortfall: s.shortfall,
        in_progress_quarter: s.in_progress_quarter,
        retention_at_cap: s.retention_at_cap,
      }),
      emptyVerified: () => ({
        determinable: false,
        reason: "the coverage window could not be determined.",
      }),
      readFailed: (reason) => ({ determinable: false, reason }),
    }
  );

  const manifest = buildPackManifest({
    productName: PRODUCT_NAME,
    firmName: input.firm_name,
    window,
    generatedAt,
    signer: deps.signer,
    files,
    coverage,
    ds,
  });

  const pdf = renderMarkdownDocumentsToPdf(
    sections.map((s) => ({ title: s.title, markdown: s.markdown })),
    { footerLabel: PRODUCT_NAME, footerDigest: reportFile.sha256 }
  );

  return { manifest, files, pdf, aggregation, shortfall };
}
