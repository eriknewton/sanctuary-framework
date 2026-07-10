/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: generator
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Assembles the quarterly evidence pack (slice 1, the walking skeleton) from
 * already-resolved inputs: the quarter's audit entries, the retention facts,
 * and the fortress primary identity. This function is pure over its deps (it
 * performs no I/O and no server boot), so tests drive the real aggregation,
 * shortfall, rendering, PDF, and signing paths with synthetic fixtures and
 * never touch a real fortress. The CLI (`cli.ts`) resolves the deps from a
 * running server and writes the result to disk.
 */

import type { AuditEntry } from "../operational/audit-log.js";
import type { StoredIdentity } from "../core/identity.js";
import { renderMarkdownDocumentsToPdf } from "../compliance/eu_ai_act/pdf.js";
import type {
  EvidencePack,
  EvidencePackFile,
  EvidencePackInput,
  RetentionFacts,
} from "./types.js";
import { quarterWindow } from "./quarter.js";
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

/** Already-resolved inputs the generator needs (see module doc-comment). */
export interface BuildEvidencePackDeps {
  /** Every retained audit entry the quarter may draw from (the CLI passes all). */
  entries: readonly AuditEntry[];
  /** Retention posture, for covered-window shortfall detection. */
  retention: RetentionFacts;
  /** The fortress primary identity used to sign every emitted file. */
  signer: StoredIdentity;
  /** The fortress master key (used transiently for signing only). */
  masterKey: Uint8Array;
}

/**
 * Build the complete in-memory evidence pack: the quarter aggregation, the
 * covered-window shortfall disclosure, the signed Markdown report, the signed
 * manifest, and the rendered PDF.
 */
export function buildEvidencePack(
  input: EvidencePackInput,
  deps: BuildEvidencePackDeps
): EvidencePack {
  const window = quarterWindow(input.quarter);
  const aggregation = aggregateQuarter(deps.entries, window);
  const generatedAt = input.generated_at_override ?? new Date().toISOString();
  const shortfall = detectShortfall(window, deps.retention, {
    generatedAt,
    lastEntryAt: aggregation.last_entry_at,
  });

  const sections = renderSections({
    input,
    window,
    generatedAt,
    signerDid: deps.signer.did,
    productName: PRODUCT_NAME,
    aggregation,
    shortfall,
  });

  // The signed Markdown report concatenates every section with a horizontal
  // rule between them. This is the artifact the manifest signs; the PDF is a
  // human-readable render of the same sections.
  const reportMarkdown = sections
    .map((s) => s.markdown)
    .join("\n\n---\n\n") + "\n";

  const ds = makePackSigner(deps.signer, deps.masterKey);
  const reportFile: EvidencePackFile = signFile(
    REPORT_FILENAME,
    reportMarkdown,
    "text/markdown",
    ds
  );
  const files: EvidencePackFile[] = [reportFile];

  const manifest = buildPackManifest({
    productName: PRODUCT_NAME,
    firmName: input.firm_name,
    window,
    generatedAt,
    signer: deps.signer,
    files,
    shortfall,
    ds,
  });

  const pdf = renderMarkdownDocumentsToPdf(
    sections.map((s) => ({ title: s.title, markdown: s.markdown })),
    { footerLabel: PRODUCT_NAME, footerDigest: reportFile.sha256 }
  );

  return { manifest, files, pdf, aggregation, shortfall };
}
