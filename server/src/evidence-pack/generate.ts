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
  DiscreteExportsStatus,
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
/** Basename of the gathered transparency-checkpoint bundle (slice 2). */
export const TRANSPARENCY_BUNDLE_FILENAME = "transparency-bundle.json";
/** Basename of the gathered audit-chain JSONL export (slice 2). */
export const AUDIT_CHAIN_FILENAME = "audit-chain.jsonl";
/** Basename of the gathered public-anchor evidence (slice 2). */
export const ANCHOR_EVIDENCE_FILENAME = "anchor-evidence.json";

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

  // Resolve which discrete verification exports are present, so the appendix
  // references concrete files and states honestly why any is absent.
  const ex = input.discrete_exports ?? {};
  const discreteStatus: DiscreteExportsStatus = {
    transparency: ex.transparency_bundle_json
      ? { included: true, filename: TRANSPARENCY_BUNDLE_FILENAME }
      : {
          included: false,
          reason:
            ex.transparency_absent_reason ??
            "no signed transparency checkpoints were available to export from this fortress.",
        },
    audit_chain: ex.audit_chain_jsonl
      ? { included: true, filename: AUDIT_CHAIN_FILENAME }
      : {
          included: false,
          reason:
            ex.audit_chain_absent_reason ??
            "the audit-chain export could not be produced.",
        },
    anchor: ex.anchor_evidence_json
      ? { included: true, filename: ANCHOR_EVIDENCE_FILENAME }
      : {
          included: false,
          reason:
            ex.anchor_absent_reason ??
            "public transparency anchoring is opt-in and is not enabled on this install.",
        },
  };

  const sections = renderSections({
    input,
    window,
    generatedAt,
    signerDid: deps.signer.did,
    productName: PRODUCT_NAME,
    aggregation,
    shortfall,
    discreteExports: discreteStatus,
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

  // Sign each gathered discrete export into the manifest so the whole output
  // directory is tamper-evident under one manifest. The transparency bundle
  // ALSO carries its own Castle Wall signatures, verifiable independently.
  if (ex.transparency_bundle_json) {
    files.push(
      signFile(
        TRANSPARENCY_BUNDLE_FILENAME,
        ex.transparency_bundle_json,
        "application/json",
        ds
      )
    );
  }
  if (ex.audit_chain_jsonl) {
    files.push(
      signFile(AUDIT_CHAIN_FILENAME, ex.audit_chain_jsonl, "application/jsonl", ds)
    );
  }
  if (ex.anchor_evidence_json) {
    files.push(
      signFile(
        ANCHOR_EVIDENCE_FILENAME,
        ex.anchor_evidence_json,
        "application/json",
        ds
      )
    );
  }

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
