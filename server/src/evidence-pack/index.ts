/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: module barrel
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * The quarterly law-firm evidence pack (slice 1, the walking skeleton).
 * Consumers import the module surface here, not the internal file layout.
 *
 * What this module owns: the calendar-quarter aggregation of audit activity
 * (the main NEW code; the shipped log counts by size, not by period),
 * covered-window shortfall detection over the FIFO retention posture, the
 * CNA-mapped section renderers with honest coverage-basis language, the signed
 * manifest (reusing the EU AI Act bundle's signing discipline), and the PDF
 * render (reusing the zero-dependency writer in `compliance/eu_ai_act/pdf.ts`).
 */

export * from "./types.js";
export {
  parseQuarterLabel,
  quarterLabel,
  currentQuarter,
  quarterWindow,
  isInWindow,
} from "./quarter.js";
export { aggregateQuarter, categorizeEntry, detectShortfall } from "./aggregate.js";
export { renderSections, PACK_DISCLAIMER } from "./sections.js";
export type { PackSection } from "./sections.js";
export {
  buildEvidencePack,
  PRODUCT_NAME,
  REPORT_FILENAME,
  MANIFEST_FILENAME,
  PDF_FILENAME,
} from "./generate.js";
export type { BuildEvidencePackDeps } from "./generate.js";
export {
  makePackSigner,
  signFile,
  buildPackManifest,
  canonicalJSON,
} from "./signer.js";
export type { PackSigner } from "./signer.js";
export { runEvidencePack } from "./cli.js";
