/**
 * Sanctuary MCP Server — EU AI Act Templates Index
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Re-exports all template constants and helper functions for the
 * EU AI Act Compliance Bundle generator.
 */

export {
  render,
  countManualInputMarkers,
  extractManualInputHints,
  manualInputMarker,
  MANUAL_INPUT_MARKER_PREFIX,
  MANUAL_INPUT_MARKER_SUFFIX,
  type TemplateContext,
  type TemplateValue,
} from "./render.js";

export {
  HEADER_TEMPLATE,
  FOOTER_TEMPLATE,
  ROW_BLOCK_TEMPLATE,
  coverageBadge,
  formatEmitterList,
} from "./shared.js";

export { ANNEX_IV_TECHNICAL_DOCUMENTATION_TEMPLATE } from "./01_annex_iv_technical_documentation.js";
export { ARTICLE_26_DEPLOYER_LOG_TEMPLATE } from "./02_article_26_deployer_log.js";
export { ARTICLE_12_AUTOMATIC_LOGS_TEMPLATE } from "./03_article_12_automatic_logs.js";
export { RISK_MANAGEMENT_SUMMARY_TEMPLATE } from "./04_risk_management_summary.js";
export { HUMAN_OVERSIGHT_STATEMENT_TEMPLATE } from "./05_human_oversight_statement.js";
export { CRYPTOGRAPHIC_ATTESTATIONS_TEMPLATE } from "./06_cryptographic_attestations.js";
