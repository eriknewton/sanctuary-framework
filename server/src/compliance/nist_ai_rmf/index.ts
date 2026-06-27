/**
 * Sanctuary MCP Server, NIST AI RMF Crosswalk module barrel.
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thin re-export surface for the NIST AI RMF 1.0 crosswalk. Consumers
 * import from here, not from the internal layout.
 */

export type {
  NistFunction,
  NistCoverageFlag,
  NistSubcategory,
  NistCrosswalk,
  NistCoverageStats,
} from "./types.js";

export {
  NIST_CROSSWALK_V1,
  FRAMEWORK_VERSION,
  coverageStats,
  allEvidenceEmitters,
  subcategoriesByCoverage,
  subcategoriesByFunction,
  subcategoryById,
} from "./crosswalk.js";

export { renderNistCrosswalk } from "./generator.js";
export { runNistAiRmf } from "./cli.js";
