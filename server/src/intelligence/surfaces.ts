/**
 * Closed intelligence-surface contract shared by substrate configuration and
 * signed model manifests. This leaf stays dependency-free so manifest parsing
 * cannot import the broader selector type graph.
 */

/**
 * The intelligence-layer surfaces that operators can route independently.
 * Adding a surface also requires updating defaults, audit emission, and the
 * transparency UI.
 */
export type Surface =
  | "concierge"
  | "direct-agent-gate-advisor"
  | "sentinel-scoring"
  | "gate-explanation"
  | "privacy-filter-tier-2"
  | "template-suggestion";

/** Authoritative runtime enumeration of every intelligence surface. */
export const SURFACES: readonly Surface[] = [
  "concierge",
  "direct-agent-gate-advisor",
  "sentinel-scoring",
  "gate-explanation",
  "privacy-filter-tier-2",
  "template-suggestion",
] as const;
