/**
 * Sovereignty Posture Dashboard - Phase 2 query-privacy section shaper.
 *
 * Pure shaper for the Home "Query privacy" section (Phase 2 design 2026-06-19,
 * section 2.1). Surfaces the query-layer privacy posture (Opacity, principle 4)
 * for the first time, from evidence that already fires - WITHOUT overclaiming.
 *
 * Two honest rows mapped to the two real privacy tiers:
 *  - Tier A header strip (default-on, unconditional): the 24h count of outbound
 *    substrate calls that had fingerprintable headers stripped, sourced from the
 *    existing `/api/query-anonymity/stats` aggregation over
 *    `query_anonymity_headers_stripped` audit evidence.
 *  - Tier B PII rewrite (opt-in, off by default): the existing `privacy_strips`
 *    feature-health row, which reads `unconfirmed` (amber) until the deferred
 *    Rho-2.5 selector wiring lands. Carried through verbatim; never forced green.
 *
 * HONESTY CONTRACT (#617 never-fake-green + design 2.1 C overclaim flag):
 *  - This section is HEADER-METADATA HYGIENE, NOT ANONYMITY. The substrate
 *    provider still sees the query CONTENT and the authenticated API key.
 *    `header_strip_is_anonymity` is hard-`false` and the renderer must say the
 *    boundary plainly; the headline must never read "your queries are anonymous".
 *  - Tier A is event-driven and broken-zero-undetectable: a 24h count of zero is
 *    NOT a green "healthy" state, it is honestly "no calls observed in the
 *    window". The Tier-A status here is never green from absence.
 *  - Tier B is NEVER green from config alone. Its status is the feature-health
 *    `privacy_strips` row status, which is `unconfirmed` until a real
 *    `query_anonymity_pii_rewritten` event fires (the emitter is unwired today),
 *    so it carries through as `unconfirmed`, never green.
 *  - Tier C (mix-network / ZK) is NOT rendered as a capability at all (omitted).
 *
 * Pure over its injected inputs so it unit-tests without a live server.
 */

import type {
  FeatureHealthRow,
  FeatureHealthStatus,
} from "./feature-health.js";

/** Feature-registry id of the Tier B PII-rewrite row (feature-health.ts). */
export const TIER_B_FEATURE_ID = "privacy_strips";

/**
 * The minimal subset of the `/api/query-anonymity/stats` response the section
 * needs. A read-only view; kept narrow so the shaper does not couple to the full
 * stats shape.
 */
export interface QueryAnonymityStatsView {
  window: "24h";
  total_outbound_calls: number;
  total_headers_stripped: number;
}

export interface BuildQueryPrivacySectionInput {
  originMachine: string;
  /**
   * 24h header-strip stats from `/api/query-anonymity/stats` (Tier A). When the
   * endpoint read failed, pass null - the Tier-A row then reads `unconfirmed`,
   * never green (a failed read is not evidence of health).
   */
  headerStripStats: QueryAnonymityStatsView | null;
  /**
   * The Tier B PII-rewrite feature-health row (`privacy_strips`) from the
   * already-composed home feature-health panel, or null when absent. Its status
   * is carried through verbatim; this shaper never recolors it green.
   */
  tierBRow: FeatureHealthRow | null;
}

/** A single rendered privacy row. Carries the honesty-gated status + counts. */
export interface QueryPrivacyRow {
  tier: "A" | "B";
  label: string;
  /** The honesty-gated status. GREEN is never produced for Tier B from config. */
  status: FeatureHealthStatus;
  /** 24h count relevant to the row (header strips for A; rewrites for B). */
  count: number;
  /** Whether the operator can opt out of this tier (Tier A is unconditional). */
  opt_in: boolean;
}

/**
 * The Query-privacy Home section shape. `/v1`-compatible via `origin_machine`.
 * The `header_strip_is_anonymity` flag is the structural anchor for the
 * overclaim guard: it is hard-`false` so a test pins that the panel can never be
 * relabeled to imply anonymity.
 */
export interface QueryPrivacySection {
  origin_machine: string;
  /** 24h count of outbound substrate calls with headers stripped (Tier A). */
  header_strip_calls_24h: number;
  /** 24h count of individual headers stripped (Tier A). */
  headers_stripped_24h: number;
  /**
   * HARD FALSE, never configurable. Header stripping is metadata hygiene, not
   * anonymity: the substrate provider still sees query content + the API key.
   * The renderer reads this to keep the headline honest.
   */
  header_strip_is_anonymity: false;
  rows: QueryPrivacyRow[];
}

/**
 * Map a Tier-A 24h header-strip count to an honest status. Tier A is
 * event-driven + broken-zero-undetectable, so a zero count is `unconfirmed`
 * (amber), never green: absence of recent calls is not evidence the strip is
 * healthy. A positive count is `active` (green) - real strip evidence fired.
 * A failed/absent read is `unconfirmed`, never green.
 */
export function tierAStatusFromCount(
  calls: number | null,
): FeatureHealthStatus {
  if (calls === null) return "unconfirmed";
  return calls > 0 ? "active" : "unconfirmed";
}

/**
 * Build the Query-privacy Home section. Pure.
 *
 * Tier A status is derived from real header-strip evidence (active only on a
 * positive 24h count). Tier B status is the feature-health `privacy_strips` row
 * status carried through verbatim (never recolored): it is `unconfirmed` today
 * because the rewrite emitter is unwired, and stays non-green until a real
 * rewrite event fires.
 */
export function buildQueryPrivacySection(
  input: BuildQueryPrivacySectionInput,
): QueryPrivacySection {
  const stats = input.headerStripStats;
  const calls = stats ? stats.total_outbound_calls : null;
  const stripped = stats ? stats.total_headers_stripped : 0;

  // Tier B status: carry through the feature-health row verbatim. If absent,
  // fail closed to `unconfirmed` (amber), never green.
  const tierBStatus: FeatureHealthStatus =
    input.tierBRow !== null ? input.tierBRow.status : "unconfirmed";
  const tierBCount = input.tierBRow !== null ? input.tierBRow.invocation_count : 0;

  const rows: QueryPrivacyRow[] = [
    {
      tier: "A",
      label: "Header strip (metadata)",
      status: tierAStatusFromCount(calls),
      count: stripped,
      opt_in: false,
    },
    {
      tier: "B",
      label: "PII rewrite (opt-in)",
      status: tierBStatus,
      count: tierBCount,
      opt_in: true,
    },
  ];

  return {
    origin_machine: input.originMachine,
    header_strip_calls_24h: calls ?? 0,
    headers_stripped_24h: stripped,
    header_strip_is_anonymity: false,
    rows,
  };
}
