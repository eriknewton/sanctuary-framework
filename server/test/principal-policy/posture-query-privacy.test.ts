import { describe, expect, it } from "vitest";
import {
  buildQueryPrivacySection,
  tierAStatusFromCount,
  TIER_B_FEATURE_ID,
  type QueryAnonymityStatsView,
} from "../../src/principal-policy/posture-query-privacy.js";
import type { FeatureHealthRow } from "../../src/principal-policy/feature-health.js";

/**
 * Phase 2 query-privacy section honesty contract (#617 never-fake-green +
 * design 2026-06-19 2.1 C overclaim flag). The section surfaces the Opacity
 * principle for the first time, but:
 *  - it must NEVER imply anonymity (header stripping is metadata hygiene only);
 *  - Tier A is never green from absence (zero 24h calls reads unconfirmed);
 *  - Tier B (PII rewrite) is NEVER green from config alone (its emitter is
 *    unwired, so the carried-through feature-health status stays unconfirmed).
 */

const OM = "fortress:test";

function statsView(
  calls: number,
  stripped: number,
): QueryAnonymityStatsView {
  return { window: "24h", total_outbound_calls: calls, total_headers_stripped: stripped };
}

function tierBRow(status: FeatureHealthRow["status"], count: number): FeatureHealthRow {
  return {
    origin_machine: OM,
    feature_id: TIER_B_FEATURE_ID,
    label: "Query-privacy PII rewrite (opt-in)",
    liveness: "event_driven",
    status,
    basis: "no_activity_event_driven",
    invocation_count: count,
    last_evidence_at: null,
    broken_zero_detectable: false,
    audit_integrity_ok: true,
    freshness_window_ms: 600000,
  };
}

describe("query-privacy section - never imply anonymity", () => {
  it("header_strip_is_anonymity is hard-false regardless of activity", () => {
    const busy = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(42, 900),
      tierBRow: tierBRow("unconfirmed", 0),
    });
    expect(busy.header_strip_is_anonymity).toBe(false);
    const quiet = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(0, 0),
      tierBRow: null,
    });
    expect(quiet.header_strip_is_anonymity).toBe(false);
  });
});

describe("query-privacy section - Tier A header strip honesty", () => {
  it("green only on real strip evidence in the window", () => {
    expect(tierAStatusFromCount(5)).toBe("active");
    expect(tierAStatusFromCount(0)).toBe("unconfirmed");
    expect(tierAStatusFromCount(null)).toBe("unconfirmed");
    // Absence is never green.
    expect(tierAStatusFromCount(0)).not.toBe("active");
    expect(tierAStatusFromCount(null)).not.toBe("active");
  });

  it("a quiet 24h window renders Tier A unconfirmed, never green", () => {
    const section = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(0, 0),
      tierBRow: tierBRow("unconfirmed", 0),
    });
    const tierA = section.rows.find((r) => r.tier === "A");
    expect(tierA).toBeDefined();
    expect(tierA!.status).toBe("unconfirmed");
    expect(tierA!.opt_in).toBe(false);
  });

  it("a busy window renders Tier A active with the real stripped count", () => {
    const section = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(10, 220),
      tierBRow: tierBRow("unconfirmed", 0),
    });
    const tierA = section.rows.find((r) => r.tier === "A");
    expect(tierA!.status).toBe("active");
    expect(section.header_strip_calls_24h).toBe(10);
    expect(section.headers_stripped_24h).toBe(220);
  });

  it("a failed/null stats read is unconfirmed, never green", () => {
    const section = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: null,
      tierBRow: tierBRow("unconfirmed", 0),
    });
    const tierA = section.rows.find((r) => r.tier === "A");
    expect(tierA!.status).toBe("unconfirmed");
    expect(section.header_strip_calls_24h).toBe(0);
  });
});

describe("query-privacy section - Tier B PII rewrite never green from config", () => {
  it("carries the feature-health status through verbatim and stays unconfirmed", () => {
    const section = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(3, 60),
      tierBRow: tierBRow("unconfirmed", 0),
    });
    const tierB = section.rows.find((r) => r.tier === "B");
    expect(tierB).toBeDefined();
    expect(tierB!.status).toBe("unconfirmed");
    expect(tierB!.status).not.toBe("active");
    expect(tierB!.opt_in).toBe(true);
  });

  it("when the Tier B row is absent it fails closed to unconfirmed, never green", () => {
    const section = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(3, 60),
      tierBRow: null,
    });
    const tierB = section.rows.find((r) => r.tier === "B");
    expect(tierB!.status).toBe("unconfirmed");
    expect(tierB!.status).not.toBe("active");
  });

  it("ONLY a real rewrite event (feature-health active) can color Tier B green", () => {
    // This proves the green path is gated by feature-health evidence, not config:
    // the shaper never invents green; it only mirrors an `active` row.
    const section = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(3, 60),
      tierBRow: tierBRow("active", 4),
    });
    const tierB = section.rows.find((r) => r.tier === "B");
    expect(tierB!.status).toBe("active");
    expect(tierB!.count).toBe(4);
  });
});
