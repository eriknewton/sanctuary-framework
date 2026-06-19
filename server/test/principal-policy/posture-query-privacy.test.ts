import { describe, expect, it } from "vitest";
import {
  buildQueryPrivacySection,
  tierAStatusFromCount,
  tierAEvidence,
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
  it("green only when headers were ACTUALLY stripped in the window", () => {
    // Green is keyed on stripped > 0, NOT calls-observed (#617).
    expect(tierAStatusFromCount(5, 12)).toBe("active");
    // Calls observed but nothing stripped: NEVER green (the #617 misread).
    expect(tierAStatusFromCount(5, 0)).toBe("unconfirmed");
    expect(tierAStatusFromCount(5, 0)).not.toBe("active");
    // No calls / failed read: never green.
    expect(tierAStatusFromCount(0, 0)).toBe("unconfirmed");
    expect(tierAStatusFromCount(null, null)).toBe("unconfirmed");
    expect(tierAStatusFromCount(0, 0)).not.toBe("active");
    expect(tierAStatusFromCount(null, null)).not.toBe("active");
  });

  it("tierAEvidence classifies the three windows distinctly", () => {
    expect(tierAEvidence(5, 12)).toBe("stripped");
    expect(tierAEvidence(5, 0)).toBe("none_to_strip");
    expect(tierAEvidence(0, 0)).toBe("no_calls");
    expect(tierAEvidence(null, null)).toBe("no_calls");
    // The three are mutually distinct - no two windows collapse to one class.
    const classes = [
      tierAEvidence(5, 12),
      tierAEvidence(5, 0),
      tierAEvidence(0, 0),
    ];
    expect(new Set(classes).size).toBe(3);
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

  // #617 HARD REQUIREMENT: a window where outbound calls fired but NO headers
  // were stripped (calls > 0, stripped = 0) must be visually + semantically
  // DISTINGUISHABLE from a window where headers were actually stripped. A viewer
  // must never be able to mistake the 0-stripped state for "stripping happened".
  it("the 0-headers-stripped window is distinguishable from the N>0-stripped window", () => {
    // Window 1: 30 calls fired, but NONE carried a strippable header.
    const noneStripped = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(30, 0),
      tierBRow: tierBRow("unconfirmed", 0),
    });
    // Window 2: 30 calls fired, 90 headers actually stripped.
    const stripped = buildQueryPrivacySection({
      originMachine: OM,
      headerStripStats: statsView(30, 90),
      tierBRow: tierBRow("unconfirmed", 0),
    });

    const noneRow = noneStripped.rows.find((r) => r.tier === "A")!;
    const strippedRow = stripped.rows.find((r) => r.tier === "A")!;

    // Same calls count, so the ONLY thing distinguishing them is the strip
    // evidence - which is exactly what the honesty fix keys the green chip on.
    expect(noneStripped.header_strip_calls_24h).toBe(
      stripped.header_strip_calls_24h,
    );

    // 1) The status itself differs: green `active` ONLY when stripping happened.
    expect(strippedRow.status).toBe("active");
    expect(noneRow.status).toBe("unconfirmed");
    expect(noneRow.status).not.toBe(strippedRow.status);

    // 2) The section-level green discriminator differs - the renderer keys the
    //    green chip on `tier_a_strip_observed`, so a 0-stripped window can never
    //    light green.
    expect(stripped.tier_a_strip_observed).toBe(true);
    expect(noneStripped.tier_a_strip_observed).toBe(false);

    // 3) The honesty discriminator on the row differs, so the rendered copy
    //    cannot collapse the two cases.
    expect(strippedRow.tier_a_evidence).toBe("stripped");
    expect(noneRow.tier_a_evidence).toBe("none_to_strip");
    expect(noneRow.tier_a_evidence).not.toBe(strippedRow.tier_a_evidence);

    // 4) Belt-and-suspenders: the 0-stripped state can NEVER co-occur with the
    //    green chip - i.e. there is no input where headers_stripped_24h === 0 and
    //    tier_a_strip_observed === true. This is the misread the #617 fix forbids.
    expect(noneStripped.headers_stripped_24h).toBe(0);
    expect(noneStripped.tier_a_strip_observed).toBe(false);
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
