import { describe, expect, it } from "vitest";
import {
  buildDistressTile,
  type DistressTileSignalView,
} from "../../src/principal-policy/posture-distress.js";
import {
  HABEAS_DISTRESS_PORT,
  HABEAS_LOCAL_RULE_ID,
} from "../../src/castle-wall/allowlist/habeas-port.js";

/**
 * Phase 2 distress tile honesty contract (#617 never-fake-green + design
 * 2026-06-19 2.4 C). The tile reports FACTS only: a count + most-recent time +
 * the static guaranteed-egress policy fact. It carries NO health/active claim
 * and NO green color (the shape has no status field by construction), and an
 * empty inbox is "no distress signals recorded", never a fabricated green.
 */

const OM = "fortress:test";

function sig(received_at: string, reason: string, severity: string): DistressTileSignalView {
  return { received_at, reason, severity };
}

describe("distress tile - facts only, never a fabricated green", () => {
  it("the tile shape carries no status/color field (never-green is structural)", () => {
    const tile = buildDistressTile({ originMachine: OM, signals: [] });
    // A future edit cannot color this green because there is no status field to
    // set: assert the shape stays facts-only.
    expect("status" in tile).toBe(false);
    expect("color" in tile).toBe(false);
    expect("healthy" in tile).toBe(false);
    expect("active" in tile).toBe(false);
  });

  it("an empty inbox is zero signals with null most-recent, not a green all-well", () => {
    const tile = buildDistressTile({ originMachine: OM, signals: [] });
    expect(tile.signal_count).toBe(0);
    expect(tile.most_recent_at).toBeNull();
    expect(tile.most_recent_reason).toBeNull();
    expect(tile.most_recent_severity).toBeNull();
  });

  it("surfaces the count and newest signal facts (newest-first input)", () => {
    const tile = buildDistressTile({
      originMachine: OM,
      signals: [
        sig("2026-06-19T10:00:00.000Z", "policy_constraint", "urgent"),
        sig("2026-06-18T09:00:00.000Z", "resource_exhaustion", "notice"),
      ],
    });
    expect(tile.signal_count).toBe(2);
    expect(tile.most_recent_at).toBe("2026-06-19T10:00:00.000Z");
    expect(tile.most_recent_reason).toBe("policy_constraint");
    expect(tile.most_recent_severity).toBe("urgent");
  });
});

describe("distress tile - guaranteed-egress is a structural policy fact", () => {
  it("always carries the reserved habeas rule id and loopback port", () => {
    const tile = buildDistressTile({ originMachine: OM, signals: [] });
    expect(tile.guaranteed_egress.rule_id).toBe(HABEAS_LOCAL_RULE_ID);
    expect(tile.guaranteed_egress.port).toBe(HABEAS_DISTRESS_PORT);
    // It is present even with signals; it is a static policy fact, not derived
    // from inbox state.
    const withSignals = buildDistressTile({
      originMachine: OM,
      signals: [sig("2026-06-19T10:00:00.000Z", "other", "notice")],
    });
    expect(withSignals.guaranteed_egress.rule_id).toBe(HABEAS_LOCAL_RULE_ID);
    expect(withSignals.guaranteed_egress.port).toBe(HABEAS_DISTRESS_PORT);
  });

  it("propagates the origin machine for /v1-compatible merge", () => {
    const tile = buildDistressTile({ originMachine: OM, signals: [] });
    expect(tile.origin_machine).toBe(OM);
  });
});
