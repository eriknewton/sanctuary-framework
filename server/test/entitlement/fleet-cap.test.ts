/**
 * Fleet control plane PR-2: the NODE-COUNT enforcement gate - pure-core tests.
 *
 * These are the Definition-of-Done for the enforcement arithmetic + the ratified
 * "never gate security" invariant:
 *
 *  1. resolveFleetCap branch table: every fail-closed branch (no license /
 *     invalid / expired / not-yet-valid / non-node meter / malformed count)
 *     resolves to the COMMUNITY floor, never unlimited; a valid node grant lifts
 *     the cap; unlimited grants lift it entirely; a paid grant never LOWERS a
 *     fleet below its free/grandfathered floor.
 *  2. Grandfather baseline: an existing >5-node fleet keeps its count free; a
 *     malformed baseline degrades to 0 (never a silent cap-lift).
 *  3. applyFleetCap "keep wall, drop from console": over-cap nodes leave the
 *     CENTRAL roster; policy_distribution (free security) is preserved VERBATIM;
 *     within-cap / unlimited / unavailable rosters pass through unchanged.
 *  4. THE INVARIANT: an unlicensed / over-cap fleet still carries its
 *     policy_distribution rail intact (proxy for "policy-push is never gated");
 *     capping only ever REMOVES central-roster nodes, never touches the rail.
 */

import { describe, expect, it } from "vitest";
import {
  COMMUNITY_FREE_NODE_CAP,
  resolveFleetCap,
  applyFleetCap,
  type ResolvedEntitlementView,
} from "../../src/entitlement/fleet-cap.js";
import {
  type FleetRoster,
  type FleetRosterNode,
} from "../../src/principal-policy/fleet-roster.js";

// ── Fixtures ─────────────────────────────────────────────────────────────────

function node(id: string, trust: FleetRosterNode["trust_state"] = "admitted"): FleetRosterNode {
  return {
    node_id: id,
    label: null,
    trust_state: trust,
    trust_evaluable: true,
    reach: "recent",
    node_mode: "local",
    provider_in_trust_boundary: true,
    last_sync_received_at: "2026-07-05T00:00:00.000Z",
    policy: {
      version: 3,
      hash: "h",
      hash_algorithm: "sha256",
      applied_at: "2026-07-05T00:00:00.000Z",
      source_event_id: "e1",
      drift_state: "in_sync",
    },
    first_seen: "2026-07-01T00:00:00.000Z",
    last_seen: "2026-07-05T00:00:00.000Z",
  };
}

/** A live roster with `count` admitted nodes and a real policy_distribution rail. */
function roster(count: number): FleetRoster {
  const nodes = Array.from({ length: count }, (_, i) => node(`n${i}`));
  return {
    available: true,
    enabled: true,
    fortress_id: "fortress-1",
    node_id: "n0",
    eviction_serial: 0,
    nodes,
    summary: {
      total: nodes.length,
      admitted: nodes.length,
      revoked: 0,
      untrusted: 0,
    },
    sync_health: {
      reachable: nodes.length,
      stale: 0,
      never: 0,
      oldest_last_sync: nodes.length > 0 ? "2026-07-05T00:00:00.000Z" : null,
      freshness_window_ms: 600_000,
    },
    // A real policy-distribution rail with a live operator policy. The invariant
    // tests assert this survives capping BYTE-FOR-BYTE.
    policy_distribution: {
      available: true,
      operator_policy: {
        version: 7,
        hash: "policy-hash",
        hash_algorithm: "sha256",
        applied_at: "2026-07-05T00:00:00.000Z",
        source_event_id: "policy-event",
      },
      summary: { in_sync: count, drifted: 0, unknown: 0 },
    },
  };
}

const granted = (
  overrides: Partial<ResolvedEntitlementView> = {},
): ResolvedEntitlementView => ({
  granted: true,
  tier: "team",
  entitledCount: 25,
  pricingUnit: "node",
  ...overrides,
});

// ── resolveFleetCap: fail-closed branch table ────────────────────────────────

describe("resolveFleetCap - fail-closed branch table", () => {
  it("no license (absent) → community floor, never unlimited", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "absent" });
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("no_license");
    expect(cap.tier).toBe("community");
  });

  it("invalid signature → community floor", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "bad_signature" });
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("invalid");
  });

  it("expired → community floor with reason expired", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "expired" });
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.reason).toBe("expired");
    expect(cap.paid).toBe(false);
  });

  it("not-yet-valid → community floor with reason not_yet_valid", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "not_yet_valid" });
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.reason).toBe("not_yet_valid");
  });

  it("an UNKNOWN deny reason collapses to invalid (never reads as granted)", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "some_new_reason" });
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("invalid");
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
  });

  it("granted node license with finite count lifts the cap to that count", () => {
    const cap = resolveFleetCap(granted({ entitledCount: 25 }));
    expect(cap.maxNodes).toBe(25);
    expect(cap.paid).toBe(true);
    expect(cap.reason).toBe("granted");
    expect(cap.tier).toBe("team");
  });

  it("granted node license with null count → UNLIMITED", () => {
    const cap = resolveFleetCap(granted({ entitledCount: null }));
    expect(cap.maxNodes).toBeNull();
    expect(cap.paid).toBe(true);
    expect(cap.reason).toBe("granted");
  });

  it("a paid grant NEVER lowers the fleet below the community floor", () => {
    // A (nonsensical but possible) 2-node grant must not drop a fleet below 5.
    const cap = resolveFleetCap(granted({ entitledCount: 2 }));
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.paid).toBe(true);
  });

  it("granted but NON-node meter (seat/fleet) does NOT lift the node cap (fail-closed)", () => {
    const seat = resolveFleetCap(granted({ pricingUnit: "seat", entitledCount: null }));
    expect(seat.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(seat.paid).toBe(false);
    expect(seat.reason).toBe("invalid");
  });

  it("granted but MALFORMED entitledCount → community floor (never unlimited)", () => {
    const bad = resolveFleetCap(
      granted({ entitledCount: -3 as unknown as number }),
    );
    expect(bad.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(bad.paid).toBe(false);
    expect(bad.reason).toBe("invalid");
    const nan = resolveFleetCap(granted({ entitledCount: NaN as unknown as number }));
    expect(nan.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(nan.paid).toBe(false);
  });

  it("graceActive is surfaced on a granted-in-grace resolution", () => {
    const cap = resolveFleetCap(granted({ graceActive: true }));
    expect(cap.graceActive).toBe(true);
    expect(cap.paid).toBe(true);
  });
});

// ── Grandfathering ───────────────────────────────────────────────────────────

describe("resolveFleetCap - grandfather baseline", () => {
  it("an existing >5-node fleet keeps its baseline count free (community)", () => {
    const cap = resolveFleetCap(
      { granted: false, tier: "community", reason: "absent" },
      8,
    );
    expect(cap.maxNodes).toBe(8);
    expect(cap.paid).toBe(false);
    expect(cap.reason).toBe("grandfathered");
  });

  it("a NEW fleet (baseline 0) gets the plain 5-node cap", () => {
    const cap = resolveFleetCap(
      { granted: false, tier: "community", reason: "absent" },
      0,
    );
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.reason).toBe("no_license");
  });

  it("a baseline BELOW the free cap does not lower the cap", () => {
    const cap = resolveFleetCap(
      { granted: false, tier: "community", reason: "absent" },
      3,
    );
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    expect(cap.reason).toBe("no_license");
  });

  it("a MALFORMED baseline degrades to 0 - never a silent cap-lift", () => {
    const cap = resolveFleetCap(
      { granted: false, tier: "community", reason: "absent" },
      -999 as unknown as number,
    );
    expect(cap.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
    const nanBaseline = resolveFleetCap(
      { granted: false, tier: "community", reason: "absent" },
      NaN as unknown as number,
    );
    expect(nanBaseline.maxNodes).toBe(COMMUNITY_FREE_NODE_CAP);
  });

  it("a paid grant above the grandfathered floor supersedes it", () => {
    const cap = resolveFleetCap(granted({ entitledCount: 50 }), 8);
    expect(cap.maxNodes).toBe(50);
    expect(cap.paid).toBe(true);
  });

  it("a paid grant BELOW the grandfathered floor is raised to the floor", () => {
    const cap = resolveFleetCap(granted({ entitledCount: 6 }), 8);
    expect(cap.maxNodes).toBe(8);
    expect(cap.paid).toBe(true);
  });
});

// ── applyFleetCap: keep wall, drop from console ──────────────────────────────

describe("applyFleetCap - keep wall, drop from console", () => {
  it("drops nodes beyond the cap from the CENTRAL roster and recomputes summary", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "absent" }); // 5
    const result = applyFleetCap(roster(8), cap);
    expect(result.roster.nodes).toHaveLength(5);
    expect(result.droppedNodeCount).toBe(3);
    expect(result.roster.summary.total).toBe(5);
    expect(result.roster.summary.admitted).toBe(5);
    // Retention is stable/deterministic: the first 5 nodes in order are kept.
    expect(result.roster.nodes.map((n) => n.node_id)).toEqual([
      "n0",
      "n1",
      "n2",
      "n3",
      "n4",
    ]);
  });

  it("a within-cap roster passes through unchanged (0 dropped)", () => {
    const cap = resolveFleetCap(granted({ entitledCount: 25 }));
    const result = applyFleetCap(roster(3), cap);
    expect(result.roster.nodes).toHaveLength(3);
    expect(result.droppedNodeCount).toBe(0);
  });

  it("an UNLIMITED cap never drops a node", () => {
    const cap = resolveFleetCap(granted({ entitledCount: null }));
    const result = applyFleetCap(roster(50), cap);
    expect(result.roster.nodes).toHaveLength(50);
    expect(result.droppedNodeCount).toBe(0);
  });

  it("an unavailable/absent roster passes through unchanged", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "absent" });
    const absent = { ...roster(0), available: false };
    const result = applyFleetCap(absent, cap);
    expect(result.roster.available).toBe(false);
    expect(result.droppedNodeCount).toBe(0);
  });

  it("recomputes sync_health over the RETAINED nodes only (liveness, not trust)", () => {
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "absent" }); // 5
    const result = applyFleetCap(roster(8), cap);
    // 5 retained nodes, all `recent` in the fixture.
    expect(result.roster.sync_health.reachable).toBe(5);
    expect(result.roster.sync_health.stale).toBe(0);
    expect(result.roster.sync_health.never).toBe(0);
  });
});

// ── THE INVARIANT: policy-push (free security) is NEVER gated ─────────────────

describe("applyFleetCap - policy-push (free security) is NEVER gated", () => {
  it("an UNLICENSED (community) OVER-cap fleet keeps its policy_distribution rail VERBATIM", () => {
    const original = roster(9); // 9 nodes, unlicensed → community cap of 5
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "absent" });
    const result = applyFleetCap(original, cap);

    // Nodes beyond 5 left the console…
    expect(result.roster.nodes).toHaveLength(5);
    expect(result.droppedNodeCount).toBe(4);

    // …but the policy-distribution rail (free security function) is UNCHANGED -
    // same object identity, same operator policy, uncapped. This is the concrete
    // proof that "we never gate your security": policy push is neither reduced by
    // nor counted toward the node-count cap.
    expect(result.roster.policy_distribution).toBe(original.policy_distribution);
    expect(result.roster.policy_distribution.available).toBe(true);
    expect(result.roster.policy_distribution.operator_policy).toEqual(
      original.policy_distribution.operator_policy,
    );
  });

  it("even at the tightest (over-cap) community resolution, the operator policy is still distributed", () => {
    const original = roster(100);
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "invalid" });
    const result = applyFleetCap(original, cap);
    // The console shows only 5 nodes, but policy-push remains available to ALL of
    // them: the rail's operator_policy is intact regardless of the cap.
    expect(result.roster.policy_distribution.operator_policy).not.toBeNull();
    expect(result.roster.policy_distribution.available).toBe(true);
  });

  it("passthrough fields (available/enabled/fortress_id/node_id/eviction_serial) are unchanged by capping", () => {
    const original = roster(8);
    const cap = resolveFleetCap({ granted: false, tier: "community", reason: "absent" });
    const result = applyFleetCap(original, cap);
    expect(result.roster.available).toBe(original.available);
    expect(result.roster.enabled).toBe(original.enabled);
    expect(result.roster.fortress_id).toBe(original.fortress_id);
    expect(result.roster.node_id).toBe(original.node_id);
    expect(result.roster.eviction_serial).toBe(original.eviction_serial);
  });
});
