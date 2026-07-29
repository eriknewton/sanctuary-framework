/**
 * Fleet control plane, Add-Machine slice: the PURE enrollment-headroom view
 * (`computeFleetCapacityView`) - pure-core tests.
 *
 * This is the Definition-of-Done arithmetic behind `GET /api/fleet/capacity`
 * and the `POST /api/fleet/enroll-token` pre-check:
 *
 *  1. Unlimited cap (`maxNodes: null`): always `remaining: null`,
 *     `at_capacity: false`, `enrollment_allowed: true`, regardless of the
 *     active-node count.
 *  2. Within cap: `remaining` is the exact headroom, never at capacity.
 *  3. Exactly at cap: `remaining: 0`, `at_capacity: true`.
 *  4. Over cap (roster already exceeds a shrunk cap): `remaining` clamps to
 *     `0`, NEVER negative; `at_capacity: true`.
 *  5. Roster-unavailable (active count 0 or malformed): honest absence, never
 *     a fabricated at-capacity block, never a negative-count crash.
 *  6. `enrollment_allowed` is always exactly `!at_capacity` - the module's
 *     documented advisory-only contract.
 */

import { describe, expect, it } from "vitest";
import {
  computeFleetCapacityView,
  type FleetCapacityView,
} from "../../src/entitlement/fleet-capacity.js";
import type { FleetCap } from "../../src/entitlement/fleet-cap.js";

function cap(overrides: Partial<FleetCap> = {}): FleetCap {
  return {
    maxNodes: 25,
    paid: true,
    tier: "team",
    reason: "granted",
    graceActive: false,
    ...overrides,
  };
}

describe("computeFleetCapacityView - unlimited cap", () => {
  it("null max_nodes always reports remaining null, never at capacity", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: null, tier: "fleet" }), 999);
    expect(view.max_nodes).toBeNull();
    expect(view.remaining).toBeNull();
    expect(view.at_capacity).toBe(false);
    expect(view.enrollment_allowed).toBe(true);
    expect(view.active_nodes).toBe(999);
    expect(view.tier).toBe("fleet");
  });

  it("unlimited with zero active nodes is still not at capacity", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: null }), 0);
    expect(view.at_capacity).toBe(false);
    expect(view.remaining).toBeNull();
  });
});

describe("computeFleetCapacityView - within cap", () => {
  it("reports exact remaining headroom and not at capacity", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: 25 }), 7);
    expect(view.active_nodes).toBe(7);
    expect(view.max_nodes).toBe(25);
    expect(view.remaining).toBe(18);
    expect(view.at_capacity).toBe(false);
    expect(view.enrollment_allowed).toBe(true);
  });

  it("community floor (5) with 0 active nodes", () => {
    const view = computeFleetCapacityView(
      cap({ maxNodes: 5, paid: false, tier: "community", reason: "no_license" }),
      0,
    );
    expect(view.remaining).toBe(5);
    expect(view.at_capacity).toBe(false);
    expect(view.reason).toBe("no_license");
    expect(view.tier).toBe("community");
  });
});

describe("computeFleetCapacityView - exactly at cap", () => {
  it("remaining is 0 and at_capacity is true at the exact boundary", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: 5 }), 5);
    expect(view.remaining).toBe(0);
    expect(view.at_capacity).toBe(true);
    expect(view.enrollment_allowed).toBe(false);
  });
});

describe("computeFleetCapacityView - over cap (roster already exceeds a shrunk cap)", () => {
  it("remaining clamps to 0, never negative", () => {
    // e.g. a downgrade shrunk the cap to 5 but the roster still shows 8 active
    // nodes (before the next applyFleetCap tick reshapes the central roster).
    const view = computeFleetCapacityView(cap({ maxNodes: 5 }), 8);
    expect(view.remaining).toBe(0);
    expect(view.remaining).not.toBeLessThan(0);
    expect(view.at_capacity).toBe(true);
    expect(view.enrollment_allowed).toBe(false);
  });

  it("far over cap still clamps to exactly 0, not a large negative", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: 5 }), 500);
    expect(view.remaining).toBe(0);
  });
});

describe("computeFleetCapacityView - roster-unavailable / malformed active count", () => {
  it("negative active count normalizes to 0 (honest absence), never underflows remaining", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: 25 }), -3);
    expect(view.active_nodes).toBe(0);
    expect(view.remaining).toBe(25);
    expect(view.at_capacity).toBe(false);
  });

  it("NaN active count normalizes to 0", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: 25 }), NaN);
    expect(view.active_nodes).toBe(0);
    expect(view.remaining).toBe(25);
  });

  it("non-integer active count normalizes to 0", () => {
    const view = computeFleetCapacityView(cap({ maxNodes: 25 }), 3.5);
    expect(view.active_nodes).toBe(0);
  });
});

describe("computeFleetCapacityView - enrollment_allowed is always !at_capacity", () => {
  it.each([
    [cap({ maxNodes: null }), 100],
    [cap({ maxNodes: 25 }), 0],
    [cap({ maxNodes: 25 }), 24],
    [cap({ maxNodes: 25 }), 25],
    [cap({ maxNodes: 25 }), 30],
  ] as const)("view %#: enrollment_allowed === !at_capacity", (fleetCap, active) => {
    const view: FleetCapacityView = computeFleetCapacityView(fleetCap, active);
    expect(view.enrollment_allowed).toBe(!view.at_capacity);
  });

  it("never throws on any input shape", () => {
    expect(() => computeFleetCapacityView(cap(), Infinity)).not.toThrow();
    expect(() => computeFleetCapacityView(cap(), -Infinity)).not.toThrow();
  });
});
