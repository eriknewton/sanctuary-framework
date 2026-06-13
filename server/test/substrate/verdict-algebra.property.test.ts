/**
 * Property-style proof of the verdict-algebra invariant (design §3.4; RFC §4.2a):
 * ADDING A PLUGIN NEVER LOOSENS AN OUTCOME.
 *
 * We exhaustively / randomly verify intersectVerdicts is:
 *   - monotone: adding any decision never moves the outcome toward permit
 *   - commutative: order of plugin decisions does not change the result
 *   - associative / order-independent under permutation
 *   - idempotent: duplicating a decision changes nothing
 *   - deny-absorbing: a host or plugin deny dominates everything
 *   - permit-only-from-host: permit is reachable ONLY when the host permits AND every
 *     plugin returns no_objection
 */

import { describe, it, expect } from "vitest";

import {
  intersectVerdicts,
  type EnforcementDecision,
  type HostDecision,
  type ComposedOutcome,
} from "../../src/substrate/index.js";

const HOSTS: HostDecision[] = ["permit", "escalate", "deny"];
const PLUGINS: EnforcementDecision[] = ["deny", "plugin_error", "escalate", "observe", "no_objection"];

// permit(0) == no_objection(0) at the floor; ascend toward deny.
const STRICTNESS: Record<ComposedOutcome, number> = {
  permit: 0,
  no_objection: 0,
  observe: 1,
  escalate: 2,
  plugin_error: 3,
  deny: 4,
};

function strictness(o: ComposedOutcome): number {
  return STRICTNESS[o];
}

function permute<T>(arr: T[]): T[][] {
  if (arr.length <= 1) return [arr];
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i++) {
    const rest = [...arr.slice(0, i), ...arr.slice(i + 1)];
    for (const p of permute(rest)) out.push([arr[i]!, ...p]);
  }
  return out;
}

function randDecisions(n: number, seed: number): EnforcementDecision[] {
  // tiny LCG for deterministic pseudo-randomness
  let s = seed >>> 0;
  const next = () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0xffffffff;
  };
  return Array.from({ length: n }, () => PLUGINS[Math.floor(next() * PLUGINS.length)]!);
}

describe("intersectVerdicts — monotone, never loosens", () => {
  it("adding any single decision never moves the outcome toward permit", () => {
    for (const host of HOSTS) {
      for (let trial = 0; trial < 200; trial++) {
        const base = randDecisions(trial % 6, trial + 1);
        const before = intersectVerdicts(host, base);
        for (const extra of PLUGINS) {
          const after = intersectVerdicts(host, [...base, extra]);
          expect(strictness(after)).toBeGreaterThanOrEqual(strictness(before));
        }
      }
    }
  });

  it("commutative + permutation-invariant (order does not change result)", () => {
    for (const host of HOSTS) {
      for (let trial = 0; trial < 60; trial++) {
        const base = randDecisions(4, trial + 100);
        const baseline = intersectVerdicts(host, base);
        for (const perm of permute(base)) {
          expect(intersectVerdicts(host, perm)).toBe(baseline);
        }
      }
    }
  });

  it("idempotent: duplicating a decision changes nothing", () => {
    for (const host of HOSTS) {
      for (const d of PLUGINS) {
        expect(intersectVerdicts(host, [d])).toBe(intersectVerdicts(host, [d, d, d]));
      }
    }
  });

  it("deny is absorbing (host deny or any plugin deny → deny)", () => {
    for (const plugins of [[], ["no_objection"], ["observe"], ["escalate", "no_objection"]] as EnforcementDecision[][]) {
      expect(intersectVerdicts("deny", plugins)).toBe("deny");
    }
    for (const host of HOSTS) {
      expect(intersectVerdicts(host, ["deny"])).toBe("deny");
      expect(intersectVerdicts(host, ["no_objection", "deny", "observe"])).toBe("deny");
    }
  });

  it("permit is reachable ONLY from host permit + all no_objection", () => {
    // host permit, all no_objection → permit
    expect(intersectVerdicts("permit", [])).toBe("permit");
    expect(intersectVerdicts("permit", ["no_objection", "no_objection"])).toBe("permit");
    // any non-no_objection plugin decision removes permit
    for (const d of ["deny", "plugin_error", "escalate", "observe"] as EnforcementDecision[]) {
      expect(intersectVerdicts("permit", [d])).not.toBe("permit");
    }
    // a non-permit host can never become permit
    for (const host of ["escalate", "deny"] as HostDecision[]) {
      for (let trial = 0; trial < 50; trial++) {
        expect(intersectVerdicts(host, randDecisions(5, trial))).not.toBe("permit");
      }
    }
  });

  it("an unknown/garbage decision is treated as plugin_error, never as a permit", () => {
    const garbage = "totally_made_up" as unknown as EnforcementDecision;
    expect(intersectVerdicts("permit", [garbage])).toBe("plugin_error");
    // and adding it to a no-objection set still cannot yield permit
    expect(intersectVerdicts("permit", ["no_objection", garbage])).toBe("plugin_error");
  });

  it("a no_objection verdict never authorizes (permit comes only from the host)", () => {
    // The classic attack: four no_objection cannot override a host deny.
    expect(
      intersectVerdicts("deny", ["no_objection", "no_objection", "no_objection", "no_objection"]),
    ).toBe("deny");
  });
});
