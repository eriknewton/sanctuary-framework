/**
 * `entitlement/plan-catalog.ts` (Slice 1 — fleet billing plan catalog).
 *
 * Pure data + a pure lookup, no I/O and no crypto: covers the Team plan's
 * mapping onto the shipped v2 claim shape, the overage math, catalog
 * immutability, and barrel-export parity. No dollar amounts appear anywhere
 * in this file (public repo; pricing wording is owner-gated).
 */

import { describe, it, expect } from "vitest";
import * as entitlementBarrel from "../../src/entitlement/index.js";
import {
  ALL_ENTITLEMENT_FEATURE_FLAGS,
  DEFAULT_GRACE_DAYS,
  PLAN_CATALOG,
  PLAN_NAMES,
  TEAM_INCLUDED_NODES,
  TEAM_MAX_EXTRA_NODES,
  getPlanClaimTemplate,
  isPlanName,
} from "../../src/entitlement/plan-catalog.js";

describe("plan-catalog — catalog mapping correctness", () => {
  it("PLAN_NAMES contains exactly 'team' (Pro is deferred, D4)", () => {
    expect(PLAN_NAMES).toEqual(["team"]);
  });

  it("isPlanName accepts 'team' and rejects everything else, including near-misses", () => {
    expect(isPlanName("team")).toBe(true);
    expect(isPlanName("Team")).toBe(false);
    expect(isPlanName("pro")).toBe(false);
    expect(isPlanName("fleet")).toBe(false);
    expect(isPlanName("")).toBe(false);
    expect(isPlanName(undefined)).toBe(false);
    expect(isPlanName(42)).toBe(false);
  });

  it("the team template maps exactly onto D1: tier=team, pricingUnit=node, full feature set, shipped grace default", () => {
    const template = getPlanClaimTemplate("team");
    expect(template.tier).toBe("team");
    expect(template.pricingUnit).toBe("node");
    expect(template.defaultGraceDays).toBe(DEFAULT_GRACE_DAYS);
    expect(template.defaultGraceDays).toBe(14);
    // D2: Team gets the FULL current KNOWN_FEATURES set, not a subset.
    expect([...template.featureFlags].sort()).toEqual(
      [...ALL_ENTITLEMENT_FEATURE_FLAGS].sort(),
    );
    expect(template.featureFlags).toEqual([
      "roster",
      "policy-dist",
      "kill-safety",
      "console",
    ]);
  });

  it("getPlanClaimTemplate throws on a name outside the closed PlanName set (defense in depth past isPlanName)", () => {
    expect(() =>
      getPlanClaimTemplate("pro" as unknown as Parameters<typeof getPlanClaimTemplate>[0]),
    ).toThrow(/unknown plan/);
  });

  it("PLAN_CATALOG has exactly the plans PLAN_NAMES names, no more and no fewer (full-set parity, not a first-entry check)", () => {
    expect(Object.keys(PLAN_CATALOG).sort()).toEqual([...PLAN_NAMES].sort());
  });
});

describe("plan-catalog — overage math (entitledCount)", () => {
  it("entitledCount(0) = 10 (the flat included-node floor, D1)", () => {
    expect(getPlanClaimTemplate("team").entitledCount(0)).toBe(10);
    expect(getPlanClaimTemplate("team").entitledCount(0)).toBe(TEAM_INCLUDED_NODES);
  });

  it("entitledCount(3) = 13 (included floor + purchased overage)", () => {
    expect(getPlanClaimTemplate("team").entitledCount(3)).toBe(13);
  });

  it("entitledCount rejects a negative or non-integer overage rather than returning a wrong count", () => {
    const template = getPlanClaimTemplate("team");
    expect(() => template.entitledCount(-1)).toThrow(RangeError);
    expect(() => template.entitledCount(1.5)).toThrow(RangeError);
    expect(() => template.entitledCount(Number.NaN)).toThrow(RangeError);
  });

  it("TEAM_MAX_EXTRA_NODES is DERIVED as MAX_SAFE_INTEGER - TEAM_INCLUDED_NODES, not a bare literal (round-2 finding, register id EFC-01)", () => {
    expect(TEAM_MAX_EXTRA_NODES).toBe(Number.MAX_SAFE_INTEGER - TEAM_INCLUDED_NODES);
    expect(getPlanClaimTemplate("team").maxExtraNodes).toBe(TEAM_MAX_EXTRA_NODES);
    // The bound exists so the SUM never exceeds MAX_SAFE_INTEGER.
    expect(TEAM_INCLUDED_NODES + TEAM_MAX_EXTRA_NODES).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("entitledCount accepts extraNodes exactly AT maxExtraNodes (inclusive bound, sum is the safe-integer ceiling)", () => {
    const template = getPlanClaimTemplate("team");
    expect(template.entitledCount(TEAM_MAX_EXTRA_NODES)).toBe(Number.MAX_SAFE_INTEGER);
    expect(Number.isSafeInteger(template.entitledCount(TEAM_MAX_EXTRA_NODES))).toBe(true);
  });

  it("entitledCount rejects extraNodes one past maxExtraNodes and rejects an unsafe-integer input outright", () => {
    const template = getPlanClaimTemplate("team");
    expect(() => template.entitledCount(TEAM_MAX_EXTRA_NODES + 1)).toThrow(RangeError);
    // Number.MAX_SAFE_INTEGER + 1 is still `Number.isInteger`-true but NOT
    // `Number.isSafeInteger`-true — this is exactly the class the finding
    // named (an unsafe integer that a naive isInteger check would accept).
    expect(Number.isInteger(Number.MAX_SAFE_INTEGER + 1)).toBe(true);
    expect(Number.isSafeInteger(Number.MAX_SAFE_INTEGER + 1)).toBe(false);
    expect(() => template.entitledCount(Number.MAX_SAFE_INTEGER + 1)).toThrow(RangeError);
  });
});

describe("plan-catalog — immutability (catalog snapshot)", () => {
  it("PLAN_CATALOG, its team entry, and featureFlags are all frozen", () => {
    expect(Object.isFrozen(PLAN_CATALOG)).toBe(true);
    expect(Object.isFrozen(PLAN_CATALOG.team)).toBe(true);
    expect(Object.isFrozen(PLAN_CATALOG.team.featureFlags)).toBe(true);
    expect(Object.isFrozen(ALL_ENTITLEMENT_FEATURE_FLAGS)).toBe(true);
    expect(Object.isFrozen(PLAN_NAMES)).toBe(true);
  });

  it("mutating the frozen team template throws (ESM strict mode) and never corrupts the live catalog", () => {
    const before = getPlanClaimTemplate("team").pricingUnit;
    expect(() => {
      // @ts-expect-error — intentionally attempting a forbidden mutation.
      PLAN_CATALOG.team.pricingUnit = "seat";
    }).toThrow(TypeError);
    expect(getPlanClaimTemplate("team").pricingUnit).toBe(before);
  });
});

describe("plan-catalog — barrel parity (server/src/entitlement/index.ts)", () => {
  it("re-exports every plan-catalog symbol byte-identically, full set not first-entry", () => {
    expect(entitlementBarrel.PLAN_NAMES).toEqual(PLAN_NAMES);
    expect(entitlementBarrel.isPlanName).toBe(isPlanName);
    expect(entitlementBarrel.getPlanClaimTemplate).toBe(getPlanClaimTemplate);
    expect(entitlementBarrel.PLAN_CATALOG).toBe(PLAN_CATALOG);
    expect(entitlementBarrel.ALL_ENTITLEMENT_FEATURE_FLAGS).toBe(
      ALL_ENTITLEMENT_FEATURE_FLAGS,
    );
    expect(entitlementBarrel.TEAM_INCLUDED_NODES).toBe(TEAM_INCLUDED_NODES);
    expect(entitlementBarrel.TEAM_MAX_EXTRA_NODES).toBe(TEAM_MAX_EXTRA_NODES);
    expect(entitlementBarrel.DEFAULT_GRACE_DAYS).toBe(DEFAULT_GRACE_DAYS);
  });
});
