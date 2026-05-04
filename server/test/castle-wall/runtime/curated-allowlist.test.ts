/**
 * Castle Wall runtime curated-allowlist tests.
 *
 * Asserts the E6.1 default-not-enabled invariant and the resolveCuratedRules
 * filter; ensures the canonical curated set is frozen and can't be mutated
 * by callers.
 */

import { describe, it, expect } from "vitest";

import {
  CURATED_ALLOWLIST,
  resolveCuratedRules,
} from "../../../src/castle-wall/runtime/curated-allowlist.js";

describe("castle-wall/runtime/curated-allowlist : invariants", () => {
  it("ships at least one curated entry", () => {
    expect(CURATED_ALLOWLIST.length).toBeGreaterThan(0);
  });

  it("default_enabled is false on every curated entry (E6.1)", () => {
    for (const entry of CURATED_ALLOWLIST) {
      expect(entry.default_enabled).toBe(false);
    }
  });

  it("every curated rule has disposition 'allow'", () => {
    for (const entry of CURATED_ALLOWLIST) {
      expect(entry.rule.disposition).toBe("allow");
    }
  });

  it("every curated rule_id matches its embedded rule.id", () => {
    for (const entry of CURATED_ALLOWLIST) {
      expect(entry.rule.id).toBe(entry.rule_id);
    }
  });

  it("curated set is frozen", () => {
    expect(Object.isFrozen(CURATED_ALLOWLIST)).toBe(true);
    expect(Object.isFrozen(CURATED_ALLOWLIST[0])).toBe(true);
  });
});

describe("castle-wall/runtime/curated-allowlist : resolveCuratedRules", () => {
  it("returns only the rules whose ids the operator selected", () => {
    const all = CURATED_ALLOWLIST.map((e) => e.rule_id);
    const ids = [all[0]!];
    const rules = resolveCuratedRules(ids);
    expect(rules.length).toBe(1);
    expect(rules[0]!.id).toBe(ids[0]);
  });

  it("returns empty when no ids selected", () => {
    expect(resolveCuratedRules([]).length).toBe(0);
  });

  it("ignores unknown rule ids", () => {
    const rules = resolveCuratedRules(["does-not-exist"]);
    expect(rules.length).toBe(0);
  });
});
