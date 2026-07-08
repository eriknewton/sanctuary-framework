/**
 * Castle Wall Observe / Learn Allow-List v1 -- synthesis tests.
 *
 * CI DoD test 2: every suggested rule passes the existing rule validator; a
 * malformed one is dropped, never offered.
 */

import { describe, it, expect } from "vitest";
import {
  synthesizeCandidateRule,
  synthesizeCandidateRules,
  naiveRegisteredDomain,
  widenableRegisteredDomain,
  REFUSED_MULTI_LABEL_PUBLIC_SUFFIXES,
} from "../../../src/castle-wall/observe/synthesize.js";
import { validateRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { CandidateObservation } from "../../../src/castle-wall/observe/types.js";

function candidate(overrides: Partial<CandidateObservation> = {}): CandidateObservation {
  return {
    agent_id: "agent-1",
    agent_template: "claude-code",
    host: "api.example.com",
    ip: "203.0.113.5",
    port: 443,
    protocol: "tcp",
    hostname_source: "sni",
    times_seen: 3,
    first_seen: "2026-07-07T10:00:00.000Z",
    last_seen: "2026-07-07T10:05:00.000Z",
    would_be_disposition: "denied",
    exfil_risk: false,
    ...overrides,
  };
}

const CREATED_AT = "2026-07-07T12:00:00.000Z";

describe("synthesizeCandidateRule (D-Q2 default: exact host:port)", () => {
  it("synthesizes a valid, exact host:port allow rule scoped to the agent's template by default", () => {
    const rule = synthesizeCandidateRule(candidate(), CREATED_AT);
    expect(rule).not.toBeNull();
    expect(validateRule(rule!)).toEqual([]);
    expect(rule!.disposition).toBe("allow");
    expect(rule!.derived).toBe(true);
    expect(rule!.match).toEqual({ host: ["api.example.com"], port: [443], protocol: "tcp" });
    expect(rule!.scope).toEqual({ template_ids: ["claude-code"] });
  });

  it("falls back to an ip match when no hostname was observed", () => {
    const rule = synthesizeCandidateRule(candidate({ host: null }), CREATED_AT);
    expect(rule).not.toBeNull();
    expect(validateRule(rule!)).toEqual([]);
    expect(rule!.match).toEqual({ ip: ["203.0.113.5"], port: [443], protocol: "tcp" });
  });

  it("returns null (never offered) for an opaque observation with no usable host or ip", () => {
    const rule = synthesizeCandidateRule(candidate({ host: null, ip: "" }), CREATED_AT);
    expect(rule).toBeNull();
  });

  it("returns null for a candidate whose ip is not a valid IP literal (fails validateRule)", () => {
    const rule = synthesizeCandidateRule(candidate({ host: null, ip: "not-an-ip" }), CREATED_AT);
    expect(rule).toBeNull();
  });

  it("scopes to the agent instance under per_instance_domain", () => {
    const rule = synthesizeCandidateRule(candidate(), CREATED_AT, "per_instance_domain");
    expect(rule).not.toBeNull();
    expect(rule!.scope).toEqual({ agent_ids: ["agent-1"] });
    expect(rule!.match).toEqual({ host: ["api.example.com"], port: [443], protocol: "tcp" });
  });

  it("is deterministic: the same candidate + granularity always yields the same rule id", () => {
    const a = synthesizeCandidateRule(candidate(), CREATED_AT);
    const b = synthesizeCandidateRule(candidate(), "2026-07-08T00:00:00.000Z");
    expect(a!.id).toBe(b!.id);
  });

  it("emits a UDP protocol rule when the observation was UDP", () => {
    const rule = synthesizeCandidateRule(candidate({ protocol: "udp" }), CREATED_AT);
    expect(rule!.match.protocol).toBe("udp");
  });
});

describe("synthesizeCandidateRule (D-Q2 explicit opt-in: per_template_etld1)", () => {
  it("widens to the naive registered domain, scoped to template, and shows the widening in the description", () => {
    const rule = synthesizeCandidateRule(candidate({ host: "api.example.com" }), CREATED_AT, "per_template_etld1");
    expect(rule).not.toBeNull();
    expect(validateRule(rule!)).toEqual([]);
    expect(rule!.match).toEqual({
      host: ["example.com"],
      host_pattern: "*.example.com",
      port: [443],
      protocol: "tcp",
    });
    expect(rule!.description).toMatch(/widened/);
  });

  it("never widens an IP-only observation to a domain grant -- returns null instead", () => {
    const rule = synthesizeCandidateRule(candidate({ host: null }), CREATED_AT, "per_template_etld1");
    expect(rule).toBeNull();
  });

  it("returns null for a single-label host (no domain to widen to)", () => {
    const rule = synthesizeCandidateRule(candidate({ host: "localhost" }), CREATED_AT, "per_template_etld1");
    expect(rule).toBeNull();
  });

  it("REFUSES a widening that lands on a known multi-label public suffix (co.uk), never signs *.co.uk (FIX 3)", () => {
    const rule = synthesizeCandidateRule(candidate({ host: "shop.foo.co.uk" }), CREATED_AT, "per_template_etld1");
    expect(rule).toBeNull();
  });

  it("REFUSES another public-suffix widening (com.au)", () => {
    const rule = synthesizeCandidateRule(candidate({ host: "www.acme.com.au" }), CREATED_AT, "per_template_etld1");
    expect(rule).toBeNull();
  });

  it("still allows a legitimate two-label registered domain widening (example.com)", () => {
    const rule = synthesizeCandidateRule(candidate({ host: "api.example.com" }), CREATED_AT, "per_template_etld1");
    expect(rule).not.toBeNull();
    expect(rule!.match.host_pattern).toBe("*.example.com");
  });
});

describe("widenableRegisteredDomain (public-suffix refusal chokepoint, FIX 3)", () => {
  it("returns the registered domain for a legitimate host", () => {
    expect(widenableRegisteredDomain("api.example.com")).toBe("example.com");
  });

  it("returns null when the naive result is a known multi-label public suffix", () => {
    expect(widenableRegisteredDomain("shop.foo.co.uk")).toBeNull();
    expect(widenableRegisteredDomain("www.acme.com.au")).toBeNull();
    expect(widenableRegisteredDomain("site.co.jp")).toBeNull();
  });

  it("returns null for an IP literal or single-label host", () => {
    expect(widenableRegisteredDomain("203.0.113.5")).toBeNull();
    expect(widenableRegisteredDomain("localhost")).toBeNull();
  });

  it("every entry in the refusal set is exactly two dot-separated labels (matches the naive heuristic's output shape)", () => {
    for (const suffix of REFUSED_MULTI_LABEL_PUBLIC_SUFFIXES) {
      expect(suffix.split(".").length, `suffix ${suffix} must be two labels`).toBe(2);
    }
    expect(REFUSED_MULTI_LABEL_PUBLIC_SUFFIXES.size).toBeGreaterThan(0);
  });
});

describe("naiveRegisteredDomain", () => {
  it("returns the last two labels for a multi-label hostname", () => {
    expect(naiveRegisteredDomain("api.example.com")).toBe("example.com");
    expect(naiveRegisteredDomain("deep.sub.api.example.com")).toBe("example.com");
  });

  it("returns null for an IP literal", () => {
    expect(naiveRegisteredDomain("203.0.113.5")).toBeNull();
    expect(naiveRegisteredDomain("::1")).toBeNull();
  });

  it("returns null for a single-label host", () => {
    expect(naiveRegisteredDomain("localhost")).toBeNull();
  });
});

describe("synthesizeCandidateRules (batch)", () => {
  it("returns a rule per valid candidate and drops unsynthesizable ones without aborting the batch", () => {
    const good = candidate();
    const bad = candidate({ host: null, ip: "", agent_id: "agent-2" });
    const { rules, dropped } = synthesizeCandidateRules([good, bad], CREATED_AT);
    expect(rules).toHaveLength(1);
    expect(dropped).toHaveLength(1);
    expect(dropped[0]).toBe(bad);
    for (const rule of rules) {
      expect(validateRule(rule)).toEqual([]);
    }
  });

  it("applies a per-row granularity function", () => {
    const a = candidate({ host: "a.example.com" });
    const b = candidate({ host: "b.example.com", agent_id: "agent-2" });
    const { rules } = synthesizeCandidateRules([a, b], CREATED_AT, (c) =>
      c.agent_id === "agent-2" ? "per_instance_domain" : "per_template_domain",
    );
    expect(rules[0]!.scope).toEqual({ template_ids: ["claude-code"] });
    expect(rules[1]!.scope).toEqual({ agent_ids: ["agent-2"] });
  });

  it("defaults to per_template_domain when no granularity function is supplied", () => {
    const { rules } = synthesizeCandidateRules([candidate()], CREATED_AT);
    expect(rules[0]!.scope).toEqual({ template_ids: ["claude-code"] });
  });
});
