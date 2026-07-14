/**
 * Castle Wall allowlist rule schema tests.
 *
 * Pure structural validation of AllowlistRule. Cryptographic checks live in
 * parse.test.ts; this file just exercises validateRule.
 */

import { describe, it, expect } from "vitest";
import {
  CASTLE_WALL_SCHEMA_VERSION_V1,
} from "../../../src/castle-wall/constants.js";
import {
  validateRule,
  type AllowlistRule,
} from "../../../src/castle-wall/allowlist/schema.js";

function validRule(): AllowlistRule {
  return {
    id: "rule-001",
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: "2026-05-03T12:00:00.000Z",
    description: "allow Anthropic",
    match: { host: "api.anthropic.com", port: 443, protocol: "tcp" },
    scope: { template_ids: ["claude-code"] },
    disposition: "allow",
  };
}

describe("castle-wall/allowlist/schema/validateRule", () => {
  it("accepts a fully populated valid rule", () => {
    expect(validateRule(validRule())).toEqual([]);
  });

  it("rejects an unknown schema_version", () => {
    const r = { ...validRule(), schema_version: 99 } as unknown as AllowlistRule;
    const issues = validateRule(r);
    expect(issues.some((s) => s.includes("schema_version"))).toBe(true);
  });

  it("rejects a rule with no match conditions", () => {
    const r: AllowlistRule = { ...validRule(), match: {} };
    const issues = validateRule(r);
    expect(issues.some((s) => s.includes("match"))).toBe(true);
  });

  it("rejects an unknown disposition", () => {
    const r = { ...validRule(), disposition: "nope" } as unknown as AllowlistRule;
    const issues = validateRule(r);
    expect(issues.some((s) => s.includes("disposition"))).toBe(true);
  });

  it("accepts host_pattern alone", () => {
    const r: AllowlistRule = { ...validRule(), match: { host_pattern: "api.*.openai.com" } };
    expect(validateRule(r)).toEqual([]);
  });

  it("accepts port-only match", () => {
    const r: AllowlistRule = { ...validRule(), match: { port: [443, 80] } };
    expect(validateRule(r)).toEqual([]);
  });

  it("rejects missing id", () => {
    const r = { ...validRule(), id: "" } as AllowlistRule;
    const issues = validateRule(r);
    expect(issues.some((s) => s.includes("id"))).toBe(true);
  });

  // IP / CIDR matcher (#380)

  it("accepts an ip-only match (single and array, both families)", () => {
    expect(validateRule({ ...validRule(), match: { ip: "1.1.1.1" } })).toEqual([]);
    expect(
      validateRule({ ...validRule(), match: { ip: ["1.1.1.1", "2001:4860:4860::8888"] } })
    ).toEqual([]);
  });

  it("accepts a cidr-only match (single and array, both families)", () => {
    expect(validateRule({ ...validRule(), match: { cidr: "10.0.0.0/8" } })).toEqual([]);
    expect(
      validateRule({ ...validRule(), match: { cidr: ["192.168.0.0/16", "2001:db8::/32"] } })
    ).toEqual([]);
  });

  it("rejects a malformed ip (fail closed, not silently dropped)", () => {
    const issues = validateRule({ ...validRule(), match: { ip: "999.1.1.1" } });
    expect(issues.some((s) => s.includes("ip"))).toBe(true);
  });

  it("rejects a malformed cidr (bad prefix and missing slash)", () => {
    expect(
      validateRule({ ...validRule(), match: { cidr: "10.0.0.0/33" } }).some((s) =>
        s.includes("cidr")
      )
    ).toBe(true);
    expect(
      validateRule({ ...validRule(), match: { cidr: "10.0.0.0" } }).some((s) =>
        s.includes("cidr")
      )
    ).toBe(true);
  });

  it("rejects one bad entry in an otherwise-valid ip array", () => {
    const issues = validateRule({ ...validRule(), match: { ip: ["1.1.1.1", "not-an-ip"] } });
    expect(issues.some((s) => s.includes("ip"))).toBe(true);
  });

  it("rejects a non-string ip entry", () => {
    const r = { ...validRule(), match: { ip: [1234] } } as unknown as AllowlistRule;
    expect(validateRule(r).some((s) => s.includes("ip"))).toBe(true);
  });

  // ---- codex round-6: type-level axis validation (Rust serde parity) ------

  it("rejects null axis values (Rust reads null as axis-absent => any-destination)", () => {
    for (const match of [{ host: null }, { ip: null }, { cidr: null }, { port: null }]) {
      const r = { ...validRule(), match } as unknown as AllowlistRule;
      expect(validateRule(r).length, JSON.stringify(match)).toBeGreaterThan(0);
    }
  });

  it("rejects wrong-typed axis scalars and members", () => {
    for (const match of [
      { host: 123 },
      { host: ["ok.example.com", 7] },
      { host: "" },
      { port: "8741" },
      { port: 70000 },
      { port: 0 },
      { port: 443.5 },
      { port: [443, "80"] },
      { host_pattern: "" },
      { host_pattern: 9 },
    ]) {
      const r = { ...validRule(), match } as unknown as AllowlistRule;
      expect(validateRule(r).length, JSON.stringify(match)).toBeGreaterThan(0);
    }
  });

  it("rejects empty axis arrays (present-but-empty differs across evaluators)", () => {
    for (const match of [{ host: [] }, { ip: [] }, { cidr: [] }, { port: [] }]) {
      const r = { ...validRule(), match } as unknown as AllowlistRule;
      expect(validateRule(r).length, JSON.stringify(match)).toBeGreaterThan(0);
    }
  });

  it("rejects an invalid protocol value", () => {
    const r = {
      ...validRule(),
      match: { host: "x.example.com", protocol: "quic" },
    } as unknown as AllowlistRule;
    expect(validateRule(r).length).toBeGreaterThan(0);
  });

  it("accepts all three protocol spellings", () => {
    for (const protocol of ["tcp", "udp", "tcp+udp"]) {
      const r = {
        ...validRule(),
        match: { host: "x.example.com", protocol },
      } as unknown as AllowlistRule;
      expect(validateRule(r)).toEqual([]);
    }
  });

  it("rejects unknown fields at rule, match, and scope level (daemon serde parity)", () => {
    const base = validRule();
    const cases: AllowlistRule[] = [
      { ...base, novel_field: true } as unknown as AllowlistRule,
      { ...base, match: { ...base.match, future_axis: ["x"] } } as unknown as AllowlistRule,
      { ...base, scope: { ...base.scope, group_ids: ["g"] } } as unknown as AllowlistRule,
    ];
    for (const r of cases) {
      const issues = validateRule(r);
      expect(issues.length).toBeGreaterThan(0);
      expect(issues.some((i) => i.includes("unknown field"))).toBe(true);
    }
  });

  it("accepts the modeled optional fields (derived, time_window)", () => {
    const r = {
      ...validRule(),
      derived: true,
      time_window: { start: "09:00", end: "17:00" },
    } as AllowlistRule;
    expect(validateRule(r)).toEqual([]);
  });

  it("rejects array-valued match/scope/time_window (Rust refuses arrays for structs)", () => {
    for (const r of [
      { ...validRule(), match: [] },
      { ...validRule(), scope: [] },
      { ...validRule(), time_window: [] },
    ] as unknown as AllowlistRule[]) {
      expect(validateRule(r).length).toBeGreaterThan(0);
    }
  });

  it("rejects malformed scope id lists", () => {
    for (const scope of [
      { agent_ids: "not-an-array" },
      { agent_ids: [""] },
      { template_ids: [42] },
    ]) {
      const r = { ...validRule(), scope } as unknown as AllowlistRule;
      expect(validateRule(r).length, JSON.stringify(scope)).toBeGreaterThan(0);
    }
  });

  // --- S5-0 (2026-07-14): scope.uids, the per-uid rule-scope axis ---

  it("accepts a rule scoped to one or more uids", () => {
    const r = { ...validRule(), scope: { uids: [601] } };
    expect(validateRule(r)).toEqual([]);
    const r2 = { ...validRule(), scope: { uids: [600, 601] } };
    expect(validateRule(r2)).toEqual([]);
  });

  it("accepts uids composed alongside agent_ids/template_ids (OR-composition axis)", () => {
    const r = {
      ...validRule(),
      scope: { agent_ids: ["specific-agent"], template_ids: ["coding-assistant"], uids: [601] },
    };
    expect(validateRule(r)).toEqual([]);
  });

  it("rejects malformed scope.uids", () => {
    for (const scope of [
      { uids: "not-an-array" },
      { uids: [0] }, // root can never be a scope member
      { uids: [-1] },
      { uids: [6.5] },
      { uids: ["601"] },
      { uids: [0x100000000] }, // above UInt32.max: fails the sysext [UInt32] decode (LOW-1)
    ]) {
      const r = { ...validRule(), scope } as unknown as AllowlistRule;
      expect(validateRule(r).length, JSON.stringify(scope)).toBeGreaterThan(0);
    }
  });

  it("accepts scope.uids at exactly UInt32.max (boundary)", () => {
    const r = { ...validRule(), scope: { uids: [0xffffffff] } };
    expect(validateRule(r)).toEqual([]);
  });

  it("an empty scope.uids array means 'all' (same convention as agent_ids/template_ids)", () => {
    const r = { ...validRule(), scope: { uids: [] } };
    expect(validateRule(r)).toEqual([]);
  });
});
