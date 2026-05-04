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
});
