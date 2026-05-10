/**
 * AgentCard per_day_max zero-cap rejection at policy-load (full-sweep #84).
 *
 * per_day_max: 0 is rejected at validation time. Operators should omit
 * the capability entirely to ban it, not set a zero cap.
 */

import { describe, it, expect } from "vitest";

import { validateCapability } from "../../src/agent-contract/schema.js";
import { AgentCardSchemaError } from "../../src/agent-contract/errors.js";

describe("validateCapability per_day_max zero-cap rejection (#84)", () => {
  it("rejects per_day_max: 0 at validation time", () => {
    expect(() =>
      validateCapability({
        kind: "read-slot",
        target: "ns:*",
        constraints: { per_day_max: 0 },
      })
    ).toThrow(AgentCardSchemaError);
    expect(() =>
      validateCapability({
        kind: "read-slot",
        target: "ns:*",
        constraints: { per_day_max: 0 },
      })
    ).toThrow(/per_day_max must be a positive integer/);
  });

  it("rejects negative per_day_max", () => {
    expect(() =>
      validateCapability({
        kind: "read-slot",
        target: "ns:*",
        constraints: { per_day_max: -5 },
      })
    ).toThrow(/per_day_max must be a positive integer/);
  });

  it("accepts per_day_max: 1 (minimum valid)", () => {
    const result = validateCapability({
      kind: "read-slot",
      target: "ns:*",
      constraints: { per_day_max: 1 },
    });
    expect(result.constraints?.per_day_max).toBe(1);
  });

  it("accepts capability without constraints (no per_day_max)", () => {
    const result = validateCapability({
      kind: "read-slot",
      target: "ns:*",
    });
    expect(result.constraints).toBeUndefined();
  });
});
