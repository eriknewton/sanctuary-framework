/**
 * The fixed refusal literal the behavioural witnesses compare against equals
 * the boundary refusal the implementation returns. This file reads the
 * boundary refusal's own exports, so it checks the new surface itself and is
 * not a behavioural witness.
 */
import { describe, expect, it } from "vitest";
import {
  boundaryRefusal,
  fixedDenial,
  REFUSAL_TEXT,
  refusalResult,
} from "../../src/agent-native/safety-base.js";
import {
  EXPECTED_REFUSAL_TEXT,
  expectedRefusal,
  expectedRefusalBody,
} from "../helpers/expected-refusal.js";

describe("the witnesses' fixed refusal literal", () => {
  it("deep-equals refusalResult() and serializes to REFUSAL_TEXT", () => {
    expect(expectedRefusal()).toEqual(refusalResult());
    expect(EXPECTED_REFUSAL_TEXT).toBe(REFUSAL_TEXT);
    expect(expectedRefusalBody()).toEqual(boundaryRefusal());
  });

  it("the boundary refusal is one frozen object, and the fixed-denial alias returns it", () => {
    expect(refusalResult()).toBe(refusalResult());
    expect(Object.isFrozen(refusalResult())).toBe(true);
    expect(fixedDenial("audit:ref")).toBe(boundaryRefusal());
    expect(fixedDenial("audit:other", "unavailable", "hours")).toBe(boundaryRefusal());
  });
});
