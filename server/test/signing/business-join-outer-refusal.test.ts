// Exported outer admission returns a typed refusal for malformed callers.
// W-JOIN-BOUNDS
import {expect, it} from "vitest";
import {APPEND_CONTRACT} from "../../src/signing/business-append-contract.js";
import {joinOuterValid, type JoinRecord} from "../../src/signing/record-joins.js";
it("refuses a null body without throwing from the public outer validator", () => {
  const valid = structuredClone(APPEND_CONTRACT.lifecycle_events.admit.record) as unknown as JoinRecord;
  expect(joinOuterValid(valid)).toBe(true);
  const invalid = {...valid, body: null} as unknown as JoinRecord;
  expect(() => joinOuterValid(invalid)).not.toThrow();
  expect(joinOuterValid(invalid)).toBe(false);
});
