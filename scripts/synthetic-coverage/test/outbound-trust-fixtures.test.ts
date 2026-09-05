import { describe, expect, it } from "vitest";
import "../fixtures/outbound-trust/context-gate-source-of-truth.js";
import "../fixtures/outbound-trust/query-anonymity.js";
import { listClaims } from "../registry.js";

const outboundClaims = listClaims().filter((claim) => ["14", "15"].includes(claim.id));
const fixtures = outboundClaims.flatMap((claim) =>
  claim.fixtures.map((fixture) => ({ claim, fixture })),
);

expect(outboundClaims.map((claim) => claim.id).sort()).toEqual(["14", "15"]);
expect(fixtures).toHaveLength(8);

describe("outbound-trust synthetic fixtures", () => {
  for (const { claim, fixture } of fixtures) {
    it(`${claim.id}: ${fixture.name}`, async () => {
      const result = await fixture.fn();
      expect(result.passed, result.message).toBe(true);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  }
});
