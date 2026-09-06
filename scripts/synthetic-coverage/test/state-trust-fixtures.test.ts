import { describe, expect, it } from "vitest";
import "../fixtures/state-trust/config-profile-fail-closed.js";
import "../fixtures/state-trust/critical-audit-durability.js";
import "../fixtures/state-trust/exit-bundle.js";
import { listClaims } from "../registry.js";

const stateTrustClaims = listClaims().filter((claim) => ["3", "7", "13"].includes(claim.id));
const fixtures = stateTrustClaims.flatMap((claim) =>
  claim.fixtures.map((fixture) => ({ claim, fixture })),
);

expect(stateTrustClaims.map((claim) => claim.id).sort()).toEqual(["13", "3", "7"]);
expect(fixtures).toHaveLength(14);

describe("state-trust synthetic fixtures", () => {
  for (const { claim, fixture } of fixtures) {
    it(`${claim.id}: ${fixture.name}`, async () => {
      const result = await fixture.fn();
      expect(result.passed, result.message).toBe(true);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  }
});
