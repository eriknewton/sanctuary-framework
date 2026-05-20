import { describe, expect, it } from "vitest";
import "../fixtures/audit-and-envelope/audit-chain-verifier.js";
import "../fixtures/audit-and-envelope/state-envelope-migration.js";
import { listClaims } from "../registry.js";

const auditEnvelopeClaims = listClaims().filter((claim) => ["4", "6"].includes(claim.id));
const fixtures = auditEnvelopeClaims.flatMap((claim) =>
  claim.fixtures.map((fixture) => ({ claim, fixture })),
);

expect(auditEnvelopeClaims.map((claim) => claim.id).sort()).toEqual(["4", "6"]);
expect(fixtures).toHaveLength(9);

describe("audit-and-envelope synthetic fixtures", () => {
  for (const { claim, fixture } of fixtures) {
    it(`${claim.id}: ${fixture.name}`, async () => {
      const result = await fixture.fn();
      expect(result.passed, result.message).toBe(true);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  }
});
