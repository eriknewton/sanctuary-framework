import { describe, expect, it } from "vitest";
import "../fixtures/substrate-trust/attestation-envelope.js";
import "../fixtures/substrate-trust/audit-chain-checkpoint.js";
import "../fixtures/substrate-trust/certificate-to-key.js";
import "../fixtures/substrate-trust/custody-key-isolation.js";
import "../fixtures/substrate-trust/identity-signing.js";
import { listClaims } from "../registry.js";

const substrateClaims = listClaims().filter((claim) =>
  ["4", "5", "8", "18", "19"].includes(claim.id),
);
const fixtures = substrateClaims.flatMap((claim) =>
  claim.fixtures.map((fixture) => ({ claim, fixture })),
);

expect(substrateClaims.map((claim) => claim.id).sort()).toEqual([
  "18",
  "19",
  "4",
  "5",
  "8",
]);
expect(fixtures).toHaveLength(16);

describe("substrate trust synthetic fixtures", () => {
  for (const { claim, fixture } of fixtures) {
    it(`${claim.id}: ${fixture.name}`, async () => {
      const result = await fixture.fn();
      expect(result.passed, result.message).toBe(true);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  }
});
