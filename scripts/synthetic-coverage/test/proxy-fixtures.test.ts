import { describe, expect, it } from "vitest";
import "../fixtures/proxy/proxy-env-isolation.js";
import "../fixtures/proxy/proxy-sse-ssrf.js";
import "../fixtures/proxy/proxy-tool-discovery.js";
import { listClaims } from "../registry.js";

const proxyClaims = listClaims().filter((claim) => ["15", "16", "17"].includes(claim.id));
const fixtures = proxyClaims.flatMap((claim) =>
  claim.fixtures.map((fixture) => ({ claim, fixture })),
);

expect(proxyClaims.map((claim) => claim.id).sort()).toEqual(["15", "16", "17"]);
expect(fixtures).toHaveLength(12);

describe("proxy synthetic fixtures", () => {
  for (const { claim, fixture } of fixtures) {
    it(`${claim.id}: ${fixture.name}`, async () => {
      const result = await fixture.fn();
      expect(result.passed, result.message).toBe(true);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  }
});
