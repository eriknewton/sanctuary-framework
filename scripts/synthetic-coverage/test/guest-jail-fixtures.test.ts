import { describe, expect, it } from "vitest";
import "../fixtures/castle-wall/guest-jail-confinement.js";
import { listClaims } from "../registry.js";

// Row 21: hostile-guest containment (B2 inner-confinement, seccomp-deny-AF_VSOCK).
const guestJailClaim = listClaims().find((claim) => claim.id === "21");

expect(guestJailClaim, "row-21 guest-jail claim is registered").toBeDefined();
expect(guestJailClaim!.fixtures.length, "row-21 has at least one fixture").toBeGreaterThanOrEqual(1);

describe("row-21 hostile-guest jail synthetic fixtures", () => {
  for (const fixture of guestJailClaim!.fixtures) {
    it(`21: ${fixture.name}`, async () => {
      const result = await fixture.fn();
      expect(result.passed, result.message).toBe(true);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  }
});
