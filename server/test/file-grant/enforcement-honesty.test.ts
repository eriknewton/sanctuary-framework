/**
 * Governed File-Grant v1 -- pure enforcement-honesty verdict (Fix 3).
 *
 * `determineEnforcement` is the single place the met/unverified/unmet decision
 * is made. The never-overclaim rule (Invariant #5, build spec section 10): a
 * bare uid split is NEVER "met"; "met" requires an actual readability
 * verification; a same-owner or no-agent-uid box is honestly "unmet".
 */

import { describe, expect, it } from "vitest";

import { determineEnforcement } from "../../src/file-grant/lifecycle.js";

describe("determineEnforcement (Fix 3 honesty)", () => {
  it("unmet when no dedicated agent uid is configured", () => {
    expect(
      determineEnforcement({ agentUid: null, sourceOwnerUid: 501, readVerified: false }),
    ).toBe("unmet");
  });

  it("unmet when the source owner uid is unknown", () => {
    expect(
      determineEnforcement({ agentUid: 502, sourceOwnerUid: null, readVerified: false }),
    ).toBe("unmet");
  });

  it("unmet when the agent uid equals the source-file owner (no boundary; kills the sudo false-met)", () => {
    expect(
      determineEnforcement({ agentUid: 502, sourceOwnerUid: 502, readVerified: false }),
    ).toBe("unmet");
  });

  it("unverified for a real uid split with NO on-hardware readability verification", () => {
    expect(
      determineEnforcement({ agentUid: 502, sourceOwnerUid: 501, readVerified: false }),
    ).toBe("unverified");
  });

  it("met ONLY when a distinct agent uid's read access has actually been verified", () => {
    expect(
      determineEnforcement({ agentUid: 502, sourceOwnerUid: 501, readVerified: true }),
    ).toBe("met");
  });

  it("never met from a uid split alone, even when verified but same-owner", () => {
    // Defensive: verification cannot manufacture a boundary that does not exist.
    expect(
      determineEnforcement({ agentUid: 502, sourceOwnerUid: 502, readVerified: true }),
    ).toBe("unmet");
  });
});
