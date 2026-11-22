import { describe, expect, it } from "vitest";
import {
  EXPECTED_ASSURANCE_ROW_COUNT,
  PROVEN_TESTS_STATUS,
  loadAssuranceMatrix,
  normalizeStatus,
} from "../assurance-matrix.js";

describe("loadAssuranceMatrix", () => {
  it("parses the canonical matrix at its pinned row count", () => {
    const rows = loadAssuranceMatrix();

    expect(rows).toHaveLength(EXPECTED_ASSURANCE_ROW_COUNT);
    expect(rows.map((row) => row.label)).toEqual(
      expect.arrayContaining([
        "Tamper-evident audit chain",
        "Egress enforcement: Linux (Castle Wall Phase 1)",
        "Identity signing authority (PR #270, raw identity_sign Tier 1)",
        "State envelope integrity / default verify-on-read",
        "Hostile-guest containment: macOS box launcher jails uncooperative plugins (B2 inner-confinement, seccomp-deny-AF_VSOCK)",
        "Verifiable transparency checkpoint format and offline verifier",
      ]),
    );
    expect(rows.map((row) => row.id)).toEqual(
      Array.from({ length: EXPECTED_ASSURANCE_ROW_COUNT }, (_, index) => String(index + 1)),
    );
  });

  it("reads proven (tests) as proven, so the proven-row fixture rule still applies", () => {
    expect(normalizeStatus(PROVEN_TESTS_STATUS)).toBe("proven");
    expect(normalizeStatus("proven")).toBe("proven");
    expect(normalizeStatus("proven (drill)")).toBe("unknown");

    const byLabel = new Map(loadAssuranceMatrix().map((row) => [row.label, row.status]));
    expect(byLabel.get("State encryption")).toBe("proven");
    expect(byLabel.get("Approval gating (Tier 1 / Tier 2 / Tier 3 policy)")).toBe("proven");
    expect([...byLabel.values()]).not.toContain("unknown");
  });
});
