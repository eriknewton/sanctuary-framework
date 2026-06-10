import { describe, expect, it } from "vitest";
import { loadAssuranceMatrix } from "../assurance-matrix.js";

describe("loadAssuranceMatrix", () => {
  it("parses the canonical 21 row matrix", () => {
    const rows = loadAssuranceMatrix();

    expect(rows).toHaveLength(21);
    expect(rows.map((row) => row.label)).toEqual(
      expect.arrayContaining([
        "Tamper-evident audit chain",
        "Egress enforcement: Linux (Castle Wall Phase 1)",
        "Identity signing authority (PR #270, raw identity_sign Tier 1)",
        "State envelope integrity / default verify-on-read",
        "Hostile-guest containment: macOS box launcher jails uncooperative plugins (B2 inner-confinement, seccomp-deny-AF_VSOCK)",
      ]),
    );
    expect(rows.map((row) => row.id)).toEqual(
      Array.from({ length: 21 }, (_, index) => String(index + 1)),
    );
  });
});
