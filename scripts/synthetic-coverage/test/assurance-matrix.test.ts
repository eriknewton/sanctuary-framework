import { describe, expect, it } from "vitest";
import { loadAssuranceMatrix } from "../assurance-matrix.js";

describe("loadAssuranceMatrix", () => {
  it("parses the canonical 20 row matrix", () => {
    const rows = loadAssuranceMatrix();

    expect(rows).toHaveLength(20);
    expect(rows.map((row) => row.label)).toEqual(
      expect.arrayContaining([
        "Tamper-evident audit chain",
        "Egress enforcement: Linux (Castle Wall Phase 1)",
        "Identity signing authority (PR #270, raw identity_sign Tier 1)",
        "State envelope integrity / default verify-on-read",
      ]),
    );
    expect(rows.map((row) => row.id)).toEqual(
      Array.from({ length: 20 }, (_, index) => String(index + 1)),
    );
  });
});
