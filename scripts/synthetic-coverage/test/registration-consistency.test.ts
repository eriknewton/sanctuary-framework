import { describe, expect, it } from "vitest";
import "../register-all.js";
import { loadAssuranceMatrix } from "../assurance-matrix.js";
import { listClaims } from "../registry.js";

describe("canonical fixture row bindings", () => {
  it("binds every registered claim label to its actual assurance matrix row", () => {
    const rows = new Map(loadAssuranceMatrix().map((row) => [row.id, row]));
    const claims = listClaims();
    expect(claims.length).toBeGreaterThan(0);

    for (const claim of claims) {
      expect(rows.get(claim.id)?.label, `assurance row ${claim.id}: ${claim.label}`)
        .toBe(claim.label);
    }
  });
});
