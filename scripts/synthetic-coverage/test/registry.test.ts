import { describe, expect, it } from "vitest";
import { getClaim, listClaims, registerFixture } from "../registry.js";

const pass = async () => ({ passed: true, durationMs: 1 });

describe("fixture registry", () => {
  it("starts empty, dedupes by claim id and fixture name, and sorts by id", () => {
    expect(listClaims()).toEqual([]);
    registerFixture("999", "Synthetic test claim", "same-fixture", pass);
    registerFixture("999", "Synthetic test claim", "same-fixture", pass);
    expect(getClaim("999")?.fixtures).toHaveLength(1);

    registerFixture("1001", "Later synthetic claim", "later-fixture", pass);
    registerFixture("1000", "Earlier synthetic claim", "earlier-fixture", pass);
    expect(listClaims().map((claim) => claim.id)).toEqual(["999", "1000", "1001"]);
  });
});
