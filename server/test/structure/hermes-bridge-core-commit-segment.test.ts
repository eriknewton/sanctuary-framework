import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SOURCE = readFileSync(join(process.cwd(), "src/hermes-memory-bridge/bridge-core.ts"), "utf8");

describe("Hermes bridge core commit segment structure", () => {
  it("keeps the final record read and commit check in one synchronous segment", () => {
    const hook = SOURCE.indexOf("private async assertAllowedToCommit");
    const end = SOURCE.indexOf("const checked = this.ledger.commitCheck", hook);
    // Pin the final snapshot after admission durability; the earlier snapshot precedes an intentional await.
    const start = SOURCE.lastIndexOf("const entry = this.ledger.snapshot().entry;", end);
    expect(start).toBeGreaterThan(-1);
    const admission = SOURCE.indexOf('kind: "insert_admitted"', hook);
    const durable = SOURCE.indexOf("await this.awaitDurabilityForAllow(slot)", admission);
    expect(admission).toBeGreaterThan(hook);
    expect(durable).toBeGreaterThan(admission);
    expect(start).toBeGreaterThan(durable);
    expect(end).toBeGreaterThan(start);

    const segment = SOURCE.slice(start, end).replace(/\/\/.*$/gmu, "");
    expect(segment).not.toMatch(/\bawait\b/u);
    expect(segment).not.toMatch(/\bPromise\b/u);
    expect(segment).toContain("const record = this.recordSnapshot(slot.recordId);");
    expect(segment).toContain("const recordCurrent =");
  });
});
