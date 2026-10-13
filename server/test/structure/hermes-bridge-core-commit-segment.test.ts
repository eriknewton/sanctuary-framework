import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SOURCE = readFileSync(join(process.cwd(), "src/hermes-memory-bridge/bridge-core.ts"), "utf8");

describe("Hermes bridge core commit segment structure", () => {
  it("keeps the final record read and commit check in one synchronous segment", () => {
    const hook = SOURCE.indexOf("private async assertAllowedToCommit");
    const start = SOURCE.indexOf("const entry = this.ledger.snapshot().entry;", hook);
    const end = SOURCE.indexOf("const checked = this.ledger.commitCheck", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);

    const segment = SOURCE.slice(start, end).replace(/\/\/.*$/gmu, "");
    expect(segment).not.toMatch(/\bawait\b/u);
    expect(segment).not.toMatch(/\bPromise\b/u);
    expect(segment).toContain("const record = this.recordSnapshot(slot.recordId);");
    expect(segment).toContain("const recordCurrent =");
  });
});
