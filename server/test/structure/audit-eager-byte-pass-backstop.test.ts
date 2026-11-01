import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("append fingerprint handoff to the byte pass", () => {
  it("pins the minimum interval and forbids append-time fingerprint refresh", () => {
    const source = readFileSync(new URL("../../src/operational/audit-log.ts", import.meta.url), "utf8");
    // Must match ensureFreshEagerView in operational/audit-log.ts: both clocks
    // independently require the byte pass after an own write clears its hint.
    expect(source).toMatch(/const backstopDue\s*=[\s\S]*?Math\.min\(this\.eagerBytePassIntervalMs, this\.eagerReverifyIntervalMs\)/);
    const append = source.slice(source.indexOf("private async persistChainedEntry("), source.indexOf("private trimInMemoryRetention("));
    expect(append).toContain("this.expectedStoreFingerprint = null");
    expect(append).not.toContain("refreshExpectedStoreFingerprint()");
    expect(append).not.toMatch(/lastFullVerifyAtMs\s*=|integrityFindings\s*=/);
  });
});
