import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

function read(relativeToRepoRoot: string): string {
  return readFileSync(join(REPO_ROOT, relativeToRepoRoot), "utf8");
}

function around(source: string, anchor: string): string {
  const index = source.indexOf(anchor);
  expect(index, `missing source anchor: ${anchor}`).toBeGreaterThanOrEqual(0);
  return source.slice(Math.max(0, index - 1_100), index + anchor.length + 450);
}

function expectNear(source: string, anchor: string, snippets: readonly string[]): void {
  const window = around(source, anchor);
  for (const snippet of snippets) {
    expect(window).toContain(snippet);
  }
}

describe("Principal-policy gate invariant comment hygiene", () => {
  it("keeps the approval proof rebinding rationale at proofMatches", () => {
    const source = read("server/src/principal-policy/gate.ts");

    expectNear(source, "const proofMatches =", [
      "a bearer approval_ref is not authority by",
      "hash equality binds the current args hash",
      "compound-plan proofs out of the direct-tool path",
      "cross-session proof theft",
      "field-splice substitutions",
    ]);
  });

  it("keeps the single-use replay rationale at consumeIfUnconsumed", () => {
    const source = read("server/src/principal-policy/gate.ts");

    expectNear(source, "const consumed = this.approvalProofStore.consumeIfUnconsumed(approvalRef);", [
      "Single-use replay invariant",
      "linearization point",
      "deny instead of reusing a once-valid human approval",
    ]);
  });
});
