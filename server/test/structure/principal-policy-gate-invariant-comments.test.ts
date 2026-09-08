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

/**
 * The runtime freezes whatever `principal-policy.yaml` resolves to as the
 * policy (AGENTS.md MUST-NEVER #7), so EVERY reader of that path must use the
 * no-follow, regular-file-only custody read. One reader on a plain
 * symlink-following `readFile` reopens the class the others closed: the
 * shipped surfaces would disagree about whether a planted link is the policy.
 */
describe("every principal-policy reader uses the no-follow custody read", () => {
  const READERS = [
    // The runtime's own load, which is the read the whole invariant is about.
    "server/src/principal-policy/loader.ts",
    // `sanctuary doctor`, which may not be more permissive than the reader
    // whose health it reports.
    "server/src/cli/doctor.ts",
    // The federation policy-push hash source.
    "server/src/cli/federation.ts",
    // `sanctuary agents show` / `agents config`, both the display read and the
    // read-then-rewrite mutation base.
    "server/src/cli/agents/cli.ts",
  ] as const;

  for (const reader of READERS) {
    it(`reads the policy path through readFileCustody in ${reader}`, () => {
      const source = read(reader);
      // Every read site in these files names the path `policyPath`, derived
      // from the single `principalPolicyPath` definition in loader.ts.
      expect(source).toContain("principalPolicyPath");
      expect(source).toContain("readFileCustody(policyPath");
      // A bare `readFile(policyPath` follows a symlink at that path, so it
      // would report (or rewrite from) a policy this fortress does not own.
      // Scoped to the policy path on purpose: these files legitimately read
      // other files with a plain readFile.
      expect(source).not.toMatch(/[^a-zA-Z]readFile\(policyPath/);
    });
  }
});
