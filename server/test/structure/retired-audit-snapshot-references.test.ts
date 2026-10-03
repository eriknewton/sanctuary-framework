// Capability prose: the review-sprint snapshots retired from the public tree on
// 2026-10-02 (AGENTS.md MUST-NEVER #9) stay retired. No source or public doc may
// point a reader back at them, and the passphrase regression guard in the wrap CLI
// keeps its invariant comment, now citing only a bare finding id.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

// Must match the files removed in the 2026-10-02 retirement PR; private copies
// live in the coordinator archive.
const RETIRED = [
  "SECURITY_AUDIT.md",
  "BUG_REPORT.md",
  "REMEDIATION_PLAN.md",
  "SPRINT_EVAL.md",
  "SPRINT_CONTRACT.md",
  "SPRINT_RESULT.md",
  "MERGE_GATE_REPORT.md",
  "DELTA_REVIEW_REPORT.md",
  "KNOWN_ISSUES.md",
  "DELTA_REVIEW_V0.9.0_RC1.md",
] as const;

// Public root docs plus the server source tree: the surfaces a reader follows.
const ROOT_DOCS = ["README.md", "SECURITY.md", "SANCTUARY_ARCHITECTURE.md", "ROADMAP.md", "ASSURANCE_MATRIX.md"];

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|md)$/.test(name)) out.push(full);
  }
  return out;
}

describe("retired audit snapshot references", () => {
  it("leaves no pointer to a retired snapshot in server source or the public root docs", () => {
    const files = [...walk(join(REPO_ROOT, "server", "src")), ...ROOT_DOCS.map((f) => join(REPO_ROOT, f))];
    const hits: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const name of RETIRED) {
        if (text.includes(name)) hits.push(`${relative(REPO_ROOT, file)} -> ${name}`);
      }
    }
    expect(hits).toEqual([]);
  });

  it("keeps the wrap CLI passphrase invariant comment, citing a bare finding id", () => {
    const source = readFileSync(join(REPO_ROOT, "server", "src", "wrap", "cli.ts"), "utf8");
    const anchor = "// Invariant: the resolved credential never reaches argv or the rewritten";
    const at = source.indexOf(anchor);
    expect(at, "missing invariant anchor").toBeGreaterThanOrEqual(0);
    expect(source.slice(at, at + 600)).toContain("Regression guard for private finding SEC-061");
  });
});
