import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
// Single source of truth for the fixture set (shared with the baseline
// generator and the PR ratchet test, so the three can never drift).
import "./register-all.js";
import { buildReport, renderMarkdownSummary } from "./report.js";

function findRepoRoot(start = process.cwd()): string {
  let current = resolve(start);
  while (true) {
    if (existsSync(resolve(current, "ASSURANCE_MATRIX.md"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      throw new Error(`Unable to locate repository root from ${start}`);
    }
    current = parent;
  }
}

async function main(): Promise<void> {
  const platform = process.platform === "darwin" ? "macos" : "linux";
  const sha = process.env.GITHUB_SHA ?? "local";
  const report = await buildReport({ platform, sha });
  const outDir = resolve(findRepoRoot(), "scripts/synthetic-coverage/.out");
  mkdirSync(outDir, { recursive: true });
  writeFileSync(resolve(outDir, "report.json"), JSON.stringify(report, null, 2));
  writeFileSync(resolve(outDir, "report.md"), renderMarkdownSummary(report));
  console.log(renderMarkdownSummary(report));
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
