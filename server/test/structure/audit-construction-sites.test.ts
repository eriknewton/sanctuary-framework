/** Audit log construction options are confined to a reviewed set of files. */
// fail-before-exempt: this test pins the reviewed set of construction sites, which the base already satisfies; its witness is the mutant that adds an unreviewed site.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

const sourceRoot = fileURLToPath(new URL("../../src/", import.meta.url));
// Must match the reviewed construction branch in src/operational/audit-log.ts.
const reviewedFiles = [
  "cli/audit-chain-repair-plan.ts",
  "cli/castle-wall.ts",
  "operational/audit-store-split.ts",
  "wrap/cli.ts",
  "wrap/init.ts",
];

function matchingFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return matchingFiles(path);
    return entry.isFile() && /\bintegrityMode\s*:\s*["']lenient["']/.test(readFileSync(path, "utf8"))
      ? [relative(sourceRoot, path)]
      : [];
  });
}

it("audit construction sites are the reviewed set", () => {
  // Full-set equality makes every new file require review, including non-CLI construction sites.
  expect(matchingFiles(sourceRoot).sort()).toEqual([...reviewedFiles].sort());
});
