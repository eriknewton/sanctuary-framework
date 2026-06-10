/**
 * Repo-wide retired-vocabulary gate.
 *
 * Enforces the cocoon-retirement rule (2026-05-24, canonical memo:
 * Wiki/concepts/sanctuary-vocabulary-canonical-2026-05-24.md): the retired
 * term must not appear in any current artifact, public or internal.
 *
 * The rule was tried once before and drifted back in via integration code.
 * This gate is the structural layer that prevents a second drift: any new
 * occurrence outside the frozen exemptions below fails CI.
 *
 * Exemptions (each one deliberate):
 *  - Archive/        — historical record, exempt per the canonical memo.
 *  - CHANGELOG.md    — release notes describe past releases under the names
 *                      they shipped with; rewriting them would falsify history.
 *  - Frozen literals — on-disk filenames written by earlier releases
 *                      (profile + unwrap-meta files) that discovery and
 *                      unwrap must keep reading, and the removed legacy
 *                      export names asserted absent by wrap-cli tests.
 *                      Stripped before scanning so they can be referenced
 *                      by compat code, fixtures, and layout docs.
 */

import { describe, it, expect } from "vitest";
import { readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

/** Directories never scanned (by name, at any depth). */
const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".sanctuary-drill",
  "target",
  "__pycache__",
  ".venv",
  "venv",
]);

/** Top-level paths exempt as historical record. */
const EXEMPT_PATHS = ["Archive", "CHANGELOG.md"];

/** Files exempt because their job is to reference the retired term. */
const EXEMPT_FILES = new Set([
  // This gate.
  "server/test/vocabulary/no-retired-vocabulary.test.ts",
  // README-scoped vocabulary gate (predates this one; asserts absence).
  "server/test/wrap/readme.test.ts",
]);

/**
 * Frozen literals stripped from content before scanning. These are the ONLY
 * permissible carriers of the retired term in current artifacts:
 *  - the two on-disk filenames earlier releases wrote (compat reads, test
 *    fixtures simulating existing installs, and layout docs describing them);
 *  - the removed legacy export names, asserted absent by tests;
 *  - the retired dashboard route, asserted absent by fortress-view tests.
 */
const FROZEN_LITERALS = [
  "cocoon-profile.json",
  "cocoon-meta.json",
  "parseCocoonArgs",
  "runCocoon",
  "/api/cocoon/pause",
];

/** Text file extensions worth scanning. */
const TEXT_EXTS = new Set([
  ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx", ".py", ".sh", ".rs",
  ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".html", ".css",
  ".swift", ".c", ".h", ".plist", ".xml", ".sql", ".env", ".command",
]);

async function collectFiles(dir: string, out: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const full = join(dir, entry.name);
    const rel = relative(REPO_ROOT, full).split(sep).join("/");
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      if (EXEMPT_PATHS.includes(rel)) continue;
      await collectFiles(full, out);
    } else {
      if (EXEMPT_PATHS.includes(rel) || EXEMPT_FILES.has(rel)) continue;
      const dot = entry.name.lastIndexOf(".");
      const ext = dot >= 0 ? entry.name.slice(dot).toLowerCase() : "";
      if (!TEXT_EXTS.has(ext)) continue;
      out.push(full);
    }
  }
}

describe("retired-vocabulary gate", () => {
  it("no current artifact contains the retired term outside frozen exemptions", async () => {
    const files: string[] = [];
    await collectFiles(REPO_ROOT, files);
    expect(files.length).toBeGreaterThan(100); // sanity: the walk found the repo

    const offenders: string[] = [];
    for (const file of files) {
      let content = await readFile(file, "utf-8").catch(() => "");
      for (const literal of FROZEN_LITERALS) {
        content = content.split(literal).join("");
      }
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (/cocoon/i.test(lines[i])) {
          const rel = relative(REPO_ROOT, file).split(sep).join("/");
          offenders.push(`${rel}:${i + 1}: ${lines[i].trim().slice(0, 120)}`);
        }
      }
    }

    expect(
      offenders,
      `Retired vocabulary found (cocoon-retirement rule 2026-05-24). ` +
        `Replace with "Protect" (user-facing) / "wrap" (CLI + internal), ` +
        `or "fortress" / "encrypted state store" for the storage concept:\n` +
        offenders.join("\n")
    ).toEqual([]);
  });

  it("no current file is named after the retired term", async () => {
    const files: string[] = [];
    await collectFiles(REPO_ROOT, files);
    const badNames = files
      .map((f) => relative(REPO_ROOT, f).split(sep).join("/"))
      .filter((rel) => /cocoon/i.test(rel));
    expect(badNames).toEqual([]);
  });
});
