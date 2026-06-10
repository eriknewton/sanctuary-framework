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
 *  - Frozen literals — the removed legacy export names asserted absent by
 *                      wrap-cli tests and the retired dashboard route
 *                      asserted absent by fortress-view tests. Stripped
 *                      before scanning, repo-wide.
 *  - Legacy filenames — on-disk filenames written by earlier releases
 *                      (profile + unwrap-meta files). New writes use the
 *                      wrap-* names; the legacy names survive ONLY in the
 *                      fallback-read modules (read-both, write-new) and
 *                      their compat tests, allowlisted per-file below.
 */

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
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
 * Frozen literals stripped from content before scanning, repo-wide:
 *  - the removed legacy export names, asserted absent by tests;
 *  - the retired dashboard route, asserted absent by fortress-view tests.
 */
const FROZEN_LITERALS = [
  "parseCocoonArgs",
  "runCocoon",
  "/api/cocoon/pause",
];

/**
 * Legacy on-disk filenames written by pre-sweep releases. The read-both,
 * write-new migration confines each literal to its fallback-read module
 * and the compat test that proves legacy installs still work. Any other
 * file referencing these names fails the gate — new code must use
 * `wrap-profile.json` / `wrap-meta.json`.
 */
const LEGACY_FILENAME_ALLOWLIST: Record<string, ReadonlySet<string>> = {
  "cocoon-profile.json": new Set([
    "server/src/cli/agents/discovery.ts",
    "server/test/wrap/legacy-filename-compat.test.ts",
  ]),
  "cocoon-meta.json": new Set([
    "server/src/wrap/config-reader.ts",
    "server/test/wrap/legacy-filename-compat.test.ts",
  ]),
};

/** Text file extensions worth scanning. */
const TEXT_EXTS = new Set([
  ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx", ".py", ".sh", ".rs",
  ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".html", ".css",
  ".swift", ".c", ".h", ".plist", ".xml", ".sql", ".env", ".command",
]);

/**
 * Enumerate the repo's CURRENT, SHIPPING artifacts: git-tracked files only.
 *
 * The gate scopes the cocoon-retirement rule to "current artifacts" — i.e.
 * what the repo actually ships. That is exactly the git-tracked set. Walking
 * the filesystem instead (the old approach) also scanned gitignored / untracked
 * local scratch (e.g. a developer's local `Review/`, `docs/builds/`, stray
 * build summaries, or a nested agent worktree under `.claude/worktrees/`),
 * which a clean CI checkout never has — producing local-only false failures
 * with no equivalent in CI. Listing tracked files makes local == CI and keeps
 * the gate scoped to artifacts that ship. All exemptions below still apply.
 */
function collectFiles(out: string[]): void {
  const tracked = execFileSync("git", ["ls-files", "-z"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  })
    .split("\0")
    .filter((p) => p.length > 0);

  for (const rel of tracked) {
    const topSegment = rel.split("/")[0]!;
    if (SKIP_DIRS.has(topSegment)) continue;
    if (EXEMPT_PATHS.includes(rel) || EXEMPT_FILES.has(rel)) continue;
    // A top-level exempt PATH (e.g. "Archive") also covers everything under it.
    if (EXEMPT_PATHS.some((p) => rel === p || rel.startsWith(`${p}/`))) continue;
    const base = rel.slice(rel.lastIndexOf("/") + 1);
    const dot = base.lastIndexOf(".");
    const ext = dot >= 0 ? base.slice(dot).toLowerCase() : "";
    if (!TEXT_EXTS.has(ext)) continue;
    out.push(join(REPO_ROOT, ...rel.split("/")));
  }
}

describe("retired-vocabulary gate", () => {
  it("no current artifact contains the retired term outside frozen exemptions", async () => {
    const files: string[] = [];
    collectFiles(files);
    expect(files.length).toBeGreaterThan(100); // sanity: the walk found the repo

    const offenders: string[] = [];
    for (const file of files) {
      const rel = relative(REPO_ROOT, file).split(sep).join("/");
      let content = await readFile(file, "utf-8").catch(() => "");
      for (const literal of FROZEN_LITERALS) {
        content = content.split(literal).join("");
      }
      for (const [literal, allowedFiles] of Object.entries(
        LEGACY_FILENAME_ALLOWLIST
      )) {
        if (allowedFiles.has(rel)) {
          content = content.split(literal).join("");
        }
      }
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (/cocoon/i.test(lines[i])) {
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
    collectFiles(files);
    const badNames = files
      .map((f) => relative(REPO_ROOT, f).split(sep).join("/"))
      .filter((rel) => /cocoon/i.test(rel));
    expect(badNames).toEqual([]);
  });
});
