/**
 * Repo-wide retired-vocabulary gate.
 *
 * Enforces TWO retirement rules:
 *
 *  1. The cocoon-retirement rule (2026-05-24, canonical memo:
 *     Wiki/concepts/sanctuary-vocabulary-canonical-2026-05-24.md): the retired
 *     term must not appear in any current artifact, public or internal.
 *  2. The layer-numbering-retirement rule (2026-05-24): the four sovereignty
 *     layers are named (Cognitive / Operational / Selective Disclosure /
 *     Verifiable Reputation), and the legacy `l1`-`l4` DIRECTORY / TOKEN
 *     prefixes are gone (renamed to `cognitive`/`operational`/`disclosure`/
 *     `reputation` across PR-0..5 of the 2026-06 rename). This gate is the
 *     structural capstone that prevents the prefixes from creeping back in.
 *
 * The cocoon rule was tried once before and drifted back in via integration
 * code; both clauses below are the structural layer that prevents a second
 * drift: any new occurrence outside the frozen exemptions fails CI.
 *
 * --- What the L1-L4 clause polices, and what it deliberately does NOT ---
 *
 * It polices the two drift forms the rename actually ELIMINATED, both of which
 * are mechanically distinguishable from legitimate prose:
 *   (a) the lowercase hyphenated layer-token form
 *       `l[1-4]-(cognitive|operational|disclosure|reputation)` — the old
 *       directory / HKDF-prefix shape; and
 *   (b) the directory PATH-PREFIX form `(src|test)/l[1-4]/` — the renamed
 *       source/test directory shape.
 *
 * It deliberately does NOT police the bare uppercase prose form `\bL[1-4]\b`.
 * That form was NEVER a directory or symbol name — it is the well-understood
 * shorthand the architecture docs, code comments, audit report text, and
 * user-visible display labels use for the layers ("Create L1 tools", "L1=
 * Cognitive", the audit-report table). It appears in 100+ current files as
 * legitimate, pre-existing usage, and the frozen wire surface (below)
 * deliberately RETAINS it. A clause flagging it would be all carve-out and
 * would enforce nothing — the opposite of a guard.
 *
 * Exemptions (each one deliberate):
 *  - Archive/        — historical record, exempt per the canonical memo.
 *  - CHANGELOG.md    — release notes describe past releases under the names
 *                      they shipped with; rewriting them would falsify history.
 *  - Frozen literals — for cocoon: the removed legacy export names asserted
 *                      absent by wrap-cli tests and the retired dashboard route
 *                      asserted absent by fortress-view tests. For L1-L4: the
 *                      four lowercase layer-token literals that are deliberately
 *                      frozen — `l4-reputation` is a LIVE HKDF crypto info-
 *                      string (renaming it would silently break decryption of
 *                      every user's Verifiable-Reputation store; see
 *                      docs/hkdf-info-string-registry.md), and `l1-cognitive`
 *                      / `l2-operational` / `l3-disclosure` are frozen
 *                      architecture-documentation tokens (HKDF-label module-
 *                      owner annotations, reorg manifest, READMEs). Stripped
 *                      before scanning, repo-wide.
 *  - Frozen UPPERCASE wire surface — NOT scanned by this gate (the uppercase
 *                      form is out of scope, see above), but recorded here as
 *                      the durable "these are deliberate, not drift" list per
 *                      the §4 frozen-surface decision (Erik-ratified): the MCP
 *                      tool names `l2_hardening_status` / `l2_verify_isolation`;
 *                      the SHR keys `layers.l1_cognitive`..`l4_reputation`; the
 *                      sovereignty-audit gap IDs `GAP-L1-*`..`GAP-L4-*`, the
 *                      `SovereigntyGap.layer` union values `"L1".."L4"`, and the
 *                      reputation manifest `{ name: "L1" }` records. All are
 *                      signed/verifier-pinned or AI-facing contracts; renaming
 *                      buys breakage, not clarity.
 *  - Path-prefix exempt — docs/research/RESEARCH_ZK_UPGRADE_L3.md references
 *                      hypothetical `test/l3/groth16-*.test.ts` files that were
 *                      never built (a proposed future-design doc, not a shipped
 *                      artifact). Exempt from the (b) path-prefix clause only.
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
 * Frozen lowercase layer-token literals stripped before the L1-L4 lowercase-
 * hyphen scan, repo-wide. `l4-reputation` is a LIVE HKDF crypto info-string
 * (frozen — renaming breaks decryption); the other three are frozen
 * architecture-documentation tokens. New code must use the named directories
 * (`cognitive`/`operational`/`disclosure`/`reputation`); any NEW lowercase
 * `l[1-4]-(named)` token that is not one of these exact frozen literals fails
 * the gate.
 */
const FROZEN_LAYER_TOKENS = [
  "l1-cognitive",
  "l2-operational",
  "l3-disclosure",
  "l4-reputation",
];

/** Matches the renamed-away layer-token form `l[1-4]-(named-layer)`. */
const LAYER_TOKEN_RE = /l[1-4]-(cognitive|operational|disclosure|reputation)/;

/**
 * Matches the renamed-away source/test directory PATH-PREFIX form, e.g.
 * `src/l2/...` or `test/l3/...`. The directories were renamed in PR-0..5.
 */
const LAYER_PATH_PREFIX_RE = /\b(src|test)\/l[1-4]\//;

/**
 * Files exempt from the path-prefix clause (b) only: a research doc citing
 * hypothetical, never-built `test/l3/groth16-*.test.ts` files.
 */
const LAYER_PATH_PREFIX_EXEMPT = new Set([
  "docs/research/RESEARCH_ZK_UPGRADE_L3.md",
]);

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

  it("no current artifact reintroduces the retired l1-l4 layer-token or directory prefixes", async () => {
    const files: string[] = [];
    collectFiles(files);
    expect(files.length).toBeGreaterThan(100); // sanity: the walk found the repo

    const offenders: string[] = [];
    for (const file of files) {
      const rel = relative(REPO_ROOT, file).split(sep).join("/");
      const raw = await readFile(file, "utf-8").catch(() => "");

      // (a) lowercase hyphenated layer-token form, after stripping the frozen
      //     layer-token literals (l4-reputation HKDF crypto label + the three
      //     frozen architecture-doc tokens). Anything else of this shape is
      //     NEW drift and fails.
      let stripped = raw;
      for (const literal of FROZEN_LAYER_TOKENS) {
        stripped = stripped.split(literal).join("");
      }
      const strippedLines = stripped.split("\n");
      for (let i = 0; i < strippedLines.length; i++) {
        if (LAYER_TOKEN_RE.test(strippedLines[i])) {
          offenders.push(
            `${rel}:${i + 1} (layer-token): ${strippedLines[i].trim().slice(0, 120)}`
          );
        }
      }

      // (b) source/test directory PATH-PREFIX form (src/lN/ or test/lN/),
      //     scanned on raw content. The renamed directories must not reappear.
      if (!LAYER_PATH_PREFIX_EXEMPT.has(rel)) {
        const rawLines = raw.split("\n");
        for (let i = 0; i < rawLines.length; i++) {
          if (LAYER_PATH_PREFIX_RE.test(rawLines[i])) {
            offenders.push(
              `${rel}:${i + 1} (dir-prefix): ${rawLines[i].trim().slice(0, 120)}`
            );
          }
        }
      }
    }

    expect(
      offenders,
      `Retired l1-l4 layer numbering found (layer-numbering-retirement rule ` +
        `2026-05-24). Use the named layer directories/tokens ` +
        `(cognitive/operational/disclosure/reputation). If this is a ` +
        `deliberate frozen site (a live HKDF info-string, a signed wire key, ` +
        `or an AI-facing tool name), add it to the documented carve-out list ` +
        `in this file:\n` +
        offenders.join("\n")
    ).toEqual([]);
  });
});
