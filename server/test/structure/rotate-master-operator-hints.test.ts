/**
 * Rotate-master operator guidance names only parser-accepted flags.
 *
 * This guard keeps operator-facing recovery text aligned with the command
 * surface without a hand-mirrored flag list: the accepted set comes from the
 * parser-owned helper used beside parseArgs, then every --flag token after a
 * rotate-master mention, to the end of its line, is checked against it. String
 * `+` joins and shell line continuations are joined first.
 *
 * Scope: server/src TypeScript, server/**, docs/** Markdown, and the root
 * README. Other Markdown and scripts are not walked (root CHANGELOG, ROADMAP,
 * SECURITY, AGENTS, plugin/, quickstart/, integrations/, rfcs/, and the like);
 * generated, dependency, and vendored directories are skipped.
 *
 * Remaining bounds: a flag built by template interpolation or an interleaved
 * expression (`"... rotate-master " + x + "--abort"`); a rotate-master mention
 * and its flag on separate lines of one template literal; a flag named on a
 * line with no rotate-master mention (for example usage option rows); and
 * single-dash or upper-case flags. A flag directly after "There is no" is
 * skipped, because that phrasing denies the flag rather than recommending it.
 */
import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { rotateMasterAcceptedLongFlags } from "../../src/cli/rotate-master.js";
import { CustodyRotationInProgressError } from "../../src/core/master-custody.js";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");
const SERVER_ROOT = join(REPO_ROOT, "server");
const DOCS_ROOT = join(REPO_ROOT, "docs");
const README = join(REPO_ROOT, "README.md");

const SKIPPED_DIRS = new Set([
  ".git",
  "dist",
  "node_modules",
  "third_party",
  "vendor",
  "vendored",
]);

interface SourceFile {
  readonly absPath: string;
  readonly relPath: string;
}

interface Hint {
  readonly relPath: string;
  readonly line: number;
  readonly flag: string;
  readonly excerpt: string;
}

function sourceFileFromText(source: string): SourceFile {
  return {
    absPath: source,
    relPath: source,
  };
}

function walkFiles(
  dir: string,
  extensions: readonly string[],
  out: SourceFile[],
): void {
  for (const entry of readdirSync(dir)) {
    if (SKIPPED_DIRS.has(entry)) continue;
    const absPath = join(dir, entry);
    const stat = statSync(absPath);
    if (stat.isDirectory()) {
      walkFiles(absPath, extensions, out);
    } else if (extensions.some((extension) => entry.endsWith(extension))) {
      out.push({ absPath, relPath: relative(REPO_ROOT, absPath) });
    }
  }
}

function collectScannedFiles(): SourceFile[] {
  const files: SourceFile[] = [];
  walkFiles(SERVER_SRC, [".ts"], files);
  walkFiles(SERVER_ROOT, [".md"], files);
  if (existsSync(DOCS_ROOT)) walkFiles(DOCS_ROOT, [".md"], files);
  if (existsSync(README)) files.push({ absPath: README, relPath: "README.md" });
  return files;
}

// Joins operator text that source or Markdown splits across lines: a string
// literal `+` join (any quote style on either side) and a shell line
// continuation. Interleaved expressions (`"a " + x + "b"`) are not joined.
function joinSplitOperatorText(source: string): string {
  return source
    .replace(/["'`]\s*\+\s*["'`]/g, "")
    .replace(/\\\r?\n[ \t]*/g, " ");
}

function findRotateMasterFlagHintsInSource(
  file: SourceFile,
  source: string,
): Hint[] {
  const normalized = joinSplitOperatorText(source);
  const hints: Hint[] = [];
  normalized.split("\n").forEach((lineText, idx) => {
    const anchor = lineText.search(/\brotate-master\b/);
    if (anchor === -1) return;
    // The span runs to the end of the line, not to the next quote: a quoted
    // path, a contraction, or a second command on the same line can only add
    // flags to check, so an over-match fails this test loudly rather than
    // hiding an unaccepted flag.
    const commandSpan = lineText.slice(anchor);
    for (const flag of commandSpan.matchAll(/--[a-z0-9-]+/g)) {
      // "There is no --x" tells the operator a flag does not exist; it is the
      // one phrasing that may name an unaccepted flag.
      const before = commandSpan.slice(0, flag.index);
      if (/\bthere is no\s+$/i.test(before)) continue;
      hints.push({
        relPath: file.relPath,
        line: idx + 1,
        flag: flag[0],
        excerpt: commandSpan.trim(),
      });
    }
  });
  return hints;
}

function findRotateMasterFlagHints(file: SourceFile): Hint[] {
  return findRotateMasterFlagHintsInSource(
    file,
    readFileSync(file.absPath, "utf8"),
  );
}

describe("rotate-master operator flag guidance", () => {
  it("checks every flag in a rotate-master command span", () => {
    const hints = findRotateMasterFlagHintsInSource(
      sourceFileFromText(
        "run `sanctuary rotate-master --fortress <path> --abort`",
      ),
      "run `sanctuary rotate-master --fortress <path> --abort`",
    );

    expect(hints.map((hint) => hint.flag)).toEqual(["--fortress", "--abort"]);
  });

  it("checks flags across joined operator text", () => {
    const hints = findRotateMasterFlagHintsInSource(
      sourceFileFromText("fixture"),
      '"sanctuary rotate-master " +\n "--abort"',
    );

    expect(hints.map((hint) => hint.flag)).toEqual(["--abort"]);
  });

  it.each([
    ["a quoted path", 'run `sanctuary rotate-master --fortress "<path>" --abort`'],
    ["a contraction in joined text", `"sanctuary rotate-master --resume " + "don't --abort"`],
    ["a mixed-quote join", '"sanctuary rotate-master " +\n `--abort`'],
    ["a shell line continuation", "sanctuary rotate-master \\\n  --abort"],
    ["a positional before the flag", "sanctuary rotate-master now --abort"],
    ["a denial earlier on the line", "rotate-master: there is no --x; run --abort"],
  ])("checks every flag through %s", (_shape, text) => {
    const flags = findRotateMasterFlagHintsInSource(
      sourceFileFromText("fixture"),
      text,
    ).map((hint) => hint.flag);

    expect(flags).toContain("--abort");
  });

  it("pins the in-progress custody hint to parser-accepted flags", () => {
    const accepted = new Set(rotateMasterAcceptedLongFlags());
    const hints = findRotateMasterFlagHintsInSource(
      sourceFileFromText("CustodyRotationInProgressError"),
      new CustodyRotationInProgressError().message,
    );

    expect(hints.length).toBeGreaterThan(0);
    for (const hint of hints) {
      expect(accepted.has(hint.flag), hint.flag).toBe(true);
    }
  });

  it("names only flags accepted by the rotate-master parser", () => {
    const accepted = new Set(rotateMasterAcceptedLongFlags());
    expect(accepted.size).toBeGreaterThan(0);

    const hints = collectScannedFiles().flatMap(findRotateMasterFlagHints);
    expect(hints.length).toBeGreaterThan(0);

    const unaccepted = hints.filter((hint) => !accepted.has(hint.flag));
    if (unaccepted.length > 0) {
      const detail = unaccepted
        .map(
          (hint) =>
            `  ${hint.relPath}:${hint.line}: ${hint.flag} in ${hint.excerpt}`,
        )
        .join("\n");
      throw new Error(
        `rotate-master guidance names flag(s) the parser does not accept:\n${detail}`,
      );
    }
  });
});
