/**
 * Rotate-master operator guidance names only parser-accepted flags.
 *
 * This guard keeps operator-facing recovery text aligned with the command
 * surface without a hand-mirrored flag list: the accepted set comes from the
 * parser-owned helper used beside parseArgs, then every --flag token after a
 * rotate-master command anchor is checked against it. Scope covers source plus
 * operator Markdown; generated, dependency, and vendored directories are
 * skipped because they are not authored guidance. Remaining bound: a flag name
 * built through template interpolation is not a literal operator hint.
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

function collapseJoinedStringLiterals(source: string): string {
  let current = source;
  let previous: string;
  do {
    previous = current;
    current = current
      .replace(/"((?:\\.|[^"\\])*)"\s*\+\s*"((?:\\.|[^"\\])*)"/g, '"$1$2"')
      .replace(/'((?:\\.|[^'\\])*)'\s*\+\s*'((?:\\.|[^'\\])*)'/g, "'$1$2'")
      .replace(/`((?:\\.|[^`\\])*)`\s*\+\s*`((?:\\.|[^`\\])*)`/g, "`$1$2`");
  } while (current !== previous);
  return current;
}

function findRotateMasterFlagHintsInSource(
  file: SourceFile,
  source: string,
): Hint[] {
  const normalized = collapseJoinedStringLiterals(source);
  const hints: Hint[] = [];
  normalized.split("\n").forEach((lineText, idx) => {
    for (const command of lineText.matchAll(
      /(?:\bsanctuary\s+)?\brotate-master\b(?=\s+--)/g,
    )) {
      const commandTail = lineText.slice(command.index);
      const boundary = commandTail.search(/["'`]/);
      const commandSpan =
        boundary === -1 ? commandTail : commandTail.slice(0, boundary);
      for (const flag of commandSpan.matchAll(/--[a-z0-9-]+/g)) {
        hints.push({
          relPath: file.relPath,
          line: idx + 1,
          flag: flag[0],
          excerpt: commandSpan.trim(),
        });
      }
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
