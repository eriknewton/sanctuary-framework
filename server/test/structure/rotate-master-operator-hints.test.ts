/**
 * Rotate-master operator guidance names only parser-accepted flags.
 *
 * This guard keeps operator-facing recovery text aligned with the command
 * surface without a hand-mirrored flag list: the accepted set comes from the
 * parser-owned helper used beside parseArgs, then every
 * `sanctuary rotate-master --flag` hint in server/src is checked against it.
 */
import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { rotateMasterAcceptedLongFlags } from "../../src/cli/rotate-master.js";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

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

function walkTsFiles(dir: string, out: SourceFile[]): void {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist") continue;
    const absPath = join(dir, entry);
    const stat = statSync(absPath);
    if (stat.isDirectory()) {
      walkTsFiles(absPath, out);
    } else if (entry.endsWith(".ts")) {
      out.push({ absPath, relPath: relative(REPO_ROOT, absPath) });
    }
  }
}

function findRotateMasterFlagHints(file: SourceFile): Hint[] {
  const source = readFileSync(file.absPath, "utf8");
  const hints: Hint[] = [];
  source.split("\n").forEach((lineText, idx) => {
    for (const match of lineText.matchAll(/sanctuary\s+rotate-master\s+(--[a-z0-9-]+)/g)) {
      hints.push({
        relPath: file.relPath,
        line: idx + 1,
        flag: match[1]!,
        excerpt: lineText.trim(),
      });
    }
  });
  return hints;
}

describe("rotate-master operator flag guidance", () => {
  it("names only flags accepted by the rotate-master parser", () => {
    const accepted = new Set(rotateMasterAcceptedLongFlags());
    expect(accepted.size).toBeGreaterThan(0);

    const files: SourceFile[] = [];
    walkTsFiles(SERVER_SRC, files);
    const hints = files.flatMap(findRotateMasterFlagHints);
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
