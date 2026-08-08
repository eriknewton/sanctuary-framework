import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const CLI_ROOT = join(process.cwd(), "src", "cli");
const CLI_ENTRY = join(process.cwd(), "src", "cli.ts");
const ALLOW_MARKER = "cli-argv-indexof-allowed:";
const HAND_ROLLED_ARGV_SEARCH = /\.[\s\n]*(indexOf|lastIndexOf|findIndex)[\s\n]*\(/g;

async function tsFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) return tsFiles(path);
      if (entry.isFile() && entry.name.endsWith(".ts")) return [path];
      return [];
    }),
  );
  return nested.flat();
}

async function cliFiles(): Promise<string[]> {
  return [CLI_ENTRY, ...(await tsFiles(CLI_ROOT))];
}

function lineNumberAt(source: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) {
    if (source[i] === "\n") line += 1;
  }
  return line;
}

function hasAllowMarker(lines: string[], lineNumber: number): boolean {
  return [lineNumber - 2, lineNumber - 1, lineNumber].some((index) =>
    lines[index]?.includes(ALLOW_MARKER),
  );
}

function sourceExcerpt(lines: string[], lineNumber: number): string {
  return lines[lineNumber - 1]?.trim() ?? "";
}

function handRolledArgvSearchOffenders(
  source: string,
  rel: string,
): string[] {
  const lines = source.split("\n");
  const offenders: string[] = [];
  for (const match of source.matchAll(HAND_ROLLED_ARGV_SEARCH)) {
    const lineNumber = lineNumberAt(source, match.index ?? 0);
    if (hasAllowMarker(lines, lineNumber)) continue;
    offenders.push(`${rel}:${lineNumber}: ${sourceExcerpt(lines, lineNumber)}`);
  }
  return offenders;
}

describe("CLI argv parser chokepoint", () => {
  it("keeps value-flag parsing out of hand-rolled indexOf calls", async () => {
    const offenders: string[] = [];
    for (const file of await cliFiles()) {
      const rel = relative(process.cwd(), file);
      offenders.push(...handRolledArgvSearchOffenders(await readFile(file, "utf8"), rel));
    }

    expect(offenders).toEqual([]);
  });

  it("detects split-only argv parsing shapes the live scan must reject", () => {
    const source = `
const a = argv.findIndex((value) => value === "--fortress");
const b = argv.lastIndexOf("--fortress");
const c = rest.indexOf("--fortress");
const d = argv
  .indexOf("--fortress");
`;
    expect(handRolledArgvSearchOffenders(source, "synthetic.ts")).toEqual([
      'synthetic.ts:2: const a = argv.findIndex((value) => value === "--fortress");',
      'synthetic.ts:3: const b = argv.lastIndexOf("--fortress");',
      'synthetic.ts:4: const c = rest.indexOf("--fortress");',
      'synthetic.ts:6: .indexOf("--fortress");',
    ]);
  });
});

/**
 * Residual boundary: the dominant live blind spot is inline index-based scanning
 * that advances through `argv` manually, for example `argv[++i]`. This guard also
 * does not try to catch computed-property calls (`argv["indexOf"](...)`), aliased
 * methods (`const f = argv.indexOf; f(...)`), wrappers outside `server/src/cli.ts`
 * and `server/src/cli/**`, or parsing hidden behind a helper that does not itself
 * call one of these Array methods.
 */
