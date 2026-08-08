import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const CLI_ROOT = join(process.cwd(), "src", "cli");
const ALLOW_MARKER = "cli-argv-indexof-allowed:";

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

describe("CLI argv parser chokepoint", () => {
  it("keeps value-flag parsing out of hand-rolled indexOf calls", async () => {
    const offenders: string[] = [];
    for (const file of await tsFiles(CLI_ROOT)) {
      const rel = relative(process.cwd(), file);
      const lines = (await readFile(file, "utf8")).split("\n");
      lines.forEach((line, index) => {
        if (!/\bargv\.indexOf\(/.test(line)) return;
        if (line.includes(ALLOW_MARKER)) return;
        offenders.push(`${rel}:${index + 1}: ${line.trim()}`);
      });
    }

    expect(offenders).toEqual([]);
  });
});
