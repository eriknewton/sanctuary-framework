import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("SDW architecture write gate", () => {
  it("keeps backend writes centralized in write-gate.ts", async () => {
    const root = join(process.cwd(), "src", "sdw");
    const offenders: string[] = [];
    for (const file of await listTsFiles(root)) {
      const relative = file.slice(root.length + 1);
      if (relative === "write-gate.ts") continue;
      const source = await readFile(file, "utf8");
      if (/\b(?:storage|backend)\.write\s*\(/.test(source)) {
        offenders.push(relative);
      }
    }
    expect(offenders).toEqual([]);
  });
});

async function listTsFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await listTsFiles(path)));
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      out.push(path);
    }
  }
  return out;
}
