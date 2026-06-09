import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("SDW architecture write gate", () => {
  it("keeps SDW backend writes centralized in the write gate", async () => {
    const root = join(process.cwd(), "src", "sdw");
    const offenders: string[] = [];
    for (const file of await listTsFiles(root)) {
      const relative = file.slice(root.length + 1);
      if (relative === "write-gate.ts") {
        continue;
      }
      const source = await readFile(file, "utf8");
      if (relative === "lmdb-backend.ts") {
        if (!source.includes("assertSdwRawWriteAuthorized(namespace);")) {
          offenders.push(`${relative}: missing raw SDW namespace guard`);
        }
        if (!source.includes("prepareSdwBackendWrite(persistable, encryptionKey, fortressId)")) {
          offenders.push(`${relative}: missing transactional write gate`);
        }
        continue;
      }
      const directWritePatterns = [
        /\b(?:storage|backend|txn|this\.storage|this\.backend)\.write\s*\(/,
        /\bwrite\s*\(\s*["']_sdw_/,
        /\bput(?:Sync)?\s*\(\s*compositeKey\s*\(/,
      ];
      if (directWritePatterns.some((pattern) => pattern.test(source))) {
        offenders.push(`${relative}: raw write call`);
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
