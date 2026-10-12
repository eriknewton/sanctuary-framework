import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf8");
}

function sourceFiles(dir: string): string[] {
  const absolute = join(ROOT, dir);
  const out: string[] = [];
  for (const item of readdirSync(absolute)) {
    const full = join(absolute, item);
    const relative = `${dir}/${item}`;
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(relative));
    } else if (item.endsWith(".ts")) {
      out.push(relative);
    }
  }
  return out;
}

function callSites(pattern: RegExp): string[] {
  const sites: string[] = [];
  for (const file of sourceFiles("src")) {
    const text = read(file);
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i]!.includes("export function ")) continue;
      if (pattern.test(lines[i]!)) {
        sites.push(`${file}:${i + 1}`);
      }
      pattern.lastIndex = 0;
    }
  }
  return sites.sort();
}

describe("state import and checkpoint restore writer-key resolver parity", () => {
  it("keeps the production import and restore verification call set on the shared helpers", () => {
    const stateStore = read("src/cognitive/state-store.ts");
    const tools = read("src/cognitive/tools.ts");
    const checkpointCli = read("src/cli/checkpoint.ts");

    expect(stateStore).toContain("createStateImportWriterKeyResolver");
    expect(tools).toContain("createStateImportWriterKeyResolver");
    expect(checkpointCli).toContain("createStateImportWriterKeyResolver");
    expect(stateStore).not.toContain("normalizeImportPublicKeys");

    const signatureCallSites = callSites(
      /verifyStateEntrySignaturesWithAuthenticatedKey\(/g,
    ).map((site) => site.replace(/:\d+$/, ""));
    expect(signatureCallSites).toEqual([
      "src/cognitive/state-store.ts",
      "src/cognitive/state-store.ts",
      "src/cognitive/state-store.ts",
      "src/cognitive/state-store.ts",
      "src/cognitive/state-store.ts",
      "src/cognitive/state-store.ts",
    ]);

    const resolverFactorySites = callSites(
      /createStateImportWriterKeyResolver\(/g,
    ).map((site) => site.replace(/:\d+$/, ""));
    expect(resolverFactorySites).toEqual([
      "src/cli/checkpoint.ts",
      "src/cognitive/tools.ts",
    ]);
  });
});
