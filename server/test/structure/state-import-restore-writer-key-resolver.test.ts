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

const PRODUCTION_RESOLVER_CALLS = [
  "src/cli/checkpoint.ts:preflightCheckpointRestore:publicKeyResolver",
  "src/cli/checkpoint.ts:restoreCheckpoint:publicKeyResolver",
  "src/cognitive/tools.ts:.import:publicKeyResolver",
  "src/cognitive/tools.ts:assertImportVersionFloors:publicKeyResolver",
  "src/memory-checkpoint/restore.ts:.import:deps.publicKeyResolver",
  "src/memory-checkpoint/restore.ts:assertImportVersionFloors:deps.publicKeyResolver",
  "src/memory-checkpoint/restore.ts:preflightCheckpointRestore:deps",
] as const;

function findMatchingParen(text: string, openIndex: number): number {
  let depth = 0;
  for (let i = openIndex; i < text.length; i++) {
    const char = text[i];
    if (char === "(") depth++;
    if (char === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function productionResolverCalls(
  files: Record<string, string>,
): string[] {
  const calls: string[] = [];
  for (const [file, text] of Object.entries(files)) {
    for (const token of [
      ".import(",
      ".assertImportVersionFloors(",
      "restoreCheckpoint(",
      "preflightCheckpointRestore(",
    ]) {
      let index = text.indexOf(token);
      while (index !== -1) {
        const lineStart = text.lastIndexOf("\n", index) + 1;
        const line = text.slice(lineStart, text.indexOf("\n", lineStart));
        if (!line.includes("export async function")) {
          const openIndex = index + token.length - 1;
          const closeIndex = findMatchingParen(text, openIndex);
          const callText = closeIndex === -1
            ? text.slice(index, index + token.length)
            : text.slice(index, closeIndex + 1);
          const callee = token === ".assertImportVersionFloors("
            ? "assertImportVersionFloors"
            : token.slice(0, -1);
          const resolver = callText.includes("deps.publicKeyResolver")
            ? "deps.publicKeyResolver"
            : callText.includes("publicKeyResolver")
              ? "publicKeyResolver"
              : callText.includes("preflightCheckpointRestore(deps)")
                ? "deps"
                : "missing";
          calls.push(`${file}:${callee}:${resolver}`);
        }
        index = text.indexOf(token, index + token.length);
      }
    }
  }
  return calls.sort();
}

function assertProductionResolverParity(files: Record<string, string>): void {
  expect(productionResolverCalls(files)).toEqual([...PRODUCTION_RESOLVER_CALLS].sort());

  for (const file of ["src/cli/checkpoint.ts", "src/cognitive/tools.ts"]) {
    expect(files[file]).toMatch(
      /const publicKeyResolver = createStateImportWriterKeyResolver\(\(kid\) =>/
    );
  }
}

describe("state import and checkpoint restore writer-key resolver parity", () => {
  it("keeps the production import and restore verification call set on the shared helpers", () => {
    const files = Object.fromEntries(
      sourceFiles("src").map((file) => [file, read(file)])
    );
    const stateStore = files["src/cognitive/state-store.ts"]!;
    const tools = files["src/cognitive/tools.ts"]!;
    const checkpointCli = files["src/cli/checkpoint.ts"]!;

    expect(stateStore).toContain("createStateImportWriterKeyResolver");
    expect(tools).toContain("createStateImportWriterKeyResolver");
    expect(checkpointCli).toContain("createStateImportWriterKeyResolver");
    expect(stateStore).not.toContain("normalizeImportPublicKeys");
    assertProductionResolverParity(files);

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

  it("would fail if a production restore caller used a hand-written current-key resolver", () => {
    const files = Object.fromEntries(
      sourceFiles("src").map((file) => [file, read(file)])
    );
    files["src/cli/checkpoint.ts"] = files["src/cli/checkpoint.ts"]!.replace(
      /const publicKeyResolver = createStateImportWriterKeyResolver\(\(kid\) =>\n\s+boot\.identityManager\.get\(kid\)\n\s+\);/,
      "const publicKeyResolver = (_kid: string) => [boot.primary.publicKey];"
    );

    expect(() => assertProductionResolverParity(files)).toThrow();
  });
});
