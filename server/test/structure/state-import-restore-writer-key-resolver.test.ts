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
const RESOLVER_ARGUMENT_INDEX = 2;

interface ResolverCall {
  file: string;
  callee: string;
  resolver: string;
}

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

function splitTopLevelArgs(text: string): string[] {
  const args: string[] = [];
  let start = 0;
  let depth = 0;
  let quote: "\"" | "'" | "`" | null = null;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i]!;
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }
    if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      continue;
    }
    if (char === "(" || char === "{" || char === "[") depth++;
    if (char === ")" || char === "}" || char === "]") depth--;
    if (char === "," && depth === 0) {
      args.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  const tail = text.slice(start).trim();
  if (tail.length > 0) args.push(tail);
  return args;
}

function isFunctionDeclaration(text: string, index: number): boolean {
  const prefix = text.slice(Math.max(0, index - "export async function ".length), index);
  return /(?:^|\s)(?:export\s+)?(?:async\s+)?function\s+$/.test(prefix);
}

function exactResolverArg(args: string[], index: number): string {
  const resolver = args[index]?.trim() ?? "missing";
  return resolver === "publicKeyResolver" || resolver === "deps.publicKeyResolver"
    ? resolver
    : "missing";
}

function exactObjectResolverArg(args: string[]): string {
  const objectArg = args[0]?.trim() ?? "";
  if (objectArg === "deps") return "deps";
  if (!objectArg.startsWith("{") || !objectArg.endsWith("}")) return "missing";
  if (/\bpublicKeyResolver\s*:/.test(objectArg)) return "missing";
  return /^\s*publicKeyResolver,\s*$/m.test(objectArg) ? "publicKeyResolver" : "missing";
}

function productionResolverCalls(
  files: Record<string, string>,
): string[] {
  const calls: ResolverCall[] = [];
  for (const [file, text] of Object.entries(files)) {
    for (const token of [
      ".import(",
      ".assertImportVersionFloors(",
      "restoreCheckpoint(",
      "preflightCheckpointRestore(",
    ]) {
      let index = text.indexOf(token);
      while (index !== -1) {
        if (!isFunctionDeclaration(text, index)) {
          const openIndex = index + token.length - 1;
          const closeIndex = findMatchingParen(text, openIndex);
          const argText = closeIndex === -1 ? "" : text.slice(openIndex + 1, closeIndex);
          const args = splitTopLevelArgs(argText);
          const callee = token === ".assertImportVersionFloors("
            ? "assertImportVersionFloors"
            : token.slice(0, -1);
          const resolver = token === ".import(" || token === ".assertImportVersionFloors("
            ? exactResolverArg(args, RESOLVER_ARGUMENT_INDEX)
            : exactObjectResolverArg(args);
          calls.push({ file, callee, resolver });
        }
        index = text.indexOf(token, index + token.length);
      }
    }
  }
  return calls.map((call) => `${call.file}:${call.callee}:${call.resolver}`).sort();
}

function assertProductionResolverParity(files: Record<string, string>): void {
  expect(productionResolverCalls(files)).toEqual([...PRODUCTION_RESOLVER_CALLS].sort());

  for (const file of ["src/cli/checkpoint.ts", "src/cognitive/tools.ts"]) {
    const declarations = files[file]!.match(/\b(?:const|let|var)\s+publicKeyResolver\b/g) ?? [];
    expect(declarations, file).toHaveLength(1);
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

  it("would fail if a production import caller used a renamed current-key resolver", () => {
    const files = Object.fromEntries(
      sourceFiles("src").map((file) => [file, read(file)])
    );
    files["src/cognitive/tools.ts"] = files["src/cognitive/tools.ts"]!.replace(
      /          result = await stateStore\.import\(\n            args\.bundle as string,\n            \(args\.conflict_resolution as "skip" \| "overwrite" \| "version"\) \?\?\n              "skip",\n            publicKeyResolver,/,
      `          const publicKeyResolverCurrentOnly = (kid: string): Uint8Array[] | null => {
            const held = identityMgr.get(kid);
            return held ? [fromBase64url(held.public_key)] : null;
          };
          result = await stateStore.import(
            args.bundle as string,
            (args.conflict_resolution as "skip" | "overwrite" | "version") ??
              "skip",
            publicKeyResolverCurrentOnly,`
    );

    expect(() => assertProductionResolverParity(files)).toThrow();
  });

  it("would fail if a production checkpoint caller used an inline writer-chain resolver", () => {
    const files = Object.fromEntries(
      sourceFiles("src").map((file) => [file, read(file)])
    );
    files["src/cli/checkpoint.ts"] = files["src/cli/checkpoint.ts"]!.replace(
      /      assessParked: async \(\) => assessHarnessParked\(await buildRestoreParkedSource\(\)\),\n      publicKeyResolver,\n    }\);/,
      `      assessParked: async () => assessHarnessParked(await buildRestoreParkedSource()),
      publicKeyResolver: (kid: string) => {
        const held = boot.identityManager.get(kid);
        if (!held) return null;
        return resolveAuthenticatedIdentityWriterPublicKeys(held).map((k) => k.publicKey);
      },
    });`
    );

    expect(() => assertProductionResolverParity(files)).toThrow();
  });
});
