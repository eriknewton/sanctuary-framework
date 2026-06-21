import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const SERVER_SRC = join(REPO_ROOT, "server", "src");

interface WriteCall {
  relativePath: string;
  firstArg: string;
  context: string;
}

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

function readBalancedCall(source: string, openParen: number): string {
  let depth = 0;
  let quote: '"' | "'" | "`" | null = null;
  let escaped = false;
  for (let i = openParen; i < source.length; i++) {
    const ch = source[i]!;
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(") depth++;
    if (ch === ")") {
      depth--;
      if (depth === 0) return source.slice(openParen + 1, i);
    }
  }
  return source.slice(openParen + 1);
}

function firstArgument(callBody: string): string {
  let depth = 0;
  let quote: '"' | "'" | "`" | null = null;
  let escaped = false;
  for (let i = 0; i < callBody.length; i++) {
    const ch = callBody[i]!;
    if (quote !== null) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      continue;
    }
    if (ch === "(" || ch === "{" || ch === "[") depth++;
    if (ch === ")" || ch === "}" || ch === "]") depth--;
    if (ch === "," && depth === 0) return callBody.slice(0, i).trim();
  }
  return callBody.trim();
}

function storageWriteCalls(): WriteCall[] {
  const calls: WriteCall[] = [];
  const pattern = /(?:this\.|ctx\.|opts\.|options\.)?storage\.write\s*\(/g;
  for (const file of tsFiles(SERVER_SRC)) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(pattern)) {
      const openParen = source.indexOf("(", match.index);
      const body = readBalancedCall(source, openParen);
      const start = Math.max(0, match.index - 220);
      const end = Math.min(source.length, openParen + body.length + 220);
      calls.push({
        relativePath: relative(REPO_ROOT, file),
        firstArg: firstArgument(body).replace(/\s+/g, " "),
        context: source.slice(start, end).replace(/\s+/g, " "),
      });
    }
  }
  return calls;
}

function isReservedLiteral(firstArg: string): boolean {
  const match = firstArg.match(/^["'`]([^"'`]+)["'`]$/);
  return match !== null && match[1]!.startsWith("_");
}

function isInternalConstant(firstArg: string): boolean {
  return /^[A-Z][A-Z0-9_]*$/.test(firstArg);
}

function isAllowedDynamicWrite(call: WriteCall): boolean {
  if (
    call.relativePath === "server/src/cognitive/state-store.ts" &&
    (call.firstArg === "namespace" || call.firstArg === "ns")
  ) {
    return true;
  }
  if (
    call.relativePath === "server/src/core/master-rotation.ts" &&
    call.firstArg === "namespace"
  ) {
    return true;
  }
  const allowed = [
    {
      path: "server/src/exit/bundle.ts",
      context: "async function stageArtifact",
      reason: "exit import stages only internal _exit_* artifact namespaces",
    },
    {
      path: "server/src/transparency/anchoring.ts",
      context: "storage.write(namespace, key, bytes)",
      reason: "transparency checkpoint helper uses frozen internal namespaces",
    },
    {
      path: "server/src/transparency/emitter.ts",
      context: "storage.write(namespace, key, bytes)",
      reason: "transparency emitter helper uses frozen internal namespaces",
    },
  ];
  return allowed.some(
    (item) =>
      call.relativePath === item.path && call.context.includes(item.context),
  );
}

describe("state provenance write chokepoint", () => {
  it("has no unaudited direct raw storage writes to variable namespaces", () => {
    const unsafe = storageWriteCalls().filter((call) => {
      if (isReservedLiteral(call.firstArg)) return false;
      if (isInternalConstant(call.firstArg)) return false;
      return !isAllowedDynamicWrite(call);
    });

    expect(
      unsafe.map((call) => `${call.relativePath}: storage.write(${call.firstArg}, ...)`),
      "Every direct raw storage write with a variable namespace must be audited. " +
        "Export-eligible user state should route through StateStore.write so " +
        "Slice-2 provenance is minted at the chokepoint.",
    ).toEqual([]);
  });
});
