/** Runtime import allowlist for the pure snapshot entry and its trust boundary. */
import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../src");
const ALLOWED = [
  "audit/chain.ts", "audit/checkpoint-shape.ts", "cli/argv.ts", "cli/audit-chain-verify.ts",
  "core/encoding.ts", "core/encryption.ts", "core/hashing.ts", "core/identity.ts", "core/random.ts", "core/rotation-chain.ts",
  "errors/config-error.ts", "errors/index.ts", "errors/profile-error.ts", "errors/untrusted-diagnostic.ts",
  "evidence-pack/snapshot-contract.ts", "evidence-pack/snapshot-nested.ts", "evidence-pack/snapshot-trust.ts", "evidence-pack/snapshot-verify.ts",
  "hermes-memory-bridge/constants.ts", "hermes-memory-bridge/strict-json.ts", "lockdown/status.ts", "transparency/checkpoint.ts", "transparency/verify.ts",
];
// Existing audit CLI imports filesystem helpers; the pure entry never calls its I/O functions.
const EXTERNAL = new Set(["@noble/curves/ed25519", "@noble/hashes/sha256", "@noble/hashes/hmac", "@noble/hashes/sha512", "@noble/hashes/hkdf", "@noble/ciphers/aes.js", "node:crypto", "crypto", "node:fs", "node:fs/promises", "node:path"]);
function imports(source: string): string[] {
  const tree = ts.createSourceFile("fixture.ts", source, ts.ScriptTarget.Latest, true); const specs: string[] = [];
  function visit(node: ts.Node) {
    if (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly) {
      const bindings = node.importClause?.namedBindings;
      const onlyTypes = bindings && ts.isNamedImports(bindings) && bindings.elements.length > 0 && bindings.elements.every(e => e.isTypeOnly) && !node.importClause?.name;
      if (!onlyTypes && ts.isStringLiteral(node.moduleSpecifier)) specs.push(node.moduleSpecifier.text);
    }
    if (ts.isExportDeclaration(node) && !node.isTypeOnly && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) specs.push(node.moduleSpecifier.text);
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === "require"))) {
      const argument = node.arguments[0]; expect(argument && ts.isStringLiteral(argument)).toBe(true); if (argument && ts.isStringLiteral(argument)) specs.push(argument.text);
    }
    ts.forEachChild(node, visit);
  }
  visit(tree); return specs;
}
function crawl(): { files: string[]; external: string[] } {
  const seen = new Set<string>(); const external = new Set<string>();
  const queue = ["evidence-pack/snapshot-verify.ts", "evidence-pack/snapshot-contract.ts", "evidence-pack/snapshot-trust.ts", "evidence-pack/snapshot-nested.ts"];
  while (queue.length) {
    const file = queue.shift()!; if (seen.has(file)) continue; seen.add(file);
    for (const spec of imports(readFileSync(resolve(ROOT, file), "utf8"))) {
      if (!spec.startsWith(".")) { external.add(spec); continue; }
      const target = resolve(ROOT, dirname(file), spec.replace(/\.js$/, ".ts")); expect(existsSync(target)).toBe(true); queue.push(relative(ROOT, target));
    }
  }
  return { files: [...seen].sort(), external: [...external].sort() };
}
describe("snapshot verifier import graph", () => {
  it("matches the complete runtime allowlist and cannot reach exporter or server startup", () => { const graph = crawl(); expect(graph.files).toEqual([...ALLOWED].sort()); expect(graph.external.filter(s => !EXTERNAL.has(s))).toEqual([]); });
  it("parser sees side effects, reexports, dynamic imports and require but excludes type-only edges", () => { expect(imports('import "./a.js"; export { b } from "./b.js"; import("./c.js"); require("./d.js"); import type { E } from "./e.js";')).toEqual(["./a.js", "./b.js", "./c.js", "./d.js"]); });
});
