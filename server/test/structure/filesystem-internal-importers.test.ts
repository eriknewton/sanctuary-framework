/**
 * Import-graph pin for the two internal entries of storage/filesystem.ts.
 *
 * `createDirectoryCapabilityWorkerStorage` builds the worker executor that skips
 * the strict lock requirement, so exactly one module may import it: the Darwin
 * directory-capability worker. `withFilesystemLockTestHooks` injects lock test
 * hooks, so no production or script module may import it at all. Both must
 * match the comments on those exports in src/storage/filesystem.ts.
 *
 * The graph is read with the TypeScript parser over every source file under
 * server/src and server/scripts, so static imports, re-exports, dynamic imports
 * and require calls are all edges. Any edge to filesystem.ts that does not name
 * its bindings (a namespace import, `export *`, or an undestructured dynamic
 * import) could reach both entries, so the set of such opaque edges must be empty.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const TARGET = resolve(SERVER, "src/storage/filesystem.ts");
const SOURCE_EXTENSIONS = new Set([".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"]);
const WORKER_FACTORY = "createDirectoryCapabilityWorkerStorage";
const TEST_HOOK_INJECTION = "withFilesystemLockTestHooks";

interface Edge { specifier: string; names: string[] | "opaque" }

/** Every runtime edge in one source file, with the bindings it names. */
function edges(fileName: string, source: string): Edge[] {
  const tree = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const found: Edge[] = [];
  const named = (elements: readonly (ts.ImportSpecifier | ts.ExportSpecifier)[]): string[] =>
    elements.filter(element => !element.isTypeOnly).map(element => (element.propertyName ?? element.name).text);
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && !node.importClause?.isTypeOnly) {
      const bindings = node.importClause?.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) found.push({ specifier: node.moduleSpecifier.text, names: "opaque" });
      else found.push({
        specifier: node.moduleSpecifier.text,
        names: [...(node.importClause?.name ? ["default"] : []), ...(bindings && ts.isNamedImports(bindings) ? named(bindings.elements) : [])],
      });
    }
    if (ts.isExportDeclaration(node) && !node.isTypeOnly && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      found.push({
        specifier: node.moduleSpecifier.text,
        names: node.exportClause && ts.isNamedExports(node.exportClause) ? named(node.exportClause.elements) : "opaque",
      });
    }
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === "require"))) {
      const argument = node.arguments[0];
      const specifier = argument && ts.isStringLiteralLike(argument) ? argument.text : "<computed>";
      // Only `const { a, b } = await import(...)` or `= require(...)` names its bindings; any other use can reach every export.
      let parent: ts.Node = node.parent;
      while (ts.isAwaitExpression(parent) || ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent) || ts.isSatisfiesExpression(parent) || ts.isNonNullExpression(parent)) parent = parent.parent;
      const names = ts.isVariableDeclaration(parent) && ts.isObjectBindingPattern(parent.name) && parent.name.elements.every(element => !element.dotDotDotToken)
        ? parent.name.elements.map(element => (element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName : element.name as ts.Identifier).text)
        : "opaque";
      found.push({ specifier, names });
    }
    ts.forEachChild(node, visit);
  };
  visit(tree);
  return found;
}

function sourceFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (entry === "node_modules") continue;
    if (statSync(path).isDirectory()) files.push(...sourceFiles(path));
    else if (SOURCE_EXTENSIONS.has(extname(entry)) && !entry.endsWith(".d.ts") && !entry.endsWith(".d.mts")) files.push(path);
  }
  return files;
}

/** Resolve a relative specifier the way the TypeScript sources write it (`.js` naming a `.ts` file). */
function resolvesToTarget(fromFile: string, specifier: string): boolean {
  if (specifier === "<computed>") return true;
  if (!specifier.startsWith(".")) return false;
  const base = resolve(dirname(fromFile), specifier);
  return [base, base.replace(/\.js$/, ".ts"), base.replace(/\.mjs$/, ".mts"), `${base}.ts`].includes(TARGET);
}

function importersOfTarget(): { naming: (name: string) => string[]; opaque: string[]; all: string[] } {
  const byFile = new Map<string, Array<string[] | "opaque">>();
  for (const root of ["src", "scripts"]) {
    for (const file of sourceFiles(resolve(SERVER, root))) {
      for (const edge of edges(file, readFileSync(file, "utf8"))) {
        if (!resolvesToTarget(file, edge.specifier)) continue;
        const key = relative(SERVER, file);
        byFile.set(key, [...(byFile.get(key) ?? []), edge.names]);
      }
    }
  }
  const files = [...byFile.keys()].sort();
  return {
    all: files,
    opaque: files.filter(file => byFile.get(file)!.includes("opaque")),
    naming: (name: string) => files.filter(file => byFile.get(file)!.some(names => names !== "opaque" && names.includes(name))),
  };
}

describe("filesystem.ts internal entries import graph", () => {
  it("only the Darwin worker imports the worker-exemption factory, and nothing reaches filesystem.ts opaquely", () => {
    const graph = importersOfTarget();
    // The scan is only meaningful if it sees the known importers of the storage module.
    expect(graph.all).toEqual(expect.arrayContaining(["src/storage/directory-capability-worker.ts", "src/storage/index.ts", "src/index.ts"]));
    expect(graph.naming(WORKER_FACTORY)).toEqual(["src/storage/directory-capability-worker.ts"]);
    expect(graph.opaque).toEqual([]);
  });

  it("no production or script module imports the lock test-hook injection", () => {
    expect(importersOfTarget().naming(TEST_HOOK_INJECTION)).toEqual([]);
  });

  it("the edge parser names bindings and treats unnamed reach as opaque", () => {
    const source = [
      'import { a, b as c, type T } from "./x.js";',
      'import * as all from "./ns.js";',
      'export { d } from "./re.js";',
      'export * from "./star.js";',
      'const { e, f: g } = await import("./dyn.js");',
      'const module = await import("./dyn-opaque.js");',
      'const { h } = require("./req.js");',
      'const { i } = await import(computed) as { i: unknown };',
      'import type { U } from "./types.js";',
    ].join("\n");
    expect(edges("fixture.ts", source)).toEqual([
      { specifier: "./x.js", names: ["a", "b"] },
      { specifier: "./ns.js", names: "opaque" },
      { specifier: "./re.js", names: ["d"] },
      { specifier: "./star.js", names: "opaque" },
      { specifier: "./dyn.js", names: ["e", "f"] },
      { specifier: "./dyn-opaque.js", names: "opaque" },
      { specifier: "./req.js", names: ["h"] },
      { specifier: "<computed>", names: ["i"] },
    ]);
  });
});
