// fail-before-exempt: new worker entry, no base behaviour; the positive control proves the scan detects a forbidden reach.
import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(HERE, "../../src");
const ENTRY = resolve(SRC, "local-recompile/worker-entry.ts");
const FORBIDDEN_FIXTURE = resolve(HERE, "__fixtures__/local-recompile-worker-forbidden-entry.ts");

// Files the worker must never reach: the shared audit log, the selector, every
// substrate client, master-key holders, the store-key derivation and the server.
const FORBIDDEN_FILES = [
  "operational/audit-log.ts",
  "intelligence/selector.ts",
  "cognitive/state-store.ts",
  "core/master-custody.ts",
  "core/master-rotation.ts",
  "local-recompile/store-keys.ts",
  "index.ts",
  "router.ts",
];
const FORBIDDEN_DIRECTORIES = ["intelligence/substrates/"];

interface Edge { specifier: string; dynamic: boolean }

/** Static and dynamic module edges; type-only imports are erased at build and are not edges. */
function edges(source: string): Edge[] {
  const tree = ts.createSourceFile("module.ts", source, ts.ScriptTarget.Latest, true);
  const found: Edge[] = [];
  function visit(node: ts.Node): void {
    if (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly && ts.isStringLiteral(node.moduleSpecifier)) {
      const bindings = node.importClause?.namedBindings;
      const onlyTypes = bindings !== undefined && ts.isNamedImports(bindings) && bindings.elements.length > 0 &&
        bindings.elements.every((element) => element.isTypeOnly) && node.importClause?.name === undefined;
      if (!onlyTypes) found.push({ specifier: node.moduleSpecifier.text, dynamic: false });
    }
    if (ts.isExportDeclaration(node) && !node.isTypeOnly && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      found.push({ specifier: node.moduleSpecifier.text, dynamic: false });
    }
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      const argument = node.arguments[0];
      found.push({ specifier: argument && ts.isStringLiteral(argument) ? argument.text : "<computed>", dynamic: true });
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
      const argument = node.arguments[0];
      found.push({ specifier: argument && ts.isStringLiteral(argument) ? argument.text : "<computed>", dynamic: true });
    }
    // `import x = require("...")` is a static edge like an import declaration.
    if (ts.isImportEqualsDeclaration(node) && !node.isTypeOnly && ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteral(node.moduleReference.expression)) {
      found.push({ specifier: node.moduleReference.expression.text, dynamic: false });
    }
    // A require built by createRequire can load any module. Only the form that resolves a path and
    // loads nothing, createRequire(...).resolve(...), is not an edge.
    // The callee may be the bare name or a property of a namespace import (`m.createRequire`).
    const callee = ts.isCallExpression(node) ? node.expression : undefined;
    const createsRequire = callee !== undefined &&
      ((ts.isIdentifier(callee) && callee.text === "createRequire") || (ts.isPropertyAccessExpression(callee) && callee.name.text === "createRequire"));
    if (ts.isCallExpression(node) && createsRequire) {
      const parent = node.parent;
      const resolvesOnly = ts.isPropertyAccessExpression(parent) && parent.expression === node && parent.name.text === "resolve" &&
        ts.isCallExpression(parent.parent) && parent.parent.expression === parent;
      if (!resolvesOnly) found.push({ specifier: "<createRequire>", dynamic: true });
    }
    // process.getBuiltinModule loads a module by a runtime name.
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "getBuiltinModule") {
      const argument = node.arguments[0];
      found.push({ specifier: argument && ts.isStringLiteral(argument) ? argument.text : "<computed>", dynamic: true });
    }
    ts.forEachChild(node, visit);
  }
  visit(tree);
  return found;
}

function closure(entry: string): { files: string[]; dynamic: string[] } {
  const seen = new Set<string>();
  const dynamic: string[] = [];
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.shift()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const edge of edges(readFileSync(file, "utf8"))) {
      if (edge.dynamic) dynamic.push(`${relative(SRC, file)} -> ${edge.specifier}`);
      if (!edge.specifier.startsWith(".")) continue;
      const target = resolve(dirname(file), edge.specifier.replace(/\.js$/, ".ts"));
      expect(existsSync(target), `${relative(SRC, file)} -> ${edge.specifier}`).toBe(true);
      queue.push(target);
    }
  }
  return { files: [...seen].map((file) => relative(SRC, file)).sort(), dynamic };
}

function forbiddenReach(files: string[]): string[] {
  return files.filter((file) => FORBIDDEN_FILES.includes(file) || FORBIDDEN_DIRECTORIES.some((dir) => file.startsWith(dir)));
}

describe("local job worker import graph", () => {
  it("the worker cannot reach the shared audit log, the selector, the Ollama client or a master-key holder", () => {
    const graph = closure(ENTRY);
    expect(graph.files).toContain("local-recompile/worker-entry.ts");
    expect(graph.files).toContain("storage/filesystem.ts");
    expect(forbiddenReach(graph.files)).toEqual([]);
    expect(graph.dynamic).toEqual([]);
  });

  it("the scan detects a forbidden import", () => {
    const graph = closure(FORBIDDEN_FIXTURE);
    expect(forbiddenReach(graph.files)).toContain("operational/audit-log.ts");
  });

  it("the parser sees dynamic imports and require but not type-only edges", () => {
    expect(edges('import "./a.js"; export { b } from "./b.js"; import("./c.js"); require("./d.js"); import type { E } from "./e.js";'))
      .toEqual([
        { specifier: "./a.js", dynamic: false },
        { specifier: "./b.js", dynamic: false },
        { specifier: "./c.js", dynamic: true },
        { specifier: "./d.js", dynamic: true },
      ]);
  });

  it("the parser sees createRequire loaders, getBuiltinModule and import-equals, and allows a resolve-only createRequire", () => {
    expect(edges([
      'import x = require("./f.js");',
      "const load = createRequire(import.meta.url); load(name);",
      'createRequire(import.meta.url)("./g.js");',
      'process.getBuiltinModule("node:fs");',
      'const path = createRequire(import.meta.url).resolve("tsx");',
    ].join("\n"))).toEqual([
      { specifier: "./f.js", dynamic: false },
      { specifier: "<createRequire>", dynamic: true },
      { specifier: "<createRequire>", dynamic: true },
      { specifier: "node:fs", dynamic: true },
    ]);
  });

  it("the parser sees createRequire reached through a namespace import, and allows its resolve-only form", () => {
    expect(edges([
      'import * as m from "node:module";',
      'm.createRequire(import.meta.url)("./h.js");',
      'const path = m.createRequire(import.meta.url).resolve("tsx");',
    ].join("\n"))).toEqual([
      { specifier: "node:module", dynamic: false },
      { specifier: "<createRequire>", dynamic: true },
    ]);
  });
});
