/**
 * Import-graph pin for the two internal entries of storage/filesystem.ts.
 *
 * `createDirectoryCapabilityWorkerStorage` builds the worker executor that skips
 * the strict lock requirement, so exactly one module may import it: the Darwin
 * directory-capability worker. `withFilesystemLockTestHooks` injects lock test
 * hooks, so no production or script module may import it at all. Both must
 * match the comments on those exports in src/storage/filesystem.ts.
 *
 * The graph is read with the TypeScript parser over every source file in the
 * runtime roots of server/ (RUNTIME_ROOTS), and a totality check proves no
 * source file outside those roots and the declared non-runtime roots exists.
 * Static imports, re-exports, `import x = require()`, dynamic imports, `require`
 * calls and calls through a `createRequire` result are all edges, and relative,
 * absolute and file-URL specifiers all resolve. A binding name is decoded from
 * an identifier or a string literal; any reach the parser cannot name (a
 * namespace import, `export *`, an undestructured load, a computed or rest
 * destructure, an aliased or member loader) is an opaque edge, and opaque reach
 * of filesystem.ts fails the guard closed.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SERVER = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const TARGET = resolve(SERVER, "src/storage/filesystem.ts");
const WORKER = resolve(SERVER, "src/storage/directory-capability-worker.ts");
const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]);
const DECLARATION_SUFFIXES = [".d.ts", ".d.mts", ".d.cts"];
const WORKER_FACTORY = "createDirectoryCapabilityWorkerStorage";
const TEST_HOOK_INJECTION = "withFilesystemLockTestHooks";
/** Placeholder specifier for a load whose module the parser cannot read statically. */
const COMPUTED = "<computed>";

/**
 * Source roots under server/ that ship or run as product code. src is the tsup
 * input; scripts holds build steps and the evidence-pack entries tsup bundles;
 * electron, examples and public hold runnable shells and served scripts. bin is
 * shell only and has no module source.
 */
const RUNTIME_ROOTS = ["src", "scripts", "electron", "examples", "public"];
/** Roots that never run in production: the test suite and design references. */
const NON_RUNTIME_ROOTS = ["test", "docs"];
/** Generated output and dependency directories directly under server/, skipped by the totality walk only. */
const GENERATED_DIRECTORIES = new Set(["node_modules", "dist", "dist-typecheck", "evidence-pack-dist", "coverage", "playwright-report", "test-results", "reports"]);
/** Top-level build configuration, which configures the build but is not shipped. */
const BUILD_CONFIG = /^[^/\\]+\.config\.[cm]?[jt]s$/;

/** The allowed importers of each protected export, as server-relative paths. */
const PROTECTED_EXPORTS = new Map<string, ReadonlySet<string>>([
  [WORKER_FACTORY, new Set([relative(SERVER, WORKER)])],
  [TEST_HOOK_INJECTION, new Set()],
]);

interface Edge { specifier: string; names: string[] | "opaque" }

/** Strip expression wrappers that do not change which value flows through. */
function isTransparentWrapper(node: ts.Node): boolean {
  return ts.isAwaitExpression(node) || ts.isParenthesizedExpression(node) || ts.isAsExpression(node)
    || ts.isSatisfiesExpression(node) || ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node);
}

function outermost(node: ts.Node): ts.Node {
  let outer = node;
  while (isTransparentWrapper(outer.parent)) outer = outer.parent;
  return outer;
}

function innermost(node: ts.Expression): ts.Expression {
  let inner = node;
  while (ts.isParenthesizedExpression(inner) || ts.isAsExpression(inner) || ts.isSatisfiesExpression(inner) || ts.isNonNullExpression(inner) || ts.isTypeAssertionExpression(inner)) inner = inner.expression;
  return inner;
}

/** A module export or destructured property name as the runtime sees it, or undefined when it is not static. */
function staticPropertyName(name: ts.Node | undefined): string | undefined {
  // Identifier and string-literal `.text` are the cooked names, so escapes decode to the real export name.
  if (name && (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name))) return name.text;
  return undefined;
}

/** True when an identifier reads a value, not when it names a declaration, a property or a type. */
function isValueReference(id: ts.Identifier): boolean {
  const parent = id.parent;
  if (ts.isPropertyAccessExpression(parent) && parent.name === id) return false;
  if (ts.isQualifiedName(parent) || ts.isImportSpecifier(parent) || ts.isImportClause(parent) || ts.isNamespaceImport(parent) || ts.isImportEqualsDeclaration(parent)) return false;
  if (ts.isExportSpecifier(parent)) return !parent.parent.parent.moduleSpecifier && (parent.propertyName ?? parent.name) === id;
  if (ts.isBindingElement(parent)) return false;
  if (ts.isLabeledStatement(parent) || ts.isBreakOrContinueStatement(parent) || ts.isJsxAttribute(parent)) return false;
  const named = parent as ts.Node & { name?: ts.Node };
  if (named.name === id && !ts.isShorthandPropertyAssignment(parent)) return false;
  for (let node: ts.Node = parent; !ts.isSourceFile(node); node = node.parent) if (ts.isTypeNode(node) && !ts.isExpressionWithTypeArguments(node)) return false;
  return true;
}

/** Every runtime edge in one source file, with the bindings it names. */
function edges(fileName: string, source: string): Edge[] {
  const tree = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const found: Edge[] = [];
  const named = (elements: readonly (ts.ImportSpecifier | ts.ExportSpecifier)[]): string[] =>
    elements.filter(element => !element.isTypeOnly).map(element => (element.propertyName ?? element.name).text);

  // Local names bound to createRequire itself, and to a createRequire result, collected before the walk so order does not matter.
  const createRequireNames = new Set(["createRequire"]);
  const loaderNames = new Set(["require"]);
  const collectFactories = (node: ts.Node): void => {
    if (ts.isImportSpecifier(node) && (node.propertyName ?? node.name).text === "createRequire") createRequireNames.add(node.name.text);
    if (ts.isBindingElement(node) && ts.isIdentifier(node.name) && staticPropertyName(node.propertyName ?? node.name) === "createRequire") createRequireNames.add(node.name.text);
    ts.forEachChild(node, collectFactories);
  };
  collectFactories(tree);
  const isCreateRequireReference = (node: ts.Expression): boolean => {
    const inner = innermost(node);
    return (ts.isIdentifier(inner) && createRequireNames.has(inner.text))
      || (ts.isPropertyAccessExpression(inner) && inner.name.text === "createRequire")
      || (ts.isElementAccessExpression(inner) && ts.isStringLiteralLike(inner.argumentExpression) && inner.argumentExpression.text === "createRequire");
  };
  const isCreateRequireCall = (node: ts.Expression): boolean => {
    const inner = innermost(node);
    return ts.isCallExpression(inner) && isCreateRequireReference(inner.expression);
  };
  const collectLoaders = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && isCreateRequireCall(node.initializer)) loaderNames.add(node.name.text);
    ts.forEachChild(node, collectLoaders);
  };
  collectLoaders(tree);
  const isLoader = (node: ts.Expression): boolean => {
    const inner = innermost(node);
    return (ts.isIdentifier(inner) && loaderNames.has(inner.text)) || isCreateRequireCall(inner);
  };

  /** How a loader value is used: a direct load call, an inert lookup, a declared alias, or anything the parser cannot follow. */
  const loaderUse = (node: ts.Node): "load" | "inert" | "alias" | "opaque" => {
    const outer = outermost(node);
    const parent = outer.parent;
    if (ts.isCallExpression(parent) && parent.expression === outer) return "load";
    // `require.resolve` returns a path and never evaluates the module; loading that path later is a computed edge.
    if (ts.isPropertyAccessExpression(parent) && parent.expression === outer && parent.name.text === "resolve") return "inert";
    if (ts.isTypeOfExpression(parent)) return "inert";
    if (ts.isVariableDeclaration(parent) && parent.initializer === outer && ts.isIdentifier(parent.name)) return "alias";
    return "opaque";
  };

  /** Only `const { a, b } = load(...)` names its bindings; any other use can reach every export. */
  const destructuredNames = (call: ts.CallExpression): string[] | "opaque" => {
    const outer = outermost(call);
    const parent = outer.parent;
    if (!ts.isVariableDeclaration(parent) || parent.initializer !== outer || !ts.isObjectBindingPattern(parent.name)) return "opaque";
    const names: string[] = [];
    for (const element of parent.name.elements) {
      if (element.dotDotDotToken) return "opaque";
      // A computed or otherwise unrecognized key could be any export, so it is opaque rather than guessed.
      const name = element.propertyName ? staticPropertyName(element.propertyName) : staticPropertyName(element.name);
      if (name === undefined) return "opaque";
      names.push(name);
    }
    return names;
  };
  const loadEdge = (call: ts.CallExpression): Edge => {
    const argument = call.arguments[0];
    return { specifier: argument && ts.isStringLiteralLike(argument) ? argument.text : COMPUTED, names: destructuredNames(call) };
  };

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
    if (ts.isImportEqualsDeclaration(node) && !node.isTypeOnly && ts.isExternalModuleReference(node.moduleReference)) {
      const reference = node.moduleReference.expression;
      found.push({ specifier: ts.isStringLiteralLike(reference) ? reference.text : COMPUTED, names: "opaque" });
    }
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || isLoader(node.expression))) found.push(loadEdge(node));
    // A createRequire call whose result is not loaded, looked up inertly or bound to a tracked name escapes the model.
    if (ts.isCallExpression(node) && isCreateRequireReference(node.expression) && loaderUse(node) === "opaque") found.push({ specifier: COMPUTED, names: "opaque" });
    if (ts.isIdentifier(node) && (createRequireNames.has(node.text) || loaderNames.has(node.text)) && isValueReference(node)) {
      // The createRequire factory itself may only be called; passing or aliasing it hides every load it makes.
      if (createRequireNames.has(node.text) && loaderUse(node) !== "load") found.push({ specifier: COMPUTED, names: "opaque" });
      // A tracked loader may only be called or looked up inertly; an alias or argument hides the module it loads.
      if (loaderNames.has(node.text) && !["load", "inert"].includes(loaderUse(node))) found.push({ specifier: COMPUTED, names: "opaque" });
    }
    const memberName = ts.isPropertyAccessExpression(node) ? node.name.text
      : ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression) ? node.argumentExpression.text : undefined;
    // A member createRequire (`nodeModule.createRequire`) may likewise only be called.
    if (memberName === "createRequire" && loaderUse(node) !== "load") found.push({ specifier: COMPUTED, names: "opaque" });
    // `module.require`, `require.main.require` and similar member loaders are not modelled, so they fail closed.
    if (memberName === "require") found.push({ specifier: COMPUTED, names: "opaque" });
    ts.forEachChild(node, visit);
  };
  visit(tree);
  return found;
}

/** True when the guard scans a file with this name: a module source, not a declaration file. */
function isScannedSource(fileName: string): boolean {
  return SOURCE_EXTENSIONS.has(extname(fileName)) && !DECLARATION_SUFFIXES.some(suffix => fileName.endsWith(suffix));
}

/** Every module source under `directory`; `skipTopLevel` names only its direct children, so nothing nested in a root is ever skipped. */
function sourceFiles(directory: string, skipTopLevel: (entry: string) => boolean = () => false): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      if (!skipTopLevel(entry)) files.push(...sourceFiles(path));
    } else if (isScannedSource(entry)) files.push(path);
  }
  return files;
}

/** The module stem that names filesystem.ts under any source extension, case-folded because macOS paths are case-insensitive. */
function moduleStem(path: string): string {
  return path.replace(/\.(?:[cm]?[jt]sx?)$/i, "").toLowerCase();
}

/**
 * Resolve a specifier the way Node and the TypeScript sources may: a relative
 * or absolute path, read both as a path and as a URL (which decodes escapes and
 * drops a query or hash), or a file URL. A computed specifier, or a file URL that
 * cannot be decoded, is assumed to reach the target.
 */
function resolvesToTarget(fromFile: string, specifier: string): boolean {
  if (specifier === COMPUTED) return true;
  const candidates: string[] = [];
  try {
    if (/^file:/i.test(specifier)) candidates.push(fileURLToPath(new URL(specifier)));
    else if (specifier.startsWith(".") || isAbsolute(specifier)) {
      candidates.push(resolve(dirname(fromFile), specifier.replace(/[?#].*$/, "")));
      candidates.push(fileURLToPath(new URL(specifier, pathToFileURL(fromFile))));
    } else return false;
  } catch {
    return true;
  }
  return candidates.some(candidate => moduleStem(candidate) === moduleStem(TARGET));
}

/** Every protected or opaque reach of filesystem.ts in one source file that its path is not allowed. */
function violations(fileName: string, source: string): string[] {
  const file = relative(SERVER, fileName);
  const found: string[] = [];
  for (const edge of edges(fileName, source)) {
    if (!resolvesToTarget(fileName, edge.specifier)) continue;
    if (edge.names === "opaque") found.push(`${file}: opaque reach via ${edge.specifier}`);
    else for (const name of edge.names) if (PROTECTED_EXPORTS.get(name)?.has(file) === false) found.push(`${file}: ${name}`);
  }
  return found;
}

function runtimeSourceFiles(): string[] {
  return RUNTIME_ROOTS.flatMap(root => sourceFiles(resolve(SERVER, root)));
}

function importersOfTarget(): { naming: (name: string) => string[]; opaque: string[]; all: string[] } {
  const byFile = new Map<string, Array<string[] | "opaque">>();
  for (const file of runtimeSourceFiles()) {
    for (const edge of edges(file, readFileSync(file, "utf8"))) {
      if (!resolvesToTarget(file, edge.specifier)) continue;
      const key = relative(SERVER, file);
      byFile.set(key, [...(byFile.get(key) ?? []), edge.names]);
    }
  }
  const files = [...byFile.keys()].sort();
  return {
    all: files,
    opaque: files.filter(file => byFile.get(file)!.includes("opaque")),
    naming: (name: string) => files.filter(file => byFile.get(file)!.some(names => names !== "opaque" && names.includes(name))),
  };
}

const IN_STORAGE = resolve(SERVER, "src/storage/importer-fixture.ts");
const ELSEWHERE = resolve(SERVER, "src/cli/importer-fixture.ts");
const TARGET_AS_JS = resolve(SERVER, "src/storage/filesystem.js");
/** The worker's import of filesystem.ts, which must appear verbatim in the worker source. */
const WORKER_IMPORT = 'import { createDirectoryCapabilityWorkerStorage, type FilesystemStorage, serializeCapabilityError } from "./filesystem.js";';

describe("filesystem.ts internal entries import graph", () => {
  it("only the Darwin worker imports the worker-exemption factory, and nothing reaches filesystem.ts opaquely", () => {
    const graph = importersOfTarget();
    // The scan is only meaningful if it sees the known importers of the storage module.
    expect(graph.all).toEqual(expect.arrayContaining(["src/storage/directory-capability-worker.ts", "src/storage/index.ts", "src/index.ts"]));
    expect(graph.naming(WORKER_FACTORY)).toEqual(["src/storage/directory-capability-worker.ts"]);
    expect(graph.opaque).toEqual([]);
    expect(runtimeSourceFiles().flatMap(file => violations(file, readFileSync(file, "utf8")))).toEqual([]);
  });

  it("no production or script module imports the lock test-hook injection", () => {
    expect(importersOfTarget().naming(TEST_HOOK_INJECTION)).toEqual([]);
  });

  it("every module source under server/ lies in a scanned runtime root or a declared non-runtime root", () => {
    // A new source root would otherwise sit outside the scan and could import either entry unseen.
    for (const root of RUNTIME_ROOTS) expect(statSync(resolve(SERVER, root)).isDirectory()).toBe(true);
    const unclassified = sourceFiles(SERVER, entry => entry.startsWith(".") || GENERATED_DIRECTORIES.has(entry)).map(file => relative(SERVER, file)).filter(file =>
      ![...RUNTIME_ROOTS, ...NON_RUNTIME_ROOTS].some(root => file.startsWith(`${root}${sep}`)) && !BUILD_CONFIG.test(file));
    expect(unclassified).toEqual([]);
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
      'const { "j": k } = await import("./quoted.js");',
      'import { "l" as m } from "./quoted-import.js";',
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
      { specifier: "./quoted.js", names: ["j"] },
      { specifier: "./quoted-import.js", names: ["l"] },
    ]);
  });

  it("the worker's real import shape is allowed only at the worker's own path", () => {
    expect(readFileSync(WORKER, "utf8")).toContain(WORKER_IMPORT);
    expect(violations(WORKER, WORKER_IMPORT)).toEqual([]);
    expect(violations(IN_STORAGE, WORKER_IMPORT)).toEqual([`src/storage/importer-fixture.ts: ${WORKER_FACTORY}`]);
  });

  it("the inert loader uses the real tree relies on are not edges", () => {
    const source = [
      'import { createRequire } from "node:module";',
      "const require = createRequire(import.meta.url);",
      'const { version } = require("../package.json");',
      'const entry = require.resolve("./filesystem.js");',
      'const tsx = createRequire(import.meta.url).resolve("tsx");',
    ].join("\n");
    expect(violations(IN_STORAGE, source)).toEqual([]);
  });

  const protectedExports = [WORKER_FACTORY, TEST_HOOK_INJECTION];
  const flaggedFixtures: Array<[string, string, string]> = [
    ...protectedExports.flatMap((name): Array<[string, string, string]> => [
      [`quoted destructure of ${name} from a dynamic import`, IN_STORAGE, `const { "${name}": local } = await import("./filesystem.js");`],
      [`quoted destructure of ${name} from require`, IN_STORAGE, `const { "${name}": local } = require("./filesystem.js");`],
      [`escaped quoted destructure of ${name}`, IN_STORAGE, `const { "\\u${name.charCodeAt(0).toString(16).padStart(4, "0")}${name.slice(1)}": local } = await import("./filesystem.js");`],
      [`string-literal named import of ${name}`, IN_STORAGE, `import { "${name}" as local } from "./filesystem.js";`],
      [`computed literal destructure of ${name}`, IN_STORAGE, `const { ["${name}"]: local } = await import("./filesystem.js");`],
      [`absolute specifier naming ${name}`, ELSEWHERE, `import { ${name} } from ${JSON.stringify(TARGET_AS_JS)};`],
      [`file URL specifier naming ${name}`, ELSEWHERE, `const { ${name} } = await import(${JSON.stringify(pathToFileURL(TARGET_AS_JS).href)});`],
    ]),
    ["computed variable destructure", IN_STORAGE, 'const key = "anything"; const { [key]: local } = await import("./filesystem.js");'],
    ["rest destructure", IN_STORAGE, 'const { FilesystemStorage, ...rest } = await import("./filesystem.js");'],
    ["aliased createRequire loading the module whole", IN_STORAGE, 'import { createRequire as makeLoader } from "node:module";\nconst load = makeLoader(import.meta.url);\nconst storage = load("./filesystem.js");'],
    ["aliased createRequire naming the factory", IN_STORAGE, `import { createRequire as makeLoader } from "node:module";\nconst load = makeLoader(import.meta.url);\nconst { ${WORKER_FACTORY} } = load("./filesystem.js");`],
    ["createRequire result called inline", IN_STORAGE, `import { createRequire } from "node:module";\nconst hooks = createRequire(import.meta.url)("./filesystem.js").${TEST_HOOK_INJECTION};`],
    ["createRequire result passed on", ELSEWHERE, 'import { createRequire } from "node:module";\nuse(createRequire(import.meta.url));'],
    ["createRequire factory aliased", ELSEWHERE, 'import * as nodeModule from "node:module";\nconst factory = nodeModule.createRequire;'],
    ["aliased require", ELSEWHERE, 'const load = require;\nconst storage = load("../storage/filesystem.js");'],
    ["module.require", IN_STORAGE, 'const storage = module.require("./filesystem.js");'],
    ["dynamic import with a template specifier into storage", ELSEWHERE, 'const storage = await import(`../storage/${"filesystem"}.js`);'],
    ["import equals require", IN_STORAGE, 'import storage = require("./filesystem.js");'],
    ["case-folded relative specifier", ELSEWHERE, `import { ${TEST_HOOK_INJECTION} } from "../storage/FileSystem.js";`],
    ["percent-encoded relative specifier", ELSEWHERE, `const { ${TEST_HOOK_INJECTION} } = await import("../storage/file%73ystem.js");`],
  ];

  it.each(flaggedFixtures)("flags %s", (_label, fileName, source) => {
    expect(violations(fileName, source)).not.toEqual([]);
  });

  it("scans a .tsx importer and flags its reach", () => {
    const fileName = resolve(SERVER, "src/console/importer-fixture.tsx");
    const source = `import { ${TEST_HOOK_INJECTION} } from "../storage/filesystem.js";\nexport const View = () => <div>{String(${TEST_HOOK_INJECTION})}</div>;`;
    expect(isScannedSource(fileName)).toBe(true);
    expect(violations(fileName, source)).toEqual([`src/console/importer-fixture.tsx: ${TEST_HOOK_INJECTION}`]);
  });
});
