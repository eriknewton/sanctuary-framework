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
 * of filesystem.ts fails the guard closed. Runtime code may not import a module
 * source outside the scanned roots, and no scanned root may hold a symlink.
 *
 * Bound: this is a fail-closed tripwire over the import forms committed source
 * uses, not a sandbox against deliberately obfuscated code, which is the review
 * gate's job; a form it does not model fails the test rather than passing silently.
 */
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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
/**
 * Generated output and dependency paths under server/, as exact server-relative
 * paths skipped by the totality walk only; each is gitignored build, test or
 * mutation output. Any other directory, dot directories and siblings of these
 * included, is walked and classified.
 */
const GENERATED_PATHS = new Set(["node_modules", "dist", "dist-typecheck", "evidence-pack-dist", "coverage", "playwright-report", "test-results", "reports/mutation", ".stryker-tmp"]);
/**
 * Reviewed imports from runtime code into module source outside the scanned
 * roots, as "importer -> specifier". Each target is scanned as runtime code, and
 * so is every local module it imports in turn.
 */
const REVIEWED_OUT_OF_ROOT_IMPORTS = new Set([
  "scripts/calibrate-d5-perf.ts -> ../test/agent-contract/fixture.js",
  "scripts/evidence-pack-drill-isolation.ts -> ../test/setup/keychain-memory-store.js",
  "scripts/gen-at-rest-fixtures.ts -> ../test/fixtures/at-rest/fixture-stores.js",
]);
/**
 * Imports of the built package barrel, which tsup generates from src/index.ts;
 * this guard already pins that src/index.ts names neither protected export, and
 * dist is build output, so it is not scanned.
 */
const PACKAGE_BARREL_IMPORTS = new Set(["examples/dashboard-example.mjs -> ../dist/index.js"]);
/** The exact top-level build configuration files in server/, which configure the build but are not shipped. */
const BUILD_CONFIG_FILES = new Set([
  "eslint.config.js", "playwright.config.ts", "stryker.config.mjs", "tsup.boot-runtime.config.ts",
  "tsup.config.ts", "tsup.evidence-pack.config.ts", "vitest.config.ts",
]);
/** Specifiers that name the Node built-in module system, whose factory can build a loader. */
const BUILTIN_MODULE_SPECIFIERS = new Set(["module", "node:module"]);
/** node:module exports that cannot load a module, so a static named read of one is not an edge. */
const INERT_BUILTIN_MODULE_EXPORTS = new Set(["syncBuiltinESMExports", "isBuiltin", "builtinModules"]);

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
  // A binding default initializer is evaluated, so a loader passed through one is a read; the bound names are declarations.
  if (ts.isBindingElement(parent)) return parent.initializer === id;
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

  const isBuiltinModuleLoad = (node: ts.Expression): boolean => {
    let inner = innermost(node);
    while (ts.isAwaitExpression(inner)) inner = innermost(inner.expression);
    return ts.isCallExpression(inner) && (inner.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(inner.expression) && inner.expression.text === "require"))
      && inner.arguments.length > 0 && ts.isStringLiteralLike(inner.arguments[0]) && BUILTIN_MODULE_SPECIFIERS.has(inner.arguments[0].text);
  };

  // Local names bound to createRequire, to the whole built-in module object, and to a createRequire result, collected before the walk so order does not matter.
  const createRequireNames = new Set(["createRequire"]);
  const builtinModuleNames = new Set<string>();
  const loaderNames = new Set(["require"]);
  const collectFactories = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && BUILTIN_MODULE_SPECIFIERS.has(node.moduleSpecifier.text) && node.importClause && !node.importClause.isTypeOnly) {
      if (node.importClause.name) builtinModuleNames.add(node.importClause.name.text);
      const bindings = node.importClause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) builtinModuleNames.add(bindings.name.text);
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && isBuiltinModuleLoad(node.initializer)) builtinModuleNames.add(node.name.text);
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
  // Calls resolve against the importing file, so only a base that is that file is modelled; any other base is opaque.
  const hasModelledBase = (call: ts.CallExpression): boolean => {
    if (call.arguments.length !== 1) return false;
    const base = innermost(call.arguments[0]);
    return (ts.isIdentifier(base) && base.text === "__filename")
      || (ts.isPropertyAccessExpression(base) && base.name.text === "url" && ts.isMetaProperty(base.expression) && base.expression.keywordToken === ts.SyntaxKind.ImportKeyword);
  };
  const isCreateRequireCall = (node: ts.Expression): node is ts.CallExpression => {
    const inner = innermost(node);
    return ts.isCallExpression(inner) && isCreateRequireReference(inner.expression);
  };
  const isModelledCreateRequireCall = (node: ts.Expression): boolean => {
    const inner = innermost(node);
    return isCreateRequireCall(inner) && hasModelledBase(inner);
  };
  const collectLoaders = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && isModelledCreateRequireCall(node.initializer)) loaderNames.add(node.name.text);
    ts.forEachChild(node, collectLoaders);
  };
  collectLoaders(tree);
  const isLoader = (node: ts.Expression): boolean => {
    const inner = innermost(node);
    return (ts.isIdentifier(inner) && loaderNames.has(inner.text)) || isModelledCreateRequireCall(inner);
  };

  /** True for the inert main-module test `require.main === module` (either order, either equality), given the `require.main` access. */
  const isMainModuleComparison = (access: ts.Node): boolean => {
    const outer = outermost(access);
    const comparison = outer.parent;
    if (!ts.isBinaryExpression(comparison) || ![ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(comparison.operatorToken.kind)) return false;
    const other = innermost(comparison.left === outer ? comparison.right : comparison.left);
    return ts.isIdentifier(other) && other.text === "module";
  };

  /** How a loader value is used: a direct load call, an inert lookup, a declared alias, or anything the parser cannot follow. */
  const loaderUse = (node: ts.Node): "load" | "inert" | "alias" | "opaque" => {
    const outer = outermost(node);
    const parent = outer.parent;
    if (ts.isCallExpression(parent) && parent.expression === outer) return "load";
    // `require.resolve` returns a path and never evaluates the module; loading that path later is a computed edge.
    if (ts.isPropertyAccessExpression(parent) && parent.expression === outer && parent.name.text === "resolve") return "inert";
    // `require.main` is inert only when compared with `module`; any other use of it can reach `require.main.require`.
    if (ts.isPropertyAccessExpression(parent) && parent.expression === outer && parent.name.text === "main" && isMainModuleComparison(parent)) return "inert";
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
  const opaque = (): void => { found.push({ specifier: COMPUTED, names: "opaque" }); };
  /** The built-in module may be read only for createRequire or a named inert export; anything else can build an unmodelled loader. */
  const isAllowedBuiltinModuleName = (name: string): boolean => name === "createRequire" || INERT_BUILTIN_MODULE_EXPORTS.has(name);

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && !node.importClause?.isTypeOnly) {
      const bindings = node.importClause?.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) found.push({ specifier: node.moduleSpecifier.text, names: "opaque" });
      else found.push({
        specifier: node.moduleSpecifier.text,
        names: [...(node.importClause?.name ? ["default"] : []), ...(bindings && ts.isNamedImports(bindings) ? named(bindings.elements) : [])],
      });
      if (BUILTIN_MODULE_SPECIFIERS.has(node.moduleSpecifier.text) && bindings && ts.isNamedImports(bindings)
        && named(bindings.elements).some(name => !isAllowedBuiltinModuleName(name))) opaque();
    }
    if (ts.isExportDeclaration(node) && !node.isTypeOnly && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      found.push({
        specifier: node.moduleSpecifier.text,
        names: node.exportClause && ts.isNamedExports(node.exportClause) ? named(node.exportClause.elements) : "opaque",
      });
      // Re-exporting the built-in module hands its factory to importers the parser does not follow.
      if (BUILTIN_MODULE_SPECIFIERS.has(node.moduleSpecifier.text)) opaque();
    }
    if (ts.isImportEqualsDeclaration(node) && !node.isTypeOnly && ts.isExternalModuleReference(node.moduleReference)) {
      const reference = node.moduleReference.expression;
      found.push({ specifier: ts.isStringLiteralLike(reference) ? reference.text : COMPUTED, names: "opaque" });
    }
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || isLoader(node.expression))) {
      const edge = loadEdge(node);
      found.push(edge);
      if (BUILTIN_MODULE_SPECIFIERS.has(edge.specifier)) {
        const outer = outermost(node);
        const boundWhole = ts.isVariableDeclaration(outer.parent) && outer.parent.initializer === outer && ts.isIdentifier(outer.parent.name) && builtinModuleNames.has(outer.parent.name.text);
        if (edge.names === "opaque" ? !boundWhole : edge.names.some(name => !isAllowedBuiltinModuleName(name))) opaque();
      }
    }
    // A createRequire call with a base other than the importing file, or whose result is not loaded, looked up inertly or bound to a tracked name, escapes the model.
    if (ts.isCallExpression(node) && isCreateRequireReference(node.expression) && (!hasModelledBase(node) || loaderUse(node) === "opaque")) opaque();
    // `process.getBuiltinModule("module")` reaches the factory without an import, so it is not modelled.
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(innermost(node.expression)) && (innermost(node.expression) as ts.PropertyAccessExpression).name.text === "getBuiltinModule") opaque();
    if (ts.isIdentifier(node) && (createRequireNames.has(node.text) || loaderNames.has(node.text) || builtinModuleNames.has(node.text)) && isValueReference(node)) {
      // The createRequire factory itself may only be called; passing or aliasing it hides every load it makes.
      if (createRequireNames.has(node.text) && loaderUse(node) !== "load") opaque();
      // A tracked loader may only be called or looked up inertly; an alias, argument or default value hides the module it loads.
      if (loaderNames.has(node.text) && !["load", "inert"].includes(loaderUse(node))) opaque();
      if (builtinModuleNames.has(node.text)) {
        // The built-in module object may only be read through a static allowed member; a computed key or an escaping value is opaque.
        const outer = outermost(node);
        const access = outer.parent;
        const member = ts.isPropertyAccessExpression(access) && access.expression === outer ? access.name.text
          : ts.isElementAccessExpression(access) && access.expression === outer && ts.isStringLiteralLike(access.argumentExpression) ? access.argumentExpression.text : undefined;
        if (member === undefined || !isAllowedBuiltinModuleName(member)) opaque();
      }
    }
    const memberName = ts.isPropertyAccessExpression(node) ? node.name.text
      : ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression) ? node.argumentExpression.text : undefined;
    // A member createRequire (`nodeModule.createRequire`) may likewise only be called.
    if (memberName === "createRequire" && loaderUse(node) !== "load") opaque();
    // `module.require`, `require.main.require` and similar member loaders are not modelled, so they fail closed.
    if (memberName === "require") opaque();
    ts.forEachChild(node, visit);
  };
  visit(tree);
  return found;
}

/** True when the guard scans a file with this name: a module source, not a declaration file. */
function isScannedSource(fileName: string): boolean {
  return SOURCE_EXTENSIONS.has(extname(fileName)) && !DECLARATION_SUFFIXES.some(suffix => fileName.endsWith(suffix));
}

interface Walk { files: string[]; symlinks: string[] }

/**
 * Every module source under `directory`, and every symlink met on the way, which
 * is reported rather than followed because lexical resolution cannot see that an
 * alias names filesystem.ts. `skip` takes a path relative to the walk's start and
 * is meant to match exact paths, so a sibling or a nested namesake is still walked.
 */
function walk(directory: string, skip: (relativePath: string) => boolean = () => false, start = directory): Walk {
  const found: Walk = { files: [], symlinks: [] };
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (skip(relative(start, path))) continue;
    const stats = lstatSync(path);
    if (stats.isSymbolicLink()) found.symlinks.push(path);
    else if (stats.isDirectory()) {
      const nested = walk(path, skip, start);
      found.files.push(...nested.files);
      found.symlinks.push(...nested.symlinks);
    } else if (isScannedSource(entry)) found.files.push(path);
  }
  return found;
}

/** True for an exact generated path, written with forward slashes whatever the platform separator. */
function isGeneratedPath(relativePath: string): boolean {
  return GENERATED_PATHS.has(relativePath.split(sep).join("/"));
}

/** The module stem that names filesystem.ts under any source extension, case-folded because macOS paths are case-insensitive. */
function moduleStem(path: string): string {
  return path.replace(/\.(?:[cm]?[jt]sx?)$/i, "").toLowerCase();
}

/**
 * The paths a literal specifier may name, read the way Node and the TypeScript
 * sources may: a relative or absolute path, read both as a path and as a URL
 * (which decodes escapes and drops a query or hash), or a file URL. A bare
 * package or built-in specifier names no local path; "undecodable" is a file URL
 * or path that cannot be decoded, which callers treat as reaching anything.
 */
function specifierPaths(fromFile: string, specifier: string): string[] | "bare" | "undecodable" {
  try {
    if (/^file:/i.test(specifier)) return [fileURLToPath(new URL(specifier))];
    if (specifier.startsWith(".") || isAbsolute(specifier)) {
      return [resolve(dirname(fromFile), specifier.replace(/[?#].*$/, "")), fileURLToPath(new URL(specifier, pathToFileURL(fromFile)))];
    }
    return "bare";
  } catch {
    return "undecodable";
  }
}

/** A computed specifier, or one that cannot be decoded, is assumed to reach the target. */
function resolvesToTarget(fromFile: string, specifier: string): boolean {
  if (specifier === COMPUTED) return true;
  const paths = specifierPaths(fromFile, specifier);
  if (paths === "undecodable") return true;
  return paths !== "bare" && paths.some(path => moduleStem(path) === moduleStem(TARGET));
}

/** True when a server-relative path lies inside one of `roots`. */
function isUnder(file: string, roots: readonly string[]): boolean {
  return roots.some(root => file === root || file.startsWith(`${root}${sep}`));
}

/**
 * True when a resolved path could be module source: a scanned extension, or no
 * extension at all, which a bundler or loader may complete to one. A data file
 * such as package.json cannot re-export a binding.
 */
function couldBeModuleSource(path: string): boolean {
  const extension = extname(path);
  return extension === "" || SOURCE_EXTENSIONS.has(extension.toLowerCase());
}

/** Literal specifiers in one file that import module source outside the scanned roots. */
function outOfRootSpecifiers(fileName: string, source: string): string[] {
  return edges(fileName, source).map(edge => edge.specifier).filter(specifier => {
    if (specifier === COMPUTED) return false;
    const paths = specifierPaths(fileName, specifier);
    // Unscanned module source could re-export either entry, whatever its directory is called, so the destination's category never excuses it.
    return paths !== "bare" && (paths === "undecodable" || paths.some(path => couldBeModuleSource(path) && !isUnder(relative(SERVER, path), RUNTIME_ROOTS)));
  });
}

/** Every protected or opaque reach of filesystem.ts in one source file that its path is not allowed. */
function reachViolations(fileName: string, source: string): string[] {
  const file = relative(SERVER, fileName);
  const found: string[] = [];
  for (const edge of edges(fileName, source)) {
    if (!resolvesToTarget(fileName, edge.specifier)) continue;
    if (edge.names === "opaque") found.push(`${file}: opaque reach via ${edge.specifier}`);
    else for (const name of edge.names) if (PROTECTED_EXPORTS.get(name)?.has(file) === false) found.push(`${file}: ${name}`);
  }
  return found;
}

/** Every protected, opaque or out-of-root reach in one runtime-root source file, with no reviewed exception. */
function violations(fileName: string, source: string): string[] {
  const file = relative(SERVER, fileName);
  return [...reachViolations(fileName, source), ...outOfRootSpecifiers(fileName, source).map(specifier => `${file}: imports outside the scanned roots via ${specifier}`)];
}

/** True when a server-relative module source is accounted for: in a runtime or non-runtime root, or an exact build config file. */
function isClassified(file: string): boolean {
  return isUnder(file, RUNTIME_ROOTS) || isUnder(file, NON_RUNTIME_ROOTS) || BUILD_CONFIG_FILES.has(file);
}

/** The tree file a resolved module path names, completing a `.js`-style extension to its TypeScript source or an extensionless path to a file. */
function treeFileFor(path: string, files: ReadonlyMap<string, string>): string | undefined {
  const file = relative(SERVER, path);
  const stem = file.replace(/\.(?:[cm]?[jt]sx?)$/i, "");
  return [file, ...[".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"].map(extension => `${stem}${extension}`)].find(candidate => files.has(candidate));
}

/**
 * Every failure for a tree given as server-relative path to source: unclassified
 * files, violations in runtime-root files, and out-of-root imports. A reviewed
 * out-of-root import is followed instead, and its target, and everything that
 * target imports locally, is scanned as runtime code. The real tree and the
 * bridge fixtures both run through this, so the fixtures exercise the guard itself.
 */
function treeFailures(files: ReadonlyMap<string, string>, read: (file: string) => string = file => files.get(file) ?? ""): string[] {
  const failures: string[] = [];
  const ordered = [...files.keys()].sort();
  for (const file of ordered) if (!isClassified(file)) failures.push(`${file}: unclassified module source`);
  const queue = ordered.filter(file => isUnder(file, RUNTIME_ROOTS));
  const scanned = new Set(queue);
  for (let index = 0; index < queue.length; index += 1) {
    const file = queue[index];
    const fileName = resolve(SERVER, file);
    const source = read(file);
    failures.push(...reachViolations(fileName, source));
    const followed = !isUnder(file, RUNTIME_ROOTS);
    for (const specifier of outOfRootSpecifiers(fileName, source)) {
      const key = `${file} -> ${specifier}`;
      if (PACKAGE_BARREL_IMPORTS.has(key)) continue;
      if (!followed && !REVIEWED_OUT_OF_ROOT_IMPORTS.has(key)) {
        failures.push(`${file}: imports outside the scanned roots via ${specifier}`);
        continue;
      }
      const paths = specifierPaths(fileName, specifier);
      const target = Array.isArray(paths) ? treeFileFor(paths[0], files) : undefined;
      // A followed import the walk cannot find is unscanned code, so it fails rather than being assumed harmless.
      if (target === undefined) failures.push(`${file}: followed import not found via ${specifier}`);
      else if (!scanned.has(target)) {
        scanned.add(target);
        queue.push(target);
      }
    }
  }
  return failures;
}

/** Symlinks outside the non-runtime roots of a walk; a symlinked alias of filesystem.ts resolves lexically elsewhere, so the guard refuses them instead of following them. */
function refusedSymlinks(root: string, found: Walk): string[] {
  return found.symlinks.map(path => relative(root, path)).filter(file => !isUnder(file, NON_RUNTIME_ROOTS));
}

function runtimeSourceFiles(): string[] {
  return RUNTIME_ROOTS.flatMap(root => walk(resolve(SERVER, root)).files);
}

/** The whole server/ tree, minus the exact generated paths, as a walk. */
function serverWalk(): Walk {
  return walk(SERVER, isGeneratedPath);
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
const IN_STORAGE_MJS = resolve(SERVER, "src/storage/importer-fixture.mjs");
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
  });

  it("no production or script module imports the lock test-hook injection", () => {
    expect(importersOfTarget().naming(TEST_HOOK_INJECTION)).toEqual([]);
  });

  it("the real tree has no violation, out-of-root import or unclassified module source", () => {
    // A new source root would otherwise sit outside the scan and could import either entry unseen.
    for (const root of RUNTIME_ROOTS) expect(statSync(resolve(SERVER, root)).isDirectory()).toBe(true);
    const tree = new Map(serverWalk().files.map(path => [relative(SERVER, path), ""] as const));
    expect(treeFailures(tree, file => readFileSync(resolve(SERVER, file), "utf8"))).toEqual([]);
  });

  it("no symlink exists under server/ outside the non-runtime roots", () => {
    expect(refusedSymlinks(SERVER, serverWalk())).toEqual([]);
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

  it("the inert main-module comparison is not an edge", () => {
    const source = [
      'if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) void main();',
      "if (module !== require.main) skip();",
    ].join("\n");
    expect(violations(IN_STORAGE, source)).toEqual([]);
  });

  it("static reads of the built-in module and file-based createRequire bases are not edges", () => {
    const source = [
      'import { syncBuiltinESMExports } from "node:module";',
      'import * as nodeModule from "node:module";',
      'const { builtinModules } = await import("node:module");',
      "const load = nodeModule.createRequire(import.meta.url);",
      'const local = load.resolve("./filesystem.js");',
      'const fromFilename = nodeModule["createRequire"](__filename).resolve("tsx");',
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
    ["an escaping require.main value", ELSEWHERE, "const entry = require.main;"],
    ["require.main.require", IN_STORAGE, 'const storage = require.main.require("./filesystem.js");'],
    ["a loader passed through a binding default", IN_STORAGE_MJS, `import { createRequire } from "node:module";\nconst load = createRequire(import.meta.url);\nconst { x = load } = {};\nconst { ${TEST_HOOK_INJECTION}: hook } = x("./filesystem.ts");`],
    ["require passed through a parameter default", ELSEWHERE, "function run(load = require) { return load; }"],
    ["a computed member factory on the built-in module", IN_STORAGE_MJS, `import * as mod from "node:module";\nconst load = mod["create" + "Require"](import.meta.url);\nconst { ${TEST_HOOK_INJECTION}: hook } = load("./filesystem.ts");`],
    ["a computed destructure of the built-in module object", IN_STORAGE_MJS, `import * as mod from "node:module";\nconst { ["create" + "Require"]: make } = mod;\nconst load = make(import.meta.url);\nconst { ${TEST_HOOK_INJECTION}: hook } = load("./filesystem.ts");`],
    ["a computed string-literal destructure of the built-in module object", IN_STORAGE, `import * as nodeModule from "node:module";\nconst { ["createRequire"]: make } = nodeModule;\nconst load = make(import.meta.url);\nconst { ${WORKER_FACTORY}, ${TEST_HOOK_INJECTION} } = load("./filesystem.js");`],
    ["a computed string-literal destructure of an imported built-in module", IN_STORAGE, `const { ["createRequire"]: f } = await import("node:module");\nconst { ${TEST_HOOK_INJECTION} } = f(import.meta.url)("./filesystem.js");`],
    ["the built-in module default import escaping as a value", ELSEWHERE, 'import nodeModule from "node:module";\nuse(nodeModule);'],
    ["an unmodelled named built-in module export", ELSEWHERE, 'import { Module } from "node:module";'],
    ["a re-export of the built-in module", ELSEWHERE, 'export * from "node:module";'],
    ["getBuiltinModule", ELSEWHERE, 'const nodeModule = process.getBuiltinModule("module");'],
    ["a createRequire base in another directory", resolve(SERVER, "src/cli/importer-fixture.mjs"), `import { createRequire } from "node:module";\nconst load = createRequire(new URL("../storage/base.mjs", import.meta.url));\nconst { ${TEST_HOOK_INJECTION}: hook } = load("./filesystem.ts");`],
    ["a computed createRequire base", ELSEWHERE, 'import { createRequire } from "node:module";\nconst load = createRequire(base);'],
    ["runtime code importing a test module", ELSEWHERE, 'import { fixture } from "../../test/fixture.js";'],
  ];

  it.each(flaggedFixtures)("flags %s", (_label, fileName, source) => {
    expect(violations(fileName, source)).not.toEqual([]);
  });

  it("rejects a symlinked alias of filesystem.ts under a scanned root", () => {
    const root = mkdtempSync(join(tmpdir(), "fs-import-guard-"));
    try {
      mkdirSync(join(root, "src/storage"), { recursive: true });
      mkdirSync(join(root, "src/cli"), { recursive: true });
      writeFileSync(join(root, "src/storage/filesystem.ts"), "export {};\n");
      symlinkSync("filesystem.ts", join(root, "src/storage/filesystem-link.ts"));
      writeFileSync(join(root, "src/cli/importer.ts"), `import { ${WORKER_FACTORY} } from "../storage/filesystem-link.js";\n`);
      expect(refusedSymlinks(root, walk(root))).toEqual([join("src", "storage", "filesystem-link.ts")]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("skips only the exact generated paths, so their siblings and dot directories are walked", () => {
    const root = mkdtempSync(join(tmpdir(), "fs-import-guard-"));
    try {
      for (const file of ["reports/evil.ts", "reports/mutation/report.js", ".runtime/bridge.mjs", "node_modules/pkg/index.js", "evil.config.ts"]) {
        mkdirSync(dirname(join(root, file)), { recursive: true });
        writeFileSync(join(root, file), "export {};\n");
      }
      expect(walk(root, isGeneratedPath).files.map(path => relative(root, path)).sort()).toEqual([join(".runtime", "bridge.mjs"), "evil.config.ts", join("reports", "evil.ts")]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("classifies only the exact build config files and declared roots", () => {
    expect(["vitest.config.ts", "tsup.config.ts", "src/x.ts", "test/x.ts", "docs/x.jsx"].filter(file => !isClassified(file))).toEqual([]);
    expect(["evil.config.ts", "runtime.config.mjs", ".runtime/bridge.mjs", "reports/evil.ts", "new-runtime/x.ts"].filter(file => isClassified(file))).toEqual([]);
  });

  const hookBridge = `export { ${TEST_HOOK_INJECTION} } from "./src/storage/filesystem.js";`;
  const bridges: Array<[string, string, string]> = [
    ["a config-named bridge", "runtime.config.mjs", hookBridge],
    ["an undeclared build config file", "evil.config.ts", hookBridge],
    ["a dot-directory bridge", ".runtime/bridge.mjs", hookBridge.replace("./src/", "../src/")],
    ["a docs bridge", "docs/bridge.mjs", hookBridge.replace("./src/", "../src/")],
    ["a reports bridge", "reports/evil.ts", hookBridge.replace("./src/", "../src/")],
  ];

  it.each(bridges)("rejects %s reached from runtime code while the worker importer is present", (_label, bridge, source) => {
    const specifier = `../${bridge.replace(/\.ts$/, ".js")}`;
    const tree = new Map([
      [relative(SERVER, WORKER), WORKER_IMPORT],
      ["src/reachable.mjs", `import { ${TEST_HOOK_INJECTION} } from "${specifier}";`],
      [bridge, source],
    ]);
    expect(treeFailures(tree)).toContain(`src/reachable.mjs: imports outside the scanned roots via ${specifier}`);
    if (!isUnder(bridge, NON_RUNTIME_ROOTS)) expect(treeFailures(tree)).toContain(`${bridge}: unclassified module source`);
  });

  it("scans the target of a reviewed out-of-root import, and fails one it cannot find", () => {
    const reviewed = new Map([
      [relative(SERVER, WORKER), WORKER_IMPORT],
      ["scripts/gen-at-rest-fixtures.ts", 'import { stores } from "../test/fixtures/at-rest/fixture-stores.js";'],
      ["test/fixtures/at-rest/fixture-stores.ts", `export { ${TEST_HOOK_INJECTION} } from "../../../src/storage/filesystem.js";\nimport { more } from "./more.js";`],
      ["test/fixtures/at-rest/more.ts", `import { ${WORKER_FACTORY} } from "../../../src/storage/filesystem.js";`],
    ]);
    expect(treeFailures(reviewed)).toEqual([
      `test/fixtures/at-rest/fixture-stores.ts: ${TEST_HOOK_INJECTION}`,
      `test/fixtures/at-rest/more.ts: ${WORKER_FACTORY}`,
    ]);
    const missing = new Map([["scripts/gen-at-rest-fixtures.ts", 'import { stores } from "../test/fixtures/at-rest/fixture-stores.js";']]);
    expect(treeFailures(missing)).toEqual(["scripts/gen-at-rest-fixtures.ts: followed import not found via ../test/fixtures/at-rest/fixture-stores.js"]);
  });

  it("scans a .tsx importer and flags its reach", () => {
    const fileName = resolve(SERVER, "src/console/importer-fixture.tsx");
    const source = `import { ${TEST_HOOK_INJECTION} } from "../storage/filesystem.js";\nexport const View = () => <div>{String(${TEST_HOOK_INJECTION})}</div>;`;
    expect(isScannedSource(fileName)).toBe(true);
    expect(violations(fileName, source)).toEqual([`src/console/importer-fixture.tsx: ${TEST_HOOK_INJECTION}`]);
  });
});
