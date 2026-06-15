/**
 * NON-DEPENDENCY guard (DoE review C-1, the top agent-native lever).
 *
 * THE RULE (CLAUDE.md "Non-dependency principle"): Sanctuary never requires
 * Concordia, and vice versa. Sanctuary may COMPOSE with Concordia/Verascore
 * (the `composition/` module talks to the Concordia Python sidecar over RPC),
 * but it must NEVER take a hard code dependency on the Concordia or Verascore
 * packages. A single `import "@concordia-protocol"` turns an optional
 * composition into a required dependency and breaks the principle silently
 * (fresh-install tests still pass because the dev box has both checked out).
 *
 * Until now this was a prose review gate the coordinator checked by hand. This
 * test converts it into a CI-failing fact: it scans EVERY `server/src/**` TS
 * file and fails if any of them imports an external Concordia/Verascore
 * package, or reaches OUTSIDE `server/src` into a Concordia/Verascore package
 * directory (e.g. the `sidecars/concordia/` sidecar source or a sibling
 * `Concordia/` / `Verascore/` checkout).
 *
 * IMPORT-AWARE VIA THE TS COMPILER (not a regex): the specifiers are extracted
 * by parsing each file with the TypeScript compiler API and walking the AST, so
 * the module-reference forms a regex missed are covered:
 *   - static `import ... from "x"` / `export ... from "x"` / bare `import "x"`
 *   - `import x = require("x")`
 *   - dynamic `import("x")` / `await import("x")` (ImportKeyword call)
 *   - TS import-type `type T = import("x").Foo` / `let v: import("x")`
 *   - `require("x")`; the curried `createRequire(import.meta.url)("x")`; the
 *     bound form `const r = createRequire(...); r("x")`; and `.resolve` on any
 *     of those (`require.resolve("x")`, `r.resolve("x")`)
 * Comments and string literals that merely MENTION concordia/verascore are
 * ignored because only module-specifier string-literal arguments are inspected.
 * KNOWN LIMIT: a COMPUTED specifier (`import("@concordia/" + name)`) cannot be
 * resolved to a literal statically; the package.json manifest check backstops it.
 *
 * RELATIONSHIP TO `test/coordination/no-concordia-dependency.test.ts`: that
 * test crawls the import GRAPH reachable from `coordination/index.ts` only.
 * This guard is the COMPLEMENTARY whole-tree backstop — it covers every file
 * under `server/src`, not just one module's reachable graph. The two are
 * intentionally redundant on the coordination module and additive everywhere
 * else.
 *
 * WHAT IS ALLOWED:
 *   - Sanctuary's OWN local files named `concordia-adapter.ts`,
 *     `verascore-hook.ts`, etc. under `server/src/composition/` — these are
 *     relative imports of LOCAL Sanctuary code, not the external SDKs.
 *   - Comments and string literals mentioning concordia/verascore.
 *
 * WHAT IS FORBIDDEN (fails the build):
 *   - A bare-package import of an external SDK: `@concordia-protocol`,
 *     `@concordia/...`, `concordia-protocol`, `@verascore/...`, `verascore`,
 *     in ANY of the forms above.
 *   - A relative/absolute import whose resolved path escapes `server/src` and
 *     lands in a Concordia/Verascore package path. HOW TO FIX: route the
 *     interaction through the `composition/` sidecar-RPC boundary (which keeps
 *     the dependency optional + out-of-process) instead of importing the
 *     package directly.
 *   - A forbidden package listed in the root or server package.json under
 *     dependencies / devDependencies / peer / optional — that is a hard
 *     install-time dependency even with NO import statement, so the code-scan
 *     alone would false-green it. The manifest check below closes that.
 *
 * KNOWN LIMITS (documented, not gaps):
 *   - a COMPUTED specifier `import("@concordia/" + name)` cannot be resolved to
 *     a literal by any static scanner. Backstopped by the manifest check
 *     (npm-alias- and local-path-aware), since the package must be declared.
 *   - the require fn pulled off an inline dynamic import:
 *     `(await import("node:module")).createRequire(...)`. Vanishingly rare; not
 *     worth the AST complexity.
 * Traced: static import/export, bare import, `import x = require(...)`, dynamic
 * import(), TS import-type, `"x" as string`/`satisfies`/`<string>"x"`-wrapped
 * literals, triple-slash references, `require(...)`/`require.resolve(...)`,
 * direct/aliased/namespaced/default-import createRequire and its bindings, and
 * the member-require forms `module.require`/`require.main.require`/
 * `process.mainModule.require` (which a RELATIVE-path require can use to escape,
 * unbacked by the manifest — hence traced, not merely documented).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import {
  firstPartySourceFiles,
  FIRST_PARTY_SOURCE_ROOTS,
} from "./public-surface";

// server/test/structure/<file> -> repo root is four levels up.
const REPO_ROOT = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");

// Absolute, normalised first-party source roots. A relative import that
// resolves to a path INSIDE one of these is local Sanctuary code (allowed); the
// escape check only fires when a resolved path leaves all of them.
const FIRST_PARTY_ABS_ROOTS = FIRST_PARTY_SOURCE_ROOTS.map((root) =>
  normalize(join(REPO_ROOT, root)).replace(/\\/g, "/"),
);

/**
 * External SDK package specifiers that are FORBIDDEN as a bare import. A spec
 * matches if it equals the package name or is a deep import into it
 * (`pkg/subpath`). `@concordia` / `@verascore` cover any scope member.
 */
const FORBIDDEN_PACKAGES: ReadonlyArray<string> = [
  "concordia-protocol",
  "@concordia-protocol",
  "@concordia",
  "concordia", // a top-level `concordia` package (distinct from local ./concordia-*.ts files, which start with ".")
  "verascore",
  "@verascore",
];

/**
 * Path segments that, when a RESOLVED import path escapes server/src and lands
 * on/inside one of these directories, indicate a reach into a
 * Concordia/Verascore package tree. Stored leading-slash + no trailing slash;
 * the matcher accepts both a reach INTO the dir (`.../concordia/foo`) and a bare
 * import OF the dir (`.../concordia`). Leading slash keeps `/concordia` from
 * matching `/composition`.
 */
const FORBIDDEN_ESCAPED_SEGMENTS: ReadonlyArray<string> = [
  "/sidecars/concordia",
  "/concordia",
  "/verascore",
  "/Concordia",
  "/Verascore",
];

/**
 * Extract every module specifier from a TS source by walking the AST. Covers
 * static import/export, bare imports, dynamic `import(...)`, and `require(...)`.
 * Only string-literal specifiers are returned; computed specifiers (rare, and
 * not how a hard dependency is introduced) are out of scope by construction.
 */
function scriptKindFor(rel: string): ts.ScriptKind {
  if (rel.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (rel.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (rel.endsWith(".js") || rel.endsWith(".mjs") || rel.endsWith(".cjs"))
    return ts.ScriptKind.JS;
  return ts.ScriptKind.TS; // .ts / .mts / .cts
}

function extractSpecifiers(rel: string, source: string): string[] {
  const sf = ts.createSourceFile(
    rel,
    source,
    ts.ScriptTarget.Latest,
    /*setParentNodes*/ true,
    scriptKindFor(rel),
  );
  const out: string[] = [];
  // Unwrap TS type-assertion wrappers so a STATIC literal hidden behind them is
  // still seen: `"x" as string`, `"x" satisfies string`, `<string>"x"`, `("x")`.
  const unwrap = (node: ts.Node | undefined): ts.Node | undefined => {
    let n = node;
    while (
      n &&
      (ts.isAsExpression(n) ||
        ts.isSatisfiesExpression(n) ||
        ts.isTypeAssertionExpression(n) ||
        ts.isParenthesizedExpression(n) ||
        ts.isNonNullExpression(n))
    ) {
      n = n.expression;
    }
    return n;
  };
  const pushIfStringLiteral = (node: ts.Node | undefined): void => {
    const n = unwrap(node);
    if (n && ts.isStringLiteralLike(n)) out.push(n.text);
  };

  // PASS 0: resolve how `createRequire` was imported from node:module so the
  // ALIASED (`import { createRequire as cr }`), NAMESPACED
  // (`import * as mod` -> `mod.createRequire`), and DEFAULT-import
  // (`import mod from "node:module"` -> `mod.createRequire`) forms are all
  // recognised — not just a callee literally named `createRequire`.
  const createRequireLocalNames = new Set<string>(["createRequire"]);
  const moduleNamespaceNames = new Set<string>();
  const collectModuleImports = (node: ts.Node): void => {
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteralLike(node.moduleSpecifier) &&
      (node.moduleSpecifier.text === "node:module" ||
        node.moduleSpecifier.text === "module") &&
      node.importClause
    ) {
      const clause = node.importClause;
      // default import: `import mod from "node:module"` -> mod.createRequire(...)
      if (clause.name) moduleNamespaceNames.add(clause.name.text);
      const nb = clause.namedBindings;
      if (nb && ts.isNamespaceImport(nb)) {
        moduleNamespaceNames.add(nb.name.text); // import * as mod
      } else if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) {
          // { createRequire } or { createRequire as cr }
          if ((el.propertyName?.text ?? el.name.text) === "createRequire") {
            createRequireLocalNames.add(el.name.text);
          }
        }
      }
    }
    // CommonJS: `const mod = require("node:module")` (mod.createRequire) and
    // `const { createRequire: cr } = require("node:module")` (cr).
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isCallExpression(node.initializer) &&
      ts.isIdentifier(node.initializer.expression) &&
      node.initializer.expression.text === "require" &&
      ts.isStringLiteralLike(node.initializer.arguments[0]) &&
      (node.initializer.arguments[0].text === "node:module" ||
        node.initializer.arguments[0].text === "module")
    ) {
      if (ts.isIdentifier(node.name)) {
        moduleNamespaceNames.add(node.name.text); // const mod = require("node:module")
      } else if (ts.isObjectBindingPattern(node.name)) {
        for (const el of node.name.elements) {
          const prop = el.propertyName && ts.isIdentifier(el.propertyName)
            ? el.propertyName.text
            : ts.isIdentifier(el.name)
              ? el.name.text
              : undefined;
          if (prop === "createRequire" && ts.isIdentifier(el.name)) {
            createRequireLocalNames.add(el.name.text);
          }
        }
      }
    }
    ts.forEachChild(node, collectModuleImports);
  };
  collectModuleImports(sf);

  const isCreateRequireCall = (n: ts.Node): boolean => {
    if (!ts.isCallExpression(n)) return false;
    const callee = n.expression;
    // createRequire(...) / cr(...)  (local or aliased name)
    if (ts.isIdentifier(callee)) return createRequireLocalNames.has(callee.text);
    // mod.createRequire(...)  (namespace import)
    if (
      ts.isPropertyAccessExpression(callee) &&
      ts.isIdentifier(callee.expression) &&
      moduleNamespaceNames.has(callee.expression.text) &&
      callee.name.text === "createRequire"
    ) {
      return true;
    }
    return false;
  };

  // PASS 1: collect identifiers that ARE a require function — either bound to a
  // createRequire(...) result (`const r = createRequire(...); r("x")`) or
  // aliased directly to `require` (`const req = require; req("x")`). Iterate to
  // a fixpoint so a chain (`const a = require; const b = a;`) is fully resolved.
  const requireBindings = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    const before = requireBindings.size;
    const collectBindings = (node: ts.Node): void => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer &&
        !requireBindings.has(node.name.text)
      ) {
        const init = node.initializer;
        const isRequireValued =
          isCreateRequireCall(init) ||
          (ts.isIdentifier(init) &&
            (init.text === "require" || requireBindings.has(init.text)));
        if (isRequireValued) requireBindings.add(node.name.text);
      }
      ts.forEachChild(node, collectBindings);
    };
    collectBindings(sf);
    if (requireBindings.size !== before) changed = true;
  }

  /**
   * Is `expr` a `require`-like callee whose first string arg names a module?
   * Covers: the global `require`; a `const r = createRequire(...)` binding;
   * the directly-curried `createRequire(import.meta.url)(...)`; the `.resolve`
   * member of any of those; and the member-`require` forms `module.require(...)`,
   * `require.main.require(...)`, `process.mainModule.require(...)` (which a
   * relative-path require can use to escape into a Concordia tree WITHOUT a
   * package.json dependency, so the manifest check does NOT backstop them).
   */
  const isRequireCallee = (expr: ts.Expression): boolean => {
    // `require` / a createRequire-bound identifier, called directly
    if (ts.isIdentifier(expr)) {
      return expr.text === "require" || requireBindings.has(expr.text);
    }
    // `createRequire(import.meta.url)(...)`
    if (isCreateRequireCall(expr)) return true;
    if (ts.isPropertyAccessExpression(expr)) {
      const base = expr.expression;
      const baseIsRequireLike =
        (ts.isIdentifier(base) &&
          (base.text === "require" || requireBindings.has(base.text))) ||
        isCreateRequireCall(base);
      // `.resolve` on require / a binding / a createRequire(...) call
      if (expr.name.text === "resolve" && baseIsRequireLike) return true;
      // member-`require`: ONLY the known module-require bases, NOT an arbitrary
      // domain method named `.require` (e.g. `policy.require(...)` must not red):
      //   module.require / require.main.require / process.mainModule.require /
      //   <createRequire-binding>.require
      if (expr.name.text === "require") {
        if (baseIsRequireLike) return true; // <binding>.require / require.X.require
        if (ts.isIdentifier(base) && base.text === "module") return true;
        if (
          ts.isPropertyAccessExpression(base) &&
          // require.main  |  process.mainModule
          ((ts.isIdentifier(base.expression) &&
            base.expression.text === "require" &&
            base.name.text === "main") ||
            (ts.isIdentifier(base.expression) &&
              base.expression.text === "process" &&
              base.name.text === "mainModule"))
        ) {
          return true;
        }
      }
    }
    return false;
  };

  const visit = (node: ts.Node): void => {
    // import ... from "x" / export ... from "x" / bare import "x"
    if (ts.isImportDeclaration(node)) {
      pushIfStringLiteral(node.moduleSpecifier);
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
      pushIfStringLiteral(node.moduleSpecifier);
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference)
    ) {
      // import x = require("y")
      pushIfStringLiteral(node.moduleReference.expression);
    } else if (ts.isImportTypeNode(node)) {
      // type T = import("x").Foo  /  let x: import("x")
      if (ts.isLiteralTypeNode(node.argument)) {
        pushIfStringLiteral(node.argument.literal);
      }
    } else if (ts.isCallExpression(node)) {
      // dynamic import("x") / await import("x")
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        pushIfStringLiteral(node.arguments[0]);
      } else if (isRequireCallee(node.expression)) {
        // require("x") / createRequire(...)("x") / r("x") / *.resolve("x")
        pushIfStringLiteral(node.arguments[0]);
      }
    }
    ts.forEachChild(node, visit);
  };

  visit(sf);

  // Triple-slash directives live on the SourceFile, not in the child AST:
  //   /// <reference path="../../sidecars/concordia/types.d.ts" />  -> a path
  //   /// <reference types="@concordia/foo" />                       -> a pkg
  for (const ref of sf.referencedFiles) out.push(ref.fileName);
  for (const ref of sf.typeReferenceDirectives) out.push(ref.fileName);

  return out;
}

/** True if `spec` is a bare import of one of the forbidden external packages. */
function isForbiddenPackage(spec: string): boolean {
  if (spec.startsWith(".") || spec.startsWith("/")) return false; // relative/absolute, not a bare pkg
  return FORBIDDEN_PACKAGES.some(
    (pkg) => spec === pkg || spec.startsWith(`${pkg}/`),
  );
}

/**
 * For a relative/absolute spec, resolve it against the importing file and
 * report whether the resolved path escapes server/src into a forbidden tree.
 * Returns the matched fragment, or null. Bare specs return null here (handled
 * by isForbiddenPackage).
 */
function escapedForbiddenFragment(
  fromFileAbs: string,
  spec: string,
): string | null {
  if (!spec.startsWith(".") && !spec.startsWith("/")) return null;
  const resolved = normalize(
    spec.startsWith(".") ? join(dirname(fromFileAbs), spec) : spec,
  ).replace(/\\/g, "/");
  // Inside ANY first-party source root is always allowed (local Sanctuary code).
  if (FIRST_PARTY_ABS_ROOTS.some((root) => resolved.startsWith(root))) {
    return null;
  }
  for (const seg of FORBIDDEN_ESCAPED_SEGMENTS) {
    // reach INTO the dir (`/concordia/...`) OR a bare import OF it (`/concordia`)
    if (resolved.includes(`${seg}/`) || resolved.endsWith(seg)) return seg;
  }
  return null;
}

/**
 * JS/TS package.json files whose dependency tables must not name a forbidden
 * pkg. Covers every npm manifest in the repo (root, the server package, and the
 * menubar + quickstart sub-packages). Cargo.toml / Package.swift are excluded
 * by design — a Rust/Swift package cannot depend on the npm/PyPI Concordia or
 * Verascore package, so there is no non-dependency invariant to enforce there.
 */
const MANIFESTS: ReadonlyArray<string> = [
  "package.json",
  "server/package.json",
  "menubar/package.json",
  "quickstart/package.json",
];
const DEP_FIELDS: ReadonlyArray<string> = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];

describe("non-dependency guard (Sanctuary must not depend on Concordia/Verascore)", () => {
  it("no first-party source file imports an external Concordia or Verascore package", () => {
    const rels = firstPartySourceFiles();
    // sanity: the enumeration actually found the trees
    expect(rels.length).toBeGreaterThan(100);

    const violations: string[] = [];
    for (const rel of rels) {
      const abs = join(REPO_ROOT, rel);
      const source = readFileSync(abs, "utf8");
      for (const spec of extractSpecifiers(rel, source)) {
        if (isForbiddenPackage(spec)) {
          violations.push(`${rel}: import of forbidden package "${spec}"`);
        }
        const frag = escapedForbiddenFragment(abs, spec);
        if (frag) {
          violations.push(
            `${rel}: import "${spec}" escapes first-party source into a Concordia/Verascore tree (${frag})`,
          );
        }
      }
    }

    expect(
      violations,
      "Sanctuary must NEVER take a hard code dependency on Concordia or " +
        "Verascore (CLAUDE.md non-dependency principle). The following " +
        "first-party source import(s) violate it:\n  " +
        violations.join("\n  ") +
        "\n\nFIX: route the interaction through the composition/ sidecar-RPC " +
        "boundary (optional, out-of-process) instead of importing the package " +
        "directly. Local files named concordia-*.ts / verascore-*.ts " +
        "are fine — only EXTERNAL packages and escaping paths are forbidden.",
    ).toEqual([]);
  });

  it("no package.json declares a Concordia or Verascore package as a dependency", () => {
    const violations: string[] = [];
    for (const rel of MANIFESTS) {
      const abs = join(REPO_ROOT, rel);
      let pkg: Record<string, unknown>;
      try {
        pkg = JSON.parse(readFileSync(abs, "utf8")) as Record<string, unknown>;
      } catch {
        continue; // a manifest that does not exist / parse is not this guard's concern
      }
      for (const field of DEP_FIELDS) {
        const table = pkg[field];
        if (!table || typeof table !== "object") continue;
        for (const [name, value] of Object.entries(
          table as Record<string, unknown>,
        )) {
          // (a) the dependency KEY names a forbidden package
          if (isForbiddenPackage(name)) {
            violations.push(`${rel}: "${field}" declares forbidden package "${name}"`);
          }
          // (b) an npm-ALIAS value installs a forbidden package under an
          //     innocent key: "safe": "npm:@concordia/foo@1.0.0".
          if (typeof value === "string" && value.startsWith("npm:")) {
            const aliasTarget = value.slice("npm:".length).replace(/@[^@/]*$/, "");
            if (isForbiddenPackage(aliasTarget)) {
              violations.push(
                `${rel}: "${field}"."${name}" npm-aliases forbidden package "${aliasTarget}" (value "${value}")`,
              );
            }
          }
          // (c) a LOCAL-PATH value (file:/link:/workspace:/portal:/relative)
          //     that points at a forbidden tree: "safe": "file:sidecars/concordia".
          //     This is an install-time hard dependency the import scan cannot see.
          if (typeof value === "string") {
            const pathPart = value
              .replace(/^(file|link|workspace|portal):/, "")
              .replace(/\\/g, "/");
            const probe = pathPart.startsWith("/") ? pathPart : `/${pathPart}`;
            const seg = FORBIDDEN_ESCAPED_SEGMENTS.find(
              (s) => probe.includes(`${s}/`) || probe.endsWith(s),
            );
            // only treat it as a path dep if it actually looks like a path value
            // (a protocol prefix or a ./ ../ form), not a bare semver range.
            const looksLikePath =
              /^(file|link|workspace|portal):/.test(value) ||
              value.startsWith(".") ||
              value.startsWith("/");
            if (seg && looksLikePath) {
              violations.push(
                `${rel}: "${field}"."${name}" is a local-path dependency on a Concordia/Verascore tree (${seg}, value "${value}")`,
              );
            }
          }
        }
      }
    }

    expect(
      violations,
      "A package.json declares a hard dependency on Concordia/Verascore " +
        "(CLAUDE.md non-dependency principle), directly or via an npm: alias. " +
        "A declared dependency is install-time REQUIRED even with no import " +
        "statement, so this is a real break of the principle:\n  " +
        violations.join("\n  ") +
        "\n\nFIX: remove the dependency; reach Concordia/Verascore only through " +
        "the optional, out-of-process composition/ sidecar-RPC boundary.",
    ).toEqual([]);
  });
});
