/**
 * Blocked-egress attribution minting stays owned by the audit consumer.
 * S1
 */

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const SERVER_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const MINT_NAME = "mintConsumerBlockedEgress";
const MODULE_PATH = /(?:^|\/)blocked-egress-attribution(?:\.[cm]?[jt]s)?$/;
const READER_NAMES = new Set(["readConsumerMintedBlockedEgress", "ConsumerMintedBlockedEgress"]);
// Must match the mint invariant in castle-wall/runtime/blocked-egress-attribution.ts.
const ALLOWED_MINT_REFERENCES = new Set([
  "src/castle-wall/runtime/blocked-egress-attribution.ts",
  "src/castle-wall/runtime/audit-consumer.ts",
  // The guard names the mint in its inventory and synthetic fixtures, never imports it.
  "test/structure/blocked-egress-mint-single-caller.test.ts",
]);
const ALLOWED_MODULE_IMPORTERS = new Set([
  "src/castle-wall/runtime/audit-consumer.ts",
  "src/castle-wall/runtime/index.ts",
  "src/principal-policy/unified-inbox-bridge.ts",
  "src/principal-policy/unified-inbox-producers.ts",
  "test/castle-wall/runtime/audit-consumer-producer-auth.test.ts",
]);

interface SourceFile {
  path: string;
  contents: string;
}

function readSourceFiles(directory: string): SourceFile[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return readSourceFiles(path);
    if (!entry.isFile()) return [];
    return [{
      path: relative(SERVER_ROOT, path).split("\\").join("/"),
      contents: readFileSync(path, "utf8"),
    }];
  });
}

const moduleAccessCache = new WeakMap<SourceFile, ts.Node[]>();

function moduleAccesses(file: SourceFile): ts.Node[] {
  const cached = moduleAccessCache.get(file);
  if (cached) return cached;
  const accesses: ts.Node[] = [];
  const source = ts.createSourceFile(file.path, file.contents, ts.ScriptTarget.Latest, true);
  function visit(node: ts.Node): void {
    // Match the module path, including namespace imports, aliases, re-exports and dynamic loads.
    if (ts.isStringLiteralLike(node) && MODULE_PATH.test(node.text)) {
      const parent = node.parent;
      if ((ts.isImportDeclaration(parent) || ts.isExportDeclaration(parent)) && parent.moduleSpecifier === node
        || ts.isCallExpression(parent) || ts.isExternalModuleReference(parent)
        || ts.isLiteralTypeNode(parent) && ts.isImportTypeNode(parent.parent)) accesses.push(parent);
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  moduleAccessCache.set(file, accesses);
  return accesses;
}

function assertSingleCaller(files: SourceFile[]): void {
  // Full-set equality covers both roots and detects missing as well as additional references.
  expect(new Set(files.filter((file) => file.contents.includes(MINT_NAME)).map((file) => file.path)))
    .toEqual(ALLOWED_MINT_REFERENCES);
  const importers = files.map((file) => ({ ...file, accesses: moduleAccesses(file) }))
    .filter((file) => file.accesses.length > 0);
  expect(new Set(importers.map((file) => file.path))).toEqual(ALLOWED_MODULE_IMPORTERS);
  for (const file of importers) {
    const allowed = file.path === "src/castle-wall/runtime/audit-consumer.ts"
      ? new Set([...READER_NAMES, MINT_NAME, "BlockedEgressProjection"])
      : READER_NAMES;
    for (const access of file.accesses) {
      // Explicit named access prevents computed namespace reads and wildcard re-exports.
      if (ts.isImportDeclaration(access)) {
        expect(access.importClause?.name).toBeUndefined();
        const bindings = access.importClause?.namedBindings;
        expect(bindings && ts.isNamedImports(bindings)).toBe(true);
        if (bindings && ts.isNamedImports(bindings)) {
          for (const element of bindings.elements) expect(allowed.has((element.propertyName ?? element.name).text)).toBe(true);
        }
      } else if (ts.isExportDeclaration(access)) {
        const clause = access.exportClause;
        expect(clause && ts.isNamedExports(clause)).toBe(true);
        if (clause && ts.isNamedExports(clause)) {
          for (const element of clause.elements) expect(allowed.has((element.propertyName ?? element.name).text)).toBe(true);
        }
      } else {
        throw new Error(`Non-named attribution module access: ${file.path}`);
      }
    }
  }
}

describe("blocked-egress mint single caller", () => {
  const files = [...readSourceFiles(join(SERVER_ROOT, "src")), ...readSourceFiles(join(SERVER_ROOT, "test"))];

  it("restricts the full source and test importer sets and their named imports", () => {
    assertSingleCaller(files);
  });

  it.each(["src", "test"])("rejects an extra %s caller that names the mint", (root) => {
    expect(() => assertSingleCaller([...files, {
      path: `${root}/additional-caller.ts`, contents: "mintConsumerBlockedEgress(projection);",
    }])).toThrow();
  });

  it.each(["src", "test"])("rejects an extra %s namespace importer without the mint identifier", (root) => {
    expect(() => assertSingleCaller([...files, {
      path: `${root}/additional-caller.ts`,
      contents: 'import * as attribution from "../castle-wall/runtime/blocked-egress-attribution.js";',
    }])).toThrow();
  });

  it.each([
    'import * as attribution from "../castle-wall/runtime/blocked-egress-attribution.js";',
    'export * from "../castle-wall/runtime/blocked-egress-attribution.js";',
    'const attribution = await import("../castle-wall/runtime/blocked-egress-attribution.js");',
    'import { mintConsumerBlockedEgress as mint } from "../castle-wall/runtime/blocked-egress-attribution.js";',
    'import type { BlockedEgressProjection } from "../castle-wall/runtime/blocked-egress-attribution.js";',
  ])("rejects expanded access in an allowed test importer: %s", (contents) => {
    expect(() => assertSingleCaller(files.map((file) => file.path === "test/castle-wall/runtime/audit-consumer-producer-auth.test.ts"
      ? { ...file, contents } : file))).toThrow();
  });
});
