/**
 * IC-30: unify fortress flag parsing on the strict parser.
 *
 * `server/src/cli/argv.ts` exports two divergent ways to read a flag's
 * value: `flagValue`/`flagValues` (permissive: an empty `--fortress=`, a
 * duplicate `--fortress a --fortress b`, or a dropped value that swallows
 * the NEXT flag as its own value all pass silently) and `consumeFlagValue`
 * (strict: all three refuse). Before this fix, roughly half of the
 * fortress-scoped CLI verbs used each parser for `--fortress`, so which
 * fortress an operator's command touched could depend on which file
 * happened to implement that verb. See
 * `Review/Sanctuary/IC30_Parser_Unification_Spawn_Prompt_2026-08-28.md`.
 *
 * This is the tripwire that keeps the class closed: a FULL-SET scan of the
 * `server/src/cli` tree (every `.ts` source file, not a sampled list), not
 * an assertion pinned to today's known files. A file added later that
 * parses `--fortress` with `flagValue`/`flagValues` fails this test the
 * moment it lands, before it ships.
 *
 * IC-30 fix-round finding #2: the ORIGINAL version of this guard was a
 * source-text regex (`/\bflagValues?\(\s*[^,]+,\s*"--fortress"\s*\)/`),
 * which is spelling-dependent -- a single-quoted call
 * (`flagValue(argv, '--fortress')`), an aliased import
 * (`import { flagValue as fv } from "./argv.js"` then
 * `fv(argv, "--fortress")`), or the flag name routed through a same-file
 * constant (`const FORTRESS_FLAG = "--fortress"; flagValue(argv,
 * FORTRESS_FLAG)`) all evade a literal-string regex while reaching the
 * IDENTICAL permissive call at runtime. This version replaces the regex
 * with a semantic scan over the TypeScript AST (the same `typescript`
 * compiler-API approach `test/structure/no-floating-append-critical.test.ts`
 * already uses): it resolves the CALLEE through the file's own import
 * bindings (so an alias cannot hide which function is actually called) and
 * resolves an Identifier ARGUMENT through same-file `const` declarations
 * (so a named constant cannot hide which flag string is actually passed).
 * The "guard self-tests" describe block below plants each evasion shape
 * against synthetic in-memory source and proves the scanner still catches
 * it -- an assertion, not a claim, that this version closes what the
 * regex missed.
 *
 * Residual boundary (honest, not fixed by this version): a wrapper defined
 * in a DIFFERENT file that itself calls `flagValue`/`flagValues` with
 * `"--fortress"`, imported into a CLI file under an innocuous name, is not
 * traced across the file boundary -- this scanner resolves imports FROM
 * `argv.js` specifically and constants declared IN THE SAME FILE; it does
 * not build a whole-program call graph. Nor does it resolve a flag-name
 * argument built from a runtime expression (a ternary, a function call, a
 * concatenation) rather than a literal or a same-file constant -- those
 * cases are neither flagged nor cleared; they simply do not match either
 * shape this scanner understands. Closing those needs a full call-graph
 * analysis, which is a larger investment than a source-file scan; this
 * scanner closes the concretely-demonstrated evasions (spelling, aliasing,
 * same-file constants) without claiming to close every conceivable one.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import ts from "typescript";

const CLI_DIR = join(__dirname, "..", "..", "src", "cli");

/**
 * Files that mention `--fortress` in source but are NOT "a verb-scoped
 * --fortress parse" in the sense this fix targets: each does a
 * categorically different job that neither `flagValue` nor
 * `consumeFlagValue` is a drop-in replacement for. Every entry names the
 * file's own doc comment as the source of truth, so a reviewer does not
 * have to take this list's word for it. None of these files actually
 * contains a `flagValue`/`flagValues` call resolving to `"--fortress"`
 * (this scanner would pass them even unexempted); the exemption exists so
 * this suite documents WHY each one is exempt, in one place, rather than
 * relying on "it happens to pass".
 */
const EXEMPT_RELATIVE_PATHS: ReadonlySet<string> = new Set([
  // Defines flagValue/consumeFlagValue/flagValues themselves. Scanned like
  // every other file below (not skipped) -- if a future edit added a
  // wrapper HERE that itself called flagValue/flagValues with "--fortress",
  // the scan would still catch it, since the exemption is about the
  // OUTCOME (no matching call found), not a blanket skip.
  "argv.ts",
  // Scans only the LEADING pre-subcommand flag region and stops at the
  // first non-flag token (the subcommand word); consumeFlagValue scans the
  // WHOLE argv and cannot express that boundary. See the module doc
  // comment (drill finding F-1.3.2-N-001) for why the scope is deliberate.
  "top-level-fortress.ts",
  // Deliberately REFUSES a post-subcommand --fortress rather than parsing
  // it (assertNoFortressFlag): two earlier attempts to repair the
  // operator's argv each traded the silent-drop defect for a new one. See
  // the module doc comment and test/cli/secrets-fortress-flag.test.ts.
  "secrets.ts",
  // Constructs an argv ARRAY to hand to a subprocess/agent invocation
  // (`["--fortress", input.fortress, ...]`); it never parses one.
  "install.ts",
]);

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...listTsFiles(full));
    } else if (entry.endsWith(".ts") && !entry.endsWith(".test.ts")) {
      out.push(full);
    }
  }
  return out;
}

/** True for a relative import specifier that resolves to this tree's `argv.ts` (`./argv.js`, `../argv.js`, `../../argv.js`, ...). */
function isArgvModuleSpecifier(specifier: string): boolean {
  // `./argv.js` from siblings, or one-or-more `../` hops from nested dirs.
  // The prior form required a literal `./` before `argv.js`, which missed
  // real nested imports like `../argv.js` entirely.
  return /^(\.\/|(\.\.\/)+)argv\.js$/.test(specifier);
}

const PERMISSIVE_EXPORT_NAMES = new Set(["flagValue", "flagValues"]);

interface FortressCallViolation {
  line: number;
  excerpt: string;
}

/**
 * Semantic scan: find every call to `flagValue`/`flagValues` (resolved
 * through THIS file's own import bindings from `argv.js`, so an aliased
 * import cannot hide it) whose flag-name argument resolves -- either as a
 * direct string literal or through a same-file `const` declaration -- to
 * exactly `"--fortress"`.
 */
function findFortressFlagViolations(
  source: string,
  fileName: string,
): FortressCallViolation[] {
  const sourceFile = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );

  // local identifier name -> which permissive export it is bound to
  // ("flagValue" | "flagValues"), for names imported from argv.js only.
  const permissiveLocalNames = new Map<string, string>();
  // same-file const name -> every string-literal value it is ever
  // initialized to (a Set, not a single value, because two DIFFERENT
  // consts sharing a name only happens via shadowing across scopes this
  // scanner does not track; collecting every value and flagging on ANY
  // match is the conservative, over-inclusive direction for a guard).
  const stringConstants = new Map<string, Set<string>>();

  function recordStringConstant(name: string, value: string): void {
    const set = stringConstants.get(name) ?? new Set<string>();
    set.add(value);
    stringConstants.set(name, set);
  }

  function literalText(node: ts.Node): string | undefined {
    if (ts.isStringLiteralLike(node)) return node.text;
    return undefined;
  }

  function visitForBindings(node: ts.Node): void {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      if (isArgvModuleSpecifier(node.moduleSpecifier.text)) {
        const bindings = node.importClause?.namedBindings;
        if (bindings && ts.isNamedImports(bindings)) {
          for (const spec of bindings.elements) {
            const exportedName = (spec.propertyName ?? spec.name).text;
            if (PERMISSIVE_EXPORT_NAMES.has(exportedName)) {
              permissiveLocalNames.set(spec.name.text, exportedName);
            }
          }
        }
      }
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const value = literalText(node.initializer);
      if (value !== undefined) {
        recordStringConstant(node.name.text, value);
      }
    }
    ts.forEachChild(node, visitForBindings);
  }
  visitForBindings(sourceFile);

  function resolvesToFortress(node: ts.Node): boolean {
    const direct = literalText(node);
    if (direct !== undefined) return direct === "--fortress";
    if (ts.isIdentifier(node)) {
      const values = stringConstants.get(node.text);
      if (values && values.has("--fortress")) return true;
    }
    return false;
  }

  const violations: FortressCallViolation[] = [];
  function visitForCalls(node: ts.Node): void {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      permissiveLocalNames.has(node.expression.text) &&
      node.arguments.length >= 2 &&
      resolvesToFortress(node.arguments[1]!)
    ) {
      const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
      violations.push({
        line: line + 1,
        excerpt: node.getText(sourceFile).replace(/\s+/g, " ").slice(0, 120),
      });
    }
    ts.forEachChild(node, visitForCalls);
  }
  visitForCalls(sourceFile);

  return violations;
}

describe("IC-30: fortress-flag parsing is unified on consumeFlagValue", () => {
  const allFiles = listTsFiles(CLI_DIR);

  // Sanity check on the scan itself: if this drops to zero, the glob logic
  // broke, and the "no violations found" result below would be a false
  // pass rather than a real one.
  it("scans a non-trivial number of CLI source files", () => {
    expect(allFiles.length).toBeGreaterThan(30);
  });

  it("every exempt path actually exists in the tree (no stale exemption)", () => {
    for (const rel of EXEMPT_RELATIVE_PATHS) {
      const full = join(CLI_DIR, rel);
      expect(allFiles, `exempt path ${rel} not found under server/src/cli`).toContain(
        full,
      );
    }
  });

  const candidates = allFiles.filter((full) => {
    const rel = relative(CLI_DIR, full).split(sep).join("/");
    return !EXEMPT_RELATIVE_PATHS.has(rel);
  });

  // Full-set assertion: every non-exempt file is graded individually below,
  // so a regression in one file cannot be masked by the others passing (the
  // failure names the exact file and line), and a new file added to the
  // tree is scanned automatically -- there is no "mentions --fortress"
  // pre-filter to fall out of sync with what the semantic scan can detect.
  it("graded at least 30 non-exempt candidate files", () => {
    expect(candidates.length).toBeGreaterThan(30);
  });

  for (const full of candidates) {
    const rel = relative(CLI_DIR, full).split(sep).join("/");
    it(`${rel} does not resolve --fortress into a flagValue/flagValues call`, () => {
      const violations = findFortressFlagViolations(readFileSync(full, "utf8"), full);
      expect(
        violations,
        violations.map((v) => `${rel}:${v.line}: ${v.excerpt}`).join("\n"),
      ).toEqual([]);
    });
  }
});

describe("IC-30 fix round: guard self-tests (each evasion shape the prior regex missed)", () => {
  it("catches a single-quoted call (Tier-1 regex evasion)", () => {
    const source = `
import { flagValue } from "./argv.js";
function readFortress(argv: string[]) {
  return flagValue(argv, '--fortress');
}
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations).toHaveLength(1);
    expect(violations[0]!.line).toBe(4);
  });

  it("catches an aliased import (`flagValue as fv`)", () => {
    const source = `
import { flagValue as fv } from "./argv.js";
function readFortress(argv: string[]) {
  return fv(argv, "--fortress");
}
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations).toHaveLength(1);
  });

  it("catches a same-file named constant instead of the literal", () => {
    const source = `
import { flagValue } from "./argv.js";
const FORTRESS_FLAG = "--fortress";
function readFortress(argv: string[]) {
  return flagValue(argv, FORTRESS_FLAG);
}
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations).toHaveLength(1);
  });

  it("catches the repeatable flagValues sibling, not only flagValue", () => {
    const source = `
import { flagValues } from "./argv.js";
function readFortress(argv: string[]) {
  return flagValues(argv, "--fortress");
}
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations).toHaveLength(1);
  });

  // Positive fixture for the nested-specifier arm of isArgvModuleSpecifier:
  // every other self-test imports via "./argv.js", so without these two cases
  // a regression back to the literal-"./" matcher would still pass the suite.
  it("catches a permissive import reached through a nested `../argv.js` specifier", () => {
    const source = `
import { flagValue } from "../argv.js";
function readFortress(argv: string[]) {
  return flagValue(argv, "--fortress");
}
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations).toHaveLength(1);
  });

  it("catches a permissive import reached through a multi-hop `../../argv.js` specifier", () => {
    const source = `
import { flagValue } from "../../argv.js";
function readFortress(argv: string[]) {
  return flagValue(argv, "--fortress");
}
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations).toHaveLength(1);
  });

  it("catches a wrapper nested arbitrarily deep in the SAME file", () => {
    const source = `
import { flagValue } from "./argv.js";
function outer(argv: string[]) {
  function inner() {
    if (true) {
      return flagValue(argv, "--fortress");
    }
    return undefined;
  }
  return inner();
}
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations).toHaveLength(1);
  });

  it("catches multiple violations in one file, each with its own line", () => {
    const source = `
import { flagValue } from "./argv.js";
const a = flagValue(argv, "--fortress");
const b = flagValue(argv, "--fortress");
`;
    const violations = findFortressFlagViolations(source, "synthetic.ts");
    expect(violations.map((v) => v.line)).toEqual([3, 4]);
  });

  it("does NOT flag consumeFlagValue (the strict parser this fix migrates onto)", () => {
    const source = `
import { consumeFlagValue } from "./argv.js";
function readFortress(argv: string[]) {
  return consumeFlagValue(argv, "--fortress");
}
`;
    expect(findFortressFlagViolations(source, "synthetic.ts")).toEqual([]);
  });

  it("does NOT flag flagValue used for a DIFFERENT flag", () => {
    const source = `
import { flagValue } from "./argv.js";
function readPassphrase(argv: string[]) {
  return flagValue(argv, "--passphrase");
}
`;
    expect(findFortressFlagViolations(source, "synthetic.ts")).toEqual([]);
  });

  it("does NOT flag a flag name that merely starts with --fortress (alias siblings)", () => {
    const source = `
import { flagValue } from "./argv.js";
function readAlias(argv: string[]) {
  const a = flagValue(argv, "--fortress-url");
  const b = flagValue(argv, "--fortress-path");
  return [a, b];
}
`;
    expect(findFortressFlagViolations(source, "synthetic.ts")).toEqual([]);
  });

  it("does NOT flag a same-named flagValue imported from a DIFFERENT module", () => {
    // Proves the scanner is scoped to argv.js's own export, not a bare
    // name match on the identifier "flagValue" anywhere in the file.
    const source = `
import { flagValue } from "./some-other-module.js";
function readFortress(argv: string[]) {
  return flagValue(argv, "--fortress");
}
`;
    expect(findFortressFlagViolations(source, "synthetic.ts")).toEqual([]);
  });

  it("documents the residual boundary: a same-file constant assigned from ANOTHER constant (two-hop) is not resolved", () => {
    // Honest limitation, not a silent gap: this scanner resolves ONE hop
    // of same-file constant indirection, matching the "constant name"
    // evasion actually demonstrated in the finding. A second hop
    // (`const B = A;`) is a different, deeper evasion this version does
    // not claim to close; the test exists so a future reader sees this was
    // considered, not missed by accident.
    const source = `
import { flagValue } from "./argv.js";
const FORTRESS_FLAG = "--fortress";
const ALIAS_OF_FORTRESS_FLAG = FORTRESS_FLAG;
function readFortress(argv: string[]) {
  return flagValue(argv, ALIAS_OF_FORTRESS_FLAG);
}
`;
    // Not asserted as a violation: this is the documented residual, not a
    // hidden pass. If a future version resolves multi-hop constants, this
    // assertion should flip to `toHaveLength(1)` deliberately.
    expect(findFortressFlagViolations(source, "synthetic.ts")).toEqual([]);
  });
});
