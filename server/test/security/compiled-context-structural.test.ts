import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const SERVER_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const SRC_ROOT = join(SERVER_ROOT, "src");

function sourceFiles(dir = SRC_ROOT): string[] {
  const files: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) files.push(...sourceFiles(path));
    else if (path.endsWith(".ts")) files.push(path);
  }
  return files;
}

function rel(path: string): string {
  return relative(SRC_ROOT, path).replaceAll("\\", "/");
}

/**
 * Fix-round-8 (P2, round 4 item 4): finds the FIRST call, inside a named
 * method, to a function/method matching `calleeName` (an Identifier, e.g.
 * `compileSubstrateContext`, or a `this.<name>` PropertyAccessExpression,
 * e.g. `this.getOrIssueHandle`), and returns its AST position. The PRIOR
 * version of this ordering check used `indexOf` on the call's EXACT
 * argument text (`"this.getOrIssueHandle(surface, choice, { localOnly:
 * requestLocalOnly })"`), which breaks on a purely cosmetic change to that
 * call's arguments (a rename, a reformat, an added parameter) with the
 * property it exists to pin -- ordering -- completely intact. Matching on
 * the CALLEE NAME via the parser, not the full call text, survives that
 * class of change; only a change that removes the call, or reorders it
 * relative to its siblings, moves this position.
 */
function firstCallPosition(methodSource: string, calleeName: string): number {
  const sourceFile = ts.createSourceFile("method.ts", `class C { ${methodSource} }`, ts.ScriptTarget.Latest, true);
  let found = -1;
  const matches = (expr: ts.Expression): boolean => {
    if (ts.isIdentifier(expr)) return expr.text === calleeName;
    if (ts.isPropertyAccessExpression(expr) && expr.expression.kind === ts.SyntaxKind.ThisKeyword) {
      return expr.name.text === calleeName;
    }
    return false;
  };
  const visit = (node: ts.Node): void => {
    if (found !== -1) return;
    if (ts.isCallExpression(node) && matches(node.expression)) {
      found = node.getStart(sourceFile);
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

describe("Memory Integrity Slice B — frozen production assembler inventory", () => {
  it("freezes every typed selector invocation site", () => {
    const callsites = sourceFiles()
      .filter((path) => /\.invoke(?:Summarize|Classify|Redact)\s*\(/.test(readFileSync(path, "utf8")))
      .map(rel)
      .sort();
    expect(callsites).toEqual([
      "chat/operator-chat-service.ts",
      "concierge/concierge-service.ts",
      "coordination/context-transfer-extractor.ts",
      "dashboard/v1_1/wiring.ts",
      "honeypot/honeypot-compiler.ts",
      "policy-engine/english-policy-compiler.ts",
      "query-anonymity/intent-classifier.ts",
      "query-anonymity/pii-rewrite.ts",
    ]);
    const sentinelAdapter = readFileSync(
      join(SRC_ROOT, "sentinel/sentinels/suspicious-tool-call-detector.ts"),
      "utf8",
    );
    expect(sentinelAdapter).toContain("selector.invokeClassify as");
    expect(sentinelAdapter).toContain("fn.call(selector");
  });

  it("freezes provider pass-through callsites and rejects direct concierge construction", () => {
    const directClientCalls = sourceFiles()
      .filter((path) => /this\.client\.(?:generate|chat)\s*\(|this\.venice\.complete\s*\(/.test(readFileSync(path, "utf8")))
      .map(rel)
      .sort();
    expect(directClientCalls).toEqual([
      "intelligence/substrates/frontier.ts",
      "intelligence/substrates/local.ts",
      "intelligence/substrates/venice.ts",
    ]);
    const concierge = readFileSync(join(SRC_ROOT, "concierge/concierge-service.ts"), "utf8");
    expect(concierge).not.toContain("VeniceClient");
    expect(concierge).not.toContain("this.venice");
    expect(concierge).toContain('this.selector.invokeSummarize("concierge", {');
  });

  it("requires scan-after-final-assembly and scan-before-provider ordering", () => {
    const selector = readFileSync(join(SRC_ROOT, "intelligence/selector.ts"), "utf8");
    const invoke = selector.slice(selector.indexOf("  private async invoke("), selector.indexOf("  /**\n   * Append a failure entry"));
    // 2026-09-15 slice: `getOrIssueHandle` now also takes the request-scoped
    // local-only opts (see `test/structure/local-only-chokepoints.test.ts`
    // for the dedicated assertions on that addition); this still pins the
    // original claim, that context screening precedes handle construction
    // precedes invocation. Fix-round-8 (P2): pinned by CALLEE NAME via the
    // parser (`firstCallPosition`), not by the exact call text (arguments
    // included) — see that function's doc comment for why the prior
    // exact-text version was fragile independent of this property.
    const compilePos = firstCallPosition(invoke, "compileSubstrateContext");
    const getOrIssuePos = firstCallPosition(invoke, "getOrIssueHandle");
    const invokeHandlePos = firstCallPosition(invoke, "invokeHandle");
    expect(compilePos).toBeGreaterThan(-1);
    expect(getOrIssuePos).toBeGreaterThan(-1);
    expect(invokeHandlePos).toBeGreaterThan(-1);
    expect(compilePos).toBeLessThan(getOrIssuePos);
    expect(getOrIssuePos).toBeLessThan(invokeHandlePos);

    // `getOrIssueHandle` creates provider handles but is not a context assembler:
    // production callers use getSubstrate only for capability/display metadata,
    // while every provider-reaching invocation remains in the frozen invoke*
    // inventory above and crosses this post-assembly screen first.
    const directHandleInvocations = sourceFiles()
      .filter((path) => rel(path) !== "intelligence/selector.ts")
      .filter((path) => /\bhandle\.(?:summarize|classify|redact)\s*\(/.test(
        readFileSync(path, "utf8"),
      ))
      .map(rel)
      .sort();
    expect(directHandleInvocations).toEqual([]);

    const concierge = readFileSync(join(SRC_ROOT, "concierge/concierge-service.ts"), "utf8");
    // The briefing is compiled through ONE builder that also names the segment
    // this runtime authored; the context handed to the selector is that
    // builder's output verbatim, never a locally re-joined variant, or the
    // first-party prefix the claim names would no longer be a prefix of it.
    expect(concierge).toContain(
      "const compiled = compileConciergePrompt({ question, context })",
    );
    expect(concierge).toContain("context: compiled.context");
    expect(concierge).toContain(
      "contextProvenance: claimFirstPartyContext(compiled.firstPartyPrefix)",
    );
    expect(concierge).toContain("query: question");
    expect(concierge).not.toContain("compileLegacyConciergeContext");
  });

  it("freezes the set of modules allowed to mint a first-party context claim", () => {
    // The mint function is exported, so the brand alone answers "can this be
    // forged from the wire" and not "which module may claim". This full-set
    // assertion is the answer to the second question: a new caller is a
    // deliberate, visible edit here, reviewed as a claim about authorship
    // rather than arriving as an import nobody reads. Full-set equality, not
    // presence: a `toContain` would pass a second, unnoticed minting site.
    const minters = sourceFiles()
      // The declaring module matches its own `export function` line; every
      // other match is a call site.
      .filter((path) => rel(path) !== "intelligence/types.ts")
      .filter((path) => /\bclaimFirstPartyContext\s*\(/.test(readFileSync(path, "utf8")))
      .map(rel)
      .sort();
    expect(minters).toEqual(["concierge/concierge-service.ts"]);
  });

  it("requires real production reporter wiring at every runtime construction path", () => {
    const main = readFileSync(join(SRC_ROOT, "index.ts"), "utf8");
    expect(main).toContain("createDispatcherWiredCompiledContextScanner");
    expect(main).toContain("dispatcher: sentinelDispatcher");
    expect(main).toContain("setCompiledContextScanner");

    const standalone = readFileSync(join(SRC_ROOT, "dashboard-standalone.ts"), "utf8");
    expect(standalone).toContain("createCompiledContextRuntime");
    expect(standalone).toContain("compiledContextScanner: compiledContextRuntime.scanner");
    expect(standalone).toContain("sentinelFindingStore: compiledContextRuntime.findingStore");

    for (const path of ["cli/concierge.ts", "cli/policy.ts"]) {
      const source = readFileSync(join(SRC_ROOT, path), "utf8");
      expect(source).toContain("createCompiledContextRuntime");
      expect(source).toContain("compiledContextScanner: compiledContextRuntime.scanner");
    }
  });
});
