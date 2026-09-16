/**
 * Request-scoped local-only structural chokepoints (2026-09-15 slice).
 *
 * Mirrors `test/structure/q5e-selector-chokepoints.test.ts`'s technique:
 * assert code SHAPE via source-text ordering rather than only behavior, so a
 * future edit that reorders these checks (and thereby lets a hosted client
 * get constructed before the local-only guard runs) fails a test even if no
 * behavioral test happens to exercise that exact ordering.
 *
 * Fix-round-6 (P2): pins PROPERTIES, not literal call-argument strings,
 * wherever a property-level check is available (call-site counts are
 * computed over COMMENT-STRIPPED source, via the same TypeScript-parser-
 * backed `stripCodeComments` the em-dash guard uses, so a doc comment that
 * happens to mention `refusesLocalOnly(...)` in prose can never inflate the
 * count the way a bare regex over raw source did in an earlier round). The
 * ordering assertions still slice named method bodies and search within
 * them (matching `q5e-selector-chokepoints.test.ts`'s own technique), but
 * search for the FUNCTION NAME being called, not its exact argument list,
 * so a parameter-shape change (e.g. widening `refusesLocalOnly`'s second
 * parameter type) does not itself break these tests independent of the
 * property they exist to pin.
 */
import { readFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { stripCodeComments } from "./public-surface.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcRoot = join(here, "..", "..", "src");

function relativeSourcePath(path: string): string {
  return relative(srcRoot, path).replaceAll("\\", "/");
}

async function selectorSource(): Promise<string> {
  return readFile(join(srcRoot, "intelligence", "selector.ts"), "utf8");
}

/** Slice a named method's body out of `selector.ts`'s source by its declaration text, up to the next declaration. */
function sliceMethod(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle, start);
  expect(start, `could not find "${startNeedle}"`).toBeGreaterThan(-1);
  expect(end, `could not find "${endNeedle}" after "${startNeedle}"`).toBeGreaterThan(start);
  return source.slice(start, end);
}

interface ClientImportAnalysis {
  veniceImporters: string[];
  frontierImporters: string[];
}

let cachedClientImportAnalysis: ClientImportAnalysis | undefined;

/**
 * Checker-resolved IMPORT inventory (fix-round-9, P1: both reviewers on
 * round 4's construction-inventory, which still missed `const V =
 * VeniceClient; new V()` — a local rebinding is assignment-graph
 * analysis, a different question than "what did this file import," so no
 * amount of refining a construction-site walk closes it). The fix
 * subtracts construction-site tracking entirely and asserts the
 * STRONGER, fully resolvable property instead: WHO can even REFERENCE the
 * class. A file with no binding to `VeniceClient`/`FrontierClient` in
 * scope cannot construct it, rebind it, or launder it through a local
 * const under any name — there is nothing to launder. So instead of
 * hunting `new` expressions, this walks every IMPORT-introduced
 * identifier (a named import, a namespace import's own binding, or a
 * namespace import's re-exported members) in every first-party file, and
 * for each one asks the checker what it resolves to once every alias hop
 * — an import specifier, a re-export, a barrel, a namespace member — is
 * followed to the underlying class declaration. A rebinding INSIDE
 * selector.ts is irrelevant (selector.ts is allowed to hold the
 * reference); a rebinding OUTSIDE it is impossible without an import this
 * walk catches, because the only way to get `VeniceClient` into scope
 * under ANY name is an import, and every import shape funnels through
 * this same symbol resolution regardless of the local name chosen.
 *
 * Scoped to the class BINDING specifically (not "any import from
 * venice.ts/frontier.ts/the intelligence barrel"), since many files
 * legitimately import unrelated exports from those same modules (other
 * classes, capability constants, types); asserting "nobody else may
 * import ANYTHING from these modules" would fail on those unrelated,
 * harmless imports and prove nothing about hosted-client construction
 * capability. The precise property is "who can reference the CLASS," and
 * that is what this measures.
 *
 * Program-build cost: measured locally at ~1.1s for the ~985-file
 * `server/src` program+checker (well inside this suite's 30s default test
 * timeout, and consistent with `read-tool-mutation-reachability.test.ts`'s
 * existing, un-gated `ts.createProgram` precedent elsewhere in this same
 * directory) -- fast enough to run as an ordinary test, not behind a
 * separate slow-test lane. `cachedClientImportAnalysis` still memoizes it
 * once per process so the two tests that need it (VeniceClient's and
 * FrontierClient's) do not each pay the build twice.
 */
function analyzeClientImporters(): ClientImportAnalysis {
  if (cachedClientImportAnalysis) return cachedClientImportAnalysis;

  const configPath = ts.findConfigFile(srcRoot, ts.sys.fileExists, "tsconfig.json");
  expect(configPath, "could not locate server/tsconfig.json from srcRoot").toBeDefined();
  const configFile = ts.readConfigFile(configPath!, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(configFile.config, ts.sys, dirname(configPath!));
  const program = ts.createProgram(parsed.fileNames, { ...parsed.options, noEmit: true });
  const checker = program.getTypeChecker();

  function classSymbol(fileBaseName: string, className: string): ts.Symbol {
    const sourceFile = program.getSourceFiles().find((sf) => sf.fileName.endsWith(fileBaseName));
    expect(sourceFile, `program does not contain ${fileBaseName}`).toBeDefined();
    let found: ts.Symbol | undefined;
    const visit = (node: ts.Node): void => {
      if (found) return;
      if (ts.isClassDeclaration(node) && node.name?.text === className) {
        found = checker.getSymbolAtLocation(node.name);
        return;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile!);
    expect(found, `class ${className} not found in ${fileBaseName}`).toBeDefined();
    return found!;
  }

  // Follows the alias chain (import specifier -> re-export -> barrel ->
  // ... -> the real class declaration's own symbol) to its end, capped so
  // a pathological circular re-export cannot hang the test instead of
  // failing it.
  function resolveAlias(symbol: ts.Symbol): ts.Symbol {
    let current = symbol;
    for (let i = 0; i < 20 && (current.flags & ts.SymbolFlags.Alias) !== 0; i++) {
      const next = checker.getAliasedSymbol(current);
      if (next === current) break;
      current = next;
    }
    return current;
  }

  const veniceTarget = classSymbol("substrates/venice.ts", "VeniceClient");
  const frontierTarget = classSymbol("substrates/frontier.ts", "FrontierClient");
  const veniceImporters = new Set<string>();
  const frontierImporters = new Set<string>();

  const record = (resolved: ts.Symbol, sourceFile: ts.SourceFile) => {
    if (resolved === veniceTarget) veniceImporters.add(relativeSourcePath(sourceFile.fileName));
    if (resolved === frontierTarget) frontierImporters.add(relativeSourcePath(sourceFile.fileName));
  };

  for (const sourceFile of program.getSourceFiles()) {
    // First-party only: excludes lib.*.d.ts and anything under
    // node_modules that the program pulls in for type information.
    // `tsconfig.json`'s own `include`/`exclude` already restrict
    // `parsed.fileNames` to `src/**/*`; this is defense in depth against
    // `program.getSourceFiles()` (which also enumerates dependencies the
    // program needed to resolve types) rather than a load-bearing filter.
    if (sourceFile.isDeclarationFile) continue;
    if (!sourceFile.fileName.includes("/server/src/")) continue;
    for (const stmt of sourceFile.statements) {
      if (!ts.isImportDeclaration(stmt) || !stmt.importClause) continue;
      const clause = stmt.importClause;
      if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const el of clause.namedBindings.elements) {
          const symbol = checker.getSymbolAtLocation(el.name);
          if (symbol) record(resolveAlias(symbol), sourceFile);
        }
      } else if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
        // `import * as NS from "..."`: NS itself never resolves directly
        // to the class (it resolves to the MODULE's namespace symbol),
        // but `NS.VeniceClient` is a live path to it whenever the target
        // module's export list contains it -- including transitively,
        // through a barrel the namespace-imported module re-exports.
        const nsSymbol = checker.getSymbolAtLocation(clause.namedBindings.name);
        if (nsSymbol) {
          for (const exported of checker.getExportsOfModule(nsSymbol)) {
            record(resolveAlias(exported), sourceFile);
          }
        }
      }
      if (clause.name) {
        // Default import: VeniceClient/FrontierClient are never default
        // exports today, but this keeps the walk honest against that
        // changing later rather than silently having a blind spot.
        const symbol = checker.getSymbolAtLocation(clause.name);
        if (symbol) record(resolveAlias(symbol), sourceFile);
      }
    }
  }

  cachedClientImportAnalysis = {
    veniceImporters: [...veniceImporters].sort(),
    frontierImporters: [...frontierImporters].sort(),
  };
  return cachedClientImportAnalysis;
}

describe("local-only request-scoped constraint — structural chokepoints", () => {
  it("invoke() refuses a conflicting local-only request BEFORE getOrIssueHandle is ever called", async () => {
    const selector = await selectorSource();
    const body = sliceMethod(selector, "private async invoke(", "private recordRecentFailure(");

    const localOnlyCheck = body.indexOf("refusesLocalOnly(");
    const handleConstruction = body.indexOf("await this.getOrIssueHandle(");
    expect(localOnlyCheck).toBeGreaterThan(-1);
    expect(handleConstruction).toBeGreaterThan(-1);
    expect(localOnlyCheck).toBeLessThan(handleConstruction);
  });

  it("the local-only refusal branch returns a failureResponse naming local_only_violation before touching the request further", async () => {
    const selector = await selectorSource();
    const body = sliceMethod(selector, "private async invoke(", "private recordRecentFailure(");
    const guardStart = body.indexOf("refusesLocalOnly(");
    expect(guardStart).toBeGreaterThan(-1);
    // The refusal branch is the smallest `{ ... }` block opened by the
    // `if` this call sits inside; find the next `return failureResponse(`
    // after the guard and confirm it names the typed class within a
    // bounded window (the branch body), not merely somewhere later in the
    // method (which the OLD version of this test could not distinguish
    // from a much later, unrelated `local_only_violation` mention).
    const nextReturn = body.indexOf("return failureResponse(", guardStart);
    expect(nextReturn).toBeGreaterThan(guardStart);
    expect(nextReturn - guardStart).toBeLessThan(400); // same `if` block, not a later branch
    const branchWindow = body.slice(guardStart, nextReturn + 200);
    expect(branchWindow).toContain("local_only_violation");
  });

  // Item 5 (fix-round-4/5), generalized fix-round-6 (P2): ONE predicate,
  // every real enforcement site — not predicates that happen to agree, and
  // not a count a stray doc-comment mention can inflate.
  it("refusesLocalOnly is defined exactly once and has exactly four EXECUTABLE call sites (comment-stripped)", async () => {
    const selector = await selectorSource();
    const code = stripCodeComments(selector, "intelligence/selector.ts");
    expect(code.match(/function refusesLocalOnly\(/g)).toHaveLength(1);
    // Four call sites: invoke()'s pre-emptive check, guardDirectHandleCall's
    // held-handle check, getOrIssueHandle's defense-in-depth guard, and
    // tryNextSubstrate's fallback gate (fix-round-6, item that folded the
    // fallback path's separate `isLocalOnlyRequest` check into this one
    // authority too). A fifth site (or a dropped one) is a structural
    // regression this pins; comments are stripped first so a doc mention
    // of the call shape in prose cannot inflate or hide this count.
    expect(code.match(/refusesLocalOnly\(/g)).toHaveLength(5); // 1 definition + 4 calls

    const invokeBody = sliceMethod(code, "private async invoke(", "private recordRecentFailure(");
    expect(invokeBody).toContain("refusesLocalOnly(");
    expect(invokeBody).not.toMatch(/resolvedChoice !== "local"/);

    const guardBody = sliceMethod(code, "private async guardDirectHandleCall(", "private effectiveChoice(");
    expect(guardBody).toContain("refusesLocalOnly(");
    expect(guardBody).not.toMatch(/handleSubstrate === "local"/);

    const getOrIssueBody = sliceMethod(code, "private async getOrIssueHandle(", "private async issueHandle(");
    expect(getOrIssueBody).toContain("refusesLocalOnly(");
    expect(getOrIssueBody).not.toMatch(/opts\?\.localOnly && .*!== "local"/);

    // The fallback path: must use the shared predicate, and must NOT call
    // `isLocalOnlyRequest` directly as an alternate, unshared path to the
    // same conclusion (fix-round-6 P0 finding: it did, before this round).
    const fallbackBody = sliceMethod(code, "private async tryNextSubstrate(", "private async getOrIssueHandle(");
    expect(fallbackBody).toContain("refusesLocalOnly(");
    expect(fallbackBody).not.toMatch(/isLocalOnlyRequest\(/);
  });

  it("getOrIssueHandle refuses a conflicting local-only request BEFORE the issuedHandles cache lookup or issueHandle", async () => {
    const selector = await selectorSource();
    const body = sliceMethod(selector, "private async getOrIssueHandle(", "private async issueHandle(");

    const localOnlyGuard = body.indexOf("refusesLocalOnly(");
    const cacheLookup = body.indexOf("this.issuedHandles.get(key)");
    expect(localOnlyGuard).toBeGreaterThan(-1);
    expect(cacheLookup).toBeGreaterThan(-1);
    expect(localOnlyGuard).toBeLessThan(cacheLookup);
  });

  it("tryNextSubstrate checks the local-only constraint as its first statement, ahead of every other fallback gate, via the shared predicate", async () => {
    const selector = await selectorSource();
    const code = stripCodeComments(selector, "intelligence/selector.ts");
    const body = sliceMethod(code, "private async tryNextSubstrate(", "private async getOrIssueHandle(");

    const localOnlyGuard = body.indexOf("refusesLocalOnly(");
    const degradeSilentGuard = body.indexOf('this.config.fallback[surface] !== "degrade-silent"');
    expect(localOnlyGuard).toBeGreaterThan(-1);
    expect(degradeSilentGuard).toBeGreaterThan(-1);
    expect(localOnlyGuard).toBeLessThan(degradeSilentGuard);
    // Comment-stripped, so this proves the executable body itself never
    // calls `isLocalOnlyRequest` (the P0 finding: it did, reading
    // `req.localOnly` fresh after `invoke()`'s `invokeHandle` await,
    // instead of the caller's pre-await snapshot).
    expect(body).not.toMatch(/isLocalOnlyRequest\(/);
  });

  // P0 fix-round-8 (P2, item 3 of round 4's findings): this file
  // previously pinned "reads the flag as the literal first statement"
  // via a TEXTUAL regex match on the exact call shape
  // (`freezeLocalOnlyRequest(callerReq)`, etc.). That textual claim is
  // fragile in exactly the way a rename or a refactor (like round 8's own
  // subtraction, which replaced the whole copy-based approach with
  // `readLocalOnlyOnce`) breaks it without the underlying PROPERTY ever
  // having regressed -- a textual pin and a behavioral property are not
  // the same thing, and chasing the textual pin through every wording
  // change is churn this file should not carry. The single-read property
  // itself (the flag is read exactly once, at entry, regardless of
  // whether the source's `localOnly` is a plain value or a getter that
  // answers differently on each call) is proven BEHAVIORALLY instead, in
  // `test/intelligence/selector-local-only.test.ts`'s accessor-getter
  // tests (`invoke()` and each `chokepointHandle` method) and its
  // `getSubstrate()`-opts read-count test — a real getter, a real read
  // counter, a real assertion on the count, not a string match on the
  // implementation's own source text.

  it("the only file across ALL of server/src that can even REFERENCE the VeniceClient class (by any import shape, checker-resolved through every alias) is intelligence/selector.ts, and only one construction site within it is reachable from an invocation", async () => {
    // Import-restriction, not construction-site tracking (fix-round-9 P1:
    // both reviewers on round 4's construction inventory, which still
    // missed `const V = VeniceClient; new V()` — a local rebinding is
    // assignment-graph analysis, which no refinement of a construction
    // walk closes). See `analyzeClientImporters`'s own doc comment for
    // the full account and the measured build cost.
    const { veniceImporters } = analyzeClientImporters();
    expect(veniceImporters).toEqual(["intelligence/selector.ts"]);

    const selector = await selectorSource();
    // Two construction sites WITHIN selector.ts: the key-validation probe
    // (`setVeniceApiKey` -> `validateVeniceAndRecord`, an operator CONFIG
    // WRITE unrelated to any one request's localOnly flag) and the
    // invocation-path handle issuer (`veniceHandle`, reached only through
    // `issueHandle`, which the local-only guards gate). A local-only
    // request can only ever be safe from hosted-client construction if
    // the invocation path has exactly one such site.
    expect(selector.match(/new VeniceClient\(/g)).toHaveLength(2);
    const veniceHandleBody = sliceMethod(selector, "private veniceHandle(", "private frontierHandle(");
    expect(veniceHandleBody.match(/new VeniceClient\(/g)).toHaveLength(1);
  });

  it("the only file across ALL of server/src that can even REFERENCE the FrontierClient class (by any import shape, checker-resolved through every alias) is intelligence/selector.ts, reached only through the gated issuer", async () => {
    // Import-restriction, not construction-site tracking — see the
    // VeniceClient test above for why (identical reasoning applies to
    // FrontierClient).
    const { frontierImporters } = analyzeClientImporters();
    expect(frontierImporters).toEqual(["intelligence/selector.ts"]);

    const selector = await selectorSource();
    expect(selector.match(/new FrontierClient\(/g)).toHaveLength(1);
    const frontierHandleStart = selector.indexOf("private frontierHandle(");
    expect(frontierHandleStart).toBeGreaterThan(-1);
    expect(selector.indexOf("new FrontierClient(")).toBeGreaterThan(frontierHandleStart);
    const issueHandleBody = sliceMethod(selector, "private async issueHandle(", "private disabledHandle(");
    expect(issueHandleBody).toContain("this.frontierHandle(surface)");
    expect(selector.match(/\.frontierHandle\(/g)).toHaveLength(1);
  });

  // P0-1: `getSubstrate()` must never hand a caller a directly-invocable
  // raw provider handle. Structural proof that its returned methods are
  // guarded, complementing the behavioral proof in
  // `test/intelligence/selector-local-only.test.ts` ("a handle held from a
  // plain getSubstrate() call still refuses...").
  it("getSubstrate() wraps every issued handle through chokepointHandle(), whose bound methods guard-then-delegate to the raw handle, then normalize a local failure", async () => {
    const selector = await selectorSource();
    const getSubstrateBody = sliceMethod(selector, "async getSubstrate(", "private chokepointHandle(");
    expect(getSubstrateBody).toContain("this.chokepointHandle(surface, raw)");
    expect(getSubstrateBody).not.toMatch(/return raw;/);

    const wrapperBody = sliceMethod(selector, "private chokepointHandle(", "private async normalizeDirectHandleLocalFailure(");
    expect(wrapperBody).toContain("raw.summarize!(req)");
    expect(wrapperBody).toContain("raw.classify!(req)");
    expect(wrapperBody).toContain("raw.redact!(req)");
    // Every bound method calls the guard, by NAME (property, not the
    // exact argument list — fix-round-6 P2), exactly once, and calls the
    // normalizer, by name, exactly once.
    expect(wrapperBody.match(/this\.guardDirectHandleCall\(/g)).toHaveLength(3);
    expect(wrapperBody.match(/this\.normalizeDirectHandleLocalFailure\(/g)).toHaveLength(3);
    // P0 fix-round-8 (P2, item 3): `guardDirectHandleCall`'s THIRD
    // parameter is the already-read `localOnly` boolean, never the
    // request — the property check above (`this\.guardDirectHandleCall\(`
    // appearing exactly 3 times) plus `guardDirectHandleCall`'s own
    // declared parameter type below (checked structurally, not by a
    // textual "first statement" pin on the caller side, which round 7's
    // version of this test pinned and round 8's refactor broke without
    // the underlying property regressing) is what this file can durably
    // assert. The single-read behavioral property — an accessor whose
    // getter answers `true` once and `false` on every later read,
    // exercised at each of these three closures and at `invoke()` — lives
    // in `test/intelligence/selector-local-only.test.ts`, including a
    // class-backed request (prototype getters, non-enumerable) proving
    // this fix never copies/mangles the request the way round 7's did.
    const guardSignature = sliceMethod(selector, "private async guardDirectHandleCall(", "): Promise<SubstrateResponse | null> {");
    expect(guardSignature).toMatch(/localOnly:\s*boolean/);
    expect(guardSignature).not.toMatch(/req:\s*(SummarizeRequest|ClassifyRequest|RedactRequest|LocalOnlyRequest)/);

    const guardBody = sliceMethod(selector, "private async guardDirectHandleCall(", "private effectiveChoice(");
    expect(guardBody).not.toMatch(/raw\.(summarize|classify|redact)\(/);
    expect(guardBody).not.toContain("this.effectiveChoice(surface)");
    expect(guardBody).not.toContain("this.resolveConcreteChoice(surface, choice)");
    expect(guardBody).toContain("refusesLocalOnly(");
    expect(guardBody).toContain("local_only_violation");
  });

  // P1 fix-round-6: a directly held LOCAL handle's own generation failure
  // must be normalized the same way invoke()'s P2-4 normalization already
  // makes the invoke()-path read, with an audit event, not returned as the
  // raw substrate's own unaudited failure class.
  it("normalizeDirectHandleLocalFailure rewrites a genuine local failure to local_only_violation/local_unavailable with an audit attempt, but never re-normalizes an already-refused response", async () => {
    const selector = await selectorSource();
    const body = sliceMethod(selector, "private async normalizeDirectHandleLocalFailure(", "\n  }\n");
    expect(body).toContain("local_unavailable");
    expect(body).toContain("this.auditLocalOnlyRefusal(");
    // Skips a response that is ALREADY a local_only_violation refusal
    // (from guardDirectHandleCall) so it cannot overwrite a
    // binding_conflict reason with local_unavailable.
    expect(body).toContain('response.failureClass === "local_only_violation"');
  });

  // P1 fix-round-6, item 3 (subtraction, not durability): the audit
  // helper ATTEMPTS an audit event and reports a failed attempt, rather
  // than claiming every refusal WRITES one unconditionally.
  it("auditLocalOnlyRefusal reports a failed audit attempt instead of silently swallowing it", async () => {
    const selector = await selectorSource();
    const body = sliceMethod(selector, "private async auditLocalOnlyRefusal(", "\n  }\n");
    expect(body).toContain("catch (error)");
    expect(body).toContain("process.stderr.write(");
    expect(body).toMatch(/return\s*\{\s*recorded:\s*false/);
    expect(body).toMatch(/return\s*\{\s*recorded:\s*true\s*\}/);
    // The narrowed claim reaches the doc, the old absolute one does not.
    const docStart = selector.lastIndexOf("/**", selector.indexOf("private async auditLocalOnlyRefusal("));
    const doc = selector.slice(docStart, selector.indexOf("private async auditLocalOnlyRefusal("));
    expect(doc).toContain("ATTEMPTS an audit event");
    expect(doc).not.toMatch(/writes exactly one audit row/);
  });
});
