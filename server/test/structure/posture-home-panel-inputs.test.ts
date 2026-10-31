/** Panel inputs and audit readers stay explicit across the complete producer table. */
import { expect, it } from "vitest";
import ts from "typescript";
import { readFileSync } from "node:fs";
import { AUDIT_READING_HOME_PANELS } from "../../src/principal-policy/posture-routes.js";
import { POSTURE_PANEL_IDS } from "../../src/principal-policy/panel-producer.js";
it("every store read supplies its input key", () => {
  const source = readFileSync("src/principal-policy/posture-routes.ts", "utf8");
  const ast = ts.createSourceFile("posture-routes.ts", source, ts.ScriptTarget.Latest, true);
  const ids: string[] = [];
  function visit(node: ts.Node) {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "read") {
      expect(node.arguments).toHaveLength(4);
      expect(node.arguments[3].getText(ast)).not.toBe("undefined");
      ids.push((node.arguments[0] as ts.StringLiteral).text);
    }
    ts.forEachChild(node, visit);
  }
  visit(ast);
  expect(ids.sort()).toEqual([...POSTURE_PANEL_IDS].sort());
});

/** Resolve local helpers by argument position; unknown log escapes fail the inventory closed. */
function deriveAuditReaders(source: string): string[] {
  const ast = ts.createSourceFile("posture-routes.ts", source, ts.ScriptTarget.Latest, true);
  const functions = new Map<string, ts.FunctionDeclaration>();
  ast.forEachChild(node => { if (ts.isFunctionDeclaration(node) && node.name) functions.set(node.name.text, node); });
  type Input = "log" | "deps" | undefined;
  function unwrap(node: ts.Node): ts.Node {
    while (ts.isAsExpression(node) || ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node)) node = node.expression;
    return node;
  }
  function readsAudit(name: string, inputs: Input[], seen = new Set<string>()): boolean {
    const fn = functions.get(name);
    if (!fn?.body) throw new Error("Unresolved producer/helper: " + name);
    const key = name + JSON.stringify(inputs);
    if (seen.has(key)) return false;
    seen.add(key);
    // Defaults and binding patterns can introduce aliases before the visited body.
    if (fn.parameters.some(parameter => parameter.initializer || parameter.dotDotDotToken || !ts.isIdentifier(parameter.name)))
      throw new Error("Unmodelled audit parameter: " + name);
    const bindings = new Map<string, Input>();
    inputs.forEach((kind, index) => {
      if (!kind) return;
      const parameter = fn.parameters[index];
      if (!parameter || !ts.isIdentifier(parameter.name)) throw new Error("Unmodelled audit parameter: " + name);
      bindings.set(parameter.name.text, kind);
    });
    function kind(node: ts.Node): Input {
      node = unwrap(node);
      if (ts.isIdentifier(node)) return bindings.get(node.text);
      if (ts.isPropertyAccessExpression(node) && node.name.text === "auditLog" && kind(node.expression) === "deps") return "log";
      return undefined;
    }
    let reads = false;
    function visit(node: ts.Node) {
      if (kind(node) === "log" && unwrap(node.parent) !== node) {
        // Inspect the outermost cast/parenthesis once, so no recognized use silently falls through.
        let use = node;
        while (ts.isAsExpression(use.parent) || ts.isParenthesizedExpression(use.parent) || ts.isNonNullExpression(use.parent)) use = use.parent;
        const parent = use.parent;
        if (ts.isPropertyAccessExpression(parent) && parent.expression === use) {
          if (!ts.isCallExpression(parent.parent) || parent.parent.expression !== parent) throw new Error("Unmodelled audit method reference: " + parent.getText(ast));
          if (!["append", "appendCritical"].includes(parent.name.text)) reads = true;
        } else if (ts.isCallExpression(parent) && parent.arguments.includes(use as ts.Expression)) {
          if (!ts.isIdentifier(parent.expression)) throw new Error("Unmodelled audit argument call: " + parent.getText(ast));
          // Non-local readers are conservatively counted; their internal semantics are not followed.
          if (!functions.has(parent.expression.text)) reads = true;
        } else if (ts.isPropertyAssignment(parent) && parent.initializer === use && ts.isObjectLiteralExpression(parent.parent) && ts.isCallExpression(parent.parent.parent)) {
          const call = parent.parent.parent;
          if (!ts.isIdentifier(call.expression) || functions.has(call.expression.text)) throw new Error("Unmodelled audit object argument: " + call.getText(ast));
          reads = true;
        } else if (ts.isPrefixUnaryExpression(parent) && parent.operator === ts.SyntaxKind.ExclamationToken) {
          // Presence checks do not read the log.
        } else throw new Error("Unmodelled audit use: " + parent.getText(ast));
      }
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && functions.has(node.expression.text)) {
        reads = readsAudit(node.expression.text, node.arguments.map(kind), seen) || reads;
      }
      // Passing a deps container through an unmodelled shape could hide its log.
      if (ts.isIdentifier(node) && kind(node) === "deps") {
        const parent = node.parent;
        const recognized = ts.isPropertyAccessExpression(parent) && parent.expression === node ||
          ts.isCallExpression(parent) && ts.isIdentifier(parent.expression) && functions.has(parent.expression.text) && parent.arguments.includes(node);
        if (!recognized) throw new Error("Unmodelled deps use: " + parent.getText(ast));
      }
      ts.forEachChild(node, visit);
    }
    visit(fn.body);
    return reads;
  }
  // These independent callbacks do not receive the log. Their exact shapes are checked, not skipped by id.
  const independent: Record<string, string> = {
    agents_roster: "deps.listAgents()",
    exclusive_egress: "deps.exclusiveEgressPosture?.() ?? null",
    protection_subject: "deps.resolveProtectionClaimSubject?.() ?? null",
    enforcement_availability: "deps.resolveEnforcementAvailability ? deps.resolveEnforcementAvailability() : resolveEnforcementAvailability(deps)",
    vault_provision_claim: "deps.resolveVaultProvisionClaimed?.() ?? false",
  };
  const expected: string[] = [];
  function visit(node: ts.Node) {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === "read") {
      // Every read call is either modelled through the store or rejected, never silently skipped.
      const receiver = unwrap(node.expression.expression);
      if (!ts.isIdentifier(receiver) || receiver.text !== "store") throw new Error("Unmodelled store receiver");
      const [id, , producer] = node.arguments;
      if (!ts.isStringLiteral(id) || !ts.isArrowFunction(producer)) throw new Error("Unmodelled store producer");
      const panelId = id.text;
      const body = producer.body;
      if (ts.isCallExpression(body) && ts.isIdentifier(body.expression)) {
        const inputs = body.arguments.map(argument => {
          const value = unwrap(argument).getText(ast);
          if (["deps", "snapshotDeps"].includes(value)) return "deps" as const;
          if (["deps.auditLog", "snapshotDeps.auditLog"].includes(value)) return "log" as const;
          if (["exclusiveValue", "subjectValue", "availabilityValue", "records", "featureHealth"].includes(value)) return undefined;
          throw new Error("Unmodelled producer argument: " + value);
        });
        if (readsAudit(body.expression.text, inputs)) expected.push(panelId);
      } else if (independent[id.text] !== body.getText(ast).replace(/\s+/g, " ")) {
        throw new Error("Unmodelled store producer: " + id.text);
      } else {
        function inspectFallback(node: ts.Node) {
          if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
            if (node.arguments.length !== 1 || node.arguments[0].getText(ast) !== "deps") throw new Error("Unmodelled resolver fallback");
            if (readsAudit(node.expression.text, ["deps"])) expected.push(panelId);
          }
          ts.forEachChild(node, inspectFallback);
        }
        inspectFallback(body);
      }
    }
    ts.forEachChild(node, visit);
  }
  const home = functions.get("buildHome");
  if (!home?.body) throw new Error("Missing buildHome");
  visit(home.body);
  expect(expected.length).toBeGreaterThan(0);
  return expected.sort();
}

it("derives the full audit-reader set from the home producer bodies", () => {
  expect([...AUDIT_READING_HOME_PANELS].sort()).toEqual(deriveAuditReaders(readFileSync("src/principal-policy/posture-routes.ts", "utf8")));
});

it("follows renamed local producers and bare log parameters and rejects unknown shapes", () => {
  const source = (body: string, helper: string) => `function buildHome() { store.read("custody_exit", 0, () => custodyFrom(deps), ""); } function custodyFrom(deps) { ${body} } ${helper}`;
  expect(deriveAuditReaders(source("return inspect(deps.auditLog);", "function inspect(log) { return deeper(log); } function deeper(renamed) { return renamed.query(); }"))).toEqual(["custody_exit"]);
  expect(() => deriveAuditReaders('function buildHome() { store.read("digest", 0, () => unresolved(deps), ""); }')).toThrow("Unresolved producer/helper");
  expect(() => deriveAuditReaders(source("return deps.auditLog.query();", "").replace("custodyFrom(deps)", "custodyFrom({ ...deps })"))).toThrow("Unmodelled producer argument");
  expect(deriveAuditReaders('function buildHome() { store.read("digest", 0, () => inspect(deps.auditLog), ""); } function inspect(log) { return log.query(); }')).toEqual(["digest"]);
  expect(() => deriveAuditReaders(source("const saved = deps.auditLog; return saved.query();", ""))).toThrow("Unmodelled audit use");
  expect(() => deriveAuditReaders(source("return unknown.inspect(deps.auditLog);", ""))).toThrow("Unmodelled audit argument call");
  const appendOnly = source("return inspect(deps.auditLog);", "function inspect(log) { return log.append(); }");
  // Keep one actual reader so the non-empty guard does not mask append-only classification.
  const withReader = appendOnly.replace('function buildHome() {', 'function buildHome() { store.read("digest", 0, () => readDigest(deps), "");') + ' function readDigest(deps) { return deps.auditLog.query(); }';
  expect(deriveAuditReaders(withReader)).toEqual(["digest"]);
});


it("rejects parameter aliases and normalizes store receivers with another reader present", () => {
  const source = (call: string, helper: string) => `function buildHome() {
    store.read("digest", 0, () => digestFrom(deps), "");
    ${call}.read("custody_exit", 0, () => inspect(deps.auditLog), "");
  } function digestFrom(deps) { return deps.auditLog.query(); } ${helper}`;
  expect.soft(() => deriveAuditReaders(source("store", "function inspect(log, alias = log) { return alias.query(); }"))).toThrow("Unmodelled audit parameter");
  for (const receiver of ["(store)", "(store as Store)", "store!"]) {
    expect.soft(deriveAuditReaders(source(receiver, "function inspect(log) { return log.query(); }")), receiver).toEqual(["custody_exit", "digest"]);
  }
  expect.soft(() => deriveAuditReaders(source("other", "function inspect(log) { return log.query(); }"))).toThrow("Unmodelled store receiver");
  for (const parameters of ["{ query }", "...log", "log, alias = log"]) {
    expect.soft(() => deriveAuditReaders(source("store", `function inspect(${parameters}) { return 0; }`))).toThrow("Unmodelled audit parameter");
  }
});
