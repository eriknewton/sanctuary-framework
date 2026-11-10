/** Every production recorder construction must use the audit count and recovery event source. */
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";
import { expect, it } from "vitest";

const sourceRoot = join(__dirname, "../../src");
function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : entry.name.endsWith(".ts") ? [path] : [];
  });
}
function descendants(node: ts.Node): ts.Node[] {
  const result: ts.Node[] = [node];
  ts.forEachChild(node, child => { result.push(...descendants(child)); });
  return result;
}

function inspectSource(path: string, text: string) {
  const file = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true);
  const host = ts.createCompilerHost({ noLib: true });
  host.getSourceFile = name => name === path ? file : undefined;
  const checker = ts.createProgram([path], { noLib: true, noResolve: true }, host).getTypeChecker();
  const nodes = descendants(file);
  const calls = nodes.filter(ts.isCallExpression);
  const names = new Set(["LivenessRecorder"]);
  for (const node of nodes) {
    if (ts.isImportSpecifier(node) && (node.propertyName ?? node.name).text === "LivenessRecorder") names.add(node.name.text);
  }
  const sameSymbol = (a: ts.Node, b: ts.Node) => {
    const symbol = checker.getSymbolAtLocation(a);
    return symbol !== undefined && symbol === checker.getSymbolAtLocation(b);
  };
  const callsMethod = (node: ts.Node, name: string) => descendants(node).some(child =>
    ts.isCallExpression(child) && ts.isPropertyAccessExpression(child.expression) && child.expression.name.text === name);

  function reachesSubscription(node: ts.Node, seen = new Set<ts.Node>()): boolean {
    if (seen.has(node)) return false;
    seen.add(node);
    if (callsMethod(node, "onWriteLockRecovery")) return true;
    if (ts.isIdentifier(node)) {
      for (const declaration of checker.getSymbolAtLocation(node)?.declarations ?? []) {
        if (ts.isVariableDeclaration(declaration) && declaration.initializer && reachesSubscription(declaration.initializer, seen)) return true;
        if (ts.isParameter(declaration) && ts.isFunctionDeclaration(declaration.parent) && declaration.parent.name) {
          const owner = declaration.parent;
          const index = owner.parameters.indexOf(declaration);
          const argumentsAtCalls = calls.filter(call => sameSymbol(call.expression, owner.name!)).map(call => call.arguments[index]);
          if (argumentsAtCalls.length > 0 && argumentsAtCalls.every(arg => arg && reachesSubscription(arg, new Set(seen)))) return true;
        }
      }
    }
    // Follow the nullable sink installed by subscribe to the single registered daemon callback that invokes it.
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      const listener = node.parameters[0]?.name;
      for (const assignment of descendants(node).filter(ts.isBinaryExpression)) {
        if (!listener || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken || !sameSymbol(assignment.right, listener)) continue;
        const registrations = calls.filter(call => ts.isPropertyAccessExpression(call.expression) &&
          call.expression.name.text === "onWriteLockRecovery" && call.arguments.some(callback =>
            descendants(callback).some(child => ts.isCallExpression(child) && sameSymbol(child.expression, assignment.left))));
        if (registrations.length === 1) return true;
      }
    }
    return false;
  }

  const constructions = nodes.filter((node): node is ts.NewExpression | ts.CallExpression =>
    (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
    (names.has(node.expression.getText(file)) ||
      (ts.isPropertyAccessExpression(node.expression) && names.has(node.expression.name.text))));
  const errors: string[] = [];
  for (const construction of constructions) {
    const options = construction.arguments?.[0];
    const source = options && ts.isObjectLiteralExpression(options)
      ? options.properties.find(property => property.name?.getText(file) === "lockRecovery") : undefined;
    const recovery = source && ts.isPropertyAssignment(source) && ts.isObjectLiteralExpression(source.initializer) ? source.initializer : undefined;
    const property = (name: string) => recovery?.properties.find(member => member.name?.getText(file) === name);
    const count = property("count");
    const subscribe = property("subscribe");
    // Presence alone accepts fabricated healthy evidence; require the actual count and event paths at every construction.
    if (!count || !ts.isPropertyAssignment(count) || !callsMethod(count.initializer, "getWriteLockRecoveryCount")) errors.push("count source");
    if (!subscribe || !ts.isPropertyAssignment(subscribe) || !reachesSubscription(subscribe.initializer)) errors.push("subscription source");
  }
  const requiredSource = nodes.some(node => ts.isInterfaceDeclaration(node) && node.name.text === "LivenessRecorderOptions" &&
    node.members.some(member => ts.isPropertySignature(member) && member.name.getText(file) === "lockRecovery" && !member.questionToken));
  return { count: constructions.length, errors, requiredSource };
}

it("requires the real lock source in the recorder type and every production construction", () => {
  let constructions = 0;
  let requiredSource = false;
  for (const path of sourceFiles(sourceRoot)) {
    const text = readFileSync(path, "utf8");
    if (!text.includes("LivenessRecorder")) continue;
    const result = inspectSource(path, text);
    expect(result.errors, relative(sourceRoot, path)).toEqual([]);
    constructions += result.count;
    requiredSource ||= result.requiredSource;
  }
  expect(requiredSource, "lockRecovery must be required at the type boundary").toBe(true);
  expect(constructions, "the production recorder constructor must remain reachable").toBeGreaterThan(0);
});

const constructionForms = ["new LivenessRecorder", "LivenessRecorder", "new recorder.LivenessRecorder", "recorder.LivenessRecorder", "new Renamed"];
it.each(constructionForms)("rejects fabricated recovery evidence in %s", construct => {
  const result = inspectSource("fixture.ts", `
    import { LivenessRecorder as Renamed } from './recorder';
    import * as recorder from './recorder';
    ${construct}({ lockRecovery: { count: 0, lastAtMs: null, subscribe: () => undefined } });
  `);
  expect(result.count).toBe(1);
  expect(result.errors).toEqual(["count source", "subscription source"]);
});
it.each(constructionForms)("accepts direct audit recovery evidence in %s", construct => {
  const result = inspectSource("fixture.ts", `
    import { LivenessRecorder as Renamed } from './recorder';
    import * as recorder from './recorder';
    ${construct}({ lockRecovery: { count: audit.getWriteLockRecoveryCount(), lastAtMs: null,
      subscribe: listener => audit.onWriteLockRecovery(listener) } });
  `);
  expect(result.count).toBe(1);
  expect(result.errors).toEqual([]);
});
