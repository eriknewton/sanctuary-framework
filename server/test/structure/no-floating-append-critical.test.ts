import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import ts from "typescript";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const TS_ROOTS = [dirname(ROOT)];
const GENERATED_DIRECTORIES = new Set(["node_modules", "dist", ".git"]);
const CRITICAL_METHODS = new Set(["appendCritical", "appendCriticalWithReceipt", "sealThrough"]);

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (GENERATED_DIRECTORIES.has(entry)) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...sourceFiles(full));
    } else if (/\.tsx?$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

function propertyName(node: ts.Expression): string | undefined {
  if (
    ts.isPropertyAccessExpression(node) ||
    ts.isPropertyAccessChain(node)
  ) {
    return node.name.text;
  }
  if (ts.isElementAccessExpression(node) && node.argumentExpression &&
      (ts.isStringLiteral(node.argumentExpression) || ts.isNoSubstitutionTemplateLiteral(node.argumentExpression))) {
    return node.argumentExpression.text;
  }
  return undefined;
}

function isAppendCriticalCall(node: ts.Node): node is ts.CallExpression {
  return ts.isCallExpression(node) && CRITICAL_METHODS.has(propertyName(node.expression) ?? "");
}

function isFunctionBoundary(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

function isOwnedLocal(name: string, declaration: ts.Node): boolean {
  let scope = declaration.parent;
  while (scope.parent && !isFunctionBoundary(scope) && !ts.isArrowFunction(scope)) scope = scope.parent;
  const names = new Set([name]);
  const contains = (node: ts.Node): boolean => {
    if (isFunctionBoundary(node) || ts.isArrowFunction(node) || ts.isVoidExpression(node)) return false;
    return (ts.isIdentifier(node) && names.has(node.text)) || ts.forEachChild(node, contains) === true;
  };
  let owned = false;
  let grew = true;
  while (grew && !owned) {
    const size = names.size;
    const visit = (node: ts.Node): void => {
      if (node !== scope && (isFunctionBoundary(node) || ts.isArrowFunction(node))) return;
      if ((ts.isAwaitExpression(node) || ts.isReturnStatement(node)) && node.expression && contains(node.expression)) owned = true;
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && contains(node.initializer)) names.add(node.name.text);
      ts.forEachChild(node, visit);
    };
    visit(scope);
    grew = names.size > size;
  }
  return owned;
}

function isConsumed(call: ts.CallExpression): boolean {
  let current: ts.Node = call;
  for (let parent = call.parent; parent !== undefined; parent = parent.parent) {
    // A void expression discards ownership even when an outer expression is awaited.
    if (ts.isVoidExpression(parent)) return false;
    if (ts.isAwaitExpression(parent)) return true;
    if (ts.isReturnStatement(parent) && parent.expression !== undefined) return true;
    // An outer await cannot own work abandoned inside a block callback.
    if (ts.isArrowFunction(parent)) {
      const caller = parent.parent;
      const callee = ts.isCallExpression(caller) ? caller.expression : undefined;
      const name = callee && (ts.isIdentifier(callee) ? callee.text : propertyName(callee));
      // Timer and iteration callbacks discard an expression arrow's returned promise.
      if (name && ["setTimeout", "setInterval", "queueMicrotask", "forEach"].includes(name)) return false;
      return parent.body === current;
    }
    // Local promises retained for scheduling still need an await or return in the same function.
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return isOwnedLocal(parent.name.text, parent);
    if (ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(parent.left)) return isOwnedLocal(parent.left.text, parent);
    if (ts.isExpressionStatement(parent)) return false;
    if (isFunctionBoundary(parent)) return false;
    current = parent;
  }
  return false;
}

function findFloatingAppendCritical(file: string, text = readFileSync(file, "utf8")): string[] {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.ESNext, true, file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const hits: string[] = [];

  const visit = (node: ts.Node): void => {
    const callbackCallee = node.parent && ts.isCallExpression(node.parent) ? node.parent.expression : undefined;
    const callbackName = callbackCallee && (ts.isIdentifier(callbackCallee) ? callbackCallee.text : propertyName(callbackCallee));
    const detached = (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) &&
      CRITICAL_METHODS.has(propertyName(node) ?? "") && ts.isCallExpression(node.parent) && node.parent.arguments.includes(node) &&
      callbackName !== undefined && ["then", "catch", "finally", "setTimeout", "setInterval", "queueMicrotask", "forEach", "map", "flatMap", "on", "once"].includes(callbackName);
    if (detached || (isAppendCriticalCall(node) && !isConsumed(node))) {
      const { line, character } = source.getLineAndCharacterOfPosition(node.getStart(source));
      hits.push(`${relative(ROOT, file)}:${line + 1}:${character + 1}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return hits;
}

describe("critical audit promise discipline", () => {
  it("does not allow floating critical audit calls across TypeScript", () => {
    const hits = TS_ROOTS.flatMap(sourceFiles).flatMap((file) => findFloatingAppendCritical(file));

    expect(hits).toEqual([]);
  });
});

// Must match CRITICAL_METHODS above; literal fixtures detect a missing recognized method.
for (const method of ["appendCritical", "appendCriticalWithReceipt", "sealThrough"]) {
  describe(`${method} parser ownership`, () => {
    const accesses = [`log.${method}`, `log["${method}"]`, `log?.${method}`, `log?.["${method}"]`, `log[\`${method}\`]`];
    for (const access of accesses) {
      it(`refuses bare, void and detached block calls through ${access}`, () => {
        for (const text of [
          `${access}(input);`,
          `void ${access}(input);`,
          `await (void ${access}(input));`,
          `await outer(() => { ${access}(input); });`,
          `await outer(function () { ${access}(input); });`,
          `${access}?.(input);`,
          `setTimeout(() => ${access}(input));`,
          `items.forEach(() => ${access}(input));`,
          `await promise.then(${access});`,
        ]) expect(findFloatingAppendCritical("fixture.ts", text), text).toHaveLength(1);
      });
      it(`accepts awaited or returned calls through ${access}`, () => {
        for (const text of [
          `await ${access}(input);`,
          `async function own() { return ${access}(input); }`,
          `const own = () => ${access}(input);`,
          `const own = async () => { await ${access}(input); };`,
          `const own = () => { return ${access}(input); };`,
          `await ${access}?.(input);`,
        ]) expect(findFloatingAppendCritical("fixture.ts", text), text).toEqual([]);
      });
    }
  });
}
