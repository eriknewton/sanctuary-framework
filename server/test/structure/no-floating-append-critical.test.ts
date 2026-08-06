import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import ts from "typescript";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const SRC_ROOT = join(ROOT, "src");

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...sourceFiles(full));
    } else if (entry.endsWith(".ts")) {
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
  return undefined;
}

function isAppendCriticalCall(node: ts.Node): node is ts.CallExpression {
  return ts.isCallExpression(node) && propertyName(node.expression) === "appendCritical";
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

function isConsumed(call: ts.CallExpression): boolean {
  let current: ts.Node = call;
  for (let parent = call.parent; parent !== undefined; parent = parent.parent) {
    if (ts.isAwaitExpression(parent)) return true;
    if (ts.isReturnStatement(parent) && parent.expression !== undefined) return true;
    if (ts.isArrowFunction(parent)) return parent.body === current;
    if (ts.isExpressionStatement(parent)) return false;
    if (isFunctionBoundary(parent)) return false;
    current = parent;
  }
  return false;
}

function findFloatingAppendCritical(file: string): string[] {
  const text = readFileSync(file, "utf8");
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.ESNext, true);
  const hits: string[] = [];

  const visit = (node: ts.Node): void => {
    if (isAppendCriticalCall(node) && !isConsumed(node)) {
      const { line, character } = source.getLineAndCharacterOfPosition(node.getStart(source));
      hits.push(`${relative(ROOT, file)}:${line + 1}:${character + 1}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return hits;
}

describe("appendCritical promise discipline", () => {
  it("does not allow floating appendCritical calls in src", () => {
    const hits = sourceFiles(SRC_ROOT).flatMap(findFloatingAppendCritical);

    expect(hits).toEqual([]);
  });
});
