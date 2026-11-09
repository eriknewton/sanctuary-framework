import ts from 'typescript';
import { digest } from './policy.mjs';

function syntaxTokens(node, source) {
  const result = [];
  function visit(child) {
    // The parser, not a context-free scanner, distinguishes regex/template data from comments.
    if (child.kind >= ts.SyntaxKind.FirstJSDocNode && child.kind <= ts.SyntaxKind.LastJSDocNode) return;
    const children = child.getChildren(source);
    if (children.length) children.forEach(visit);
    else if (child.kind !== ts.SyntaxKind.EndOfFileToken && child.end > child.getStart(source)) {
      result.push(child);
    }
  }
  visit(node);
  return result;
}

export function fingerprint(source, message, repositoryPath) {
  // ESLint locations are one-based; compiler offsets and token positions are zero-based.
  const offset = source.getPositionOfLineAndCharacter(message.line - 1, message.column - 1);
  let leaf = source;
  function visit(node) {
    if (node.getStart(source) <= offset && offset < node.end) {
      leaf = node;
      ts.forEachChild(node, visit);
    }
  }
  visit(source);
  let statement = leaf;
  while (statement.parent && !ts.isStatement(statement)) statement = statement.parent;
  const normalize = node => syntaxTokens(node, source).map(token => [token.kind, token.getText(source)]);
  const context = [];
  for (let node = leaf.parent; node && node !== source; node = node.parent) {
    if (node.name) context.push(['named', ts.SyntaxKind[node.kind], normalize(node.name)]);
    if (ts.isIfStatement(node) || ts.isConditionalExpression(node)) {
      context.push(['branch', normalize(node.expression ?? node.condition),
        offset < (node.thenStatement ?? node.whenTrue).end ? 'then' : 'else']);
    }
    if (ts.isCaseClause(node)) context.push(['case', normalize(node.expression)]);
    if (ts.isCallExpression(node)) {
      context.push(['call', normalize(node.expression), node.arguments.map(arg =>
        ts.isArrowFunction(arg) || ts.isFunctionExpression(arg) ? ['callback'] : normalize(arg))]);
    }
  }
  // Must match preimage validation in run.mjs: statement, context and token position are mandatory.
  const preimage = JSON.stringify({
    context: context.reverse(), statement: normalize(statement),
    tokenPosition: syntaxTokens(statement, source).filter(token => token.getStart(source) < offset).length,
  });
  return {
    path: repositoryPath, rule: message.ruleId, kind: message.messageId,
    fingerprint: digest(preimage), preimage,
  };
}

export function key(entry) {
  return JSON.stringify([entry.rule, entry.path, entry.kind, entry.fingerprint]);
}
