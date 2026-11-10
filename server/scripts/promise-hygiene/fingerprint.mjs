import ts from 'typescript';
import { digest } from './policy.mjs';

function syntaxTokens(node, source) {
  const result = [];
  function visit(child) {
    // The parser distinguishes regex/template data from comments.
    if (child.kind >= ts.SyntaxKind.FirstJSDocNode && child.kind <= ts.SyntaxKind.LastJSDocNode) return;
    const children = child.getChildren(source);
    if (children.length) children.forEach(visit);
    else if (child.kind !== ts.SyntaxKind.EndOfFileToken && child.end > child.getStart(source)) result.push(child);
  }
  visit(node);
  return result;
}
const functionLike = node => ts.isArrowFunction(node) || ts.isFunctionExpression(node);
const invocation = node => ts.isCallExpression(node) || ts.isNewExpression(node);
function unparenthesize(node) {
  while (ts.isParenthesizedExpression(node)) node = node.expression;
  return node;
}

export function fingerprint(source, message, repositoryPath) {
  // ESLint locations are one-based; compiler offsets and token positions are zero-based.
  const offset = source.getPositionOfLineAndCharacter(message.line - 1, message.column - 1);
  const end = message.endLine == null ? undefined
    : source.getPositionOfLineAndCharacter(message.endLine - 1, message.endColumn - 1);
  let leaf = source;
  let callback;
  function visit(node) {
    if (node.getStart(source) <= offset && offset < node.end) {
      leaf = node;
      // Only the diagnostic node itself gets body-free reduction, never a proper descendant.
      if (functionLike(node) && node.getStart(source) === offset && node.end === end
        && invocation(node.parent) && node.parent.arguments?.includes(node)) callback = node;
      ts.forEachChild(node, visit);
    }
  }
  visit(source);
  const normalize = node => syntaxTokens(node, source).map(token => [ts.SyntaxKind[token.kind], token.getText(source)]);
  const callHead = node => [ts.isNewExpression(node) ? 'new' : 'call',
    functionLike(unparenthesize(node.expression)) ? ['iife'] : normalize(node.expression),
    (node.arguments ?? []).map(arg => functionLike(unparenthesize(arg)) ? ['callback'] : normalize(arg))];
  const holds = node => node && node.getStart(source) <= offset && offset < node.end;
  let statement = leaf;
  while (statement.parent && !ts.isStatement(statement)) statement = statement.parent;
  let role = 'statement';
  // A control statement owns only its diagnostic-bearing clause, never sibling bodies or fields.
  for (let node = leaf; node && node !== source; node = node.parent) {
    let clauses = [];
    if (ts.isCaseClause(node)) clauses = [['case-test', node.expression]];
    else if (ts.isPropertyDeclaration(node)) clauses = [['field-initializer', node.initializer]];
    else if (ts.isIfStatement(node) || ts.isWhileStatement(node) || ts.isDoStatement(node)) clauses = [['condition', node.expression]];
    else if (ts.isForStatement(node)) clauses = [['initializer', node.initializer], ['condition', node.condition], ['increment', node.incrementor]];
    else if (ts.isForOfStatement(node) || ts.isForInStatement(node)) clauses = [[ts.isForInStatement(node) ? 'for-in-expression' : node.awaitModifier ? 'for-await-expression' : 'for-of-expression', node.expression], ['initializer', node.initializer]];
    else if (ts.isSwitchStatement(node)) clauses = [['discriminant', node.expression]];
    const clause = clauses.find(([, value]) => holds(value));
    if (clause) { [role, statement] = clause; break; }
    if (ts.isStatement(node)) break;
  }
  const context = [];
  for (let node = leaf.parent; node && node !== source; node = node.parent) {
    if (node.name) context.push(['named', ts.SyntaxKind[node.kind], normalize(node.name)]);
    if (ts.isIfStatement(node) || ts.isConditionalExpression(node)) {
      const condition = node.expression ?? node.condition;
      context.push(['branch', normalize(condition), holds(condition) ? 'condition'
        : holds(node.thenStatement ?? node.whenTrue) ? 'then' : 'else']);
    }
    if (ts.isCaseClause(node)) context.push(['case', normalize(node.expression)]);
    if (invocation(node)) context.push(callHead(node));
  }
  // Must match preimage validation in run.mjs: context, statement and relative token position.
  const preimage = JSON.stringify({
    context: context.reverse(),
    statement: callback ? ['callback-argument', callHead(callback.parent),
      callback.parent.arguments.indexOf(callback), callback.parameters.map(normalize),
      callback.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.AsyncKeyword) ?? false]
      : [role, normalize(statement)],
    tokenPosition: callback ? 0 : syntaxTokens(statement, source).filter(token => token.getStart(source) < offset).length,
  });
  return { path: repositoryPath, rule: message.ruleId, kind: message.messageId, fingerprint: digest(preimage), preimage };
}

export function key(entry) {
  return JSON.stringify([entry.rule, entry.path, entry.kind, entry.fingerprint]);
}
