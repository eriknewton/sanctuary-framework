/**
 * Test-port-discipline regression gate.
 *
 * Scans `server/test/` for three anti-pattern classes:
 *
 *   Sigma-6 detection: `.listen(...)` calls in test files. Each must be
 *   either:
 *     1. Ephemeral: `.listen(0, ...)` (OS-assigned port).
 *     2. Wrapped in `bindWithRetry` (the established retry-on-
 *        EADDRINUSE helper at `server/test/util/port-collision-retry.ts`).
 *     3. Whitelisted with an inline `// port-discipline: ignore` comment
 *        (with a brief reason).
 *
 *   Sigma-7 detection: locally-declared `randomPort` helpers. The
 *   Omega-1 CI flake on `test/dashboard/api.test.ts` exposed a class
 *   of port-binding test that Sigma-6 missed: the test passes a
 *   randomly-allocated port into a constructor or factory (e.g.
 *   `startDashboardServer({ port: randomPort() })`,
 *   `new DashboardApprovalChannel({ port })`) that calls `.listen()`
 *   internally. Sigma-6's scanner only inspects `.listen()` text in
 *   the test file, so these never surfaced. The canonical replacement
 *   is `randomTestPort` from `server/test/util/port-collision-retry.ts`
 *   (paired with `bindWithRetry` when the SUT bakes the port into
 *   URLs, or `port: 0` ephemeral when the SUT reads the actual port
 *   back via `server.address()`). A local `randomPort` declaration is
 *   therefore a violation.
 *
 *   Random allocation detection uses the TypeScript AST. Flag every call
 *   whose callee, after stripping parentheses and non-null assertions, is
 *   the identifier `randomTestPort`. Exempt a call only when its nearest
 *   enclosing function-like node is an arrow function or function expression
 *   passed as the first argument of a call whose callee is the identifier
 *   `bindWithRetry`, or a same-line or preceding-line single-line comment
 *   says `port-discipline: ignore <reason>`. No intervening function boundary
 *   is allowed: nested timer callbacks and other inner functions are flagged.
 *   This includes template interpolations and direct random listen arguments.
 *   Returning a port from the attempt is accepted: this is a syntactic rule,
 *   not dataflow analysis of whether the eventual bind happens in the attempt.
 *   Named helpers must receive a port allocated inside the inline attempt.
 *
 * Enforcement: this module exports `scanRepoTests()` which is invoked
 * by the vitest regression test at
 * `server/test/scripts/test-port-discipline.test.ts`. Any new test
 * file that introduces a hardcoded port literal, an unwrapped
 * variable-port listen, a local randomPort helper, or an unprotected
 * randomTestPort allocation will fail that
 * regression test on the next `npm test` run (which is also the pre-
 * commit hook gate and the CI gate, so it cannot slip through
 * silently).
 *
 * Background: dashboard.test.ts:rate-limiting hit 9-10 EADDRINUSE
 * flakes across v1.2.x / v1.3.x cascades (Sigma-6 closed). The
 * Omega-1 CI run on iteration-8 hit a NEW flake on api.test.ts:port
 * 35292, same structural class, different file, missed by Sigma-6's
 * detection pattern. Sigma-7 ports the api.test.ts case to the
 * canonical helpers AND extends this scanner to detect the missed
 * pattern.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";

const SERVER_TEST_DIR = "server/test";
const WHITELIST_MARKER = "port-discipline: ignore";

interface Violation {
  file: string;
  line: number;
  text: string;
  reason: string;
}

function walkTestFiles(dir: string): string[] {
  const out: string[] = [];
  const ents = readdirSync(dir);
  for (const ent of ents) {
    const p = join(dir, ent);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (ent === "node_modules") continue;
      out.push(...walkTestFiles(p));
      continue;
    }
    if (ent.endsWith(".test.ts")) out.push(p);
  }
  return out;
}

/** Pattern: `.listen(<digits>` - a hardcoded port literal. */
const HARDCODED_LISTEN_RE = /\.listen\s*\(\s*([0-9]+)\s*[,)]/;
/** Pattern: `.listen(<var>` where the var is not literal `0` - needs review. */
const VAR_LISTEN_RE = /\.listen\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]/;
/**
 * Pattern: a `bindWithRetry(` CALL (not just the word). The pre-Sigma-7
 * gate matched the bare word anywhere including comments, which lets a
 * file slip through with only a TODO-style mention. The trailing `(`
 * forces a call site.
 */
const RETRY_CALL_RE = /\bbindWithRetry\s*\(/;
/**
 * Sigma-7 pattern: a locally-declared `randomPort` helper. Catches the
 * api.test.ts class that Sigma-6 missed. Whitelist the same way as
 * `.listen` (inline `// port-discipline: ignore` comment) when a local
 * helper is genuinely needed (e.g. fixture-only, never actually binds).
 */
const LOCAL_RANDOM_PORT_RE =
  /^\s*(?:export\s+)?(?:function|const|let|var)\s+randomPort\b/;

function lineHasWhitelist(line: string): boolean {
  return line.includes(WHITELIST_MARKER);
}

function fileUsesBindWithRetry(text: string): boolean {
  return RETRY_CALL_RE.test(text);
}

function stripCallWrappers(expression: ts.Expression): ts.Expression {
  while (ts.isParenthesizedExpression(expression) || ts.isNonNullExpression(expression)) {
    expression = expression.expression;
  }
  return expression;
}

function isRetryAttemptAllocation(call: ts.CallExpression): boolean {
  let enclosing: ts.Node | undefined = call.parent;
  while (enclosing && !ts.isFunctionLike(enclosing)) enclosing = enclosing.parent;
  if (!enclosing || (!ts.isArrowFunction(enclosing) && !ts.isFunctionExpression(enclosing))) {
    return false;
  }
  let argument: ts.Node = enclosing;
  while (ts.isParenthesizedExpression(argument.parent) || ts.isNonNullExpression(argument.parent)) {
    argument = argument.parent;
  }
  const retry = argument.parent;
  return ts.isCallExpression(retry) && retry.arguments[0] === argument &&
    ts.isIdentifier(retry.expression) && retry.expression.text === "bindWithRetry";
}

function scanRandomAllocations(path: string, source: string): Violation[] {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const ignoredLines = new Set<number>();
  const allocations: ts.CallExpression[] = [];
  const collectComment = (pos: number, end: number, kind: ts.CommentKind): void => {
    if (kind !== ts.SyntaxKind.SingleLineCommentTrivia) return;
    const commentPrefixLength = "//".length;
    const comment = source.slice(pos + commentPrefixLength, end).trim();
    if (!comment.startsWith(WHITELIST_MARKER)) return;
    const reason = comment.slice(WHITELIST_MARKER.length);
    if (!reason.startsWith(" ") || !reason.trim()) return;
    ignoredLines.add(file.getLineAndCharacterOfPosition(pos).line);
  };
  const visit = (node: ts.Node): void => {
    // Parser-owned trivia positions avoid treating strings and regexes as annotations.
    ts.forEachLeadingCommentRange(source, node.pos, collectComment);
    ts.forEachTrailingCommentRange(source, node.pos, collectComment);
    ts.forEachTrailingCommentRange(source, node.end, collectComment);
    if (ts.isCallExpression(node)) {
      const callee = stripCallWrappers(node.expression);
      if (ts.isIdentifier(callee) && callee.text === "randomTestPort") allocations.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);

  const violations: Violation[] = [];
  const lines = source.split("\n");
  for (const call of allocations) {
    const line = file.getLineAndCharacterOfPosition(call.getStart(file)).line;
    if (ignoredLines.has(line) || ignoredLines.has(line - 1)) continue;
    if (isRetryAttemptAllocation(call)) continue;
    violations.push({
      file: path,
      line: line + 1,
      text: lines[line]!.trim(),
      reason: "randomTestPort() outside a bindWithRetry attempt; allocate a fresh port inside the retry callback or use port: 0 when the bound port is read back",
    });
  }
  return violations;
}

export function scanFile(path: string, text?: string): Violation[] {
  const source = text ?? readFileSync(path, "utf-8");
  const lines = source.split("\n");
  const usesBindWithRetry = fileUsesBindWithRetry(source);
  const violations: Violation[] = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]!;
    if (lineHasWhitelist(line)) continue;
    // Also check the prior line for the whitelist marker, since
    // tests often put the annotation as a comment above the call.
    if (i > 0 && lineHasWhitelist(lines[i - 1]!)) continue;

    const literalMatch = line.match(HARDCODED_LISTEN_RE);
    if (literalMatch) {
      const portText = literalMatch[1]!;
      if (portText === "0") continue; // ephemeral is allowed
      violations.push({
        file: path,
        line: i + 1,
        text: line.trim(),
        reason: `hardcoded port literal ${portText}; convert to .listen(0, ...) or wrap in bindWithRetry`,
      });
      continue;
    }

    const varMatch = line.match(VAR_LISTEN_RE);
    if (varMatch) {
      // Variable-port .listen() is only safe when the file uses
      // bindWithRetry (which catches EADDRINUSE and retries with a
      // fresh port). If the file doesn't import / use bindWithRetry,
      // a stray collision will fail the test.
      if (!usesBindWithRetry) {
        violations.push({
          file: path,
          line: i + 1,
          text: line.trim(),
          reason: `.listen(<var>) without bindWithRetry - port collisions will not retry`,
        });
      }
    }

    // Sigma-7: detect a locally-declared randomPort helper. Callers
    // that go through such helpers typically do NOT call `.listen()`
    // directly (the bind happens inside an SUT constructor), so the
    // Sigma-6 .listen() scan misses them. The canonical replacement
    // is `randomTestPort` from server/test/util/port-collision-retry.ts.
    const localRandomPort = line.match(LOCAL_RANDOM_PORT_RE);
    if (localRandomPort) {
      violations.push({
        file: path,
        line: i + 1,
        text: line.trim(),
        reason:
          "local randomPort helper; replace with randomTestPort from server/test/util/port-collision-retry.ts (paired with bindWithRetry when the SUT bakes the port in, or port: 0 ephemeral when the SUT reads server.address() back)",
      });
    }
  }

  violations.push(...scanRandomAllocations(path, source));
  return violations;
}

export function scanRepoTests(testDir: string = SERVER_TEST_DIR): Violation[] {
  const files = walkTestFiles(testDir);
  const out: Violation[] = [];
  for (const f of files) {
    out.push(...scanFile(f));
  }
  return out;
}

/**
 * Helper for the regression test's failure-mode reporting. Returns a
 * concatenated, human-readable summary of the violations array, one
 * per line. Empty string when no violations.
 */
export function formatViolations(violations: Violation[]): string {
  return violations
    .map((v) => {
      const rel = relative(process.cwd(), v.file);
      return `${rel}:${v.line} - ${v.reason}\n    ${v.text}`;
    })
    .join("\n");
}
