#!/usr/bin/env node
/**
 * Sanctuary server console-discipline gate.
 *
 * Asserts that every `console.log`/`console.warn`/`console.error`/etc. call
 * in non-test TypeScript source files inside `server/src/` is either
 * (a) inside a template literal (browser-side JS embedded in HTML strings,
 *     which the server cannot route through a logger) or
 * (b) annotated with a `// SAFETY:` comment naming why raw stdout/stderr
 *     is the contract at that site (CLI subcommand JSON output, version
 *     string output, operator-facing startup or runtime error reporting,
 *     etc.).
 *
 * The gate exits 0 with a one-line PASS message when server/src/ is clean
 * and exits 1 with a list of unannotated sites otherwise.
 *
 * Files outside server/src/ (test/, node_modules/, dist/, etc.) are
 * excluded by design.
 *
 * Closes full-sweep finding #97. Mirrors Sigma-3's
 * `castle-wall-daemon/scripts/check-stdout-discipline.py` shape, applied
 * to TypeScript with backtick-template stripping added so browser-side
 * console.* embedded in HTML template literals does not count.
 *
 * Usage:
 *   npx vite-node server/scripts/check-no-raw-console.ts
 *   npx vite-node server/scripts/check-no-raw-console.ts --quiet
 *   npx vite-node server/scripts/check-no-raw-console.ts --root <path>
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const CONSOLE_CALL_RE = /\bconsole\.(log|warn|error|info|debug|trace)\b/;
const SAFETY_COMMENT_RE = /^\s*\/\/[^/!].*\bSAFETY:/;
const LINE_COMMENT_RE = /^\s*\/\/[^/!]/;
const LOOKBACK_LIMIT = 20;

export interface Site {
  path: string;
  line: number; // 1-based
  text: string;
}

/**
 * Replace double-quoted, single-quoted, and backtick-quoted string contents
 * plus the tail of any `//` line comment with placeholder spaces, so that
 * console.* calls inside string literals are not counted as real call sites
 * and so that brace/paren counting in the future would only see structural
 * source. Backtick handling tracks `${...}` interpolation: code inside the
 * interpolation is preserved (it can contain a real console.* call), code
 * inside the bare template literal text is stripped.
 *
 * The lexer is a single-pass state machine. Limitations:
 * - Nested template literals inside `${...}` are tracked one level deep via
 *   a stack; arbitrary nesting works.
 * - Regex literals are not parsed; they look like division and rarely
 *   appear in CLI source. False positives in regex literals fall through
 *   to the SAFETY-annotation requirement and surface as gate failures
 *   that the operator can resolve with an annotation or a refactor.
 */
export function scrubLine(line: string, state: LexerState): string {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    const c = line[i]!;
    const top = state.stack[state.stack.length - 1] ?? "default";

    if (top === "block-comment") {
      // Block-comment content is not code. Look for the closing `*/` and
      // emit spaces for the rest. Apostrophes and backticks inside JSDoc
      // (`Sanctuary's`, `\`sanctuary wrap\``) must NOT enter string state.
      if (c === "*" && line[i + 1] === "/") {
        state.stack.pop();
        out.push("  ");
        i += 2;
        continue;
      }
      out.push(" ");
      i += 1;
      continue;
    }

    if (top === "template-text") {
      if (c === "\\" && i + 1 < line.length) {
        out.push("  ");
        i += 2;
        continue;
      }
      if (c === "`") {
        state.stack.pop();
        out.push(" ");
        i += 1;
        continue;
      }
      if (c === "$" && line[i + 1] === "{") {
        state.stack.push("template-expr");
        state.exprBraceDepth.push(1);
        out.push("  ");
        i += 2;
        continue;
      }
      out.push(" ");
      i += 1;
      continue;
    }

    if (top === "template-expr") {
      // Inside `${...}` we run the same lexer recursively; emit the chars
      // as code so console.* calls in interpolation are caught.
      if (c === "{") {
        state.exprBraceDepth[state.exprBraceDepth.length - 1]! += 1;
        out.push(c);
        i += 1;
        continue;
      }
      if (c === "}") {
        state.exprBraceDepth[state.exprBraceDepth.length - 1]! -= 1;
        if (state.exprBraceDepth[state.exprBraceDepth.length - 1] === 0) {
          state.stack.pop();
          state.exprBraceDepth.pop();
          out.push(" ");
          i += 1;
          continue;
        }
        out.push(c);
        i += 1;
        continue;
      }
      // Fall through: emit and let the default-state checks below run. We
      // re-emit by handling string starts explicitly here so quotes inside
      // expressions are still stripped.
      if (c === '"' || c === "'") {
        state.stack.push(c === '"' ? "dqstr" : "sqstr");
        out.push(" ");
        i += 1;
        continue;
      }
      if (c === "`") {
        state.stack.push("template-text");
        out.push(" ");
        i += 1;
        continue;
      }
      if (c === "/" && line[i + 1] === "/") {
        // Line comment; rest of line is not code.
        for (let k = i; k < line.length; k++) out.push(" ");
        i = line.length;
        continue;
      }
      if (c === "/" && line[i + 1] === "*") {
        state.stack.push("block-comment");
        out.push("  ");
        i += 2;
        continue;
      }
      out.push(c);
      i += 1;
      continue;
    }

    if (top === "dqstr" || top === "sqstr") {
      if (c === "\\" && i + 1 < line.length) {
        out.push("  ");
        i += 2;
        continue;
      }
      if ((top === "dqstr" && c === '"') || (top === "sqstr" && c === "'")) {
        state.stack.pop();
        out.push(" ");
        i += 1;
        continue;
      }
      out.push(" ");
      i += 1;
      continue;
    }

    // default state
    if (c === '"') {
      state.stack.push("dqstr");
      out.push(" ");
      i += 1;
      continue;
    }
    if (c === "'") {
      state.stack.push("sqstr");
      out.push(" ");
      i += 1;
      continue;
    }
    if (c === "`") {
      state.stack.push("template-text");
      out.push(" ");
      i += 1;
      continue;
    }
    if (c === "/" && line[i + 1] === "/") {
      for (let k = i; k < line.length; k++) out.push(" ");
      i = line.length;
      continue;
    }
    if (c === "/" && line[i + 1] === "*") {
      state.stack.push("block-comment");
      out.push("  ");
      i += 2;
      continue;
    }
    out.push(c);
    i += 1;
  }
  return out.join("");
}

export interface LexerState {
  stack: Array<
    | "default"
    | "dqstr"
    | "sqstr"
    | "template-text"
    | "template-expr"
    | "block-comment"
  >;
  exprBraceDepth: number[];
}

export function newLexerState(): LexerState {
  return { stack: [], exprBraceDepth: [] };
}

export function findConsoleCallSites(
  path: string,
  lines: string[]
): Site[] {
  const state = newLexerState();
  const sites: Site[] = [];
  for (let idx = 0; idx < lines.length; idx++) {
    const scrubbed = scrubLine(lines[idx]!, state);
    if (CONSOLE_CALL_RE.test(scrubbed)) {
      sites.push({ path, line: idx + 1, text: lines[idx]!.replace(/\n$/, "") });
    }
  }
  return sites;
}

export function isAnnotated(lines: string[], siteIndex: number): boolean {
  // siteIndex is 0-based.
  // We need to walk back through contiguous console.* call lines and `//`
  // line comments, looking for `// SAFETY:`. Stop at any other code or any
  // blank line.
  //
  // Multi-line console call continuations: a line that is purely arguments
  // (no semicolon, no recognizable statement-starter) inside an open
  // console.* call is treated as a continuation that does not break walk-
  // back. This matches Sigma-3's `_looks_like_macro_continuation` heuristic.
  const start = Math.max(0, siteIndex - LOOKBACK_LIMIT);
  // We need a fresh lexer state for each walk-back, which is wasteful. Since
  // most walk-backs are short and the strings we care about are simple, we
  // accept the cost.
  const scrubbedAt = (j: number): string => {
    const localState = newLexerState();
    for (let k = 0; k <= j; k++) {
      const out = scrubLine(lines[k]!, localState);
      if (k === j) return out;
    }
    return "";
  };

  for (let j = siteIndex - 1; j >= start; j--) {
    const line = lines[j]!;
    const stripped = line.trim();
    if (stripped === "") return false;
    if (SAFETY_COMMENT_RE.test(line)) return true;
    if (LINE_COMMENT_RE.test(line)) continue;
    const scrubbed = scrubbedAt(j);
    if (CONSOLE_CALL_RE.test(scrubbed)) continue;
    if (looksLikeCallContinuation(scrubbed)) continue;
    return false;
  }
  return false;
}

const CONTINUATION_RE = /^[\s\w\.,&\*\(\)\[\]\{\}:'"<>+\-/=!?$|]*$/;
const STATEMENT_BREAKERS = new Set([
  "let", "const", "var",
  "if", "else", "switch", "case", "default",
  "for", "while", "do", "loop",
  "return", "throw", "break", "continue",
  "try", "catch", "finally",
  "function", "async", "await",
  "class", "interface", "type", "enum",
  "import", "export", "from",
  "new",
  "yield",
  "this",
]);

export function looksLikeCallContinuation(scrubbed: string): boolean {
  // If a semicolon appears, the line terminates a statement, so it is not
  // a continuation.
  if (scrubbed.includes(";")) return false;
  const s = scrubbed.trim();
  if (!s) return false;
  // Reject lines whose first identifier is a structural statement starter.
  const m = scrubbed.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)/);
  if (m) {
    const word = m[1]!;
    if (STATEMENT_BREAKERS.has(word)) return false;
  }
  return CONTINUATION_RE.test(scrubbed);
}

export function collectTsSrcFiles(root: string): string[] {
  const srcRoot = join(root, "server", "src");
  let stat;
  try {
    stat = statSync(srcRoot);
  } catch {
    return [];
  }
  if (!stat.isDirectory()) return [];
  const out: string[] = [];
  function walk(dir: string): void {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      const s = statSync(full);
      if (s.isDirectory()) walk(full);
      else if (s.isFile() && (name.endsWith(".ts") || name.endsWith(".tsx"))) {
        out.push(full);
      }
    }
  }
  walk(srcRoot);
  out.sort();
  return out;
}

export function scan(
  root: string
): { annotated: Site[]; unannotated: Site[] } {
  const annotated: Site[] = [];
  const unannotated: Site[] = [];
  for (const path of collectTsSrcFiles(root)) {
    const text = readFileSync(path, "utf-8");
    const lines = text.split(/\r?\n/);
    for (const site of findConsoleCallSites(path, lines)) {
      if (isAnnotated(lines, site.line - 1)) {
        annotated.push(site);
      } else {
        unannotated.push(site);
      }
    }
  }
  return { annotated, unannotated };
}

function formatFailure(unannotated: Site[], root: string): string {
  const out: string[] = [];
  out.push("Sanctuary server console-discipline gate FAILED.");
  out.push("");
  out.push(
    "Each console.log / console.warn / console.error / etc. call in"
  );
  out.push(
    "non-test TypeScript source under server/src/ must carry an"
  );
  out.push(
    "immediately preceding `// SAFETY:` comment naming why raw"
  );
  out.push(
    "stdout/stderr is the contract at that site, OR live inside a"
  );
  out.push(
    "template literal (browser-side JS embedded in HTML)."
  );
  out.push("");
  out.push("Doc: server/docs/logging-discipline.md");
  out.push("");
  out.push("Unannotated sites:");
  for (const site of unannotated) {
    const rel = relative(root, site.path);
    out.push(`  ${rel}:${site.line}: ${site.text.trim()}`);
  }
  out.push("");
  out.push(
    "Fix by adding a `// SAFETY: <reason>` comment block above the"
  );
  out.push(
    "call site, or by removing the call if it is residual debug."
  );
  return out.join("\n");
}

export function parseArgs(
  argv: string[],
  defaultRoot: string
): { root: string; quiet: boolean } {
  let root = defaultRoot;
  let quiet = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--quiet") {
      quiet = true;
    } else if (a === "--root") {
      root = resolve(argv[++i]!);
    }
  }
  return { root, quiet };
}

export function runMain(argv: string[], defaultRoot: string): number {
  const { root, quiet } = parseArgs(argv, defaultRoot);
  const { annotated, unannotated } = scan(root);
  if (unannotated.length > 0) {
    process.stderr.write(formatFailure(unannotated, root) + "\n");
    return 1;
  }
  if (!quiet) {
    process.stdout.write(
      `Sanctuary server console-discipline gate PASS: ` +
        `${annotated.length} annotated production-code site(s), 0 unannotated.\n`
    );
  }
  return 0;
}

export { formatFailure };
