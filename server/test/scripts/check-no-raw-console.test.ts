/**
 * Self-tests for the Sanctuary server console-discipline gate.
 *
 * Mirrors `castle-wall-daemon/scripts/test_check_stdout_discipline.py`:
 * stage synthetic TypeScript source trees in tempdirs and assert the
 * gate's classification logic. Tests are independent of the real server
 * source and continue to pass as production code evolves.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  isAnnotated,
  findConsoleCallSites,
  scan,
  scrubLine,
  newLexerState,
  looksLikeCallContinuation,
} from "../../scripts/check-no-raw-console.lib.js";

function stage(root: string, rel: string, body: string): string {
  const path = join(root, rel);
  mkdirSync(path.substring(0, path.lastIndexOf("/")), { recursive: true });
  writeFileSync(path, body, "utf-8");
  return path;
}

describe("scrubLine: lexer state machine", () => {
  it("strips double-quoted string contents", () => {
    const out = scrubLine('const x = "console.error called";', newLexerState());
    expect(out).not.toMatch(/console\.error/);
  });

  it("strips single-quoted string contents", () => {
    const out = scrubLine("const x = 'console.error here';", newLexerState());
    expect(out).not.toMatch(/console\.error/);
  });

  it("strips template literal text", () => {
    const out = scrubLine("const x = `console.error in template`;", newLexerState());
    expect(out).not.toMatch(/console\.error/);
  });

  it("preserves console.* in template-literal interpolation", () => {
    // Code inside ${...} is real and must be detected.
    const state = newLexerState();
    const out = scrubLine("const x = `pre ${ console.error('x') } post`;", state);
    expect(out).toMatch(/console\.error/);
  });

  it("strips JSDoc block-comment content (apostrophes do not open sqstr)", () => {
    const state = newLexerState();
    scrubLine("/**", state);
    scrubLine(" * Sanctuary's CLI is powered by operator's choice.", state);
    scrubLine(" */", state);
    // After block comment closes, lexer must be back at default state with
    // no spurious sqstr entry.
    expect(state.stack).toEqual([]);
    // Verify a console.error after the block comment is still detected.
    const out = scrubLine("console.error('test');", state);
    expect(out).toMatch(/console\.error/);
  });

  it("strips // line comments", () => {
    const out = scrubLine("// console.error in line comment", newLexerState());
    expect(out).not.toMatch(/console\.error/);
  });
});

describe("findConsoleCallSites", () => {
  it("finds a bare console.error", () => {
    const lines = [
      "function oops() {",
      "  console.error('oops');",
      "}",
    ];
    const sites = findConsoleCallSites("dummy.ts", lines);
    expect(sites).toHaveLength(1);
    expect(sites[0]!.line).toBe(2);
  });

  it("does not match console.error inside a string literal", () => {
    const lines = [
      "function label(): string {",
      "  return 'we use console.error here in docs';",
      "}",
    ];
    const sites = findConsoleCallSites("dummy.ts", lines);
    expect(sites).toEqual([]);
  });

  it("does not match console.error inside a template literal (browser-side JS)", () => {
    const lines = [
      "function html(): string {",
      "  return `<script>",
      "    if (!ok) { console.error('browser-side'); }",
      "  </script>`;",
      "}",
    ];
    const sites = findConsoleCallSites("dummy.ts", lines);
    expect(sites).toEqual([]);
  });

  it("does match console.error inside template-literal interpolation", () => {
    const lines = [
      "const x = `${(() => { console.error('real call'); return 1; })()}`;",
    ];
    const sites = findConsoleCallSites("dummy.ts", lines);
    expect(sites).toHaveLength(1);
  });
});

describe("isAnnotated: walk-back semantics", () => {
  it("SAFETY directly above the call passes", () => {
    const lines = [
      "// SAFETY: stdout is the contract.",
      "console.log('hi');",
    ];
    expect(isAnnotated(lines, 1)).toBe(true);
  });

  it("SAFETY covers a contiguous console.* block", () => {
    const lines = [
      "// SAFETY: stderr is the operator channel.",
      "console.error('one');",
      "console.error('two');",
      "console.error('three');",
    ];
    expect(isAnnotated(lines, 1)).toBe(true);
    expect(isAnnotated(lines, 2)).toBe(true);
    expect(isAnnotated(lines, 3)).toBe(true);
  });

  it("no SAFETY at all fails", () => {
    const lines = ["const x = 1;", "console.error('residual', x);"];
    expect(isAnnotated(lines, 1)).toBe(false);
  });

  it("SAFETY separated by a blank line does not cover the call", () => {
    const lines = [
      "// SAFETY: stdout is the contract.",
      "",
      "console.error('not covered');",
    ];
    expect(isAnnotated(lines, 2)).toBe(false);
  });

  it("SAFETY separated by unrelated code does not cover the second call", () => {
    const lines = [
      "// SAFETY: stdout is the contract.",
      "console.log('safe');",
      "const x = compute();",
      "console.error('not covered:', x);",
    ];
    expect(isAnnotated(lines, 1)).toBe(true);
    expect(isAnnotated(lines, 3)).toBe(false);
  });

  it("doc comment /// is not honored as SAFETY", () => {
    const lines = [
      "/// SAFETY: doc-comment marker should not satisfy the gate.",
      "console.error('not covered');",
    ];
    expect(isAnnotated(lines, 1)).toBe(false);
  });

  it("SAFETY covers a multi-line console.* call (walk-back through bare argument fragments)", () => {
    const lines = [
      "// SAFETY: stderr block.",
      "console.error(",
      "  `one`,",
      "  `two`,",
      ");",
    ];
    // The console.error site is on the call line (index 1). The walk-back
    // there finds the SAFETY at index 0 directly. The semicolon-bearing
    // closing line at idx 4 is not a call site (lexer sees only `);`),
    // so isAnnotated only matters for the call line.
    expect(isAnnotated(lines, 1)).toBe(true);
  });
});

describe("scan: full-tree integration", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "sanctuary-console-gate-"));
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("clean tree with one annotated site passes", () => {
    stage(
      root,
      "server/src/cli.ts",
      [
        "export function main(): void {",
        "  // SAFETY: CLI subcommand stderr.",
        "  console.error('hello');",
        "}",
      ].join("\n")
    );
    const { annotated, unannotated } = scan(root);
    expect(unannotated).toEqual([]);
    expect(annotated).toHaveLength(1);
  });

  it("unannotated site fails", () => {
    stage(
      root,
      "server/src/danger.ts",
      [
        "export function debug(): void {",
        "  console.error('residual');",
        "}",
      ].join("\n")
    );
    const { unannotated } = scan(root);
    expect(unannotated).toHaveLength(1);
    expect(unannotated[0]!.path.endsWith("danger.ts")).toBe(true);
  });

  it("browser-side console.* inside template literal is excluded", () => {
    stage(
      root,
      "server/src/dashboard-html.ts",
      [
        "export function render(): string {",
        "  return `<!DOCTYPE html><script>",
        "    fetch('/api').catch(err => console.error('browser', err));",
        "  </script>`;",
        "}",
      ].join("\n")
    );
    const { annotated, unannotated } = scan(root);
    expect(annotated).toEqual([]);
    expect(unannotated).toEqual([]);
  });

  it("real server tree passes the gate after the Sigma-5 sweep", () => {
    // Test runs against the actual repo, not the tempdir.
    const repoRoot = join(__dirname, "..", "..", "..");
    const { unannotated, annotated } = scan(repoRoot);
    expect(
      unannotated,
      `Real server tree has unannotated console.* sites: ${JSON.stringify(unannotated.slice(0, 5))}`
    ).toEqual([]);
    expect(annotated.length).toBeGreaterThanOrEqual(160);
  });
});

describe("looksLikeCallContinuation", () => {
  it("treats a bare argument fragment as a continuation", () => {
    // The function operates on already-scrubbed lines (template-literal
    // and string contents have been stripped to spaces); pass that shape.
    expect(looksLikeCallContinuation("           ,")).toBe(true);
  });

  it("does not treat a let-statement as a continuation", () => {
    expect(looksLikeCallContinuation("    let x = compute();")).toBe(false);
  });

  it("does not treat a line with semicolon as a continuation", () => {
    expect(looksLikeCallContinuation("    foo();")).toBe(false);
  });
});
