/**
 * No em-dashes in user-facing CLI strings.
 *
 * Per the no-em-dash rule (Erik directive 2026-04-21), public-facing artifacts
 * must not use em-dashes. This test enforces that for CLI source files by
 * stripping comments and JSDoc, then asserting the remaining executable code
 * (which contains the user-facing console.log/error strings, help text,
 * banners, error messages) is em-dash-free.
 *
 * Em-dashes in comments and JSDoc are intentionally permitted.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const CLI_SOURCES = [
  join(__dirname, "..", "..", "src", "cli.ts"),
  join(__dirname, "..", "..", "src", "wrap", "cli.ts"),
  join(__dirname, "..", "..", "src", "update-check.ts"),
];

/**
 * Strip JS/TS comments. Removes `/* ... *\/` block comments and `// ...`
 * line comments. Naive regex strip is sufficient here because we only need
 * to validate code-resident strings; we do not need to parse the AST.
 */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

describe("no em-dash in user-facing CLI strings", () => {
  for (const path of CLI_SOURCES) {
    it(`${path.split("/").slice(-2).join("/")} has no em-dashes outside comments`, () => {
      const source = readFileSync(path, "utf-8");
      const codeOnly = stripComments(source);
      const matches = codeOnly.match(/—/g) ?? [];
      if (matches.length > 0) {
        const lines = codeOnly.split("\n");
        const offending = lines
          .map((line, i) => ({ line, n: i + 1 }))
          .filter(({ line }) => line.includes("—"));
        const detail = offending
          .map(({ n, line }) => `  line ${n}: ${line.trim()}`)
          .join("\n");
        throw new Error(
          `Found ${matches.length} em-dash(es) in user-facing CLI source ${path}:\n${detail}\n` +
            `Replace with comma, period, colon, semicolon, or parentheses per the no-em-dash rule.`
        );
      }
      expect(matches.length).toBe(0);
    });
  }
});
