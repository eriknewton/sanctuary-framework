/**
 * Sigma-6 test-port-discipline regression gate.
 *
 * Scans `server/test/` for `.listen(...)` calls and verifies each is
 * either:
 *
 *   1. Ephemeral: `.listen(0, ...)` (OS-assigned port).
 *   2. Wrapped in `bindWithRetry` (the established retry-on-EADDRINUSE
 *      helper at `server/test/util/port-collision-retry.ts`).
 *   3. Whitelisted with an inline `// port-discipline: ignore` comment
 *      (with a brief reason).
 *
 * Enforcement: this module exports `scanRepoTests()` which is invoked
 * by the vitest regression test at
 * `server/test/scripts/test-port-discipline.test.ts`. Any new test
 * file that introduces a hardcoded port literal or an unwrapped
 * variable-port listen will fail that regression test on the next
 * `npm test` run (which is also the pre-commit hook gate and the CI
 * gate, so it cannot slip through silently).
 *
 * Background: the EADDRINUSE flake at dashboard.test.ts:rate-limiting
 * hit 9-10 incidents across v1.2.x / v1.3.x build cascades. The
 * structural fix (Sigma-6 omnibus, this gate) prevents new tests from
 * regressing the pattern.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

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

/** Pattern: `.listen(<digits>` — a hardcoded port literal. */
const HARDCODED_LISTEN_RE = /\.listen\s*\(\s*([0-9]+)\s*[,)]/;
/** Pattern: `.listen(<var>` where the var is not literal `0` — needs review. */
const VAR_LISTEN_RE = /\.listen\s*\(\s*([A-Za-z_$][\w$]*)\s*[,)]/;
/** Pattern: a snippet of `bindWithRetry`-style wrap above the listen. */
const RETRY_NEAR_BY_RE = /bindWithRetry/;

function lineHasWhitelist(line: string): boolean {
  return line.includes(WHITELIST_MARKER);
}

function fileUsesBindWithRetry(text: string): boolean {
  return RETRY_NEAR_BY_RE.test(text);
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
          reason: `.listen(<var>) without bindWithRetry — port collisions will not retry`,
        });
      }
    }
  }

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
      return `${rel}:${v.line} — ${v.reason}\n    ${v.text}`;
    })
    .join("\n");
}
