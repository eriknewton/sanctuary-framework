import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The top-level CLI handler recognises custody release failures by the exact
// diagnostics releaseKernelLock produces, because the lock error type is shared
// with acquisition refusals. This guard keeps the two sets equal in full, so a
// reworded or added producer diagnostic cannot silently fall back to the
// start-failure message.

const SRC = join(__dirname, "..", "..", "src");
const PLACEHOLDER = "<n>";

function functionBody(source: string, signature: string): string {
  const start = source.indexOf(signature);
  expect(start, `missing ${signature}`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("\n}\n", start);
  expect(end, `unterminated ${signature}`).toBeGreaterThan(start);
  return source.slice(start, end);
}

function producerDiagnostics(): Set<string> {
  const body = functionBody(readFileSync(join(SRC, "storage", "cross-process-lock.ts"), "utf8"), "function releaseKernelLock(");
  const found = new Set<string>();
  for (const match of body.matchAll(/new CrossProcessLockError\(\s*(["`])((?:\\.|(?!\1).)*)\1/g)) {
    found.add(match[2].replace(/\$\{[^}]*\}/g, PLACEHOLDER));
  }
  return found;
}

function classifierDiagnostics(): Set<string> {
  const body = functionBody(readFileSync(join(SRC, "cli.ts"), "utf8"), "async function isMasterSessionCleanupFailure(");
  const found = new Set<string>();
  for (const match of body.matchAll(/value\.message === "((?:\\.|[^"\\])*)"/g)) found.add(match[1]);
  for (const match of body.matchAll(/\/\^(.*?)\$\/\.test\(value\.message\)/g)) found.add(match[1].replace(/\\d\+/g, PLACEHOLDER));
  return found;
}

describe("custody release diagnostic parity", () => {
  it("recognises exactly the diagnostics releaseKernelLock produces", () => {
    const producer = producerDiagnostics();
    expect(producer.size).toBeGreaterThan(0);
    expect(classifierDiagnostics()).toEqual(producer);
  });
});
