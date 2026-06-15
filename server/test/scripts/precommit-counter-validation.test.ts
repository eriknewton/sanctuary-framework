/**
 * Self-tests for the test-baseline pre-commit hook's vitest-derived COUNTER
 * validation (`validate_counter` in `.githooks/pre-commit`).
 *
 * The hook extracts two counters from vitest's text output with
 * `grep -oE "[0-9]+"` — the passing-test count and the Test-Files count — and
 * then feeds them into `(( ... ))` arithmetic guards (regression check, silent
 * file-drop check). The capture is shaped like a non-negative integer, but two
 * pathological values would corrupt those guards and must fail CLOSED:
 *
 *   - a non-canonical string (non-numeric, leading-zero octal-trap), and
 *   - an over-long value that overflows bash's signed-64-bit `(( ))`
 *     arithmetic and silently wraps (the macOS system bash is 3.2), which a
 *     naive numeric `(( v > MAX ))` guard cannot catch because the comparison
 *     itself overflows.
 *
 * These tests source the EXACT shipped `validate_counter` function out of the
 * real hook file (no re-implementation — a divergent copy would defeat the
 * point) and assert its exit code across the vectors. A non-zero exit means the
 * commit would be blocked; exit 0 means the value passed validation.
 */

import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  ".githooks",
  "pre-commit",
);

/**
 * Extract the `COUNTER_MAX=...` assignment and the whole `validate_counter() {
 * ... }` function body from the shipped hook, verbatim. We deliberately do NOT
 * source the entire hook (it runs `set -euo pipefail` and the full gate
 * pipeline); we lift out exactly the unit under test.
 */
function extractValidator(): string {
  const src = readFileSync(HOOK_PATH, "utf-8");
  const lines = src.split("\n");

  const counterMaxLine = lines.find((l) => /^COUNTER_MAX=/.test(l));
  if (!counterMaxLine) {
    throw new Error("COUNTER_MAX assignment not found in hook");
  }

  const startIdx = lines.findIndex((l) => /^validate_counter\(\)\s*\{/.test(l));
  if (startIdx === -1) {
    throw new Error("validate_counter() definition not found in hook");
  }
  // Walk to the matching closing brace at column 0 (the function's own `}`).
  let endIdx = -1;
  for (let i = startIdx + 1; i < lines.length; i++) {
    if (lines[i] === "}") {
      endIdx = i;
      break;
    }
  }
  if (endIdx === -1) {
    throw new Error("validate_counter() closing brace not found in hook");
  }
  const fnBody = lines.slice(startIdx, endIdx + 1).join("\n");
  return `${counterMaxLine}\n${fnBody}`;
}

/**
 * Run the shipped validator against `value` in a real bash subprocess and
 * return its exit code. The validator calls `fail` (a logger in the hook); we
 * provide a no-op stub so the unit runs in isolation. `set -euo pipefail`
 * mirrors the hook's own shell options so the test exercises the same
 * exit-propagation semantics the hook relies on.
 */
function runValidator(value: string): number {
  const validator = extractValidator();
  const harness = [
    "set -euo pipefail",
    "fail() { :; }", // stub the hook's logger
    validator,
    // Invoke exactly as the hook does: a plain statement, NOT a command
    // substitution (bash 3.2 would not propagate an exit out of `$(...)`).
    'validate_counter "test counter" "$1"',
  ].join("\n");

  try {
    execFileSync("bash", ["-c", harness, "bash", value], {
      stdio: "ignore",
    });
    return 0;
  } catch (err) {
    const status = (err as { status?: number }).status;
    return typeof status === "number" ? status : 1;
  }
}

describe("pre-commit validate_counter — fail CLOSED on pathological counters", () => {
  it("accepts a normal passing count", () => {
    expect(runValidator("7036")).toBe(0);
  });

  it("accepts zero", () => {
    expect(runValidator("0")).toBe(0);
  });

  it("accepts the exact upper bound (100000000)", () => {
    expect(runValidator("100000000")).toBe(0);
  });

  it("rejects a non-numeric value (fail closed)", () => {
    expect(runValidator("abc")).not.toBe(0);
  });

  it("rejects a value with embedded whitespace (fail closed)", () => {
    expect(runValidator("12 34")).not.toBe(0);
  });

  it("rejects a leading-zero value — octal-parse trap (fail closed)", () => {
    expect(runValidator("007")).not.toBe(0);
  });

  it("rejects scientific-notation-shaped input (fail closed)", () => {
    expect(runValidator("1e9")).not.toBe(0);
  });

  it("rejects one past the upper bound (100000001) (fail closed)", () => {
    expect(runValidator("100000001")).not.toBe(0);
  });

  it("rejects a 19-digit overflow value — the bash-3.2 wrap trap (fail closed)", () => {
    // 9999999999999999999 > 2^63-1, so a naive (( v > MAX )) would wrap to a
    // negative number and FALSELY pass. The digit-count guard must catch it.
    expect(runValidator("9999999999999999999")).not.toBe(0);
  });

  it("rejects a 10-digit value just over the 9-digit bound (fail closed)", () => {
    expect(runValidator("1000000000")).not.toBe(0);
  });
});
