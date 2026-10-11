import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "scripts",
  "parse-vitest-summary.sh",
);

function runParser(
  contents: string,
  extraEnv: NodeJS.ProcessEnv = {},
): {
  status: number | null;
  stdout: string;
  stderr: string;
} {
  const tmpRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "sanctuary-vitest-summary-"),
  );
  const logPath = path.join(tmpRoot, "vitest-output.log");
  fs.writeFileSync(logPath, contents, "utf8");
  cleanupDirs.push(tmpRoot);

  const result = spawnSync("bash", [SCRIPT_PATH, logPath], {
    encoding: "utf8",
    env: {
      ...process.env,
      VITEST: process.env.VITEST ?? "true",
      ...extraEnv,
    },
  });

  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

/**
 * Source the shipped script (it returns before parsing when sourced) and run
 * one of its helper functions, so the tests exercise the exact bytes both
 * consumers (.githooks/pre-push and the CI baseline guard) source.
 */
function runHelper(
  fn: "compare_counts" | "count_difference" | "is_canonical_count" | "read_canonical_floor",
  args: string[],
  input = "",
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(
    "bash",
    ["-c", 'source "$1"; shift; "$@"', "helper", SCRIPT_PATH, fn, ...args],
    {
      encoding: "utf8",
      input,
      env: { ...process.env, VITEST: process.env.VITEST ?? "true" },
    },
  );
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

// 2^64 + 17345: a 20-digit count that signed 64-bit bash arithmetic wraps to
// exactly 17345, so an arithmetic comparison would call it equal to a 17345
// floor. String comparison must call it greater.
const WRAPS_TO_17345 = "18446744073709568961";

let cleanupDirs: string[] = [];

describe("scripts/parse-vitest-summary.sh", () => {
  afterEach(() => {
    for (const dir of cleanupDirs) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    cleanupDirs = [];
  });

  it("accepts the normal single summary line", () => {
    const result = runParser("Test Files  3 passed (3)\n      Tests  50 passed (50)\n");

    expect(result.status).toBe(0);
    expect(result.stdout).toBe("50\n");
    expect(result.stderr).toBe("");
  });

  it("refuses zero summary lines with a named message", () => {
    const result = runParser("Test Files  3 passed (3)\n", {
      VITEST_SUMMARY_ERROR_STYLE: "github",
    });

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("::error::");
    expect(result.stderr).toContain("Could not parse passing-test count");
    expect(result.stderr).toContain("none was found");
  });

  it("refuses two summary lines with a named message", () => {
    const result = runParser(
      "      Tests  50 passed (50)\nTest Files  3 passed (3)\n      Tests  4 passed (4)\n",
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("expected exactly one");
    expect(result.stderr).toContain("50 passed");
    expect(result.stderr).toContain("4 passed");
  });

  it("refuses two summary counts on one line with a named message", () => {
    const result = runParser(
      "Test Files  3 passed (3)\n      Tests  50 passed (50)      Tests  4 passed (4)\n",
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("count-shaped matches");
    expect(result.stderr).toContain("expected exactly one");
    expect(result.stderr).toContain("50 passed");
    expect(result.stderr).toContain("4 passed");
  });

  it.each([
    ["5 digits", "12345"],
    ["6 digits", "123456"],
    ["7 digits", "1234567"],
    ["20 digits (past signed 64-bit range)", WRAPS_TO_17345],
  ])("reads a %s count exactly, with no digit ceiling", (_label, count) => {
    const result = runParser(
      `Test Files  3 passed (3)\n      Tests  ${count} passed | 1 skipped (${count})\n`,
    );

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(`${count}\n`);
    expect(result.stderr).toBe("");
  });

  it("reads an ANSI-wrapped 7-digit count exactly", () => {
    const result = runParser(
      "\u001b[2m Test Files \u001b[22m \u001b[1m\u001b[32m3 passed\u001b[39m\u001b[22m\u001b[90m (3)\u001b[39m\n" +
        "\u001b[2m      Tests \u001b[22m \u001b[1m\u001b[32m1234567 passed\u001b[39m\u001b[22m\u001b[90m (1234567)\u001b[39m\n",
    );

    expect(result.status).toBe(0);
    expect(result.stdout).toBe("1234567\n");
    expect(result.stderr).toBe("");
  });

  it("refuses two 7-digit summary lines instead of choosing one", () => {
    const result = runParser(
      "      Tests  1234567 passed (1234567)\nTest Files  3 passed (3)\n      Tests  7654321 passed (7654321)\n",
    );

    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("expected exactly one");
  });

  it("refuses a leading-zero count with a named message instead of handing it on", () => {
    const result = runParser("Test Files  3 passed (3)\n      Tests  0050 passed (50)\n", {
      VITEST_SUMMARY_ERROR_STYLE: "github",
    });

    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("::error::");
    expect(result.stderr).toContain("not a canonical non-negative integer");
  });

  it("accepts an ANSI-wrapped summary count", () => {
    const result = runParser(
      "\u001b[2m Test Files \u001b[22m \u001b[1m\u001b[32m3 passed\u001b[39m\u001b[22m\u001b[90m (3)\u001b[39m\n" +
        "\u001b[2m      Tests \u001b[22m \u001b[1m\u001b[32m50 passed\u001b[39m\u001b[22m\u001b[90m (50)\u001b[39m\n",
    );

    expect(result.status).toBe(0);
    expect(result.stdout).toBe("50\n");
    expect(result.stderr).toBe("");
  });
});

describe("scripts/parse-vitest-summary.sh count helpers (sourced by both consumers)", () => {
  it.each([
    ["17345", "17345", "eq"],
    ["17344", "17345", "lt"],
    ["17346", "17345", "gt"],
    ["0", "0", "eq"],
    ["0", "1", "lt"],
    ["99999", "100000", "lt"],
    ["123456", "99999", "gt"],
    ["1234567", "1234567", "eq"],
    ["1234567", "1234568", "lt"],
    ["7654321", "1234567", "gt"],
    ["9223372036854775807", "9223372036854775808", "lt"],
    [WRAPS_TO_17345, "17345", "gt"],
    ["17345", WRAPS_TO_17345, "lt"],
    [WRAPS_TO_17345, WRAPS_TO_17345, "eq"],
    ["18446744073709568962", WRAPS_TO_17345, "gt"],
  ])("compare_counts %s %s prints %s", (a, b, expected) => {
    const result = runHelper("compare_counts", [a, b]);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(`${expected}\n`);
    expect(result.stderr).toBe("");
  });

  it.each([
    ["empty", ""],
    ["leading zero", "007"],
    ["negative", "-1"],
    ["plus sign", "+1"],
    ["embedded space", "1 2"],
    ["embedded newline", "50\n51"],
    ["non-digit", "12a"],
    ["decimal", "1.5"],
  ])("compare_counts refuses a %s operand with a named error and no relation", (_label, bad) => {
    for (const args of [
      [bad, "17345"],
      ["17345", bad],
    ]) {
      const result = runHelper("compare_counts", args);

      expect(result.status).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("must be a canonical non-negative integer");
    }
  });

  it.each([
    ["one count and a trailing newline", "17345\n", "17345"],
    ["one count with no trailing newline", "17345", "17345"],
    ["zero", "0\n", "0"],
    ["a 20-digit count", `${WRAPS_TO_17345}\n`, WRAPS_TO_17345],
  ])("read_canonical_floor accepts %s", (_label, raw, expected) => {
    const result = runHelper("read_canonical_floor", [], raw);

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(`${expected}\n`);
    expect(result.stderr).toBe("");
  });

  it.each([
    ["an embedded space", "123 4567\n"],
    ["an embedded newline", "123\n4567\n"],
    ["CRLF", "17345\r\n"],
    ["a second trailing newline", "17345\n\n"],
    ["a trailing space", "17345 \n"],
    ["a leading space", " 17345\n"],
    ["a tab", "17345\t\n"],
    ["an embedded NUL byte", "173\u000045\n"],
    ["a leading zero", "007\n"],
    ["a sign", "+17345\n"],
    ["an empty file", ""],
    ["a lone newline", "\n"],
  ])("read_canonical_floor refuses %s instead of normalizing it", (_label, raw) => {
    const result = runHelper("read_canonical_floor", [], raw);

    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("at most one trailing newline");
  });

  it("count_difference states a short difference exactly and never prints a wrapped number", () => {
    expect(runHelper("count_difference", ["1234567", "17345"]).stdout).toBe("1217222\n");
    expect(runHelper("count_difference", ["17345", "17345"]).stdout).toBe("0\n");

    const long = runHelper("count_difference", [WRAPS_TO_17345, "17345"]);
    expect(long.status).toBe(0);
    expect(long.stdout).toBe("(too long to subtract exactly)\n");
  });
});

describe("the pre-push hook compares counts only through the shared helper", () => {
  const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
  const hook = fs.readFileSync(path.join(REPO_ROOT, ".githooks", "pre-push"), "utf8");

  // Arithmetic comparison or subtraction on a whole count: the shape that
  // wraps silently past signed 64-bit range.
  const COUNT_ARITHMETIC = /\(\([^)]*\b(passing|baseline|prev_floor)\b[^)]*\)\)/;

  it("compares the floors and the passing count only through compare_counts", () => {
    expect(hook).toContain("source scripts/parse-vitest-summary.sh");
    expect(hook).toMatch(/compare_counts "\$baseline" "\$prev_floor"/);
    expect(hook).toMatch(/compare_counts "\$passing" "\$baseline"/);
    expect(hook).not.toMatch(COUNT_ARITHMETIC);
  });
});
