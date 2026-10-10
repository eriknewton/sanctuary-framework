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
