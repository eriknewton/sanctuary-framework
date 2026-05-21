/**
 * `sanctuary audit-chain export --help` and `sanctuary audit-chain verify --help`
 *
 * Regression tests for finding QQQQ: --help was falling through to argparse
 * which complained about missing required args instead of printing usage.
 */

import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const CLI_PATH = join(__dirname, "../../dist/cli.js");

async function runCli(...args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const result = await execFileAsync("node", [CLI_PATH, ...args], {
      timeout: 10000,
      env: { ...process.env, NODE_NO_WARNINGS: "1" },
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (err: any) {
    return {
      code: err.code ?? 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
    };
  }
}

describe("sanctuary audit-chain --help (QQQQ)", () => {
  it("audit-chain export --help exits 0 and prints usage", async () => {
    const { code, stderr } = await runCli("audit-chain", "export", "--help");
    expect(code).toBe(0);
    expect(stderr).toContain("Usage: sanctuary audit-chain export");
    expect(stderr).toContain("--output");
    expect(stderr).not.toContain("Error");
  });

  it("audit-chain verify --help exits 0 and prints usage", async () => {
    const { code, stderr } = await runCli("audit-chain", "verify", "--help");
    expect(code).toBe(0);
    expect(stderr).toContain("Usage: sanctuary audit-chain verify");
    expect(stderr).toContain("--input");
    expect(stderr).not.toContain("Error");
  });

  it("audit-chain --help exits 0 and lists subcommands", async () => {
    const { code, stderr } = await runCli("audit-chain", "--help");
    expect(code).toBe(0);
    expect(stderr).toContain("export");
    expect(stderr).toContain("verify");
  });

  it("audit-chain export -h also works", async () => {
    const { code, stderr } = await runCli("audit-chain", "export", "-h");
    expect(code).toBe(0);
    expect(stderr).toContain("Usage: sanctuary audit-chain export");
  });
});
