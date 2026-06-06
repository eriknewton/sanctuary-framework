/**
 * `sanctuary audit-chain export --help` and `sanctuary audit-chain verify --help`
 *
 * Regression tests for finding QQQQ: --help was falling through to argparse
 * which complained about missing required args instead of printing usage.
 */

import { describe, it, expect } from "vitest";
import { runCli, CLI_SUBPROCESS_TEST_TIMEOUT_MS } from "./helpers/run-cli";

describe("sanctuary audit-chain --help (QQQQ)", () => {
  it("audit-chain export --help exits 0 and prints usage", async () => {
    const { code, stderr } = await runCli("audit-chain", "export", "--help");
    expect(code).toBe(0);
    expect(stderr).toContain("Usage: sanctuary audit-chain export");
    expect(stderr).toContain("--output");
    expect(stderr).not.toContain("Error");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("audit-chain verify --help exits 0 and prints usage", async () => {
    const { code, stderr } = await runCli("audit-chain", "verify", "--help");
    expect(code).toBe(0);
    expect(stderr).toContain("Usage: sanctuary audit-chain verify");
    expect(stderr).toContain("--input");
    expect(stderr).not.toContain("Error");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("audit-chain --help exits 0 and lists subcommands", async () => {
    const { code, stderr } = await runCli("audit-chain", "--help");
    expect(code).toBe(0);
    expect(stderr).toContain("export");
    expect(stderr).toContain("verify");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("audit-chain export -h also works", async () => {
    const { code, stderr } = await runCli("audit-chain", "export", "-h");
    expect(code).toBe(0);
    expect(stderr).toContain("Usage: sanctuary audit-chain export");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});
