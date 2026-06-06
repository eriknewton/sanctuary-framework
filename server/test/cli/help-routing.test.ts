import { describe, it, expect } from "vitest";
import { runCli, CLI_SUBPROCESS_TEST_TIMEOUT_MS } from "./helpers/run-cli";

describe("CLI help routing", () => {
  it("sanctuary agents --help exits 0 without SANCTUARY_PASSPHRASE", async () => {
    const { code, stdout, stderr } = await runCli("agents", "--help");

    expect(code).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).toContain("Usage: sanctuary agents <command>");
    expect(stdout).toContain("list [--json]");
    expect(stdout).not.toContain("passphrase required");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("sanctuary wrap --help prints protect-specific help (wrap is alias for protect)", async () => {
    const { code, stdout } = await runCli("wrap", "--help");

    expect(code).toBe(0);
    expect(stdout).toContain("sanctuary protect. Protect any agent");
    expect(stdout).toContain("--openclaw");
    expect(stdout).toContain("--dashboard-port <port>");
    expect(stdout).not.toContain("Sovereignty infrastructure for agents");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("sanctuary exit --help prints exit-specific help", async () => {
    const { code, stdout } = await runCli("exit", "--help");

    expect(code).toBe(0);
    expect(stdout).toContain("Usage: sanctuary exit <command> [options]");
    expect(stdout).toContain("SANCTUARY_EXIT_BUNDLE_V1");
    expect(stdout).not.toContain("Sovereignty infrastructure for agents");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("sanctuary castle-wall prints castle-wall help instead of starting MCP", async () => {
    const { code, stdout, stderr } = await runCli("castle-wall");

    expect(code).toBe(0);
    expect(stdout).toContain("Usage:");
    expect(stdout).toContain("sanctuary castle-wall");
    expect(stderr).not.toContain("Sanctuary MCP Server");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("sanctuary castle-wall status runs without starting MCP", async () => {
    const { code, stdout, stderr } = await runCli("castle-wall", "status");

    expect(code).toBe(0);
    expect(stderr).not.toContain("Sanctuary MCP Server");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("sanctuary --help still prints top-level help", async () => {
    const { code, stdout } = await runCli("--help");

    expect(code).toBe(0);
    expect(stdout).toContain("Sovereignty infrastructure for agents");
    expect(stdout).toContain("Usage:");
    expect(stdout).toContain("sanctuary [options]");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});
