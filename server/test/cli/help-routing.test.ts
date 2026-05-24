import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const CLI_PATH = join(__dirname, "../../dist/cli.js");

async function runCli(
  ...args: string[]
): Promise<{ code: number; stdout: string; stderr: string }> {
  const env = { ...process.env, NODE_NO_WARNINGS: "1" };
  delete env.SANCTUARY_PASSPHRASE;

  try {
    const result = await execFileAsync("node", [CLI_PATH, ...args], {
      timeout: 10000,
      env,
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

describe("CLI help routing", () => {
  it("sanctuary agents --help exits 0 without SANCTUARY_PASSPHRASE", async () => {
    const { code, stdout, stderr } = await runCli("agents", "--help");

    expect(code).toBe(0);
    expect(stderr).toBe("");
    expect(stdout).toContain("Usage: sanctuary agents <command>");
    expect(stdout).toContain("list [--json]");
    expect(stdout).not.toContain("passphrase required");
  });

  it("sanctuary wrap --help prints wrap-specific help", async () => {
    const { code, stdout } = await runCli("wrap", "--help");

    expect(code).toBe(0);
    expect(stdout).toContain("sanctuary wrap. Wrap any agent");
    expect(stdout).toContain("--openclaw");
    expect(stdout).toContain("--dashboard-port <port>");
    expect(stdout).not.toContain("Sovereignty infrastructure for agents");
  });

  it("sanctuary exit --help prints exit-specific help", async () => {
    const { code, stdout } = await runCli("exit", "--help");

    expect(code).toBe(0);
    expect(stdout).toContain("Usage: sanctuary exit <command> [options]");
    expect(stdout).toContain("SANCTUARY_EXIT_BUNDLE_V1");
    expect(stdout).not.toContain("Sovereignty infrastructure for agents");
  });

  it("sanctuary castle-wall prints castle-wall help instead of starting MCP", async () => {
    const { code, stdout, stderr } = await runCli("castle-wall");

    expect(code).toBe(0);
    expect(stdout).toContain("Usage:");
    expect(stdout).toContain("sanctuary castle-wall");
    expect(stderr).not.toContain("Sanctuary MCP Server");
  });

  it("sanctuary castle-wall status runs without starting MCP", async () => {
    const { code, stdout, stderr } = await runCli("castle-wall", "status");

    expect(code).toBe(0);
    expect(stderr).not.toContain("Sanctuary MCP Server");
  });

  it("sanctuary --help still prints top-level help", async () => {
    const { code, stdout } = await runCli("--help");

    expect(code).toBe(0);
    expect(stdout).toContain("Sovereignty infrastructure for agents");
    expect(stdout).toContain("Usage:");
    expect(stdout).toContain("sanctuary [options]");
  });
});
