import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli, runCliRaw, CLI_SUBPROCESS_TEST_TIMEOUT_MS } from "./helpers/run-cli";

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

  it("sanctuary init failures print an init-specific error", async () => {
    const { code, stderr } = await runCli("init", "--recovery-out");

    expect(code).toBe(1);
    expect(stderr).toContain("Sanctuary init failed:");
    expect(stderr).toContain("--recovery-out requires a path value");
    expect(stderr).not.toContain("Sanctuary MCP Server failed to start");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);

  it("sanctuary init runInit failures print an init-specific error", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-init-cli-test-"));
    try {
      const fortress = join(tmp, "fortress");
      const recoveryOut = join(fortress, "recovery-key.txt");
      const { code, stderr } = await runCli(
        "init",
        "--fortress",
        fortress,
        "--recovery-out",
        recoveryOut,
        "--no-confirm",
        "--no-pin",
        "--no-identity",
      );

      expect(code).toBe(1);
      expect(stderr).toContain("Sanctuary init failed:");
      expect(stderr).toContain("Recovery key output path must be outside");
      expect(stderr).not.toContain("Sanctuary MCP Server failed to start");
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
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
    // Point the host-app override at a path that cannot exist so status never
    // probes a real installed Castle Wall app (slow + machine-dependent); an
    // unresolvable binary makes the content-filter probe stay silent.
    const { code, stderr } = await runCliRaw(["castle-wall", "status"], {
      env: { SANCTUARY_CASTLE_HOSTAPP: "/nonexistent/CastleWallHostApp" },
    });

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
