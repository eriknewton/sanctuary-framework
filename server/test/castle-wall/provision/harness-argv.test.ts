/**
 * Tests for Hermes gateway argv resolution (D1: the headless
 * `ai.hermes.gateway` egress-making process, never a GUI .app): resolves to
 * the re-homed Hermes runtime tree, fail-closed (throws) when it is absent.
 */

import { describe, it, expect } from "vitest";

import { resolveHermesGatewayArgv, type HarnessArgvOps } from "../../../src/castle-wall/provision/harness-argv.js";

function mockOps(existing: Set<string>): HarnessArgvOps {
  return { pathExists: async (path) => existing.has(path) };
}

describe("castle-wall/provision/harness-argv", () => {
  const agentHome = "/var/sanctuary-agents/sanctuary-hermes";
  const hermesAgentDir = `${agentHome}/.hermes/hermes-agent`;
  const systemPython = "/opt/homebrew/bin/python3";
  const mainModule = `${hermesAgentDir}/hermes_cli/main.py`;
  const sitePackages = `${hermesAgentDir}/venv/lib/python3.11/site-packages`;

  it("resolves the re-homed Hermes runtime with the hermes_cli gateway args and launchd env", async () => {
    const ops = mockOps(new Set([systemPython, mainModule, sitePackages]));
    const resolved = await resolveHermesGatewayArgv(ops, { agentHome });
    expect(resolved.harnessId).toBe("hermes");
    expect(resolved.programArguments).toEqual([
      systemPython,
      "-m",
      "hermes_cli.main",
      "gateway",
      "run",
      "--accept-hooks",
    ]);
    expect(resolved.environment).toEqual({
      HERMES_ACCEPT_HOOKS: "1",
      HOME: agentHome,
      PYTHONPATH: `${hermesAgentDir}:${sitePackages}`,
    });
  });

  it("every resolved program path is absolute (never a relative/guessed path)", async () => {
    const ops = mockOps(new Set([systemPython, mainModule, sitePackages]));
    const resolved = await resolveHermesGatewayArgv(ops, { agentHome });
    expect(resolved.programArguments[0]?.startsWith("/")).toBe(true);
  });

  it("fail-closed: throws when the re-homed runtime is absent (never guesses a global python)", async () => {
    const ops = mockOps(new Set(["/opt/homebrew/bin/python3"]));
    await expect(resolveHermesGatewayArgv(ops, { agentHome })).rejects.toThrow(/re-homed Hermes runtime/);
  });

  it("fail-closed: throws when system Python exists but hermes_cli is absent", async () => {
    const ops = mockOps(new Set([systemPython, sitePackages]));
    await expect(resolveHermesGatewayArgv(ops, { agentHome })).rejects.toThrow(/re-homed Hermes runtime/);
  });

  it("fail-closed: throws when the runtime exists but site-packages are absent", async () => {
    const ops = mockOps(new Set([systemPython, mainModule]));
    await expect(resolveHermesGatewayArgv(ops, { agentHome })).rejects.toThrow(/site-packages/);
  });
});
