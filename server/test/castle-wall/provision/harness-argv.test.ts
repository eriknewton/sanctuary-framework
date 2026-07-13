/**
 * Tests for Hermes gateway argv resolution (D1: the headless
 * `ai.hermes.gateway` egress-making process, never a GUI .app): resolves to
 * the first existing absolute python3 candidate, fail-closed (throws) when
 * none exist.
 */

import { describe, it, expect } from "vitest";

import { resolveHermesGatewayArgv, type HarnessArgvOps } from "../../../src/castle-wall/provision/harness-argv.js";

function mockOps(existing: Set<string>): HarnessArgvOps {
  return { pathExists: async (path) => existing.has(path) };
}

describe("castle-wall/provision/harness-argv", () => {
  it("resolves to the first existing candidate interpreter with the hermes_cli gateway args", async () => {
    const ops = mockOps(new Set(["/opt/homebrew/bin/python3"]));
    const resolved = await resolveHermesGatewayArgv(ops);
    expect(resolved.harnessId).toBe("hermes");
    expect(resolved.programArguments).toEqual([
      "/opt/homebrew/bin/python3",
      "-m",
      "hermes_cli.main",
      "gateway",
    ]);
  });

  it("prefers /usr/local/bin/python3 over later candidates when multiple exist", async () => {
    const ops = mockOps(new Set(["/usr/local/bin/python3", "/usr/bin/python3"]));
    const resolved = await resolveHermesGatewayArgv(ops);
    expect(resolved.programArguments[0]).toBe("/usr/local/bin/python3");
  });

  it("every resolved program path is absolute (never a relative/guessed path)", async () => {
    const ops = mockOps(new Set(["/usr/bin/python3"]));
    const resolved = await resolveHermesGatewayArgv(ops);
    expect(resolved.programArguments[0]?.startsWith("/")).toBe(true);
  });

  it("fail-closed: throws when no candidate interpreter exists (never installs with a guessed path)", async () => {
    const ops = mockOps(new Set());
    await expect(resolveHermesGatewayArgv(ops)).rejects.toThrow(/Could not resolve/);
  });
});
