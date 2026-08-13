import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import packageJson from "../../package.json";

import {
  AGENT_INSTALL_CONTRACT,
  buildAgentInstallPlan,
  runInstallCommand,
  type AgentInstallOps,
  type InstallProbeResult,
} from "../../src/cli/install.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";

class Capture extends Writable {
  chunks: string[] = [];
  _write(
    chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

function observed(overrides: Partial<InstallProbeResult> = {}): InstallProbeResult {
  return {
    cooperativeWrap: "absent",
    persistentCli: "present",
    persistentCliPath: "/usr/local/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
    persistentCliVersion: packageJson.version,
    nodePath: "/opt/homebrew/bin/node",
    castleWallApp: "not-applicable",
    castleWallBuildSha: "a61a7322ca80",
    systemExtension: "not-applicable",
    bootService: "not-applicable",
    contentFilter: "not-applicable",
    enforcement: "not-applicable",
    ...overrides,
  };
}

describe("sanctuary install agent contract", () => {
  it("is exposed as a top-level completion subcommand", () => {
    expect(TOP_LEVEL_SUBCOMMANDS).toContain("install");
  });

  it("returns one resumable agent action for an absent memory wrap", () => {
    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed(),
    });

    expect(plan.contract).toBe(AGENT_INSTALL_CONTRACT);
    expect(plan.status).toBe("agent_action");
    expect(plan.next_action?.argv).toEqual([
      "/opt/homebrew/bin/node",
      "/usr/local/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
      "protect",
      "--claude-code",
      "--no-open",
      "--agent-guided",
      "--no-provision-agent-account",
    ]);
    expect(JSON.stringify(plan)).not.toMatch(/passphrase['"\s]*:/i);
  });

  it("replaces a stale persistent CLI before returning feature-bearing actions", () => {
    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        persistentCli: "mismatch",
        persistentCliVersion: "1.3.0-rc.1",
      }),
    });

    expect(plan.status).toBe("agent_action");
    expect(plan.next_action?.id).toBe("install_persistent_cli");
    expect(plan.next_action?.argv).toEqual([
      "npm",
      "install",
      "-g",
      `@sanctuary-framework/mcp-server@${packageJson.version}`,
    ]);
  });

  it("marks memory mechanics complete but keeps recovery custody human-only", () => {
    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({ cooperativeWrap: "present" }),
    });

    expect(plan.status).toBe("complete");
    expect(plan.next_action).toBeNull();
    expect(plan.operator_actions).toHaveLength(1);
    expect(plan.operator_actions[0]?.actor).toBe("human");
    expect(plan.operator_actions[0]?.secret_boundary).toContain("must not run");
  });

  it("refuses to guess or download a full-profile enforcement artifact", () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        cooperativeWrap: "present",
        castleWallApp: "absent",
        castleWallBuildSha: null,
        systemExtension: "not loaded",
        bootService: "absent",
        contentFilter: "disabled",
        enforcement: "unavailable",
      }),
    });

    expect(plan.status).toBe("blocked");
    expect(plan.next_action).toBeNull();
    expect(plan.notes.join(" ")).toContain("never guesses or downloads");
  });

  it("makes Apple approval an explicit human checkpoint", () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        cooperativeWrap: "present",
        castleWallApp: "present",
        castleWallBuildSha: "a61a7322ca80",
        systemExtension: "[activated waiting for user]",
        bootService: "absent",
        contentFilter: "disabled",
        enforcement: "unavailable",
      }),
    });

    expect(plan.status).toBe("human_action");
    expect(plan.next_action?.actor).toBe("human");
    expect(plan.next_action?.id).toBe("approve_macos_enforcement");
    expect(plan.next_action?.argv).toBeUndefined();
  });

  it("keeps the exact privileged Hermes flow human-executed after consent", () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        cooperativeWrap: "present",
        castleWallApp: "present",
        systemExtension: "[activated enabled]",
        bootService: "absent",
        contentFilter: "disabled",
        enforcement: "unavailable",
      }),
    });

    expect(plan.status).toBe("human_action");
    expect(plan.next_action?.actor).toBe("human");
    expect(plan.next_action?.argv).toEqual([
      "sudo",
      "/usr/bin/env",
      "SANCTUARY_CASTLE_BUILD_SHA=a61a7322ca80",
      "SANCTUARY_CASTLE_SIGNER_CLIENT=/Applications/Sanctuary-CastleWall.app/Contents/MacOS/castle-wall-signer-client",
      "/opt/homebrew/bin/node",
      "/usr/local/lib/node_modules/@sanctuary-framework/mcp-server/dist/cli.js",
      "--fortress",
      "/tmp/fortress",
      "protect",
      "--hermes",
      "--no-open",
      "--provision-agent-account",
      "--agent-guided",
    ]);
  });

  it("requires every full-profile enforcement observation before completion", () => {
    const complete = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        cooperativeWrap: "present",
        castleWallApp: "present",
        systemExtension: "[activated enabled]",
        bootService: "present",
        contentFilter: "enabled",
        enforcement: "live",
      }),
    });
    const notComplete = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        cooperativeWrap: "present",
        castleWallApp: "present",
        systemExtension: "[activated enabled]",
        bootService: "present",
        contentFilter: "enabled",
        enforcement: "undetermined",
      }),
    });

    expect(complete.status).toBe("complete");
    expect(notComplete.status).toBe("human_action");
  });

  it("renders the machine-readable plan without running an action", async () => {
    const out = new Capture();
    const probe: AgentInstallOps["probe"] = async () =>
      observed({ cooperativeWrap: "present" });
    const code = await runInstallCommand({
      argv: ["--profile", "memory", "--harness", "hermes", "--json"],
      out,
      err: new Capture(),
      env: { SANCTUARY_STORAGE_PATH: "/tmp/fortress" },
      platform: "darwin",
      ops: { probe },
    });

    expect(code).toBe(0);
    expect(JSON.parse(out.text())).toMatchObject({
      contract: AGENT_INSTALL_CONTRACT,
      status: "complete",
      fortress: "/tmp/fortress",
    });
  });
});
