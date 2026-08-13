import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";

import {
  AGENT_INSTALL_CONTRACT,
  buildAgentInstallPlan,
  runInstallCommand,
  verifyCastleWallRuntimeManifest,
  type AgentInstallOps,
  type InstallProbeResult,
} from "../../src/cli/install.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";

const require = createRequire(import.meta.url);
const packageJson = require("../../package.json") as { version: string };

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
    packageManagerPath: "/opt/homebrew/bin/npm",
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

function fullObserved(overrides: Partial<InstallProbeResult> = {}): InstallProbeResult {
  return observed({
    persistentCli: "present",
    persistentCliPath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
    persistentCliVersion: packageJson.version,
    nodePath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
    castleWallApp: "present",
    ...overrides,
  });
}

describe("sanctuary install agent contract", () => {
  it("rejects a tampered sealed-runtime manifest payload", async () => {
    const contents = await mkdtemp(join(tmpdir(), "sanctuary-runtime-manifest-"));
    try {
      const paths = [
        "MacOS/sanctuary",
        "Resources/boot-runtime/node",
        "Resources/cli-runtime/dist/cli.js",
      ];
      for (const path of paths) {
        await mkdir(dirname(join(contents, path)), { recursive: true });
        await writeFile(join(contents, path), path);
      }
      const files = await Promise.all(paths.map(async (path) => {
        const bytes = await readFile(join(contents, path));
        return {
          path,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          size: bytes.length,
        };
      }));
      const bytes = Buffer.from(`${JSON.stringify({
        schema: "sanctuary.castle-wall-cli-runtime.v1",
        source_sha: "a".repeat(40),
        cli_version: packageJson.version,
        node_version: "v22.0.0",
        files,
      })}\n`);
      await expect(verifyCastleWallRuntimeManifest(bytes, contents, {
        sourceSha: "a".repeat(40), nodeVersion: "v22.0.0",
      })).resolves.toBe(true);
      await writeFile(join(contents, "Resources/cli-runtime/dist/cli.js"), "tampered");
      await expect(verifyCastleWallRuntimeManifest(bytes, contents, {
        sourceSha: "a".repeat(40), nodeVersion: "v22.0.0",
      })).resolves.toBe(false);
    } finally {
      await rm(contents, { recursive: true, force: true });
    }
  });

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
      "--fortress",
      "/tmp/fortress",
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
      "/opt/homebrew/bin/npm",
      "install",
      "-g",
      `@sanctuary-framework/mcp-server@${packageJson.version}`,
    ]);
  });

  it("blocks cleanly when a pristine host has neither npm nor a trusted bundled CLI", () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        persistentCli: "absent",
        persistentCliPath: null,
        persistentCliVersion: null,
        packageManagerPath: null,
        nodePath: "/Applications/Sanctuary-CastleWall.app/Contents/Resources/boot-runtime/node",
        castleWallApp: "present",
        systemExtension: "not loaded",
      }),
    });

    expect(plan.status).toBe("blocked");
    expect(plan.next_action).toBeNull();
    expect(plan.notes.join(" ")).toContain("never falls back to npm");
    expect(plan.notes.join(" ")).toContain("verified signed Castle Wall app");
  });

  it("resumes from the signed app runtime without npm after a clean-host handoff", () => {
    const blocked = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: observed({
        persistentCli: "absent",
        persistentCliPath: null,
        persistentCliVersion: null,
        packageManagerPath: null,
      }),
    });
    const resumed = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved({
        persistentCliPath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
        packageManagerPath: null,
        nodePath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
        castleWallApp: "present",
        systemExtension: "not loaded",
      }),
    });

    expect(blocked.status).toBe("blocked");
    expect(resumed.status).toBe("agent_action");
    expect(resumed.next_action?.id).toBe("install_cooperative_surface");
    expect(resumed.next_action?.argv?.[0]).toBe(
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
    );
    expect(resumed.next_action?.argv).not.toContain("npm");
    expect(resumed.next_action?.argv).not.toContain("npx");
    expect(resumed.next_action?.argv).not.toContain("node");
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
      observed: fullObserved({
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
      observed: fullObserved({
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
      observed: fullObserved({
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
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
      "--fortress",
      "/tmp/fortress",
      "protect",
      "--hermes",
      "--no-open",
      "--provision-agent-account",
      "--agent-guided",
      "--sealed-launcher",
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
    ]);
  });

  it("requires every full-profile enforcement observation before completion", () => {
    const complete = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved({
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
      observed: fullObserved({
        cooperativeWrap: "present",
        castleWallApp: "present",
        systemExtension: "[activated enabled]",
        bootService: "present",
        contentFilter: "enabled",
        enforcement: "undetermined",
      }),
    });
    const unknownExtension = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved({
        cooperativeWrap: "present",
        castleWallApp: "present",
        systemExtension: "unknown",
        bootService: "present",
        contentFilter: "enabled",
        enforcement: "live",
      }),
    });
    const malformedBuildSha = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved({
        cooperativeWrap: "present",
        castleWallApp: "present",
        castleWallBuildSha: "bad value &&",
        systemExtension: "[activated enabled]",
        bootService: "present",
        contentFilter: "enabled",
        enforcement: "live",
      }),
    });

    expect(complete.status).toBe("complete");
    expect(notComplete.status).toBe("human_action");
    expect(unknownExtension.status).toBe("blocked");
    expect(malformedBuildSha.status).toBe("blocked");
    expect(malformedBuildSha.next_action).toBeNull();
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
