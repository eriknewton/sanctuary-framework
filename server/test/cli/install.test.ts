import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Writable } from "node:stream";
import { describe, expect, it, vi } from "vitest";

import {
  AGENT_INSTALL_CONTRACT,
  buildAgentInstallPlan,
  parseInstallSystemExtensionState,
  runInstallCommand,
  verifyCastleWallRuntimeManifest,
  type AgentInstallOps,
  type AgentInstallPlan,
  type InstallProbeResult,
} from "../../src/cli/install.js";
import { parseWrapArgs, runWrap, type WrapOptions } from "../../src/wrap/cli.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";

const require = createRequire(import.meta.url);
const packageJson = require("../../package.json") as { version: string };

async function executeOnePlannedAction(
  plan: AgentInstallPlan,
  run: (argv: string[]) => Promise<number>,
  rerunPlanner: () => Promise<void>,
): Promise<AgentInstallPlan["next_action"]> {
  const action = plan.next_action;
  if (plan.status !== "agent_action" || action?.actor !== "agent" || action.argv === undefined) {
    throw new Error("plan did not contain one executable agent action");
  }
  const code = await run(action.argv);
  if (code === 0) {
    await rerunPlanner();
    return null;
  }
  if (action.on_nonzero === undefined) {
    throw new Error("agent action had no declared nonzero transition");
  }
  return action.on_nonzero;
}

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
    existingCustody: "present",
    nodePath: "/opt/homebrew/bin/node",
    castleWallApp: "not-applicable",
    castleWallBuildSha: "a61a7322ca80",
    systemExtension: "not-applicable",
    bootService: "not-applicable",
    contentFilter: "not-applicable",
    enforcement: "not-applicable",
    operatorTwin: "not-applicable",
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
    operatorTwin: "absent",
    ...overrides,
  });
}

describe("sanctuary install agent contract", () => {
  it("observes an active replacement beside a terminated prior system extension", () => {
    const terminated =
      "YFQSWQ9BJN ai.sanctuaryprotocol.macos.castle-wall (0.1.0/1407) CastleWallExtension [terminated waiting to uninstall on reboot]";
    const active =
      "* * YFQSWQ9BJN ai.sanctuaryprotocol.macos.castle-wall (0.1.0/1408) CastleWallExtension [activated enabled]";
    const waiting =
      "* - YFQSWQ9BJN ai.sanctuaryprotocol.macos.castle-wall (0.1.0/1408) CastleWallExtension [activated waiting for user]";
    const lookalike =
      "* * YFQSWQ9BJN ai.sanctuaryprotocol.macos.castle-wall-dev (0.1.0/9999) CastleWallDevExtension [activated enabled]";

    expect(parseInstallSystemExtensionState(`${terminated}\n${active}`)).toBe(
      "[activated enabled]",
    );
    expect(parseInstallSystemExtensionState(`${active}\n${terminated}`)).toBe(
      "[activated enabled]",
    );
    expect(parseInstallSystemExtensionState(`${terminated}\n${waiting}`)).toBe(
      "[activated waiting for user]",
    );
    expect(parseInstallSystemExtensionState(`${waiting}\n${terminated}`)).toBe(
      "[activated waiting for user]",
    );
    expect(
      parseInstallSystemExtensionState(`${terminated}\n${terminated}\n${active}`),
    ).toBe("[activated enabled]");
    expect(parseInstallSystemExtensionState(`${terminated}\n${lookalike}`)).toBe(
      "not loaded",
    );
    expect(parseInstallSystemExtensionState(terminated)).toBe("not loaded");
    expect(
      parseInstallSystemExtensionState(
        "YFQSWQ9BJN ai.sanctuaryprotocol.macos.castle-wall CastleWallExtension",
      ),
    ).toBe("not loaded");
    expect(parseInstallSystemExtensionState("No extensions")).toBe("not loaded");
  });

  it("rejects a tampered sealed-runtime manifest payload", async () => {
    const contents = await mkdtemp(join(tmpdir(), "sanctuary-runtime-manifest-"));
    try {
      const paths = [
        "MacOS/sanctuary",
        "Resources/boot-runtime/node",
        "Resources/cli-runtime/dist/cli.js",
        "Resources/cli-runtime/package.json",
        "Resources/cli-runtime/node_modules/@lmdb/lmdb-darwin-arm64/node.napi.node",
        "Resources/cli-runtime/node_modules/@msgpackr-extract/msgpackr-extract-darwin-arm64/node.napi.glibc.node",
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
      const manifest = {
        schema: "sanctuary.castle-wall-cli-runtime.v1",
        source_sha: "a".repeat(40),
        cli_version: packageJson.version,
        node_version: "v22.0.0",
        inventory: {
          file_count: files.length,
          total_bytes: files.reduce((sum, entry) => sum + entry.size, 0),
          package_count: 1,
          package_json_count: 1,
          package_internal_json_count: 0,
          nested_package_count: 0,
          packages: [{
            path: "Resources/cli-runtime/package.json",
            name: "@sanctuary-framework/mcp-server",
            version: packageJson.version,
          }],
          mach_o_count: 2,
          mach_o: paths.slice(-2),
        },
        files,
      };
      const bytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
      await expect(verifyCastleWallRuntimeManifest(bytes, contents, {
        sourceSha: "a".repeat(40), nodeVersion: "v22.0.0",
      })).resolves.toBe(true);
      for (const invalid of [
        {
          ...manifest,
          inventory: {
            ...manifest.inventory,
            file_count: manifest.inventory.file_count + 1,
            total_bytes: manifest.inventory.total_bytes + files[0]!.size,
          },
          files: [...files, files[0]!],
        },
        {
          ...manifest,
          inventory: {
            ...manifest.inventory,
            mach_o_count: manifest.inventory.mach_o_count + 1,
            mach_o: [...manifest.inventory.mach_o, manifest.inventory.mach_o[0]!],
          },
        },
        {
          ...manifest,
          inventory: {
            ...manifest.inventory,
            package_count: 2,
            packages: [
              manifest.inventory.packages[0]!,
              manifest.inventory.packages[0]!,
            ],
          },
        },
      ]) {
        await expect(verifyCastleWallRuntimeManifest(
          Buffer.from(`${JSON.stringify(invalid)}\n`),
          contents,
          { sourceSha: "a".repeat(40), nodeVersion: "v22.0.0" },
        )).resolves.toBe(false);
      }
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

  it("resumes from the signed app runtime into an exact human first-custody action", () => {
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
        existingCustody: "absent",
        persistentCliPath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
        packageManagerPath: null,
        nodePath: "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
        castleWallApp: "present",
        systemExtension: "not loaded",
      }),
    });

    expect(blocked.status).toBe("blocked");
    expect(resumed.status).toBe("human_action");
    expect(resumed.next_action?.id).toBe("prepare_local_keychain_session");
    expect(resumed.next_action?.argv?.[0]).toBe(
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
    );
    expect(resumed.next_action?.argv).not.toContain("npm");
    expect(resumed.next_action?.argv).not.toContain("npx");
    expect(resumed.next_action?.argv).not.toContain("node");
    expect(resumed.next_action?.argv).toContain("--operator-custody");
  });

  it("executes the release workflow's literal extracted-plan assertion fail closed", async () => {
    const workflow = await readFile(
      join(process.cwd(), "..", ".github", "workflows", "castle-wall-macos-release.yml"),
      "utf8",
    );
    const extracted = workflow.match(
      /printf '%s' "\$PLAN_JSON" \| EXPECTED_FORTRESS="\$ARTIFACT_CHECK_DIR\/fortress" node -e '\n([\s\S]*?)\n\s*'/,
    );
    expect(extracted?.[1]).toBeDefined();
    const assertion = extracted![1]!.replace(/^ {12}/gm, "");
    const cwd = await mkdtemp(join(tmpdir(), "sanctuary-release-plan-assertion-"));
    const fortress = join(cwd, "relative", "fortress");
    const valid = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress,
      platform: "darwin",
      observed: fullObserved({ existingCustody: "absent" }),
    });
    const run = (plan: AgentInstallPlan) => spawnSync(
      process.execPath,
      ["-e", assertion],
      {
        cwd,
        input: JSON.stringify(plan),
        encoding: "utf8",
        env: { ...process.env, EXPECTED_FORTRESS: fortress },
      },
    );
    try {
      expect(run(valid).status).toBe(0);
      const mutations: Array<[string, (plan: AgentInstallPlan) => void]> = [
        ["old agent status", (plan) => { plan.status = "agent_action"; }],
        ["wrong action id", (plan) => { plan.next_action!.id = "install_cooperative_surface"; }],
        ["wrong actor", (plan) => { plan.next_action!.actor = "agent"; }],
        ["wrong argv", (plan) => { plan.next_action!.argv![0] = "/tmp/not-the-signed-launcher"; }],
        ["npm insertion", (plan) => { plan.next_action!.argv!.splice(1, 0, "npm"); }],
        ["node insertion", (plan) => { plan.next_action!.argv!.splice(1, 0, "node"); }],
        ["missing secret boundary", (plan) => { delete plan.next_action!.secret_boundary; }],
      ];
      for (const [name, mutate] of mutations) {
        const invalid = structuredClone(valid);
        mutate(invalid);
        expect(run(invalid).status, name).not.toBe(0);
      }
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });

  it("executes a cooperative agent action once, never replans on nonzero, and hands off the exact safe action", async () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved(),
    });
    for (const failureClass of [
      "keychain rc36",
      "keychain write rc44",
      "unknown keychain failure",
      "unreadable existing fallback",
    ]) {
      const runs: string[][] = [];
      let replans = 0;
      const fallback = await executeOnePlannedAction(
        plan,
        async (argv) => {
          runs.push(argv);
          return 2;
        },
        async () => { replans += 1; },
      );
      expect(runs, failureClass).toEqual([plan.next_action!.argv]);
      expect(replans, failureClass).toBe(0);
      expect(fallback, failureClass).toEqual(plan.next_action!.on_nonzero);
      expect(fallback?.actor, failureClass).toBe("human");
      expect(fallback?.argv, failureClass).toContain("--operator-custody");
      expect(plan.next_action?.argv, failureClass).not.toContain("--operator-custody");
      expect(JSON.stringify(fallback), failureClass).not.toMatch(
        /(?:password|passphrase|recovery key|secret)["']?\s*:/i,
      );
    }
  });

  it("reruns the observed-state planner exactly once only after exit zero", async () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved(),
    });
    let executions = 0;
    let replans = 0;
    const fallback = await executeOnePlannedAction(
      plan,
      async () => { executions += 1; return 0; },
      async () => { replans += 1; },
    );
    expect(executions).toBe(1);
    expect(replans).toBe(1);
    expect(fallback).toBeNull();
  });

  it("makes true first macOS custody a secret-free human action", () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved({
        existingCustody: "absent",
      }),
    });

    expect(plan.status).toBe("human_action");
    expect(plan.next_action?.id).toBe("prepare_local_keychain_session");
    expect(plan.next_action?.actor).toBe("human");
    expect(plan.next_action?.argv).toEqual([
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
      "--fortress",
      "/tmp/fortress",
      "protect",
      "--hermes",
      "--no-open",
      "--agent-guided",
      "--sealed-launcher",
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
      "--operator-custody",
      "--no-provision-agent-account",
    ]);
    expect(plan.next_action?.description).toContain("private local desktop Terminal");
    expect(plan.next_action?.secret_boundary).toContain("Do not paste");
  });

  it("never declares the full surface complete while an operator Hermes twin is present or unknown", () => {
    for (const operatorTwin of ["present", "unknown"] as const) {
      const plan = buildAgentInstallPlan({
        profile: "full",
        harness: "hermes",
        fortress: "/tmp/fortress",
        platform: "darwin",
        observed: fullObserved({
          cooperativeWrap: "present",
          systemExtension: "[activated enabled]",
          bootService: "present",
          contentFilter: "enabled",
          enforcement: "live",
          operatorTwin,
        }),
      });

      expect(plan.status).toBe("blocked");
      expect(plan.next_action).toBeNull();
      expect(plan.notes.join(" ")).toMatch(/operator.*twin/i);
    }
  });

  it("never infers first-custody writability from the ambient session", () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved({
        existingCustody: "absent",
      }),
    });
    expect(plan.status).toBe("human_action");
    expect(plan.next_action?.actor).toBe("human");
    expect(plan.next_action?.argv?.[0]).toBe(
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
    );
  });

  it("preserves second-harness wrapping when existing custody is present", () => {
    const plan = buildAgentInstallPlan({
      profile: "full",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "darwin",
      observed: fullObserved({
        existingCustody: "present",
      }),
    });
    expect(plan.status).toBe("agent_action");
    expect(plan.next_action?.id).toBe("install_cooperative_surface");
    expect(plan.next_action?.argv).not.toContain("--operator-custody");
    expect(plan.next_action?.on_nonzero?.argv).toContain("--operator-custody");
  });

  it("uses a platform-accurate Secret Service fallback on Linux", () => {
    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "hermes",
      fortress: "/tmp/fortress",
      platform: "linux",
      observed: fullObserved({
        existingCustody: "absent",
        castleWallApp: "not-applicable",
        castleWallBuildSha: null,
        systemExtension: "not-applicable",
        bootService: "not-applicable",
        contentFilter: "not-applicable",
        enforcement: "not-applicable",
      }),
    });
    expect(plan.status).toBe("agent_action");
    expect(plan.next_action?.on_nonzero?.actor).toBe("human");
    expect(plan.next_action?.on_nonzero?.description).toContain("Secret Service");
    expect(plan.next_action?.on_nonzero?.description).not.toContain("Keychain");
    expect(plan.next_action?.on_nonzero?.argv).not.toContain("--operator-custody");
  });

  it("refuses direct agent first custody before any Hermes or fortress mutation", async () => {
    const home = await mkdtemp(join(tmpdir(), "sanctuary-keychain-preflight-"));
    const priorStorage = process.env.SANCTUARY_STORAGE_PATH;
    const exit = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code}`);
    }) as never);
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const fortress = join(home, ".sanctuary");
      await expect(runWrap({
        protectCommand: true,
        hermes: true,
        agentGuided: true,
        noOpen: true,
        provisionAgentAccount: false,
        fortress,
      }, {
        osPlatform: () => "darwin",
      })).rejects.toThrow("process.exit:2");
      expect(await readdir(home)).toEqual([]);
      expect(stderr.mock.calls.flat().join(" ")).toContain("--operator-custody");
    } finally {
      exit.mockRestore();
      stderr.mockRestore();
      if (priorStorage === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = priorStorage;
      expect(process.env.SANCTUARY_STORAGE_PATH).toBe(priorStorage);
      await rm(home, { recursive: true, force: true });
    }
  });

  it("acquires operator custody before config bootstrap and leaves zero files on failure", async () => {
    const home = await mkdtemp(join(tmpdir(), "sanctuary-operator-custody-fail-"));
    const priorStorage = process.env.SANCTUARY_STORAGE_PATH;
    try {
      const fortress = join(home, ".sanctuary");
      await expect(runWrap({
        protectCommand: true,
        hermes: true,
        agentGuided: true,
        operatorCustody: true,
        noOpen: true,
        provisionAgentAccount: false,
        fortress,
      }, {
        osPlatform: () => "darwin",
        resolvePassphrase: async () => {
          throw new Error("typed keychain write refusal");
        },
      })).rejects.toThrow("typed keychain write refusal");
      expect(await readdir(home)).toEqual([]);
    } finally {
      if (priorStorage === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = priorStorage;
      expect(process.env.SANCTUARY_STORAGE_PATH).toBe(priorStorage);
      await rm(home, { recursive: true, force: true });
    }
  });

  it("resolves successful operator custody once before bootstrap and consumes the cached value", async () => {
    const home = await mkdtemp(join(tmpdir(), "sanctuary-operator-custody-success-"));
    const priorHome = process.env.HOME;
    const priorStorage = process.env.SANCTUARY_STORAGE_PATH;
    let resolves = 0;
    let inventoryAtResolve: string[] | undefined;
    try {
      const fortress = join(home, ".sanctuary");
      process.env.HOME = home;
      await runWrap({
        protectCommand: true,
        claudeCode: true,
        agentGuided: true,
        operatorCustody: true,
        noOpen: true,
        provisionAgentAccount: false,
        fortress,
      }, {
        osPlatform: () => "darwin",
        resolvePassphrase: async () => {
          resolves += 1;
          inventoryAtResolve = await readdir(home);
          return {
            value: "operator-custody-test-value",
            location: "fixture-keychain",
            source: "generated",
          };
        },
        startDashboard: async () => ({
          url: "http://127.0.0.1:0",
          port: 0,
          host: "127.0.0.1",
          mode: "co-located",
          stop: async () => undefined,
          setV11Bindings: () => undefined,
          setV11LoopbackAutoAuth: () => undefined,
          updateSources: () => undefined,
        } as never),
        openBrowser: async () => undefined,
        installClaudeCodeAllowlist: async () => ({
          installedAt: join(home, ".claude", "settings.json"),
          alreadyPresent: true,
          added: [],
        }),
      });
      expect(resolves).toBe(1);
      expect(inventoryAtResolve).toEqual([]);
      expect(await readdir(fortress)).toContain("state");
    } finally {
      if (priorHome === undefined) delete process.env.HOME;
      else process.env.HOME = priorHome;
      if (priorStorage === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = priorStorage;
      await rm(home, { recursive: true, force: true });
    }
  });

  it("rejects --operator-custody outside the exact human agent-guided action", async () => {
    const home = await mkdtemp(join(tmpdir(), "sanctuary-operator-flag-refusal-"));
    const priorHome = process.env.HOME;
    const sentinel = join(home, "sentinel");
    await writeFile(sentinel, "unchanged");
    process.env.HOME = home;
    const exit = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Error(`process.exit:${code}`);
    }) as never);
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const invalid: Array<{
        name: string;
        options: Partial<WrapOptions>;
        os: NodeJS.Platform;
        agentGuided?: boolean;
      }> = [
        { name: "non-Darwin", options: { hermes: true, noOpen: true }, os: "linux" },
        { name: "missing agent contract", options: { hermes: true, noOpen: true }, os: "darwin", agentGuided: false },
        { name: "zero harnesses", options: { noOpen: true }, os: "darwin" },
        { name: "multiple harnesses", options: { hermes: true, claudeCode: true, noOpen: true }, os: "darwin" },
        { name: "generic wrap", options: { wrap: "/tmp/config", noOpen: true }, os: "darwin" },
        { name: "explicit passphrase", options: { hermes: true, noOpen: true, passphrase: "must-not-render" }, os: "darwin" },
        { name: "plaintext backup", options: { hermes: true, noOpen: true, writePassphraseBackup: "/tmp/no" }, os: "darwin" },
        { name: "development runtime", options: { hermes: true, noOpen: true, devDist: "/tmp/no" }, os: "darwin" },
        { name: "untrusted sealed path", options: { hermes: true, noOpen: true, sealedLauncher: "/tmp/no" }, os: "darwin" },
        { name: "missing no-open", options: { hermes: true }, os: "darwin" },
        { name: "dry run", options: { hermes: true, noOpen: true, dryRun: true }, os: "darwin" },
        { name: "preflight", options: { hermes: true, noOpen: true, preflight: true }, os: "darwin" },
        { name: "preflight JSON", options: { hermes: true, noOpen: true, preflightJson: true }, os: "darwin" },
        { name: "strict preflight", options: { hermes: true, noOpen: true, preflightStrict: true }, os: "darwin" },
        { name: "unwrap", options: { hermes: true, noOpen: true, unwrap: true }, os: "darwin" },
        { name: "no dashboard", options: { hermes: true, noOpen: true, noDashboard: true }, os: "darwin" },
        { name: "custom port", options: { hermes: true, noOpen: true, port: 3502 }, os: "darwin" },
        { name: "plaintext remote", options: { hermes: true, noOpen: true, allowPlaintextRemote: true }, os: "darwin" },
        { name: "transparency", options: { hermes: true, noOpen: true, anchorTransparency: true }, os: "darwin" },
        { name: "exclusive egress", options: { hermes: true, noOpen: true, exclusiveEgress: true }, os: "darwin" },
        { name: "overwrite destination", options: { hermes: true, noOpen: true, overwriteDestination: true }, os: "darwin" },
        { name: "repair", options: { hermes: true, noOpen: true, repairEgressGate: true }, os: "darwin" },
        { name: "stand down", options: { hermes: true, noOpen: true, standDownAgent: true }, os: "darwin" },
        { name: "transient override", options: { hermes: true, noOpen: true, overrideTransientPfRules: true }, os: "darwin" },
        { name: "unprotect", options: { hermes: true, noOpen: true, unprotectEgressGate: true }, os: "darwin" },
      ];
      for (const testCase of invalid) {
        stderr.mockClear();
        await expect(runWrap({
          protectCommand: true,
          agentGuided: testCase.agentGuided ?? true,
          operatorCustody: true,
          provisionAgentAccount: false,
          ...testCase.options,
        }, {
          osPlatform: () => testCase.os,
        }), testCase.name).rejects.toThrow("process.exit:2");
        const rendered = stderr.mock.calls.flat().join(" ");
        expect(rendered, testCase.name).toContain("valid only on the planner-declared human");
        expect(rendered, testCase.name).not.toContain("must-not-render");
        expect(await readFile(sentinel, "utf8"), testCase.name).toBe("unchanged");
        expect(await readdir(home), testCase.name).toEqual(["sentinel"]);
      }
    } finally {
      exit.mockRestore();
      stderr.mockRestore();
      if (priorHome === undefined) delete process.env.HOME;
      else process.env.HOME = priorHome;
      await rm(home, { recursive: true, force: true });
    }
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
      "--strict",
      "--sealed-launcher",
      "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/sanctuary",
    ]);

    const argv = plan.next_action?.argv ?? [];
    const protectIndex = argv.indexOf("protect");
    expect(protectIndex).toBeGreaterThan(-1);
    expect(parseWrapArgs(argv.slice(protectIndex + 1)).preflightStrict).toBe(true);
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
