/**
 * Wrap CLI tests — argument parser, success panel, and port fallback logic.
 *
 * These exercise the pure functions only: config rewriting and dashboard
 * boot are covered by integration tests elsewhere.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseWrapArgs,
  formatWrapSuccess,
  runWrap,
  WRAP_GOVERNOR_DEFAULTS,
  type DashboardStarter,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";

describe("parseWrapArgs", () => {
  it("parses --openclaw flag", () => {
    expect(parseWrapArgs(["--openclaw"]).openclaw).toBe(true);
  });

  it("parses --claude-code flag", () => {
    expect(parseWrapArgs(["--claude-code"]).claudeCode).toBe(true);
  });

  it("parses --cursor flag", () => {
    expect(parseWrapArgs(["--cursor"]).cursor).toBe(true);
  });

  it("parses --hermes flag", () => {
    expect(parseWrapArgs(["--hermes"]).hermes).toBe(true);
  });

  it("parses --cline flag", () => {
    expect(parseWrapArgs(["--cline"]).cline).toBe(true);
  });

  it("parses --wrap with path", () => {
    expect(parseWrapArgs(["--wrap", "/etc/x.json"]).wrap).toBe("/etc/x.json");
  });

  it("parses --unwrap", () => {
    expect(parseWrapArgs(["--unwrap"]).unwrap).toBe(true);
  });

  it("parses --passphrase", () => {
    expect(parseWrapArgs(["--passphrase", "hunter2"]).passphrase).toBe("hunter2");
  });

  it("parses --port", () => {
    expect(parseWrapArgs(["--port", "9000"]).port).toBe(9000);
  });

  it("parses --dry-run", () => {
    expect(parseWrapArgs(["--dry-run"]).dryRun).toBe(true);
  });

  it("parses --no-open", () => {
    expect(parseWrapArgs(["--no-open"]).noOpen).toBe(true);
  });

  it("parses combined flags", () => {
    const opts = parseWrapArgs([
      "--openclaw",
      "--passphrase", "secret",
      "--port", "3502",
      "--no-open",
      "--dry-run",
    ]);
    expect(opts.openclaw).toBe(true);
    expect(opts.passphrase).toBe("secret");
    expect(opts.port).toBe(3502);
    expect(opts.noOpen).toBe(true);
    expect(opts.dryRun).toBe(true);
  });

  it("returns an empty object for no arguments", () => {
    expect(parseWrapArgs([])).toEqual({});
  });

  it("no longer exports the retired legacy aliases", async () => {
    const mod = await import("../../src/wrap/cli.js");
    expect("parseCocoonArgs" in mod).toBe(false);
    expect("runCocoon" in mod).toBe(false);
  });
});

describe("WRAP_GOVERNOR_DEFAULTS", () => {
  it("are unchanged from the original defaults", () => {
    expect(WRAP_GOVERNOR_DEFAULTS.volume_limit).toBe(200);
    expect(WRAP_GOVERNOR_DEFAULTS.rate_limit_per_tool).toBe(20);
    expect(WRAP_GOVERNOR_DEFAULTS.lifetime_limit).toBe(1000);
  });
});

describe("formatWrapSuccess", () => {
  const baseInfo = {
    toolName: "OpenClaw",
    version: "0.9.0-rc.1",
    toolCount: 74,
    serverCount: 2,
    dashboardUrl: "http://localhost:3501?session=short",
    browserOpened: true,
    passphraseLocation: "macOS Keychain",
    passphraseSource: "generated",
    // Honesty (audit seam #1): the "Your agent is protected / Castle Wall Full"
    // hero is now reserved for an observed daemon arm. The baseline fixture
    // models the armed case; the not-armed case is covered separately below.
    castleWallArmed: true,
  };

  it("includes wrapped tool name and version", () => {
    const out = formatWrapSuccess(baseInfo);
    expect(out).toContain("Wrapped");
    expect(out).toContain("OpenClaw");
    expect(out).toContain("0.9.0-rc.1");
  });

  it("pluralises server count correctly", () => {
    const one = formatWrapSuccess({ ...baseInfo, serverCount: 1 });
    expect(one).toContain("1 upstream server");
    expect(one).not.toContain("1 upstream servers");

    const many = formatWrapSuccess({ ...baseInfo, serverCount: 3 });
    expect(many).toContain("3 upstream servers");
  });

  it("says 'Opened in your browser' when browser_opened is true", () => {
    expect(formatWrapSuccess(baseInfo)).toContain("Opened in your browser");
  });

  it("notes browser suppression when --no-open is used", () => {
    expect(formatWrapSuccess({ ...baseInfo, browserOpened: false })).toContain(
      "browser auto-open suppressed"
    );
  });

  it("includes the agent-protected summary line when Castle Wall armed", () => {
    const out = formatWrapSuccess(baseInfo);
    expect(out).toContain("Your agent is protected");
    expect(out).toContain("Castle Wall Full");
    expect(out).toContain("Sentinels Degraded (no TEE)");
    expect(out).toContain("Charter Full");
    expect(out).toContain("Heralds Full");
    // L1-L4 numbering was MANDATORY-retired 2026-05-24; it must not reappear.
    expect(out).not.toMatch(/\bL[1-4]\b/);
  });

  // Honesty (audit seam #1): when the Castle Wall daemon failed to arm, the
  // banner must NOT claim "protected" / "Castle Wall Full" — that contradicted
  // the loud "traffic NOT filtered" warning printed seconds earlier.
  it("does NOT claim protected / Full when Castle Wall did not arm", () => {
    const out = formatWrapSuccess({ ...baseInfo, castleWallArmed: false });
    expect(out).not.toContain("Your agent is protected");
    expect(out).not.toContain("Castle Wall Full");
    expect(out).toContain("Castle Wall NOT ARMED");
    expect(out).toContain("enforcement is not confirmed");
  });

  // Honesty (audit seam #1): with no arm signal threaded, default conservative —
  // never render "Full" on presence/absence of a field alone.
  it("renders unknown (never Full) when no arm signal is threaded", () => {
    const { castleWallArmed: _omit, ...noSignal } = baseInfo;
    const out = formatWrapSuccess(noSignal);
    expect(out).not.toContain("Castle Wall Full");
    expect(out).toContain("Castle Wall status unknown");
    expect(out).not.toContain("Your agent is protected");
  });

  it("includes the dashboard URL without the long-lived token", () => {
    expect(formatWrapSuccess(baseInfo)).toContain(
      "http://localhost:3501?session=short"
    );
    expect(formatWrapSuccess(baseInfo)).not.toContain("?token=");
  });
});

// ── Port fallback ─────────────────────────────────────────────────────

/**
 * We cover the port-fallback logic by driving the internal helper via a
 * synthetic DashboardStarter that throws EADDRINUSE for known-busy ports.
 * This exercises the loop without touching real sockets.
 */
describe("port fallback", () => {
  function makeStarter(busyPorts: number[]): {
    starter: DashboardStarter;
    attempts: number[];
  } {
    const attempts: number[] = [];
    const starter: DashboardStarter = async (opts) => {
      attempts.push(opts.port);
      if (busyPorts.includes(opts.port)) {
        const err = new Error(`EADDRINUSE: port ${opts.port}`) as Error & {
          code: string;
        };
        err.code = "EADDRINUSE";
        throw err;
      }
      return {
        url: `http://localhost:${opts.port}`,
        port: opts.port,
        host: "127.0.0.1",
        stop: async () => {},
        publish: () => {},
        publishActivity: () => {},
        publishApproval: () => {},
      };
    };
    return { starter, attempts };
  }

  async function startWithFallback(
    starter: DashboardStarter,
    preferred: number
  ) {
    // Inline port-fallback behaviour that mirrors the CLI logic.
    const MAX = 3510;
    let lastErr: unknown;
    for (let port = preferred; port <= MAX; port++) {
      try {
        return await starter({
          port,
          mode: "co-located",
          authToken: "t",
          serverVersion: "test",
        });
      } catch (err) {
        lastErr = err;
        const code = (err as { code?: string }).code;
        if (code !== "EADDRINUSE") throw err;
      }
    }
    throw new Error(`No free port: ${(lastErr as Error).message}`);
  }

  it("binds to the preferred port when free", async () => {
    const { starter, attempts } = makeStarter([]);
    const handle = await startWithFallback(starter, 3501);
    expect(handle.port).toBe(3501);
    expect(attempts).toEqual([3501]);
  });

  it("advances to the next port when the preferred is busy", async () => {
    const { starter, attempts } = makeStarter([3501, 3502]);
    const handle = await startWithFallback(starter, 3501);
    expect(handle.port).toBe(3503);
    expect(attempts).toEqual([3501, 3502, 3503]);
  });

  it("rethrows non-EADDRINUSE errors immediately", async () => {
    const starter: DashboardStarter = async () => {
      throw new Error("TLS cert missing");
    };
    await expect(startWithFallback(starter, 3501)).rejects.toThrow(
      "TLS cert missing"
    );
  });

  it("gives up after exhausting the range", async () => {
    const busy = [];
    for (let p = 3501; p <= 3510; p++) busy.push(p);
    const { starter } = makeStarter(busy);
    await expect(startWithFallback(starter, 3501)).rejects.toThrow(/No free/);
  });
});

// ── SEC-061 regression: --passphrase must never land in the rewritten config ─
//
// End-to-end-lite test: invoke `runWrap` against a temp config file and assert
// that a user-supplied `--passphrase` value is never passed to the config
// rewrite. See Archive/DELTA_REVIEW_V0.9.0_RC1.md SEC-061 / CLEAN-018.

describe("runWrap — SEC-061 passphrase leak regression", () => {
  let tempHome: string;
  let originalHome: string | undefined;
  let configPath: string;

  function fakeDashboardStarter(): DashboardStarter {
    return async (opts) => ({
      url: `http://127.0.0.1:${opts.port}`,
      port: opts.port,
      host: "127.0.0.1",
      stop: async () => {},
      publish: () => {},
      publishActivity: () => {},
      publishApproval: () => {},
    });
  }

  beforeEach(async () => {
    tempHome = await mkdtemp(join(tmpdir(), "sanctuary-runwrap-"));
    originalHome = process.env.HOME;
    process.env.HOME = tempHome;
    configPath = join(tempHome, "openclaw.json");
    await writeFile(
      configPath,
      JSON.stringify({
        mcp: {
          servers: {
            demo: {
              command: "node",
              args: ["demo-server.js"],
            },
          },
        },
      }),
      "utf-8"
    );
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    await rm(tempHome, { recursive: true, force: true });
  });

  /**
   * The rewrite spy both records the args it received AND writes a minimal
   * post-rewrite file shape so the downstream verifyRewrittenConfig step
   * (which reads configPath and expects `mcp.servers.sanctuary.command`)
   * passes without coupling the test to the real rewrite implementation.
   */
  function makeRewriteSpy(): ReturnType<typeof vi.fn> {
    return vi.fn(async (_agentConfig, command: string, args: string[]) => {
      await writeFile(
        configPath,
        JSON.stringify({
          mcp: {
            servers: {
              sanctuary: { command, args },
            },
          },
        }),
        "utf-8"
      );
      return configPath;
    });
  }

  it("does not write the user-supplied --passphrase into the rewritten agent config", async () => {
    const rewriteSpy = makeRewriteSpy();
    const persistSpy = vi.fn(async (_value: string) => ({
      location: "macOS Keychain",
      source: "keychain" as const,
    }));
    const openBrowser = vi.fn(async () => {});

    const deps: RunWrapDeps = {
      startDashboard: fakeDashboardStarter(),
      openBrowser,
      persistPassphrase: persistSpy,
      rewriteConfig: rewriteSpy,
    };

    const sentinel = "CHECK-ME-NOT-IN-CONFIG-xxx";

    await runWrap(
      { wrap: configPath, passphrase: sentinel, noOpen: true },
      deps
    );

    expect(rewriteSpy).toHaveBeenCalledTimes(1);
    const rewriteArgs = rewriteSpy.mock.calls[0]?.[2] as string[];
    expect(rewriteArgs).toEqual(["@sanctuary-framework/mcp-server"]);
    expect(rewriteArgs.join(" ")).not.toContain(sentinel);
    expect(rewriteArgs).not.toContain("--passphrase");

    expect(persistSpy).toHaveBeenCalledTimes(1);
    expect(persistSpy).toHaveBeenCalledWith(sentinel);

    // The on-disk config must also not contain the sentinel anywhere.
    const onDisk = await readFile(configPath, "utf-8");
    expect(onDisk).not.toContain(sentinel);
    expect(onDisk).not.toContain("--passphrase");
  });

  it("emits fallback warning on linux (SEC-063)", async () => {
    const rewriteSpy = makeRewriteSpy();
    const resolveSpy = vi.fn(async () => ({
      value: "random-generated-value",
      location: join(tempHome, ".sanctuary", "passphrase.enc"),
      source: "generated" as const,
    }));

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runWrap(
        { wrap: configPath, noOpen: true },
        {
          startDashboard: fakeDashboardStarter(),
          openBrowser: async () => {},
          resolvePassphrase: resolveSpy,
          rewriteConfig: rewriteSpy,
        }
      );

      const allOutput = stderrSpy.mock.calls.map(c => c.join(" ")).join("\n");
      // The fallback warning only fires when the Keychain path is
      // unavailable. On macOS the passphrase resolver lands in Keychain
      // and the fallback banner is skipped by design. On Linux/Windows
      // there is no Keychain, so the banner always appears — this is
      // what the test was written to cover. Guard the platform-specific
      // assertion so CI (linux) enforces it but the MBA/Mini1 dev
      // loop doesn't break the suite.
      if (process.platform !== "darwin") {
        expect(allOutput).toContain("Passphrase stored in encrypted fallback file");
        expect(allOutput).toContain("sanctuary export-passphrase");
      }
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it("does not emit fallback warning when Keychain succeeds", async () => {
    const rewriteSpy = makeRewriteSpy();
    const resolveSpy = vi.fn(async () => ({
      value: "random-generated-value",
      location: "macOS Keychain",
      source: "generated" as const,
    }));

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runWrap(
        { wrap: configPath, noOpen: true },
        {
          startDashboard: fakeDashboardStarter(),
          openBrowser: async () => {},
          resolvePassphrase: resolveSpy,
          rewriteConfig: rewriteSpy,
        }
      );

      const allOutput = stderrSpy.mock.calls.map(c => c.join(" ")).join("\n");
      expect(allOutput).not.toContain("encrypted fallback file");
    } finally {
      stderrSpy.mockRestore();
    }
  });

  it("rewrites with a constant args list even when no --passphrase is supplied", async () => {
    const rewriteSpy = makeRewriteSpy();
    const resolveSpy = vi.fn(async () => ({
      value: "random-generated-value",
      location: "macOS Keychain",
      source: "generated",
    }));

    await runWrap(
      { wrap: configPath, noOpen: true },
      {
        startDashboard: fakeDashboardStarter(),
        openBrowser: async () => {},
        resolvePassphrase: resolveSpy,
        rewriteConfig: rewriteSpy,
      }
    );

    const rewriteArgs = rewriteSpy.mock.calls[0]?.[2] as string[];
    expect(rewriteArgs).toEqual(["@sanctuary-framework/mcp-server"]);
  });
});

// ── v0.10.0 WP1: multi-tenancy env var wiring ────────────────────────────
//
// These cover `runWrap` end-to-end-lite, proving the CLI routes through
// `resolveStoragePath()` and `resolveDashboardPort()` so two agents on one
// host can pick distinct storage dirs + dashboard start ports without
// manual CLI flags.

describe("runWrap — v0.10.0 WP1 multi-tenancy env vars", () => {
  let tempHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalDashboardPort: string | undefined;
  let configPath: string;

  function capturingDashboardStarter(seen: { port?: number }): DashboardStarter {
    return async (opts) => {
      seen.port = opts.port;
      return {
        url: `http://127.0.0.1:${opts.port}`,
        port: opts.port,
        host: "127.0.0.1",
        stop: async () => {},
        publish: () => {},
        publishActivity: () => {},
        publishApproval: () => {},
      };
    };
  }

  function makeRewriteSpy(path: string): ReturnType<typeof vi.fn> {
    return vi.fn(async (_agentConfig, command: string, args: string[]) => {
      await writeFile(
        path,
        JSON.stringify({
          mcp: {
            servers: {
              sanctuary: { command, args },
            },
          },
        }),
        "utf-8"
      );
      return path;
    });
  }

  beforeEach(async () => {
    tempHome = await mkdtemp(join(tmpdir(), "sanctuary-wp1-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalDashboardPort = process.env.SANCTUARY_DASHBOARD_PORT;
    process.env.HOME = tempHome;
    configPath = join(tempHome, "openclaw.json");
    await writeFile(
      configPath,
      JSON.stringify({
        mcp: {
          servers: {
            demo: { command: "node", args: ["demo-server.js"] },
          },
        },
      }),
      "utf-8"
    );
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined)
      delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    if (originalDashboardPort === undefined)
      delete process.env.SANCTUARY_DASHBOARD_PORT;
    else process.env.SANCTUARY_DASHBOARD_PORT = originalDashboardPort;
    await rm(tempHome, { recursive: true, force: true });
  });

  it("writes wrap-profile.json under SANCTUARY_STORAGE_PATH when set", async () => {
    const tenantDir = join(tempHome, "tenant-a");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;

    const seen: { port?: number } = {};
    await runWrap(
      { wrap: configPath, noOpen: true },
      {
        startDashboard: capturingDashboardStarter(seen),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig: makeRewriteSpy(configPath),
      }
    );

    const profile = JSON.parse(
      await readFile(join(tenantDir, "wrap-profile.json"), "utf-8")
    );
    expect(profile.version).toBe(1);
  });

  it("picks SANCTUARY_DASHBOARD_PORT when no --port is supplied", async () => {
    process.env.SANCTUARY_DASHBOARD_PORT = "3507";

    const seen: { port?: number } = {};
    await runWrap(
      { wrap: configPath, noOpen: true },
      {
        startDashboard: capturingDashboardStarter(seen),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig: makeRewriteSpy(configPath),
      }
    );

    expect(seen.port).toBe(3507);
  });

  it("prefers an explicit --port over SANCTUARY_DASHBOARD_PORT", async () => {
    process.env.SANCTUARY_DASHBOARD_PORT = "3507";

    const seen: { port?: number } = {};
    // Pick an explicit port inside the 3501–3510 fallback range so the CLI
    // does not exhaust the range before handing to our fake starter.
    await runWrap(
      { wrap: configPath, noOpen: true, port: 3503 },
      {
        startDashboard: capturingDashboardStarter(seen),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig: makeRewriteSpy(configPath),
      }
    );

    expect(seen.port).toBe(3503);
  });

  it("routes the cline flag through detection with platform='cline'", async () => {
    // Seed a Cline-shape flat mcpServers config at a temp path and drive
    // runWrap({ cline: true, wrap: <path> }). We verify platform dispatch
    // two ways: (a) the rewriteConfig spy receives an AgentConfig whose
    // platform === "cline"; (b) runWrap completes successfully through
    // the verifyRewrittenConfig step (no restoreFromBackup triggered).
    const tenantDir = join(tempHome, "tenant-cline");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;
    const clineConfigPath = join(tempHome, "cline_mcp_settings.json");
    await writeFile(
      clineConfigPath,
      JSON.stringify({
        mcpServers: {
          filesystem: { command: "node", args: ["fs.js"] },
        },
      }),
      "utf-8"
    );

    const rewriteSpy = vi.fn(
      async (
        agentConfig: { platform: string; configPath: string },
        command: string,
        args: string[]
      ) => {
        // Persist a sanctuary entry so verifyRewrittenConfig is happy.
        await writeFile(
          agentConfig.configPath,
          JSON.stringify({
            mcpServers: {
              sanctuary: { command, args },
            },
          }),
          "utf-8"
        );
        return agentConfig.configPath;
      }
    );

    const seen: { port?: number } = {};
    await runWrap(
      { wrap: clineConfigPath, cline: true, noOpen: true },
      {
        startDashboard: capturingDashboardStarter(seen),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig: rewriteSpy,
      }
    );

    expect(rewriteSpy).toHaveBeenCalledTimes(1);
    const calledWith = rewriteSpy.mock.calls[0]?.[0] as {
      platform: string;
      configPath: string;
    };
    expect(calledWith.platform).toBe("cline");
    expect(calledWith.configPath).toBe(clineConfigPath);
  });

  it("writes backup and meta under the per-tenant storage path", async () => {
    const tenantDir = join(tempHome, "tenant-b");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;

    const seen: { port?: number } = {};
    await runWrap(
      { wrap: configPath, noOpen: true },
      {
        startDashboard: capturingDashboardStarter(seen),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig: makeRewriteSpy(configPath),
      }
    );

    // The backup dir and wrap-meta.json live inside the tenant root.
    const meta = JSON.parse(
      await readFile(join(tenantDir, "backup", "wrap-meta.json"), "utf-8")
    );
    expect(meta.originalPath).toBe(configPath);
    expect(meta.backupPath.startsWith(join(tenantDir, "backup"))).toBe(true);
  });
});

// ── WP-MVP-1 Follow-up: runWrap — --hermes path ──────────────────────
//
// Integration test for the Hermes wrap-CLI surface. Exercises the full
// path: parse --hermes → detect Hermes at the canonical JSON config path
// → rewrite to route through Sanctuary → verify the rewritten config
// carries the Hermes-shaped `mcp_servers` key with a `sanctuary` entry.

describe("runWrap — --hermes wrap path (WP-MVP-1 follow-up)", () => {
  let tempHome: string;
  let originalHome: string | undefined;
  let hermesConfigPath: string;

  function fakeDashboardStarter(): DashboardStarter {
    return async (opts) => ({
      url: `http://127.0.0.1:${opts.port}`,
      port: opts.port,
      host: "127.0.0.1",
      stop: async () => {},
      publish: () => {},
      publishActivity: () => {},
      publishApproval: () => {},
    });
  }

  beforeEach(async () => {
    tempHome = await mkdtemp(join(tmpdir(), "sanctuary-hermes-"));
    originalHome = process.env.HOME;
    process.env.HOME = tempHome;

    // Seed ~/.hermes/cli-config.json with the Hermes canonical shape.
    const hermesDir = join(tempHome, ".hermes");
    await import("node:fs/promises").then((fs) =>
      fs.mkdir(hermesDir, { recursive: true })
    );
    hermesConfigPath = join(hermesDir, "cli-config.json");
    await writeFile(
      hermesConfigPath,
      JSON.stringify({
        model_provider: "self-hosted",
        mcp_servers: {
          filesystem: {
            command: "node",
            args: ["fs-server.js"],
          },
          github: {
            command: "npx",
            args: ["-y", "@github/mcp-server"],
            env: { GITHUB_TOKEN: "tok_hermes" },
          },
        },
      }),
      "utf-8"
    );
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    await rm(tempHome, { recursive: true, force: true });
  });

  it("auto-detects ~/.hermes/cli-config.json when --hermes is passed", async () => {
    const rewriteSpy = vi.fn(async (agentConfig, command: string, args: string[]) => {
      // Write a minimal post-rewrite shape that the verifier is happy with:
      // Hermes uses snake_case mcp_servers, and verifyRewrittenConfig now
      // reads that key.
      await writeFile(
        hermesConfigPath,
        JSON.stringify({
          model_provider: "self-hosted",
          mcp_servers: {
            sanctuary: { command, args },
          },
        }),
        "utf-8"
      );
      return hermesConfigPath;
    });

    await runWrap(
      { hermes: true, noOpen: true },
      {
        startDashboard: fakeDashboardStarter(),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig: rewriteSpy,
      }
    );

    expect(rewriteSpy).toHaveBeenCalledTimes(1);
    const callArgs = rewriteSpy.mock.calls[0]!;
    const passedConfig = callArgs[0] as { platform: string; configPath: string };
    expect(passedConfig.platform).toBe("hermes");
    expect(passedConfig.configPath).toBe(hermesConfigPath);
  });

  it("rewrites Hermes config preserving top-level siblings and existing servers", async () => {
    // This test uses the real rewrite (no spy) to prove the Hermes-shape
    // emission end-to-end.
    await runWrap(
      { hermes: true, noOpen: true },
      {
        startDashboard: fakeDashboardStarter(),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
      }
    );

    const rewritten = JSON.parse(await readFile(hermesConfigPath, "utf-8"));

    // Top-level sibling preserved
    expect(rewritten.model_provider).toBe("self-hosted");
    // Hermes-shape key preserved (snake_case)
    expect(rewritten.mcp_servers).toBeDefined();
    expect(rewritten.mcpServers).toBeUndefined();
    // Sanctuary added
    expect(rewritten.mcp_servers.sanctuary).toBeDefined();
    expect(rewritten.mcp_servers.sanctuary.command).toBe("npx");
    // Existing servers preserved with env vars intact
    expect(rewritten.mcp_servers.filesystem).toBeDefined();
    expect(rewritten.mcp_servers.github).toBeDefined();
    expect(rewritten.mcp_servers.github.env).toEqual({
      GITHUB_TOKEN: "tok_hermes",
    });
  });
});
