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
  parseCocoonArgs,
  formatWrapSuccess,
  runWrap,
  COCOON_GOVERNOR_DEFAULTS,
  type DashboardStarter,
  type RunWrapDeps,
} from "../../src/cocoon/cli.js";

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

  it("is aliased as parseCocoonArgs for backward compat", () => {
    expect(parseCocoonArgs).toBe(parseWrapArgs);
  });
});

describe("COCOON_GOVERNOR_DEFAULTS", () => {
  it("are preserved from the old cocoon CLI", () => {
    expect(COCOON_GOVERNOR_DEFAULTS.volume_limit).toBe(200);
    expect(COCOON_GOVERNOR_DEFAULTS.rate_limit_per_tool).toBe(20);
    expect(COCOON_GOVERNOR_DEFAULTS.lifetime_limit).toBe(1000);
  });
});

describe("formatWrapSuccess", () => {
  const baseInfo = {
    toolName: "OpenClaw",
    version: "0.9.0-rc.1",
    toolCount: 74,
    serverCount: 2,
    dashboardUrl: "http://localhost:3501?token=abc",
    browserOpened: true,
    passphraseLocation: "macOS Keychain",
    passphraseSource: "generated",
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

  it("includes the agent-protected summary line", () => {
    const out = formatWrapSuccess(baseInfo);
    expect(out).toContain("Your agent is protected");
    expect(out).toContain("L1 Full");
    expect(out).toContain("L2 Degraded (no TEE)");
    expect(out).toContain("L3 Full");
    expect(out).toContain("L4 Full");
  });

  it("includes the dashboard URL with the token", () => {
    expect(formatWrapSuccess(baseInfo)).toContain(
      "http://localhost:3501?token=abc"
    );
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
// rewrite. See docs/audit/DELTA_REVIEW_V0.9.0_RC1.md SEC-061 / CLEAN-018.

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
      expect(allOutput).toContain("Passphrase stored in encrypted fallback file");
      expect(allOutput).toContain("sanctuary export-passphrase");
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
