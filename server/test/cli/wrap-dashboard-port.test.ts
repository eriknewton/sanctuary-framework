import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseWrapArgs,
  runWrap,
  type DashboardStarter,
} from "../../src/cocoon/cli.js";

describe("sanctuary wrap --dashboard-port", () => {
  let tempHome: string;
  let configPath: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalDashboardPort: string | undefined;

  beforeEach(async () => {
    tempHome = await mkdtemp(join(tmpdir(), "sanctuary-wrap-dashboard-port-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalDashboardPort = process.env.SANCTUARY_DASHBOARD_PORT;

    process.env.HOME = tempHome;
    configPath = join(tempHome, "agent.json");
    await writeFile(
      configPath,
      JSON.stringify({
        mcpServers: {
          demo: { command: "node", args: ["demo-server.js"] },
        },
      }),
      "utf-8",
    );
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    if (originalDashboardPort === undefined) delete process.env.SANCTUARY_DASHBOARD_PORT;
    else process.env.SANCTUARY_DASHBOARD_PORT = originalDashboardPort;
    await rm(tempHome, { recursive: true, force: true });
  });

  it("parses --dashboard-port as the preferred dashboard port", () => {
    const opts = parseWrapArgs(["--dashboard-port", "3502"]);
    expect(opts.port).toBe(3502);
  });

  it("rejects invalid --dashboard-port values", () => {
    expect(() => parseWrapArgs(["--dashboard-port", "1023"])).toThrow(
      /1024 to 65535/,
    );
    expect(() => parseWrapArgs(["--dashboard-port", "abc"])).toThrow(
      /positive integer/,
    );
    expect(() => parseWrapArgs(["--dashboard-port"])).toThrow(
      /requires a port value/,
    );
  });

  it("uses --dashboard-port over SANCTUARY_DASHBOARD_PORT", async () => {
    process.env.SANCTUARY_DASHBOARD_PORT = "3507";

    const seen: { port?: number } = {};
    const startDashboard: DashboardStarter = async (opts) => {
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

    await runWrap(
      parseWrapArgs([
        "--wrap",
        configPath,
        "--fortress",
        join(tempHome, "fortress"),
        "--dashboard-port",
        "3502",
        "--no-open",
      ]),
      {
        startDashboard,
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "generated-passphrase",
          location: "macOS Keychain",
          source: "generated",
        }),
        rewriteConfig: vi.fn(async (_agentConfig, command: string, args: string[]) => {
          await writeFile(
            configPath,
            JSON.stringify({ mcpServers: { sanctuary: { command, args } } }),
            "utf-8",
          );
          return configPath;
        }),
      },
    );

    expect(seen.port).toBe(3502);
  });
});
