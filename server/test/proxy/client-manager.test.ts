/**
 * Proxy ClientManager tests
 *
 * Covers: server name validation, max upstream limit, getStatus/getServerConfig,
 * callTool rejection for unconfigured servers, shutdown safety.
 * Not covered: real MCP SDK transport, network I/O, reconnection timing.
 */

import { describe, it, expect, vi } from "vitest";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  buildUpstreamStdioEnv,
  ClientManager,
} from "../../src/proxy/client-manager.js";
import type { UpstreamServer } from "../../src/sovereignty-profile.js";

// Mock the MCP SDK transports to prevent real process spawning
vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: vi.fn().mockImplementation(() => ({
    connect: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    listTools: vi.fn(async () => ({ tools: [] })),
    callTool: vi.fn(async () => ({ content: [] })),
  })),
}));

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: vi.fn().mockImplementation(() => ({
    close: vi.fn(async () => {}),
  })),
}));

vi.mock("@modelcontextprotocol/sdk/client/sse.js", () => ({
  SSEClientTransport: vi.fn().mockImplementation(() => ({
    close: vi.fn(async () => {}),
  })),
}));

function makeServer(name: string, overrides?: Partial<UpstreamServer>): UpstreamServer {
  return {
    name,
    enabled: true,
    default_tier: 3,
    transport: { type: "stdio", command: "node", args: ["server.js"] },
    ...overrides,
  } as UpstreamServer;
}

async function waitForConnectionAttempt(): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, 0));
}

function latestStdioEnv(): Record<string, string> {
  const mock = vi.mocked(StdioClientTransport);
  const lastCall = mock.mock.calls.at(-1);
  expect(lastCall).toBeDefined();
  return lastCall![0].env as Record<string, string>;
}

async function withProcessEnv(
  values: Record<string, string>,
  run: () => Promise<void>
): Promise<void> {
  const previous: Record<string, string | undefined> = {};
  for (const key of Object.keys(values)) {
    previous[key] = process.env[key];
    process.env[key] = values[key];
  }

  try {
    await run();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

describe("ClientManager", () => {
  describe("server name validation", () => {
    it("accepts valid server names", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("valid-name_123")]);
      const status = cm.getStatus();
      expect(status.length).toBe(1);
      expect(status[0]!.name).toBe("valid-name_123");
    });

    it("rejects server names with special characters", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("bad name!@#")]);
      const status = cm.getStatus();
      expect(status.length).toBe(0);
    });

    it("rejects server names with spaces", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("has space")]);
      expect(cm.getStatus().length).toBe(0);
    });
  });

  describe("max upstream servers", () => {
    it("rejects more than 20 upstream servers", async () => {
      const cm = new ClientManager();
      const servers = Array.from({ length: 21 }, (_, i) => makeServer(`s${i}`));
      await expect(cm.configure(servers)).rejects.toThrow("Maximum 20 upstream servers");
    });

    it("accepts exactly 20 servers", async () => {
      const cm = new ClientManager();
      const servers = Array.from({ length: 20 }, (_, i) => makeServer(`s${i}`));
      await cm.configure(servers);
      // Should not throw
    });
  });

  describe("getStatus", () => {
    it("returns empty status when no servers configured", () => {
      const cm = new ClientManager();
      expect(cm.getStatus()).toEqual([]);
    });

    it("returns server status after configure", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("test-server")]);
      const status = cm.getStatus();
      expect(status).toHaveLength(1);
      expect(status[0]!.name).toBe("test-server");
    });
  });

  describe("getServerConfig", () => {
    it("returns undefined for unconfigured server", () => {
      const cm = new ClientManager();
      expect(cm.getServerConfig("nope")).toBeUndefined();
    });
  });

  describe("state change callback", () => {
    it("fires callback on state changes", async () => {
      const callback = vi.fn();
      const cm = new ClientManager({ onStateChange: callback });
      await cm.configure([makeServer("cb-test")]);

      // Wait for async connection attempt
      await new Promise(r => setTimeout(r, 100));
      expect(callback).toHaveBeenCalled();
      await cm.shutdown();
    });
  });

  describe("shutdown", () => {
    it("completes without error on empty manager", async () => {
      const cm = new ClientManager();
      await cm.shutdown();
    });

    it("cleans up after configure", async () => {
      const cm = new ClientManager();
      await cm.configure([makeServer("s1")]);
      await cm.shutdown();
      const status = cm.getStatus();
      expect(status.every(s => s.state === "disconnected")).toBe(true);
    });
  });

  describe("getAllTools", () => {
    it("returns empty map with no connections", () => {
      const cm = new ClientManager();
      expect(cm.getAllTools().size).toBe(0);
    });
  });

  describe("callTool", () => {
    it("rejects call to unconfigured server", async () => {
      const cm = new ClientManager();
      await expect(cm.callTool("nope", "tool", {})).rejects.toThrow();
    });
  });

  describe("stdio environment isolation", () => {
    it("does not pass Sanctuary or generic API key values from the parent process env", async () => {
      await withProcessEnv(
        {
          SANCTUARY_PASSPHRASE: "parent-passphrase",
          SANCTUARY_DASHBOARD_AUTH_TOKEN: "parent-dashboard-token",
          SANCTUARY_CUSTOM_SETTING: "parent-sanctuary-value",
          THIRD_PARTY_API_KEY: "parent-api-key",
        },
        async () => {
          const cm = new ClientManager();
          vi.mocked(StdioClientTransport).mockClear();

          await cm.configure([makeServer("env-isolated")]);
          await waitForConnectionAttempt();

          const env = latestStdioEnv();
          expect(env.SANCTUARY_PASSPHRASE).toBeUndefined();
          expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBeUndefined();
          expect(env.SANCTUARY_CUSTOM_SETTING).toBeUndefined();
          expect(env.THIRD_PARTY_API_KEY).toBeUndefined();
          expect(Object.keys(env).every(key => !key.startsWith("SANCTUARY_"))).toBe(true);
          await cm.shutdown();
        }
      );
    });

    it("passes explicit operator configured env vars after deny filtering", async () => {
      const cm = new ClientManager();
      vi.mocked(StdioClientTransport).mockClear();

      await cm.configure([
        makeServer("operator-env", {
          transport: {
            type: "stdio",
            command: "node",
            args: ["server.js"],
            env: {
              OPERATOR_CONFIGURED_MODE: "enabled",
              SAFE_UPSTREAM_LABEL: "filesystem",
              SANCTUARY_PASSPHRASE: "must-not-pass",
              SERVICE_API_KEY: "must-not-pass",
              OPENAI_PROJECT: "must-not-pass",
            },
          },
        }),
      ]);
      await waitForConnectionAttempt();

      const env = latestStdioEnv();
      expect(env.OPERATOR_CONFIGURED_MODE).toBe("enabled");
      expect(env.SAFE_UPSTREAM_LABEL).toBe("filesystem");
      expect(env.SANCTUARY_PASSPHRASE).toBeUndefined();
      expect(env.SERVICE_API_KEY).toBeUndefined();
      expect(env.OPENAI_PROJECT).toBeUndefined();
      await cm.shutdown();
    });
  });

  describe("buildUpstreamStdioEnv", () => {
    it("uses the default allowlist plus explicit safe config and drops adversarial names", () => {
      const env = buildUpstreamStdioEnv(
        {
          SAFE_FEATURE_FLAG: "true",
          "BAD-NAME": "bad",
          SANCTUARY_PUBLIC_VALUE: "bad",
          TOOL_API_KEY: "bad",
          SESSION_TOKEN: "bad",
          CLIENT_SECRET: "bad",
          DB_PASSWORD: "bad",
          VAULT_PASSPHRASE: "bad",
          AWS_REGION: "bad",
          GCP_PROJECT: "bad",
          AZURE_TENANT: "bad",
          OPENAI_ORG_ID: "bad",
          ANTHROPIC_VERSION: "bad",
          GOOGLE_APPLICATION_CREDENTIALS: "bad",
        },
        {
          PATH: "/usr/bin",
          HOME: "/tmp/home",
          LANG: "en_US.UTF-8",
          LC_ALL: "C",
          LC_CTYPE: "UTF-8",
          TZ: "UTC",
          TMPDIR: "/tmp",
          USER: "operator",
          SHELL: "/bin/zsh",
          THIRD_PARTY_API_KEY: "parent-secret",
          SANCTUARY_PASSPHRASE: "parent-secret",
        }
      );

      expect(env).toEqual({
        PATH: "/usr/bin",
        HOME: "/tmp/home",
        LANG: "en_US.UTF-8",
        LC_ALL: "C",
        LC_CTYPE: "UTF-8",
        TZ: "UTC",
        TMPDIR: "/tmp",
        SAFE_FEATURE_FLAG: "true",
      });
    });
  });
});
