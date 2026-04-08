/**
 * Config Reader Tests
 *
 * Verifies agent config detection, parsing, backup, and restore
 * for the Cocoon CLI wrapper.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  detectAgentConfig,
  backupConfig,
  restoreConfig,
  saveCocoonMeta,
  findLatestBackup,
  rewriteConfigForCocoon,
} from "../../src/cocoon/config-reader.js";

describe("Config Reader", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = join(tmpdir(), `sanctuary-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {}
  });

  // ── Config parsing ──────────────────────────────────────────────

  describe("config parsing", () => {
    it("reads OpenClaw-style mcpServers config", async () => {
      const configPath = join(tmpDir, "config.json");
      await writeFile(configPath, JSON.stringify({
        mcpServers: {
          filesystem: {
            command: "node",
            args: ["server.js"],
          },
          github: {
            command: "npx",
            args: ["-y", "@github/mcp-server"],
            env: { GITHUB_TOKEN: "tok_123" },
          },
        },
      }));

      const result = await detectAgentConfig("openclaw", configPath);
      expect(result).not.toBeNull();
      expect(result!.servers).toHaveLength(2);
      expect(result!.servers[0]!.name).toBe("filesystem");
      expect(result!.servers[0]!.transport).toBe("stdio");
      expect(result!.servers[0]!.command).toBe("node");
      expect(result!.servers[0]!.args).toEqual(["server.js"]);
      expect(result!.servers[1]!.name).toBe("github");
      expect(result!.servers[1]!.env).toEqual({ GITHUB_TOKEN: "tok_123" });
    });

    it("reads SSE server configs", async () => {
      const configPath = join(tmpDir, "config.json");
      await writeFile(configPath, JSON.stringify({
        mcpServers: {
          remote: {
            url: "http://localhost:8080/sse",
          },
        },
      }));

      const result = await detectAgentConfig("openclaw", configPath);
      expect(result).not.toBeNull();
      expect(result!.servers).toHaveLength(1);
      expect(result!.servers[0]!.transport).toBe("sse");
      expect(result!.servers[0]!.url).toBe("http://localhost:8080/sse");
    });

    it("sanitizes server names with special characters", async () => {
      const configPath = join(tmpDir, "config.json");
      await writeFile(configPath, JSON.stringify({
        mcpServers: {
          "my server.v2": {
            command: "node",
            args: ["server.js"],
          },
        },
      }));

      const result = await detectAgentConfig("generic", configPath);
      expect(result).not.toBeNull();
      expect(result!.servers[0]!.name).toBe("my-server-v2");
    });

    it("returns null for non-existent file", async () => {
      const result = await detectAgentConfig("openclaw", "/nonexistent/config.json");
      expect(result).toBeNull();
    });

    it("returns null for invalid JSON", async () => {
      const configPath = join(tmpDir, "config.json");
      await writeFile(configPath, "not json");

      const result = await detectAgentConfig("generic", configPath);
      expect(result).toBeNull();
    });

    it("returns empty servers for config with no mcpServers", async () => {
      const configPath = join(tmpDir, "config.json");
      await writeFile(configPath, JSON.stringify({ theme: "dark" }));

      const result = await detectAgentConfig("openclaw", configPath);
      expect(result).not.toBeNull();
      expect(result!.servers).toHaveLength(0);
    });

    it("skips sanctuary entries in claude-code config", async () => {
      const configPath = join(tmpDir, "settings.json");
      await writeFile(configPath, JSON.stringify({
        mcpServers: {
          sanctuary: { command: "npx", args: ["@sanctuary-framework/mcp-server"] },
          filesystem: { command: "node", args: ["fs-server.js"] },
        },
      }));

      const result = await detectAgentConfig("claude-code", configPath);
      expect(result).not.toBeNull();
      expect(result!.servers).toHaveLength(1);
      expect(result!.servers[0]!.name).toBe("filesystem");
    });
  });

  // ── Backup and restore ──────────────────────────────────────────

  describe("backup and restore", () => {
    it("backs up a config file and restores it", async () => {
      const original = join(tmpDir, "original.json");
      const content = JSON.stringify({ mcpServers: { test: { command: "echo" } } });
      await writeFile(original, content);

      // Backup
      const backupPath = await backupConfig(original);
      expect(backupPath).toContain("config-backup-");

      // Modify the original
      await writeFile(original, JSON.stringify({ modified: true }));

      // Restore
      await restoreConfig(backupPath, original);
      const restored = await readFile(original, "utf-8");
      expect(restored).toBe(content);
    });
  });

  // ── Config rewrite ──────────────────────────────────────────────

  describe("rewriteConfigForCocoon", () => {
    it("preserves existing servers in OpenClaw format", async () => {
      const configPath = join(tmpDir, "openclaw.json");
      const original = {
        mcp: {
          servers: {
            concordia: {
              command: "python",
              args: ["-m", "concordia_protocol"],
              env: { CONCORDIA_KEY: "secret123" },
            },
            filesystem: {
              command: "node",
              args: ["fs-server.js"],
            },
          },
        },
      };
      await writeFile(configPath, JSON.stringify(original));

      const agentConfig = await detectAgentConfig("openclaw", configPath);
      expect(agentConfig).not.toBeNull();

      await rewriteConfigForCocoon(
        agentConfig!,
        "npx",
        ["@sanctuary-framework/mcp-server"],
        { SANCTUARY_PASSPHRASE: "test" }
      );

      const rewritten = JSON.parse(await readFile(configPath, "utf-8"));

      // Sanctuary entry added
      expect(rewritten.mcp.servers.sanctuary).toBeDefined();
      expect(rewritten.mcp.servers.sanctuary.command).toBe("npx");
      expect(rewritten.mcp.servers.sanctuary.env).toEqual({ SANCTUARY_PASSPHRASE: "test" });

      // Existing servers preserved with env vars intact
      expect(rewritten.mcp.servers.concordia).toBeDefined();
      expect(rewritten.mcp.servers.concordia.command).toBe("python");
      expect(rewritten.mcp.servers.concordia.env).toEqual({ CONCORDIA_KEY: "secret123" });
      expect(rewritten.mcp.servers.filesystem).toBeDefined();
    });

    it("preserves existing servers in flat mcpServers format", async () => {
      const configPath = join(tmpDir, "claude-code.json");
      const original = {
        mcpServers: {
          github: {
            command: "npx",
            args: ["-y", "@github/mcp-server"],
            env: { GITHUB_TOKEN: "tok_abc" },
          },
        },
      };
      await writeFile(configPath, JSON.stringify(original));

      const agentConfig = await detectAgentConfig("claude-code", configPath);
      expect(agentConfig).not.toBeNull();

      await rewriteConfigForCocoon(agentConfig!, "npx", ["@sanctuary-framework/mcp-server"]);

      const rewritten = JSON.parse(await readFile(configPath, "utf-8"));

      // Sanctuary added
      expect(rewritten.mcpServers.sanctuary).toBeDefined();

      // Existing server preserved with env vars
      expect(rewritten.mcpServers.github).toBeDefined();
      expect(rewritten.mcpServers.github.env).toEqual({ GITHUB_TOKEN: "tok_abc" });
    });

    it("inherits sanctuary env vars when none explicitly provided", async () => {
      const configPath = join(tmpDir, "openclaw.json");
      const original = {
        mcp: {
          servers: {
            sanctuary: {
              command: "npx",
              args: ["@sanctuary-framework/mcp-server"],
              env: {
                SANCTUARY_PASSPHRASE: "my-secret",
                SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok_abc",
                SANCTUARY_DASHBOARD_ENABLED: "true",
              },
            },
            concordia: {
              command: "python",
              args: ["-m", "concordia_protocol"],
              env: { CONCORDIA_KEY: "ckey123" },
            },
          },
        },
      };
      await writeFile(configPath, JSON.stringify(original));

      const agentConfig = await detectAgentConfig("openclaw", configPath);
      expect(agentConfig).not.toBeNull();

      // Call WITHOUT sanctuaryEnv — should inherit from existing config
      await rewriteConfigForCocoon(
        agentConfig!,
        "npx",
        ["@sanctuary-framework/mcp-server", "--passphrase", "my-secret"]
      );

      const rewritten = JSON.parse(await readFile(configPath, "utf-8"));

      // Sanctuary env vars inherited from original
      expect(rewritten.mcp.servers.sanctuary.env).toEqual({
        SANCTUARY_PASSPHRASE: "my-secret",
        SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok_abc",
        SANCTUARY_DASHBOARD_ENABLED: "true",
      });

      // Sanctuary command/args updated to new values
      expect(rewritten.mcp.servers.sanctuary.command).toBe("npx");
      expect(rewritten.mcp.servers.sanctuary.args).toContain("--passphrase");

      // Other servers still preserved with their env vars
      expect(rewritten.mcp.servers.concordia.env).toEqual({ CONCORDIA_KEY: "ckey123" });
    });

    it("explicit sanctuaryEnv overrides inherited env vars", async () => {
      const configPath = join(tmpDir, "openclaw.json");
      const original = {
        mcp: {
          servers: {
            sanctuary: {
              command: "npx",
              args: ["@sanctuary-framework/mcp-server"],
              env: {
                SANCTUARY_PASSPHRASE: "old-secret",
                SANCTUARY_DASHBOARD_ENABLED: "true",
              },
            },
          },
        },
      };
      await writeFile(configPath, JSON.stringify(original));

      const agentConfig = await detectAgentConfig("openclaw", configPath);

      // Call WITH explicit sanctuaryEnv — should override, not inherit
      await rewriteConfigForCocoon(
        agentConfig!,
        "npx",
        ["@sanctuary-framework/mcp-server"],
        { SANCTUARY_PASSPHRASE: "new-secret" }
      );

      const rewritten = JSON.parse(await readFile(configPath, "utf-8"));

      // Only the explicitly passed env vars, not the old ones
      expect(rewritten.mcp.servers.sanctuary.env).toEqual({
        SANCTUARY_PASSPHRASE: "new-secret",
      });
    });

    it("preserves top-level mcp fields in OpenClaw format", async () => {
      const configPath = join(tmpDir, "openclaw.json");
      const original = {
        mcp: {
          defaultTimeout: 30000,
          servers: {
            concordia: { command: "python", args: ["-m", "concordia_protocol"] },
          },
        },
        theme: "dark",
      };
      await writeFile(configPath, JSON.stringify(original));

      const agentConfig = await detectAgentConfig("openclaw", configPath);
      await rewriteConfigForCocoon(agentConfig!, "npx", ["@sanctuary-framework/mcp-server"]);

      const rewritten = JSON.parse(await readFile(configPath, "utf-8"));

      // Top-level mcp fields preserved
      expect(rewritten.mcp.defaultTimeout).toBe(30000);
      // Non-mcp fields preserved
      expect(rewritten.theme).toBe("dark");
      // Both servers present
      expect(rewritten.mcp.servers.sanctuary).toBeDefined();
      expect(rewritten.mcp.servers.concordia).toBeDefined();
    });
  });

  // ── Cocoon metadata ─────────────────────────────────────────────

  describe("cocoon metadata", () => {
    it("saves and finds latest backup metadata", async () => {
      // Save cocoon meta to the global backup dir
      await saveCocoonMeta({
        backupPath: "/tmp/test-backup.json",
        originalPath: "/tmp/test-original.json",
        platform: "openclaw",
        wrappedAt: new Date().toISOString(),
      });

      const meta = await findLatestBackup();
      expect(meta).not.toBeNull();
      expect(meta!.backupPath).toBe("/tmp/test-backup.json");
      expect(meta!.originalPath).toBe("/tmp/test-original.json");
    });
  });
});
