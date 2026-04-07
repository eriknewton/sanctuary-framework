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
