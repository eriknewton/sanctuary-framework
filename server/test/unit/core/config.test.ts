/**
 * Sanctuary MCP Server — Configuration Tests
 *
 * Tests for config precedence (Bug 1: env vars must override file config)
 * and version stamping (Bug 2: version must come from package.json, not stored config).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { loadConfig, defaultConfig, SANCTUARY_VERSION } from "../../../src/config.js";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("loadConfig", () => {
  let tempDir: string;

  beforeEach(async () => {
    // Create a unique temp directory for each test
    tempDir = join(tmpdir(), `sanctuary-config-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    // Clean env vars
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;
    delete process.env.SANCTUARY_DASHBOARD_PORT;
    delete process.env.SANCTUARY_DASHBOARD_HOST;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_WEBHOOK_ENABLED;
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_TRANSPORT;
    delete process.env.SANCTUARY_HTTP_PORT;
    delete process.env.SANCTUARY_PRIVACY_FILTER;
    delete process.env.SANCTUARY_PRIVACY_FILTER_FAIL_MODE;
    delete process.env.SANCTUARY_PRIVACY_FILTER_COMMAND;
    delete process.env.SANCTUARY_PRIVACY_FILTER_TIMEOUT_MS;

    // Clean up temp dir
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });

  describe("Bug 1: Config precedence — env vars override file config", () => {
    it("env var SANCTUARY_DASHBOARD_ENABLED=true overrides file dashboard.enabled=false", async () => {
      // Simulate the exact Mac Mini scenario: sanctuary.json has enabled:false,
      // env var sets true. Before the fix, file would win.
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: false, port: 3501, host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
      const config = await loadConfig(configFile);

      expect(config.dashboard.enabled).toBe(true);
    });

    it("env var SANCTUARY_DASHBOARD_ENABLED=false overrides file dashboard.enabled=true", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: true, port: 3501, host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_DASHBOARD_ENABLED = "false";
      const config = await loadConfig(configFile);

      expect(config.dashboard.enabled).toBe(false);
    });

    it("env var SANCTUARY_DASHBOARD_PORT overrides file value", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: false, port: 9999, host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_DASHBOARD_PORT = "4000";
      const config = await loadConfig(configFile);

      expect(config.dashboard.port).toBe(4000);
    });

    it("env var SANCTUARY_WEBHOOK_ENABLED=true overrides file webhook.enabled=false", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        webhook: { enabled: false, url: "", secret: "", callback_port: 3502, callback_host: "127.0.0.1" },
      }));

      process.env.SANCTUARY_WEBHOOK_ENABLED = "true";
      const config = await loadConfig(configFile);

      expect(config.webhook.enabled).toBe(true);
    });

    it("file config values apply when no env var overrides them", async () => {
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        dashboard: { enabled: true, port: 7777, host: "0.0.0.0" },
      }));

      // No env vars set — file values should apply
      const config = await loadConfig(configFile);

      expect(config.dashboard.enabled).toBe(true);
      expect(config.dashboard.port).toBe(7777);
      expect(config.dashboard.host).toBe("0.0.0.0");
    });
  });

  describe("Bug 2: Version string — always from package.json", () => {
    it("version comes from package.json even when sanctuary.json stores an old version", async () => {
      // Simulate the Mac Mini scenario: sanctuary.json stores version "0.3.0"
      // from first run, but package.json is 0.5.0
      const configFile = join(tempDir, "sanctuary.json");
      await writeFile(configFile, JSON.stringify({
        ...defaultConfig(),
        version: "0.3.0",
      }));

      const config = await loadConfig(configFile);

      expect(config.version).toBe(SANCTUARY_VERSION);
      expect(config.version).not.toBe("0.3.0");
    });

    it("version matches SANCTUARY_VERSION constant", async () => {
      // No config file — defaults only
      const config = await loadConfig(join(tempDir, "nonexistent.json"));
      expect(config.version).toBe(SANCTUARY_VERSION);
    });
  });

  describe("Config file missing — graceful fallback", () => {
    it("returns valid defaults when config file does not exist", async () => {
      const config = await loadConfig(join(tempDir, "nonexistent.json"));

      expect(config.dashboard.enabled).toBe(false);
      expect(config.dashboard.port).toBe(3501);
      expect(config.transport).toBe("stdio");
    });

    it("env vars still apply when config file is missing", async () => {
      process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
      process.env.SANCTUARY_HTTP_PORT = "5000";

      const config = await loadConfig(join(tempDir, "nonexistent.json"));

      expect(config.dashboard.enabled).toBe(true);
      expect(config.http_port).toBe(5000);
    });
  });

  describe("Privacy filter config", () => {
    it("defaults to local placeholder filtering with fallback fail mode", async () => {
      const config = await loadConfig(join(tempDir, "nonexistent.json"));
      expect(config.privacy_filter).toEqual({
        mode: "local",
        fail_mode: "fallback",
        command: "opf",
        timeout_ms: 5000,
      });
    });

    it("env vars override privacy filter config", async () => {
      process.env.SANCTUARY_PRIVACY_FILTER = "opf";
      process.env.SANCTUARY_PRIVACY_FILTER_FAIL_MODE = "closed";
      process.env.SANCTUARY_PRIVACY_FILTER_COMMAND = "/tmp/mock-opf";
      process.env.SANCTUARY_PRIVACY_FILTER_TIMEOUT_MS = "750";

      const config = await loadConfig(join(tempDir, "nonexistent.json"));
      expect(config.privacy_filter).toEqual({
        mode: "opf",
        fail_mode: "closed",
        command: "/tmp/mock-opf",
        timeout_ms: 750,
      });
    });

    it("rejects invalid privacy filter mode", async () => {
      process.env.SANCTUARY_PRIVACY_FILTER = "remote";
      await expect(loadConfig(join(tempDir, "nonexistent.json"))).rejects.toThrow(
        /privacy_filter\.mode/
      );
    });
  });
});
