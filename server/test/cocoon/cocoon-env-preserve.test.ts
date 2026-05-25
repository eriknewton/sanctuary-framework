/**
 * Cocoon env-var preservation tests — verifies that running
 * `cocoon --openclaw` / `wrap --openclaw` preserves the three
 * critical env vars in the rewritten config.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { rewriteConfigForCocoon, type AgentConfig } from "../../src/wrap/config-reader.js";

describe("Cocoon env-var preservation", () => {
  let tmpDir: string;
  let configPath: string;

  // Save and restore process.env around each test
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = [
    "SANCTUARY_PASSPHRASE",
    "SANCTUARY_DASHBOARD_AUTH_TOKEN",
    "SANCTUARY_DASHBOARD_ENABLED",
  ] as const;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "cocoon-env-test-"));
    configPath = join(tmpDir, "openclaw.json");
    for (const key of ENV_KEYS) {
      savedEnv[key] = process.env[key];
    }
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
    for (const key of ENV_KEYS) {
      if (savedEnv[key] === undefined) delete process.env[key];
      else process.env[key] = savedEnv[key];
    }
  });

  it("preserves env vars when passed explicitly as 4th param", async () => {
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [{ name: "test-server", transport: "stdio", command: "node", args: ["test.js"] }],
      rawConfig: { mcp: { servers: { "test-server": { command: "node", args: ["test.js"] } } } },
    };
    await writeFile(configPath, JSON.stringify(config.rawConfig), { mode: 0o600 });

    await rewriteConfigForCocoon(config, "npx", ["@sanctuary-framework/mcp-server"], {
      SANCTUARY_PASSPHRASE: "test-pass",
      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok-123",
      SANCTUARY_DASHBOARD_ENABLED: "true",
    });

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_PASSPHRASE).toBe("test-pass");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("tok-123");
    expect(env.SANCTUARY_DASHBOARD_ENABLED).toBe("true");
  });

  it("falls back to process.env when no explicit env and no existing entry", async () => {
    process.env.SANCTUARY_PASSPHRASE = "from-env";
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "env-tok";
    process.env.SANCTUARY_DASHBOARD_ENABLED = "true";

    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [{ name: "other", transport: "stdio", command: "node", args: ["x.js"] }],
      rawConfig: { mcp: { servers: { other: { command: "node", args: ["x.js"] } } } },
    };
    await writeFile(configPath, JSON.stringify(config.rawConfig), { mode: 0o600 });

    await rewriteConfigForCocoon(config, "npx", ["@sanctuary-framework/mcp-server"]);

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_PASSPHRASE).toBe("from-env");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("env-tok");
    expect(env.SANCTUARY_DASHBOARD_ENABLED).toBe("true");
  });

  it("inherits from existing sanctuary entry env when no explicit env", async () => {
    // Clear process.env so it doesn't interfere
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;

    const rawConfig = {
      mcp: {
        servers: {
          sanctuary: {
            command: "npx",
            args: ["@sanctuary-framework/mcp-server"],
            env: {
              SANCTUARY_PASSPHRASE: "existing-pass",
              SANCTUARY_DASHBOARD_AUTH_TOKEN: "existing-tok",
              SANCTUARY_DASHBOARD_ENABLED: "true",
            },
          },
          other: { command: "node", args: ["x.js"] },
        },
      },
    };
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [{ name: "other", transport: "stdio", command: "node", args: ["x.js"] }],
      rawConfig,
    };
    await writeFile(configPath, JSON.stringify(rawConfig), { mode: 0o600 });

    await rewriteConfigForCocoon(config, "npx", ["@sanctuary-framework/mcp-server"]);

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_PASSPHRASE).toBe("existing-pass");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("existing-tok");
    expect(env.SANCTUARY_DASHBOARD_ENABLED).toBe("true");
  });

  it("does not inject env vars when none are available", async () => {
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;

    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [{ name: "other", transport: "stdio", command: "node", args: ["x.js"] }],
      rawConfig: { mcp: { servers: { other: { command: "node", args: ["x.js"] } } } },
    };
    await writeFile(configPath, JSON.stringify(config.rawConfig), { mode: 0o600 });

    await rewriteConfigForCocoon(config, "npx", ["@sanctuary-framework/mcp-server"]);

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const sanctuaryEntry = result.mcp.servers.sanctuary;
    expect(sanctuaryEntry.env).toBeUndefined();
  });
});
