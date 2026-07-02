/**
 * Wrap env-var preservation tests — verifies that running
 * `wrap --openclaw` preserves the
 * critical env vars in the rewritten config.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { rewriteConfigForWrap, type AgentConfig } from "../../src/wrap/config-reader.js";

describe("Wrap env-var preservation", () => {
  let tmpDir: string;
  let configPath: string;

  // Save and restore process.env around each test
  const savedEnv: Record<string, string | undefined> = {};
  const ENV_KEYS = [
    "SANCTUARY_PASSPHRASE",
    "SANCTUARY_DASHBOARD_AUTH_TOKEN",
    "SANCTUARY_DASHBOARD_ENABLED",
    "SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE",
    "SANCTUARY_STORAGE_PATH",
    "SANCTUARY_FORTRESS_PATH",
  ] as const;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "wrap-env-test-"));
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

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"], {
      SANCTUARY_PASSPHRASE: "test-pass",
      SANCTUARY_DASHBOARD_AUTH_TOKEN: "tok-123",
      SANCTUARY_DASHBOARD_ENABLED: "true",
      SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE: "true",
    });

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_PASSPHRASE).toBe("test-pass");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("tok-123");
    expect(env.SANCTUARY_DASHBOARD_ENABLED).toBe("true");
    expect(env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE).toBe("true");
  });

  it("falls back to process.env when no explicit env and no existing entry", async () => {
    process.env.SANCTUARY_PASSPHRASE = "from-env";
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "env-tok";
    process.env.SANCTUARY_DASHBOARD_ENABLED = "true";
    process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE = "true";

    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [{ name: "other", transport: "stdio", command: "node", args: ["x.js"] }],
      rawConfig: { mcp: { servers: { other: { command: "node", args: ["x.js"] } } } },
    };
    await writeFile(configPath, JSON.stringify(config.rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"]);

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_PASSPHRASE).toBe("from-env");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("env-tok");
    expect(env.SANCTUARY_DASHBOARD_ENABLED).toBe("true");
    expect(env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE).toBe("true");
  });

  it("inherits from existing sanctuary entry env when no explicit env", async () => {
    for (const key of ENV_KEYS) delete process.env[key];

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

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"]);

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_PASSPHRASE).toBe("existing-pass");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("existing-tok");
    expect(env.SANCTUARY_DASHBOARD_ENABLED).toBe("true");
  });

  it("never inherits the plaintext-remote downgrade flag, even on a bare re-wrap with no explicit env", async () => {
    // The wholesale-inheritance path (no explicit env at all — a bare
    // `sanctuary protect --<harness>` from a clean shell, the most common
    // re-wrap shape the wrapped-install update advice drives) must apply
    // the same never-inherit screen as the explicit-env merge path:
    // the plaintext-remote transport downgrade is re-asserted per wrap
    // run or dropped. The tenancy pair and ordinary persisted vars ARE
    // inherited here (dropping the fortress pointer on a bare re-wrap
    // would orphan the install's identity/custody/policy/audit state).
    for (const key of ENV_KEYS) delete process.env[key];

    const rawConfig = {
      mcp: {
        servers: {
          sanctuary: {
            command: "npx",
            args: ["@sanctuary-framework/mcp-server"],
            env: {
              SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE: "true",
              SANCTUARY_DASHBOARD_AUTH_TOKEN: "persisted-tok",
              SANCTUARY_FORTRESS_PATH: "/tmp/original-fortress",
            },
          },
        },
      },
    };
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [],
      rawConfig,
    };
    await writeFile(configPath, JSON.stringify(rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"]);

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE).toBeUndefined();
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("persisted-tok");
    expect(env.SANCTUARY_FORTRESS_PATH).toBe("/tmp/original-fortress");
  });

  it("merges entry-persisted env under an explicit env (tenancy re-wrap keeps the dashboard token)", async () => {
    // Regression: a re-wrap in a shell with only SANCTUARY_STORAGE_PATH set
    // produces a non-empty explicit env. Pre-fix, that skipped the
    // existing-entry inheritance entirely and silently dropped
    // entry-persisted vars (e.g. SANCTUARY_DASHBOARD_AUTH_TOKEN written by
    // an earlier wrap) that are absent from the current shell — exactly the
    // upgrade flow the wrapped-install update advice recommends.
    for (const key of ENV_KEYS) delete process.env[key];

    const rawConfig = {
      mcp: {
        servers: {
          sanctuary: {
            command: "npx",
            args: ["@sanctuary-framework/mcp-server"],
            env: {
              SANCTUARY_DASHBOARD_AUTH_TOKEN: "persisted-tok",
              SANCTUARY_DASHBOARD_ENABLED: "true",
            },
          },
        },
      },
    };
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [],
      rawConfig,
    };
    await writeFile(configPath, JSON.stringify(rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"], {
      SANCTUARY_STORAGE_PATH: "/tmp/tenant-storage",
    });

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_STORAGE_PATH).toBe("/tmp/tenant-storage");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("persisted-tok");
    expect(env.SANCTUARY_DASHBOARD_ENABLED).toBe("true");
  });

  it("explicit env keys win over entry-persisted values on merge", async () => {
    for (const key of ENV_KEYS) delete process.env[key];

    const rawConfig = {
      mcp: {
        servers: {
          sanctuary: {
            command: "npx",
            args: ["@sanctuary-framework/mcp-server"],
            env: {
              SANCTUARY_DASHBOARD_AUTH_TOKEN: "old-tok",
              SANCTUARY_PASSPHRASE: "old-pass",
            },
          },
        },
      },
    };
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [],
      rawConfig,
    };
    await writeFile(configPath, JSON.stringify(rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"], {
      SANCTUARY_DASHBOARD_AUTH_TOKEN: "new-tok",
    });

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("new-tok");
    expect(env.SANCTUARY_PASSPHRASE).toBe("old-pass");
  });

  it("does not inherit a stale fortress path when the explicit env pins the tenancy", async () => {
    // The storage-tenancy pair is caller-authoritative on the explicit
    // path: the wrap run just wrote wrap-meta/custody/profile against its
    // own storage resolution, and a stale SANCTUARY_FORTRESS_PATH from the
    // old entry would win the spawned server's boot-time re-promotion and
    // point it at a different fortress than the one the run populated.
    for (const key of ENV_KEYS) delete process.env[key];

    const rawConfig = {
      mcp: {
        servers: {
          sanctuary: {
            command: "npx",
            args: ["@sanctuary-framework/mcp-server"],
            env: {
              SANCTUARY_FORTRESS_PATH: "/tmp/old-fortress",
              SANCTUARY_DASHBOARD_AUTH_TOKEN: "persisted-tok",
            },
          },
        },
      },
    };
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [],
      rawConfig,
    };
    await writeFile(configPath, JSON.stringify(rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"], {
      SANCTUARY_STORAGE_PATH: "/tmp/tenant-storage",
    });

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_STORAGE_PATH).toBe("/tmp/tenant-storage");
    expect(env.SANCTUARY_FORTRESS_PATH).toBeUndefined();
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("persisted-tok");
  });

  it("does not inherit the plaintext-remote downgrade flag past an explicit-env re-wrap", async () => {
    // SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE is a permissive,
    // less-secure setting: inheriting it would keep plaintext remote
    // dashboard access silently sticky across a re-wrap the operator ran
    // WITHOUT asking for it. It must be re-asserted per wrap run
    // (--allow-plaintext-remote or the env var). Ordinary persisted vars
    // (the dashboard token) still survive the same merge.
    for (const key of ENV_KEYS) delete process.env[key];

    const rawConfig = {
      mcp: {
        servers: {
          sanctuary: {
            command: "npx",
            args: ["@sanctuary-framework/mcp-server"],
            env: {
              SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE: "true",
              SANCTUARY_DASHBOARD_AUTH_TOKEN: "persisted-tok",
            },
          },
        },
      },
    };
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [],
      rawConfig,
    };
    await writeFile(configPath, JSON.stringify(rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"], {
      SANCTUARY_STORAGE_PATH: "/tmp/tenant-storage",
    });

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE).toBeUndefined();
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("persisted-tok");
  });

  it("keeps the plaintext-remote flag when the re-wrap explicitly re-asserts it", async () => {
    // The opt-in path: --allow-plaintext-remote (or the env var) lands in
    // the explicit env, and explicit keys win the merge, so an operator who
    // re-asserts the downgrade on the re-wrap keeps it.
    for (const key of ENV_KEYS) delete process.env[key];

    const rawConfig = {
      mcp: {
        servers: {
          sanctuary: {
            command: "npx",
            args: ["@sanctuary-framework/mcp-server"],
            env: {
              SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE: "true",
              SANCTUARY_DASHBOARD_AUTH_TOKEN: "persisted-tok",
            },
          },
        },
      },
    };
    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [],
      rawConfig,
    };
    await writeFile(configPath, JSON.stringify(rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"], {
      SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE: "true",
    });

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const env = result.mcp.servers.sanctuary.env;
    expect(env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE).toBe("true");
    expect(env.SANCTUARY_DASHBOARD_AUTH_TOKEN).toBe("persisted-tok");
  });

  it("does not inject env vars when none are available", async () => {
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;
    delete process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE;

    const config: AgentConfig = {
      platform: "openclaw",
      configPath,
      servers: [{ name: "other", transport: "stdio", command: "node", args: ["x.js"] }],
      rawConfig: { mcp: { servers: { other: { command: "node", args: ["x.js"] } } } },
    };
    await writeFile(configPath, JSON.stringify(config.rawConfig), { mode: 0o600 });

    await rewriteConfigForWrap(config, "npx", ["@sanctuary-framework/mcp-server"]);

    const result = JSON.parse(await readFile(configPath, "utf-8"));
    const sanctuaryEntry = result.mcp.servers.sanctuary;
    expect(sanctuaryEntry.env).toBeUndefined();
  });
});
