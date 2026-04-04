/**
 * Upstream Server Registry Tests (via SovereigntyProfile)
 *
 * Verifies:
 * - Default profile has no upstream_servers
 * - Adding upstream servers via update
 * - Server name format validation
 * - Transport config validation (stdio, sse)
 * - Tier value validation
 * - Enabling/disabling individual servers
 * - Tool override configuration
 * - Updating existing server config
 * - Maximum server name length
 * - Non-array upstream_servers rejected
 * - Missing required fields rejected
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  SovereigntyProfileStore,
  createDefaultProfile,
} from "../../src/sovereignty-profile.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

describe("Upstream Server Registry", () => {
  let store: SovereigntyProfileStore;
  let storage: MemoryStorage;
  let masterKey: Uint8Array;

  beforeEach(async () => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    store = new SovereigntyProfileStore(storage, masterKey);
    await store.load();
  });

  // ── Default profile ───────────────────────────────────────────────

  describe("default profile", () => {
    it("has no upstream_servers field", () => {
      const profile = createDefaultProfile();
      expect(profile.upstream_servers).toBeUndefined();
    });

    it("loaded profile has no upstream_servers", () => {
      const profile = store.get();
      expect(profile.upstream_servers).toBeUndefined();
    });
  });

  // ── Adding upstream servers ───────────────────────────────────────

  describe("adding upstream servers", () => {
    it("can add upstream servers via update", async () => {
      const servers = [
        {
          name: "filesystem",
          transport: { type: "stdio" as const, command: "node", args: ["server.js"] },
          enabled: true,
          default_tier: 2 as const,
        },
      ];

      const updated = await store.update({ upstream_servers: servers });
      expect(updated.upstream_servers).toHaveLength(1);
      expect(updated.upstream_servers![0]!.name).toBe("filesystem");
    });

    it("can add multiple upstream servers", async () => {
      const servers = [
        {
          name: "filesystem",
          transport: { type: "stdio" as const, command: "node" },
          enabled: true,
          default_tier: 2 as const,
        },
        {
          name: "github",
          transport: { type: "sse" as const, url: "http://localhost:3000/sse" },
          enabled: true,
          default_tier: 3 as const,
        },
      ];

      const updated = await store.update({ upstream_servers: servers });
      expect(updated.upstream_servers).toHaveLength(2);
    });

    it("persists upstream servers across reload", async () => {
      await store.update({
        upstream_servers: [
          {
            name: "test-server",
            transport: { type: "stdio" as const, command: "echo" },
            enabled: true,
            default_tier: 2 as const,
          },
        ],
      });

      // Create a new store instance pointing to the same storage
      const store2 = new SovereigntyProfileStore(storage, masterKey);
      const reloaded = await store2.load();
      expect(reloaded.upstream_servers).toHaveLength(1);
      expect(reloaded.upstream_servers![0]!.name).toBe("test-server");
    });
  });

  // ── Server name validation ────────────────────────────────────────

  describe("server name validation", () => {
    it("accepts alphanumeric names with hyphens and underscores", async () => {
      const updated = await store.update({
        upstream_servers: [
          {
            name: "my-server_01",
            transport: { type: "stdio" as const, command: "node" },
            enabled: true,
            default_tier: 2 as const,
          },
        ],
      });
      expect(updated.upstream_servers![0]!.name).toBe("my-server_01");
    });

    it("rejects names with special characters", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "my server",
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow("alphanumeric");
    });

    it("rejects names with slashes", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "my/server",
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow("alphanumeric");
    });

    it("rejects names longer than 128 characters", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "a".repeat(129),
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow("128 characters");
    });

    it("rejects empty server name", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "",
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow();
    });
  });

  // ── Transport validation ──────────────────────────────────────────

  describe("transport validation", () => {
    it("accepts stdio transport with command", async () => {
      const updated = await store.update({
        upstream_servers: [
          {
            name: "stdio-server",
            transport: { type: "stdio" as const, command: "node", args: ["index.js"] },
            enabled: true,
            default_tier: 2 as const,
          },
        ],
      });
      expect(updated.upstream_servers![0]!.transport.type).toBe("stdio");
    });

    it("accepts sse transport with url", async () => {
      const updated = await store.update({
        upstream_servers: [
          {
            name: "sse-server",
            transport: { type: "sse" as const, url: "http://localhost:8080/sse" },
            enabled: true,
            default_tier: 2 as const,
          },
        ],
      });
      expect(updated.upstream_servers![0]!.transport.type).toBe("sse");
    });

    it("rejects stdio transport without command", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "bad-stdio",
              transport: { type: "stdio" as const },
              enabled: true,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow("command");
    });

    it("rejects sse transport without url", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "bad-sse",
              transport: { type: "sse" as const },
              enabled: true,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow("url");
    });

    it("rejects invalid transport type", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "bad-type",
              transport: { type: "websocket" as any, url: "ws://localhost" },
              enabled: true,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow("Transport type must be");
    });

    it("rejects missing transport entirely", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "no-transport",
              enabled: true,
              default_tier: 2 as const,
            } as any,
          ],
        })
      ).rejects.toThrow("transport");
    });
  });

  // ── Tier validation ───────────────────────────────────────────────

  describe("tier validation", () => {
    it("accepts tier 1, 2, and 3", async () => {
      for (const tier of [1, 2, 3] as const) {
        const updated = await store.update({
          upstream_servers: [
            {
              name: `server-tier-${tier}`,
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: tier,
            },
          ],
        });
        expect(updated.upstream_servers![0]!.default_tier).toBe(tier);
      }
    });

    it("rejects invalid tier values", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "bad-tier",
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: 4 as any,
            },
          ],
        })
      ).rejects.toThrow("default_tier must be 1, 2, or 3");
    });

    it("rejects tier 0", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "zero-tier",
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: 0 as any,
            },
          ],
        })
      ).rejects.toThrow("default_tier must be 1, 2, or 3");
    });
  });

  // ── Enable/disable ────────────────────────────────────────────────

  describe("enable and disable servers", () => {
    it("can set server as enabled", async () => {
      const updated = await store.update({
        upstream_servers: [
          {
            name: "active-server",
            transport: { type: "stdio" as const, command: "node" },
            enabled: true,
            default_tier: 2 as const,
          },
        ],
      });
      expect(updated.upstream_servers![0]!.enabled).toBe(true);
    });

    it("can set server as disabled", async () => {
      const updated = await store.update({
        upstream_servers: [
          {
            name: "inactive-server",
            transport: { type: "stdio" as const, command: "node" },
            enabled: false,
            default_tier: 2 as const,
          },
        ],
      });
      expect(updated.upstream_servers![0]!.enabled).toBe(false);
    });

    it("rejects non-boolean enabled value", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "bad-enabled",
              transport: { type: "stdio" as const, command: "node" },
              enabled: "yes" as any,
              default_tier: 2 as const,
            },
          ],
        })
      ).rejects.toThrow("enabled as a boolean");
    });
  });

  // ── Tool overrides ────────────────────────────────────────────────

  describe("tool overrides", () => {
    it("can set tool_overrides on a server", async () => {
      const updated = await store.update({
        upstream_servers: [
          {
            name: "overridden-server",
            transport: { type: "stdio" as const, command: "node" },
            enabled: true,
            default_tier: 3 as const,
            tool_overrides: {
              dangerous_tool: { tier: 1 },
              safe_tool: { tier: 3 },
            },
          },
        ],
      });
      expect(updated.upstream_servers![0]!.tool_overrides).toEqual({
        dangerous_tool: { tier: 1 },
        safe_tool: { tier: 3 },
      });
    });

    it("rejects invalid tier in tool_overrides", async () => {
      await expect(
        store.update({
          upstream_servers: [
            {
              name: "bad-override",
              transport: { type: "stdio" as const, command: "node" },
              enabled: true,
              default_tier: 2 as const,
              tool_overrides: {
                some_tool: { tier: 5 as any },
              },
            },
          ],
        })
      ).rejects.toThrow("tool_overrides tier must be 1, 2, or 3");
    });
  });

  // ── Updating server config ────────────────────────────────────────

  describe("updating existing server config", () => {
    it("replaces the entire upstream_servers array on update", async () => {
      await store.update({
        upstream_servers: [
          {
            name: "server-a",
            transport: { type: "stdio" as const, command: "node" },
            enabled: true,
            default_tier: 2 as const,
          },
          {
            name: "server-b",
            transport: { type: "stdio" as const, command: "python" },
            enabled: true,
            default_tier: 3 as const,
          },
        ],
      });

      // Update with a different set
      const updated = await store.update({
        upstream_servers: [
          {
            name: "server-c",
            transport: { type: "sse" as const, url: "http://localhost:9000" },
            enabled: false,
            default_tier: 1 as const,
          },
        ],
      });

      expect(updated.upstream_servers).toHaveLength(1);
      expect(updated.upstream_servers![0]!.name).toBe("server-c");
    });

    it("updates updated_at timestamp on change", async () => {
      const before = store.get().updated_at;

      // Small delay to ensure different timestamp
      await new Promise((r) => setTimeout(r, 5));

      await store.update({
        upstream_servers: [
          {
            name: "ts-server",
            transport: { type: "stdio" as const, command: "node" },
            enabled: true,
            default_tier: 2 as const,
          },
        ],
      });

      const after = store.get().updated_at;
      expect(after).not.toBe(before);
    });
  });

  // ── Non-array rejected ────────────────────────────────────────────

  describe("non-array upstream_servers", () => {
    it("rejects non-array value for upstream_servers", async () => {
      await expect(
        store.update({
          upstream_servers: "not-an-array" as any,
        })
      ).rejects.toThrow("must be an array");
    });
  });

  // ── Environment variables ─────────────────────────────────────────

  describe("transport environment variables", () => {
    it("accepts env vars in transport config", async () => {
      const updated = await store.update({
        upstream_servers: [
          {
            name: "env-server",
            transport: {
              type: "stdio" as const,
              command: "node",
              env: { API_KEY: "secret", NODE_ENV: "production" },
            },
            enabled: true,
            default_tier: 2 as const,
          },
        ],
      });
      expect(updated.upstream_servers![0]!.transport.env).toEqual({
        API_KEY: "secret",
        NODE_ENV: "production",
      });
    });
  });
});
