/**
 * Sovereignty Profile Tools Tests
 *
 * Verifies:
 * - sanctuary/sovereignty_profile_get returns current profile
 * - sanctuary/sovereignty_profile_update applies partial changes
 * - sanctuary/sovereignty_profile_generate_prompt returns prompt text
 * - Audit log entries are created for all operations
 * - Tool handlers return proper MCP response format
 */

import { describe, it, expect, vi } from "vitest";
import { SovereigntyProfileStore } from "../src/sovereignty-profile.js";
import { createSovereigntyProfileTools } from "../src/sovereignty-profile-tools.js";
import { MemoryStorage } from "../src/storage/memory.js";
import { AuditLog } from "../src/operational/audit-log.js";
import { generateRandomKey } from "../src/core/random.js";

class FailingAuditStorage extends MemoryStorage {
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit") {
      const err = new Error("audit storage full") as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    }
    return super.write(namespace, key, data);
  }
}

async function createTestContext() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const profileStore = new SovereigntyProfileStore(storage, masterKey);
  await profileStore.load();
  const auditLog = new AuditLog(storage, masterKey);
  const { tools } = createSovereigntyProfileTools(profileStore, auditLog);

  const findTool = (name: string) => {
    const tool = tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Tool ${name} not found`);
    return tool;
  };

  return { profileStore, auditLog, tools, findTool };
}

function parseToolResult(result: { content: Array<{ type: string; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text);
}

describe("Sovereignty Profile Tools", () => {
  // ── Tool Registration ─────────────────────────────────────────────

  describe("tool registration", () => {
    it("creates 3 tools", async () => {
      const { tools } = await createTestContext();
      expect(tools).toHaveLength(3);
    });

    it("registers sanctuary/sovereignty_profile_get", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_get");
      expect(tool.name).toBe("sovereignty_profile_get");
    });

    it("registers sanctuary/sovereignty_profile_update", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_update");
      expect(tool.name).toBe("sovereignty_profile_update");
    });

    it("registers sanctuary/sovereignty_profile_generate_prompt", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_generate_prompt");
      expect(tool.name).toBe("sovereignty_profile_generate_prompt");
    });
  });

  // ── sovereignty_profile_get ───────────────────────────────────────

  describe("sovereignty_profile_get", () => {
    it("returns the current profile", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_get");
      const result = await tool.handler({});
      const data = parseToolResult(result);

      expect(data).toHaveProperty("profile");
      const profile = data.profile as Record<string, unknown>;
      expect(profile).toHaveProperty("version", 1);
      expect(profile).toHaveProperty("features");
    });

    it("returns MCP-compatible response format", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_get");
      const result = await tool.handler({});

      expect(result).toHaveProperty("content");
      expect(result.content).toHaveLength(1);
      expect(result.content[0]).toHaveProperty("type", "text");
      expect(result.content[0]).toHaveProperty("text");
    });

    it("includes message in response", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_get");
      const result = await tool.handler({});
      const data = parseToolResult(result);
      expect(data).toHaveProperty("message");
    });

    it("redacts upstream transport credentials and tier policy from agent-facing profile", async () => {
      const { profileStore, findTool } = await createTestContext();
      await profileStore.update({
        upstream_servers: [
          {
            name: "filesystem",
            transport: {
              type: "stdio",
              command: "node",
              args: ["server.js"],
              env: { API_TOKEN: "secret-token" },
            },
            enabled: true,
            default_tier: 2,
            tool_overrides: { read_file: { tier: 3 } },
          },
          {
            name: "remote",
            transport: {
              type: "sse",
              url: "https://token@example.test/sse",
            },
            enabled: false,
            default_tier: 1,
          },
        ],
      });

      const result = await findTool("sovereignty_profile_get").handler({});
      const data = parseToolResult(result);
      const text = result.content[0]!.text;
      const profile = data.profile as {
        upstream_servers: Array<Record<string, unknown>>;
      };

      expect(profile.upstream_servers).toEqual([
        {
          name: "filesystem",
          enabled: true,
          transport_type: "stdio",
          privacy_policy_bound: false,
          privacy_identity_bound: false,
        },
        {
          name: "remote",
          enabled: false,
          transport_type: "sse",
          privacy_policy_bound: false,
          privacy_identity_bound: false,
        },
      ]);
      expect(text).not.toContain("secret-token");
      expect(text).not.toContain("https://token@example.test/sse");
      expect(text).not.toContain("default_tier");
      expect(text).not.toContain("tool_overrides");
      expect(text).not.toContain("\"env\"");
      expect(text).not.toContain("\"url\"");
    });
  });

  // ── sovereignty_profile_update ────────────────────────────────────

  describe("sovereignty_profile_update", () => {
    it("enables a feature", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_update");
      const result = await tool.handler({
        zk_proofs: { enabled: true },
      });
      const data = parseToolResult(result);
      const profile = data.profile as { features: Record<string, { enabled: boolean }> };
      expect(profile.features.zk_proofs.enabled).toBe(true);
    });

    it("disables a feature", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_update");
      const result = await tool.handler({
        audit_logging: { enabled: false },
      });
      const data = parseToolResult(result);
      const profile = data.profile as { features: Record<string, { enabled: boolean }> };
      expect(profile.features.audit_logging.enabled).toBe(false);
    });

    it("updates sensitivity", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_update");
      const result = await tool.handler({
        injection_detection: { sensitivity: "high" },
      });
      const data = parseToolResult(result);
      const profile = data.profile as {
        features: { injection_detection: { enabled: boolean; sensitivity: string } };
      };
      expect(profile.features.injection_detection.sensitivity).toBe("high");
    });

    it("preserves unmodified features", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_update");
      const result = await tool.handler({
        context_gating: { enabled: true },
      });
      const data = parseToolResult(result);
      const profile = data.profile as { features: Record<string, { enabled: boolean }> };
      expect(profile.features.audit_logging.enabled).toBe(true); // Unchanged
      expect(profile.features.injection_detection.enabled).toBe(true); // Unchanged
    });

    it("handles empty update", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_update");
      const result = await tool.handler({});
      const data = parseToolResult(result);
      expect(data).toHaveProperty("profile");
    });

    it("surfaces committed profile updates when critical audit persistence fails", async () => {
      const storage = new FailingAuditStorage();
      const masterKey = generateRandomKey();
      const profileStore = new SovereigntyProfileStore(storage, masterKey);
      await profileStore.load();
      const auditLog = new AuditLog(storage, masterKey);
      const { tools } = createSovereigntyProfileTools(profileStore, auditLog);
      const tool = tools.find((candidate) => candidate.name === "sovereignty_profile_update")!;

      await expect(tool.handler({ zk_proofs: { enabled: true } })).rejects.toMatchObject({
        name: "AuditPersistenceError",
        classification: "storage_full",
      });
      expect(profileStore.get().features.zk_proofs.enabled).toBe(true);
    });

    it("persists changes across get calls", async () => {
      const { findTool } = await createTestContext();
      const updateTool = findTool("sovereignty_profile_update");
      const getTool = findTool("sovereignty_profile_get");

      await updateTool.handler({ approval_gate: { enabled: true } });
      const result = await getTool.handler({});
      const data = parseToolResult(result);
      const profile = data.profile as { features: Record<string, { enabled: boolean }> };
      expect(profile.features.approval_gate.enabled).toBe(true);
    });
  });

  // ── sovereignty_profile_generate_prompt ────────────────────────────

  describe("sovereignty_profile_generate_prompt", () => {
    it("returns system prompt text", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_generate_prompt");
      const result = await tool.handler({});
      const data = parseToolResult(result);

      expect(data).toHaveProperty("system_prompt");
      expect(typeof data.system_prompt).toBe("string");
      expect(data.system_prompt as string).toContain("Sanctuary");
    });

    it("includes token estimate", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_generate_prompt");
      const result = await tool.handler({});
      const data = parseToolResult(result);

      expect(data).toHaveProperty("token_estimate");
      expect(typeof data.token_estimate).toBe("number");
      expect(data.token_estimate as number).toBeLessThan(500);
    });

    it("reflects enabled features in prompt", async () => {
      const { findTool } = await createTestContext();
      const updateTool = findTool("sovereignty_profile_update");
      const promptTool = findTool("sovereignty_profile_generate_prompt");

      await updateTool.handler({ zk_proofs: { enabled: true } });
      const result = await promptTool.handler({});
      const data = parseToolResult(result);
      const prompt = data.system_prompt as string;

      expect(prompt).toContain("Zero-Knowledge Proofs");
      expect(prompt).toContain("zk_commit");
    });

    it("reflects disabled features as optional", async () => {
      const { findTool } = await createTestContext();
      const tool = findTool("sovereignty_profile_generate_prompt");
      const result = await tool.handler({});
      const data = parseToolResult(result);
      const prompt = data.system_prompt as string;

      expect(prompt).toContain("Optional tools available");
      expect(prompt).toContain("context gating");
    });
  });
});
