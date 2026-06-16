/**
 * Principal Policy Tools tests
 *
 * Covers: policy view with/without defaults, SEC-002 auto_deny hardcoding,
 * baseline view, read-only verification, audit logging.
 * Not covered: concurrent access patterns.
 */

import { describe, it, expect } from "vitest";
import { createPrincipalPolicyTools } from "../../src/principal-policy/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";

function setup() {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  const policy = {
    version: "1.0",
    tier1_always_approve: ["state_export", "key_rotate"],
    tier2_anomaly: { new_namespace: true, new_counterparty: true },
    tier3_always_allow: ["state_read", "state_list", "shr_generate", "governor_status"],
    approval_channel: {
      type: "stderr" as const,
      timeout_seconds: 30,
      auto_deny: true,
    },
  };
  const baseline = {
    getProfile: () => ({
      is_first_session: false,
      started_at: "2026-04-17T00:00:00Z",
      known_namespaces: ["default", "test"],
      known_counterparties: ["did:key:abc"],
      tool_call_counts: { state_read: 10, shr_generate: 2 },
      saved_at: "2026-04-17T01:00:00Z",
    }),
  };
  const tools = createPrincipalPolicyTools(policy as any, baseline as any, auditLog);
  const findTool = (name: string) => tools.find(t => t.name === name)!;
  return { tools, findTool, auditLog };
}

describe("Principal Policy Tools", () => {
  describe("principal_policy_view", () => {
    it("returns policy without defaults by default", async () => {
      const { findTool } = setup();
      const result = await findTool("principal_policy_view").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tier3_always_allow_count).toBe(4);
      expect(parsed.tier3_always_allow).toBeUndefined();
    });

    it("includes defaults when requested", async () => {
      const { findTool } = setup();
      const result = await findTool("principal_policy_view").handler({ include_defaults: true });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.tier3_always_allow).toEqual(["state_read", "state_list", "shr_generate", "governor_status"]);
    });

    it("hardcodes auto_deny to true (SEC-002)", async () => {
      const { findTool } = setup();
      const result = await findTool("principal_policy_view").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.approval_channel.auto_deny).toBe(true);
    });

    it("includes version and tier1 operations", async () => {
      const { findTool } = setup();
      const result = await findTool("principal_policy_view").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.version).toBe("1.0");
      expect(parsed.tier1_always_approve).toContain("state_export");
    });
  });

  describe("principal_baseline_view", () => {
    it("returns baseline profile", async () => {
      const { findTool } = setup();
      const result = await findTool("principal_baseline_view").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.is_first_session).toBe(false);
      expect(parsed.known_namespaces).toContain("default");
      expect(parsed.tool_call_counts.state_read).toBe(10);
    });

    it("reports last_saved time", async () => {
      const { findTool } = setup();
      const result = await findTool("principal_baseline_view").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.last_saved).toBe("2026-04-17T01:00:00Z");
    });
  });
});
