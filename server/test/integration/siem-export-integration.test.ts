/**
 * SIEM Export Integration Test
 *
 * End-to-end test of the audit_export_siem tool verifying:
 * - Tool registration and handler execution
 * - CEF and OCSF format output from live audit log
 * - Time range filtering (since/until)
 * - Tool name and decision filtering
 * - Proper error handling for invalid inputs
 *
 * Simulates a real deployment exporting events to Splunk/Datadog.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createSIEMTools } from "../../src/audit/siem-tools.js";
import { fingerprintIdentityId } from "../../src/agent-native/safety-base.js";

// The agent-callable SIEM export is scoped to the CALLER's own identity and
// emits only the agent ALLOWLIST view (no tier, no agent DID, no session id, no
// raw gate decision; severity from result/decision only). These tests seed all
// entries under the bound caller identity and assert the safe contract.
const CALLER = "agent-001";

describe("SIEM Export Integration", () => {
  let auditLog: AuditLog;
  let tool: any;

  beforeEach(async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    auditLog = new AuditLog(storage, masterKey);

    // Bind the SIEM tools to the caller identity (own-identity filter).
    const { tools } = createSIEMTools(auditLog, () => ({
      identity_id: CALLER,
      requester_identity_fingerprint: fingerprintIdentityId(CALLER),
    }));
    tool = tools.find((t) => t.name === "audit_export_siem");
    expect(tool).toBeDefined();

    // Seed the audit log with test entries (all owned by CALLER so the
    // own-identity filter returns them). The agent-safe coarse `decision` is
    // taken from the allowlisted `decision` detail; `tier`/`agent_did`/
    // `session_id` are intentionally still seeded to PROVE they never escape.
    // Note: AuditLog.append() always uses current timestamp.

    // Entry 1: sovereignty_audit, allow, success
    await auditLog.append("l2", "sovereignty_audit", CALLER, {
      decision: "allow",
      gate_decision: "approve",
      tier: 2,
      session_id: "sess-audit-1",
      agent_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcqV7aGHRH694QuspGGbLsEU",
    });

    // Entry 2: state_read, auto-allow, success
    await auditLog.append("l2", "state_read", CALLER, {
      decision: "allow",
      gate_decision: "auto-allow",
      tier: 3,
      session_id: "sess-read-1",
      agent_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcqV7aGHRH694QuspGGbLsEU",
    });

    // Entry 3: state_delete, deny, failure
    await auditLog.append("l2", "state_delete", CALLER, {
      decision: "deny_once",
      gate_decision: "deny",
      tier: 1,
      session_id: "sess-delete-1",
      agent_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcqV7aGHRH694QuspGGbLsEU",
    }, "failure");

    // Entry 4: reputation_import, deny, failure
    await auditLog.append("l4", "reputation_import", CALLER, {
      decision: "deny_once",
      gate_decision: "deny",
      tier: 1,
      session_id: "sess-rep-1",
      agent_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcqV7aGHRH694QuspGGbLsEU",
    }, "failure");

    // Give async persistence a moment to complete
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  describe("CEF export", () => {
    it("should export events in CEF format", async () => {
      const result = await tool.handler({ format: "cef" });

      expect(result.content).toHaveLength(2);
      const metadata = JSON.parse(result.content[0].text);
      const cefOutput = result.content[1].text;

      expect(metadata.format).toBe("cef");
      expect(metadata.count).toBeGreaterThan(0);
      expect(cefOutput).toMatch(/^CEF:0\|/m);
    });

    it("should produce newline-delimited CEF events", async () => {
      const result = await tool.handler({ format: "cef" });
      const cefOutput = result.content[1].text;

      const lines = cefOutput.trim().split("\n");
      lines.forEach((line) => {
        expect(line).toMatch(/^CEF:0\|/);
      });
    });

    it("should include agent-safe coarse decisions in CEF output", async () => {
      const result = await tool.handler({ format: "cef" });
      const cefOutput = result.content[1].text;

      // Coarse, agent-safe outcomes (allow / auto-allow / deny) — derived from
      // the allowlisted `decision` value and result, NOT the raw gate decision.
      expect(cefOutput).toContain("outcome=allow");
      expect(cefOutput).toContain("outcome=deny");
    });

    it("never leaks agent DID, tier, or session id in CEF output (allowlist)", async () => {
      const result = await tool.handler({ format: "cef" });
      const cefOutput = result.content[1].text;

      // Policy/identity attribution must NOT ride out through a SIEM record.
      expect(cefOutput).not.toContain("src=did:key:");
      expect(cefOutput).not.toContain("did:key:");
      expect(cefOutput).not.toContain("tier=");
      expect(cefOutput).not.toContain("cs1=sess-");
      expect(cefOutput).not.toContain("SessionId");
    });

    it("should map deny to CEF severity 8", async () => {
      const result = await tool.handler({
        format: "cef",
        filter_decision: "deny",
      });
      const cefOutput = result.content[1].text;

      expect(cefOutput).toMatch(/\|8\|/);
    });
  });

  describe("OCSF export", () => {
    it("should export events in OCSF format", async () => {
      const result = await tool.handler({ format: "ocsf" });

      expect(result.content).toHaveLength(2);
      const metadata = JSON.parse(result.content[0].text);
      const ocsfOutput = result.content[1].text;

      expect(metadata.format).toBe("ocsf");
      expect(metadata.count).toBeGreaterThan(0);

      const parsed = JSON.parse(ocsfOutput);
      expect(Array.isArray(parsed)).toBe(true);
    });

    it("should produce valid JSON array of OCSF objects", async () => {
      const result = await tool.handler({ format: "ocsf" });
      const ocsfOutput = result.content[1].text;

      const parsed = JSON.parse(ocsfOutput);
      parsed.forEach((obj: any) => {
        expect(obj.class_uid).toBe(3001);
        expect(obj.category_uid).toBe(3);
        expect(obj.api).toBeDefined();
        expect(obj.actor).toBeDefined();
        expect(obj.status_id).toBeGreaterThanOrEqual(1);
      });
    });

    it("should include all required OCSF fields", async () => {
      const result = await tool.handler({
        format: "ocsf",
        limit: 1,
      });
      const ocsfOutput = result.content[1].text;
      const [first] = JSON.parse(ocsfOutput);

      expect(first).toHaveProperty("class_uid");
      expect(first).toHaveProperty("class_name");
      expect(first).toHaveProperty("category_uid");
      expect(first).toHaveProperty("category_name");
      expect(first).toHaveProperty("severity_id");
      expect(first).toHaveProperty("time");
      expect(first).toHaveProperty("activity_id");
      expect(first).toHaveProperty("activity_name");
      expect(first).toHaveProperty("actor");
      expect(first).toHaveProperty("api");
      expect(first).toHaveProperty("status_id");
      expect(first).toHaveProperty("disposition_id");
      expect(first).toHaveProperty("metadata");
    });

    it("should map deny to OCSF severity 4 (Critical)", async () => {
      const result = await tool.handler({
        format: "ocsf",
        filter_decision: "deny",
      });
      const ocsfOutput = result.content[1].text;
      const parsed = JSON.parse(ocsfOutput);

      expect(parsed.length).toBeGreaterThan(0);
      parsed.forEach((obj: any) => {
        expect(obj.severity_id).toBe(4);
      });
    });

    it("should map deny to OCSF disposition 2 (blocked)", async () => {
      const result = await tool.handler({
        format: "ocsf",
        filter_decision: "deny",
      });
      const ocsfOutput = result.content[1].text;
      const parsed = JSON.parse(ocsfOutput);

      parsed.forEach((obj: any) => {
        expect(obj.disposition_id).toBe(2);
      });
    });
  });

  describe("Filtering", () => {
    it("should filter by decision type", async () => {
      const denyResult = await tool.handler({
        format: "cef",
        filter_decision: "deny",
      });
      const denyMetadata = JSON.parse(denyResult.content[0].text);

      const autoResult = await tool.handler({
        format: "cef",
        filter_decision: "auto-allow",
      });
      const autoMetadata = JSON.parse(autoResult.content[0].text);

      expect(denyMetadata.count).toBeGreaterThan(0);
      expect(autoMetadata.count).toBeGreaterThan(0);
      expect(denyMetadata.count + autoMetadata.count).toBeLessThanOrEqual(
        denyMetadata.total_available
      );
    });

    it("should filter by tool name substring", async () => {
      const result = await tool.handler({
        format: "cef",
        filter_tool: "state",
      });
      const metadata = JSON.parse(result.content[0].text);
      const output = result.content[1].text;

      expect(metadata.filters.tool).toBe("state");
      expect(output).toContain("state_read");
      expect(output).toContain("state_delete");
      expect(output).not.toContain("sovereignty_audit");
    });

    it("should filter by layer", async () => {
      const result = await tool.handler({
        format: "cef",
        filter_layer: "l2",
      });
      const metadata = JSON.parse(result.content[0].text);

      expect(metadata.filters.layer).toBe("l2");
      expect(metadata.count).toBeGreaterThan(0);
    });

    it("should filter by result (success/failure)", async () => {
      const failResult = await tool.handler({
        format: "cef",
        filter_result: "failure",
      });
      const failMetadata = JSON.parse(failResult.content[0].text);

      expect(failMetadata.filters.result).toBe("failure");
    });

    it("should respect since parameter (24h default if not specified)", async () => {
      const result = await tool.handler({ format: "cef" });
      const metadata = JSON.parse(result.content[0].text);
      const timeRange = metadata.time_range;

      // Should include a default since parameter (24h ago)
      expect(timeRange.since).toBeDefined();
      // The count should be at least 1 (we seeded 4 recent entries)
      expect(metadata.count).toBeGreaterThan(0);
    });
  });

  describe("Limit enforcement", () => {
    it("should respect limit parameter", async () => {
      const result = await tool.handler({
        format: "cef",
        limit: 2,
      });
      const metadata = JSON.parse(result.content[0].text);

      expect(metadata.count).toBeLessThanOrEqual(2);
    });

    it("should cap limit at 1000", async () => {
      const result = await tool.handler({
        format: "cef",
        limit: 10000,
      });
      const metadata = JSON.parse(result.content[0].text);

      expect(metadata.count).toBeLessThanOrEqual(1000);
    });

    it("should default limit to 100 if not specified", async () => {
      const result = await tool.handler({ format: "cef" });
      const metadata = JSON.parse(result.content[0].text);

      // With 4 seed entries, should be below default of 100
      expect(metadata.count).toBeLessThanOrEqual(100);
    });
  });

  describe("Error handling", () => {
    it("should reject invalid format parameter", async () => {
      const result = await tool.handler({ format: "invalid" });

      const metadata = JSON.parse(result.content[0].text);
      expect(metadata.error).toBeDefined();
    });

    it("should reject invalid since timestamp", async () => {
      const result = await tool.handler({
        format: "cef",
        since: "not-a-date",
      });

      const metadata = JSON.parse(result.content[0].text);
      expect(metadata.error).toBeDefined();
      expect(metadata.error).toContain("Invalid");
    });

    it("should reject invalid until timestamp", async () => {
      const result = await tool.handler({
        format: "cef",
        until: "not-a-date",
      });

      const metadata = JSON.parse(result.content[0].text);
      expect(metadata.error).toBeDefined();
      expect(metadata.error).toContain("Invalid");
    });
  });

  describe("Tool metadata", () => {
    it("should have correct tool name and description", () => {
      expect(tool.name).toBe("audit_export_siem");
      expect(tool.description).toContain("CEF");
      expect(tool.description).toContain("OCSF");
      expect(tool.description).toContain("Splunk");
      expect(tool.description).toContain("Datadog");
    });

    it("should have properly typed input schema", () => {
      const schema = tool.inputSchema;

      expect(schema.type).toBe("object");
      expect(schema.properties.format).toBeDefined();
      expect(schema.properties.since).toBeDefined();
      expect(schema.properties.until).toBeDefined();
      expect(schema.properties.limit).toBeDefined();
      expect(schema.properties.filter_tool).toBeDefined();
      expect(schema.properties.filter_decision).toBeDefined();
    });
  });

  describe("Output structure", () => {
    it("should include metadata and formatted events in response", async () => {
      const result = await tool.handler({ format: "cef" });

      expect(result.content).toHaveLength(2);
      expect(result.content[0].type).toBe("text");
      expect(result.content[1].type).toBe("text");

      const metadata = JSON.parse(result.content[0].text);
      expect(metadata).toHaveProperty("format");
      expect(metadata).toHaveProperty("count");
      expect(metadata).toHaveProperty("total_available");
      expect(metadata).toHaveProperty("time_range");
      expect(metadata).toHaveProperty("filters");
    });

    it("should track total_available vs count in metadata", async () => {
      const result = await tool.handler({
        format: "cef",
        limit: 1,
      });
      const metadata = JSON.parse(result.content[0].text);

      expect(metadata.count).toBeLessThanOrEqual(metadata.total_available);
    });

    it("operator export still carries the coarse SIEM signal after the Tier-1 re-tier (CISO MED-1)", async () => {
      // Re-tiering audit_export_siem to Tier 1 gates the AGENT; the OPERATOR who
      // approves the export runs the handler exactly as below. #573 reduced the
      // SIEM formatter to the agent-safe allowlist (coarse allow/deny outcome
      // derived from `result`, plus severity/disposition; the fine gate decision
      // and tier/agent_did/session were stripped as defense-in-depth). The export
      // still carries the security signal a SIEM consumer needs. NOTE: whether to
      // restore richer operator-only fields now that this surface is Tier-1 is a
      // tracked CISO re-review follow-up, intentionally NOT decided here.

      // CEF: coarse per-event outcome (allow/deny derived from result) + severity.
      const cef = (await tool.handler({ format: "cef" })).content[1].text;
      expect(cef).toContain("outcome=allow");
      expect(cef).toContain("outcome=deny");
      expect(cef).toMatch(/^CEF:0\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|\d+\|/m); // severity field

      // OCSF: severity_id + disposition_id (coarse security signal) preserved.
      const ocsf = JSON.parse((await tool.handler({ format: "ocsf" })).content[1].text);
      expect(ocsf.length).toBeGreaterThan(0);
      for (const obj of ocsf) {
        expect(obj).toHaveProperty("severity_id");
        expect(obj).toHaveProperty("disposition_id");
      }
    });
  });
});
