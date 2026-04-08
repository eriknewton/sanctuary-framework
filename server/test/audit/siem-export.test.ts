/**
 * Sanctuary MCP Server — SIEM Export Tests
 *
 * Tests for CEF and OCSF format output, filtering, and error handling.
 * Verifies that audit log exports conform to SIEM standards and meet
 * enterprise observability requirements.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { formatAsCEF, formatAsOCSF, type OCSFObject } from "../../src/audit/siem-formatter.js";
import type { AuditEntry } from "../../src/audit/audit-log.js";

// ── Helper: Create test audit entries ────────────────────────────────────

function createTestEntry(overrides?: Partial<AuditEntry>): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    layer: "l2",
    operation: "sovereignty_audit",
    identity_id: "agent-001",
    result: "success",
    details: {
      gate_decision: "approve",
      tier: 2,
      session_id: "sess-12345",
      agent_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcqV7aGHRH694QuspGGbLsEU",
    },
    ...overrides,
  };
}

// ── CEF Format Tests ────────────────────────────────────────────────────

describe("CEF Format", () => {
  describe("Header and structure", () => {
    it("should produce valid CEF header with default options", () => {
      const entry = createTestEntry();
      const cef = formatAsCEF(entry);

      expect(cef).toMatch(/^CEF:0\|Sanctuary\|MCP-Server\|0\.7\.0\|/);
    });

    it("should allow custom vendor, product, and version", () => {
      const entry = createTestEntry();
      const cef = formatAsCEF(entry, {
        vendor: "CustomVendor",
        product: "CustomProduct",
        productVersion: "1.0.0",
      });

      expect(cef).toMatch(
        /^CEF:0\|CustomVendor\|CustomProduct\|1\.0\.0\|/
      );
    });

    it("should include signature ID derived from operation name", () => {
      const entry = createTestEntry({ operation: "state_create" });
      const cef = formatAsCEF(entry);

      expect(cef).toContain("state_create");
    });

    it("should include all required CEF extension fields", () => {
      const entry = createTestEntry();
      const cef = formatAsCEF(entry);

      expect(cef).toContain("src=did:key:");
      expect(cef).toContain("act=sovereignty_audit");
      expect(cef).toContain("outcome=approve");
      expect(cef).toContain("tier=2");
      expect(cef).toContain("cs1=sess-12345");
      expect(cef).toContain("cs1Label=SessionId");
      expect(cef).toContain("layer=l2");
      expect(cef).toContain("result=success");
    });
  });

  describe("Severity mapping", () => {
    it("should map deny decisions to severity 8 (high)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "deny", tier: 2 },
      });
      const cef = formatAsCEF(entry);

      expect(cef).toMatch(/\|[^|]*\|8\|/); // Severity is 4th pipe-delimited field from end
      expect(cef).toContain("|8|");
    });

    it("should map approve + tier 1 to severity 5 (medium)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "approve", tier: 1 },
      });
      const cef = formatAsCEF(entry);

      expect(cef).toMatch(/\|5\|/);
    });

    it("should map approve + tier 2 to severity 3 (low)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "approve", tier: 2 },
      });
      const cef = formatAsCEF(entry);

      expect(cef).toMatch(/\|3\|/);
    });

    it("should map auto-allow to severity 1 (informational)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "auto-allow", tier: 3 },
      });
      const cef = formatAsCEF(entry);

      expect(cef).toMatch(/\|1\|/);
    });

    it("should default to auto-allow severity if no decision specified", () => {
      const entry = createTestEntry({ details: {} });
      const cef = formatAsCEF(entry);

      expect(cef).toMatch(/\|1\|/);
    });
  });

  describe("Field extraction and defaults", () => {
    it("should use provided agent DID in src field", () => {
      const entry = createTestEntry({
        details: { agent_did: "did:key:custom123" },
      });
      const cef = formatAsCEF(entry);

      expect(cef).toContain("src=did:key:custom123");
    });

    it("should default agent DID to 'unknown' if not provided", () => {
      const entry = createTestEntry({ details: {} });
      const cef = formatAsCEF(entry);

      expect(cef).toContain("src=unknown");
    });

    it("should include provided session ID", () => {
      const entry = createTestEntry({
        details: { session_id: "unique-sess-999" },
      });
      const cef = formatAsCEF(entry);

      expect(cef).toContain("cs1=unique-sess-999");
    });

    it("should default session ID to 'unknown' if not provided", () => {
      const entry = createTestEntry({ details: {} });
      const cef = formatAsCEF(entry);

      expect(cef).toContain("cs1=unknown");
    });

    it("should include timestamp in rt field as milliseconds", () => {
      const now = new Date();
      const entry = createTestEntry({ timestamp: now.toISOString() });
      const cef = formatAsCEF(entry);

      const expectedMs = now.getTime();
      expect(cef).toContain(`rt=${expectedMs}`);
    });

    it("should clamp tier to valid range 1-3", () => {
      const entryTier0 = createTestEntry({ details: { tier: 0 } });
      const entryTier5 = createTestEntry({ details: { tier: 5 } });

      const cefTier0 = formatAsCEF(entryTier0);
      const cefTier5 = formatAsCEF(entryTier5);

      expect(cefTier0).toContain("tier=1");
      expect(cefTier5).toContain("tier=3");
    });
  });

  describe("Newline-delimited output", () => {
    it("should produce single-line CEF with no embedded newlines", () => {
      const entry = createTestEntry();
      const cef = formatAsCEF(entry);

      expect(cef).not.toContain("\n");
      expect(cef.split("|").length).toBeGreaterThan(5);
    });
  });
});

// ── OCSF Format Tests ───────────────────────────────────────────────────

describe("OCSF Format", () => {
  describe("Structure and required fields", () => {
    it("should produce valid OCSF object with correct class and category UIDs", () => {
      const entry = createTestEntry();
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.class_uid).toBe(3001);
      expect(ocsf.class_name).toBe("API Activity");
      expect(ocsf.category_uid).toBe(3);
      expect(ocsf.category_name).toBe("Application Activity");
    });

    it("should include all required OCSF fields", () => {
      const entry = createTestEntry();
      const ocsf = formatAsOCSF(entry);

      expect(ocsf).toHaveProperty("severity_id");
      expect(ocsf).toHaveProperty("time");
      expect(ocsf).toHaveProperty("activity_id");
      expect(ocsf).toHaveProperty("activity_name");
      expect(ocsf).toHaveProperty("actor");
      expect(ocsf).toHaveProperty("api");
      expect(ocsf).toHaveProperty("status_id");
      expect(ocsf).toHaveProperty("disposition_id");
      expect(ocsf).toHaveProperty("metadata");
    });

    it("should set activity to API Call (1)", () => {
      const entry = createTestEntry();
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.activity_id).toBe(1);
      expect(ocsf.activity_name).toBe("API Call");
    });

    it("should include actor with user UID", () => {
      const entry = createTestEntry({
        details: { agent_did: "did:example:agent1" },
      });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.actor.user.uid).toBe("did:example:agent1");
    });

    it("should include API operation and service name", () => {
      const entry = createTestEntry({ operation: "state_update" });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.api.operation).toBe("state_update");
      expect(ocsf.api.service.name).toBe("sanctuary-mcp");
    });

    it("should include metadata with product info", () => {
      const entry = createTestEntry();
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.metadata.version).toBe("1.3.0");
      expect(ocsf.metadata.product.name).toBe("Sanctuary Framework");
      expect(ocsf.metadata.product.vendor_name).toBe("Erik Newton");
      expect(ocsf.metadata.product.version).toBe("0.7.0");
    });
  });

  describe("Severity mapping", () => {
    it("should map deny decision to severity 4 (Critical)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "deny" },
      });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.severity_id).toBe(4);
    });

    it("should map approve + tier 1 to severity 3 (High)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "approve", tier: 1 },
      });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.severity_id).toBe(3);
    });

    it("should map approve + tier 2 to severity 2 (Medium)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "approve", tier: 2 },
      });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.severity_id).toBe(2);
    });

    it("should map auto-allow to severity 1 (Informational)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "auto-allow", tier: 3 },
      });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.severity_id).toBe(1);
    });
  });

  describe("Status and disposition", () => {
    it("should map success result to status 1", () => {
      const entry = createTestEntry({ result: "success" });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.status_id).toBe(1);
    });

    it("should map failure result to status 2", () => {
      const entry = createTestEntry({ result: "failure" });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.status_id).toBe(2);
    });

    it("should map deny decision to disposition 2 (blocked)", () => {
      const entry = createTestEntry({
        details: { gate_decision: "deny" },
      });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.disposition_id).toBe(2);
    });

    it("should map approve/auto-allow to disposition 1 (allowed)", () => {
      const entryApprove = createTestEntry({
        details: { gate_decision: "approve" },
      });
      const entryAllow = createTestEntry({
        details: { gate_decision: "auto-allow" },
      });

      const ocsfApprove = formatAsOCSF(entryApprove);
      const ocsfAllow = formatAsOCSF(entryAllow);

      expect(ocsfApprove.disposition_id).toBe(1);
      expect(ocsfAllow.disposition_id).toBe(1);
    });
  });

  describe("Timestamp handling", () => {
    it("should convert ISO 8601 timestamp to epoch milliseconds", () => {
      const testDate = new Date("2026-04-08T15:30:45.123Z");
      const entry = createTestEntry({ timestamp: testDate.toISOString() });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.time).toBe(testDate.getTime());
    });

    it("should handle various ISO 8601 formats", () => {
      const timestamps = [
        "2026-04-08T15:30:45.123Z",
        "2026-04-08T15:30:45Z",
        "2026-04-08T15:30:45+00:00",
      ];

      timestamps.forEach((ts) => {
        const entry = createTestEntry({ timestamp: ts });
        const ocsf = formatAsOCSF(entry);

        expect(ocsf.time).toBeGreaterThan(0);
      });
    });
  });

  describe("JSON serialization", () => {
    it("should produce valid JSON object", () => {
      const entry = createTestEntry();
      const ocsf = formatAsOCSF(entry);

      // Should not throw
      const json = JSON.stringify(ocsf);
      const parsed = JSON.parse(json);

      expect(parsed.class_uid).toBe(3001);
    });

    it("should produce JSON array when multiple entries formatted", () => {
      const entries = [
        createTestEntry({ operation: "op1" }),
        createTestEntry({ operation: "op2" }),
      ];

      const ocsfObjects = entries.map((e) => formatAsOCSF(e));
      const json = JSON.stringify(ocsfObjects);
      const parsed = JSON.parse(json);

      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed.length).toBe(2);
      expect(parsed[0].api.operation).toBe("op1");
      expect(parsed[1].api.operation).toBe("op2");
    });
  });

  describe("Field extraction and defaults", () => {
    it("should use provided agent DID", () => {
      const entry = createTestEntry({
        details: { agent_did: "did:key:z6Mkq..." },
      });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.actor.user.uid).toBe("did:key:z6Mkq...");
    });

    it("should default agent DID to 'unknown' if not provided", () => {
      const entry = createTestEntry({ details: {} });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.actor.user.uid).toBe("unknown");
    });

    it("should use operation name from audit entry", () => {
      const entry = createTestEntry({ operation: "custom_operation_name" });
      const ocsf = formatAsOCSF(entry);

      expect(ocsf.api.operation).toBe("custom_operation_name");
    });
  });

  describe("Layer context", () => {
    it("should handle entries from all sovereignty layers", () => {
      const layers: Array<"l1" | "l2" | "l3" | "l4"> = ["l1", "l2", "l3", "l4"];

      layers.forEach((layer) => {
        const entry = createTestEntry({ layer });
        const ocsf = formatAsOCSF(entry);

        // Should produce valid OCSF regardless of layer
        expect(ocsf.class_uid).toBe(3001);
        expect(ocsf.api).toBeDefined();
      });
    });
  });
});

// ── Cross-format consistency tests ──────────────────────────────────────

describe("Cross-format consistency", () => {
  it("should include same gate decision in both CEF and OCSF", () => {
    const entry = createTestEntry({
      details: { gate_decision: "deny" },
    });

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    expect(cef).toContain("outcome=deny");
    expect(ocsf.disposition_id).toBe(2); // deny -> blocked
  });

  it("should include same agent DID in both formats", () => {
    const didValue = "did:key:z6MkhaXg...";
    const entry = createTestEntry({
      details: { agent_did: didValue },
    });

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    expect(cef).toContain(`src=${didValue}`);
    expect(ocsf.actor.user.uid).toBe(didValue);
  });

  it("should represent same operation in both formats", () => {
    const operation = "state_delete";
    const entry = createTestEntry({ operation });

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    expect(cef).toContain(`act=${operation}`);
    expect(ocsf.api.operation).toBe(operation);
  });

  it("should represent same timestamp in both formats", () => {
    const testDate = new Date("2026-04-08T12:00:00Z");
    const entry = createTestEntry({ timestamp: testDate.toISOString() });

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    const expectedMs = testDate.getTime();
    expect(cef).toContain(`rt=${expectedMs}`);
    expect(ocsf.time).toBe(expectedMs);
  });
});

// ── Edge cases ──────────────────────────────────────────────────────────

describe("Edge cases", () => {
  it("should handle missing details object gracefully", () => {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      layer: "l1",
      operation: "test",
      identity_id: "id",
      result: "success",
    };

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    expect(cef).toMatch(/^CEF:/);
    expect(ocsf.class_uid).toBe(3001);
  });

  it("should sanitize special characters in operation names for CEF signature ID", () => {
    const entry = createTestEntry({
      operation: "state/create:v2",
    });
    const cef = formatAsCEF(entry);

    // Special chars should be replaced with underscores
    expect(cef).toContain("state_create_v2");
  });

  it("should handle very long DID values", () => {
    const longDid =
      "did:key:" + "z".repeat(100);
    const entry = createTestEntry({
      details: { agent_did: longDid },
    });

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    expect(cef).toContain(longDid);
    expect(ocsf.actor.user.uid).toBe(longDid);
  });

  it("should handle empty operation name", () => {
    const entry = createTestEntry({ operation: "" });

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    expect(cef).toMatch(/^CEF:/);
    expect(ocsf.api.operation).toBe("");
  });

  it("should handle null/undefined in details gracefully", () => {
    const entry = createTestEntry({
      details: {
        gate_decision: null,
        tier: undefined,
      } as any,
    });

    const cef = formatAsCEF(entry);
    const ocsf = formatAsOCSF(entry);

    expect(cef).toMatch(/^CEF:/);
    expect(ocsf.class_uid).toBe(3001);
  });
});
