/**
 * Sanctuary MCP Server — SIEM Export Formatter Tests (agent-facing ALLOWLIST)
 *
 * The CEF/OCSF formatters consume ONLY the agent-facing allowlist view
 * (timestamp, operation, result, has_details) plus the explicitly-safe coarse
 * `decision` value. They never read the raw audit `details`, so the policy tier,
 * the matched rule, the agent DID, the session id, and the free-text reason can
 * never ride out through a SIEM record (CISO MED-1, property #11). Severity is
 * derived from result/decision only — never from the policy tier.
 *
 * These tests assert the SAFE contract and explicitly verify the previously-leaky
 * fields (DID / tier / session) do NOT appear.
 */

import { describe, it, expect } from "vitest";
import {
  formatAsCEF,
  formatAsOCSF,
  agentDecision,
} from "../../src/audit/siem-formatter.js";
import {
  redactAuditEntryForAgent,
  buildAgentSearchCorpus,
} from "../../src/operational/agent-audit-redaction.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import type { AgentAuditView } from "../../src/operational/agent-audit-redaction.js";

// ── Helpers ──────────────────────────────────────────────────────────────

/** Build a raw audit entry (carrying leaky details) for the redaction path. */
function createTestEntry(overrides?: Partial<AuditEntry>): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    layer: "l2",
    operation: "sovereignty_audit",
    identity_id: "agent-001",
    result: "success",
    details: {
      decision: "allow",
      gate_decision: "approve",
      tier: 2,
      session_id: "sess-12345",
      agent_did: "did:key:z6MkhaXgBZDvotDkL5257faWxcqV7aGHRH694QuspGGbLsEU",
    },
    ...overrides,
  };
}

/**
 * The allowlisted view the formatters actually receive in production.
 *
 * NOTE (CISO HIGH, 2026-06-16): `decision` was removed from the agent search
 * corpus, and siem-tools.ts NO LONGER threads a `safeDecision` to the
 * formatters — the coarse allow/deny outcome derives from the entry `result`
 * alone. So `safeDecision` is `undefined` here, mirroring production. The
 * formatter's `safeDecision` PARAMETER still exists and is honored when passed;
 * its decision-string→outcome contract is covered directly in the `agentDecision`
 * unit tests below.
 */
function viewOf(entry: AuditEntry): { view: AgentAuditView; safeDecision?: string } {
  // Reference buildAgentSearchCorpus so this test still pins that `decision` is
  // NOT in the corpus (it returns undefined); production derives outcome from
  // `result`, so we pass no safeDecision.
  void buildAgentSearchCorpus(entry).decision;
  return {
    view: redactAuditEntryForAgent(entry),
    safeDecision: undefined,
  };
}

function cefOf(entry: AuditEntry, opts?: Parameters<typeof formatAsCEF>[2]) {
  const { view, safeDecision } = viewOf(entry);
  return formatAsCEF(view, safeDecision, opts);
}

function ocsfOf(entry: AuditEntry) {
  const { view, safeDecision } = viewOf(entry);
  return formatAsOCSF(view, safeDecision);
}

// ── CEF Format Tests ────────────────────────────────────────────────────

describe("CEF Format (allowlist)", () => {
  describe("Header and structure", () => {
    it("should produce valid CEF header with default options", () => {
      expect(cefOf(createTestEntry())).toMatch(
        /^CEF:0\|Sanctuary\|MCP-Server\|0\.7\.0\|/
      );
    });

    it("should allow custom vendor, product, and version", () => {
      const cef = cefOf(createTestEntry(), {
        vendor: "CustomVendor",
        product: "CustomProduct",
        productVersion: "1.0.0",
      });
      expect(cef).toMatch(/^CEF:0\|CustomVendor\|CustomProduct\|1\.0\.0\|/);
    });

    it("should include signature ID derived from operation name", () => {
      expect(cefOf(createTestEntry({ operation: "state_create" }))).toContain(
        "state_create"
      );
    });

    it("should include the allowlisted CEF extension fields (act/outcome/rt/result)", () => {
      const cef = cefOf(createTestEntry({ details: { decision: "allow" } }));
      expect(cef).toContain("act=sovereignty_audit");
      expect(cef).toContain("outcome=allow");
      expect(cef).toContain("result=success");
      expect(cef).toMatch(/rt=\d+/);
    });

    it("never leaks agent DID, tier, session id, or layer in CEF", () => {
      const cef = cefOf(createTestEntry());
      expect(cef).not.toContain("src=did:key:");
      expect(cef).not.toContain("did:key:");
      expect(cef).not.toContain("tier=");
      expect(cef).not.toContain("cs1=");
      expect(cef).not.toContain("SessionId");
      expect(cef).not.toContain("sess-12345");
      expect(cef).not.toContain("layer=");
    });
  });

  describe("Severity mapping (from result/decision, never tier)", () => {
    it("should map deny to severity 8 (high)", () => {
      const cef = cefOf(
        createTestEntry({ result: "failure", details: { decision: "deny_once" } })
      );
      expect(cef).toContain("|8|");
    });

    it("should map allow to severity 1 (informational) regardless of tier", () => {
      // tier 1 detail present but ignored — severity stays informational.
      const cef = cefOf(createTestEntry({ details: { decision: "allow", tier: 1 } }));
      expect(cef).toMatch(/\|1\|/);
    });

    it("should default to allow severity if no decision specified and result success", () => {
      const cef = cefOf(createTestEntry({ details: {} }));
      expect(cef).toMatch(/\|1\|/);
    });

    it("should map a failure result to deny severity even without a decision", () => {
      const cef = cefOf(createTestEntry({ result: "failure", details: {} }));
      expect(cef).toContain("|8|");
    });
  });

  describe("Outcome derivation (from result; decision no longer threaded)", () => {
    // Production derives the coarse outcome from `result` alone now (decision
    // removed from the corpus, CISO HIGH 2026-06-16). The decision-string→outcome
    // contract of the agentDecision PARAMETER is covered directly below.
    it("derives outcome=deny from a failure result (even if details carry a deny decision)", () => {
      expect(
        cefOf(createTestEntry({ result: "failure", details: { decision: "deny_once" } }))
      ).toContain("outcome=deny");
    });

    it("derives outcome=allow from a success result (even if details carry a decision)", () => {
      expect(
        cefOf(createTestEntry({ result: "success", details: { decision: "allow" } }))
      ).toContain("outcome=allow");
    });

    it("should include timestamp in rt field as milliseconds", () => {
      const now = new Date();
      const cef = cefOf(createTestEntry({ timestamp: now.toISOString() }));
      expect(cef).toContain(`rt=${now.getTime()}`);
    });
  });

  describe("Newline-delimited output", () => {
    it("should produce single-line CEF with no embedded newlines", () => {
      const cef = cefOf(createTestEntry());
      expect(cef).not.toContain("\n");
      expect(cef.split("|").length).toBeGreaterThan(5);
    });
  });
});

// ── OCSF Format Tests ───────────────────────────────────────────────────

describe("OCSF Format (allowlist)", () => {
  describe("Structure and required fields", () => {
    it("should produce valid OCSF object with correct class and category UIDs", () => {
      const ocsf = ocsfOf(createTestEntry());
      expect(ocsf.class_uid).toBe(3001);
      expect(ocsf.class_name).toBe("API Activity");
      expect(ocsf.category_uid).toBe(3);
      expect(ocsf.category_name).toBe("Application Activity");
    });

    it("should include all required OCSF fields", () => {
      const ocsf = ocsfOf(createTestEntry());
      for (const f of [
        "severity_id",
        "time",
        "activity_id",
        "activity_name",
        "actor",
        "api",
        "status_id",
        "disposition_id",
        "metadata",
      ]) {
        expect(ocsf).toHaveProperty(f);
      }
    });

    it("should set activity to API Call (1)", () => {
      const ocsf = ocsfOf(createTestEntry());
      expect(ocsf.activity_id).toBe(1);
      expect(ocsf.activity_name).toBe("API Call");
    });

    it("actor uid is a fixed 'self' sentinel — never the raw agent DID", () => {
      const ocsf = ocsfOf(
        createTestEntry({ details: { agent_did: "did:example:agent1" } })
      );
      expect(ocsf.actor.user.uid).toBe("self");
      expect(JSON.stringify(ocsf)).not.toContain("did:example:agent1");
    });

    it("should include API operation and service name", () => {
      const ocsf = ocsfOf(createTestEntry({ operation: "state_update" }));
      expect(ocsf.api.operation).toBe("state_update");
      expect(ocsf.api.service.name).toBe("sanctuary-mcp");
    });

    it("should include metadata with product info", () => {
      const ocsf = ocsfOf(createTestEntry());
      expect(ocsf.metadata.version).toBe("1.3.0");
      expect(ocsf.metadata.product.name).toBe("Sanctuary Framework");
      expect(ocsf.metadata.product.vendor_name).toBe("Erik Newton");
      expect(ocsf.metadata.product.version).toBe("0.7.0");
    });

    it("never leaks tier, session id, or agent DID anywhere in the OCSF object", () => {
      const ocsf = ocsfOf(createTestEntry());
      const s = JSON.stringify(ocsf);
      expect(s).not.toContain("did:key:");
      expect(s).not.toContain("sess-12345");
      expect(s).not.toContain('"tier"');
    });
  });

  describe("Severity mapping (from result/decision, never tier)", () => {
    it("should map deny to severity 4 (Critical)", () => {
      expect(
        ocsfOf(
          createTestEntry({ result: "failure", details: { decision: "deny_once" } })
        ).severity_id
      ).toBe(4);
    });

    it("should map allow to severity 1 (Informational) regardless of tier", () => {
      expect(
        ocsfOf(createTestEntry({ details: { decision: "allow", tier: 1 } })).severity_id
      ).toBe(1);
    });
  });

  describe("Status and disposition", () => {
    it("should map success result to status 1", () => {
      expect(ocsfOf(createTestEntry({ result: "success" })).status_id).toBe(1);
    });

    it("should map failure result to status 2", () => {
      expect(ocsfOf(createTestEntry({ result: "failure" })).status_id).toBe(2);
    });

    it("should map deny decision to disposition 2 (blocked)", () => {
      expect(
        ocsfOf(
          createTestEntry({ result: "failure", details: { decision: "deny_once" } })
        ).disposition_id
      ).toBe(2);
    });

    it("should map allow to disposition 1 (allowed)", () => {
      expect(
        ocsfOf(createTestEntry({ details: { decision: "allow" } })).disposition_id
      ).toBe(1);
    });
  });

  describe("Timestamp handling", () => {
    it("should convert ISO 8601 timestamp to epoch milliseconds", () => {
      const testDate = new Date("2026-04-08T15:30:45.123Z");
      expect(
        ocsfOf(createTestEntry({ timestamp: testDate.toISOString() })).time
      ).toBe(testDate.getTime());
    });

    it("should handle various ISO 8601 formats", () => {
      for (const ts of [
        "2026-04-08T15:30:45.123Z",
        "2026-04-08T15:30:45Z",
        "2026-04-08T15:30:45+00:00",
      ]) {
        expect(ocsfOf(createTestEntry({ timestamp: ts })).time).toBeGreaterThan(0);
      }
    });
  });

  describe("JSON serialization", () => {
    it("should produce valid JSON object", () => {
      const json = JSON.stringify(ocsfOf(createTestEntry()));
      expect(JSON.parse(json).class_uid).toBe(3001);
    });

    it("should produce JSON array when multiple entries formatted", () => {
      const entries = [
        createTestEntry({ operation: "op1" }),
        createTestEntry({ operation: "op2" }),
      ];
      const parsed = JSON.parse(JSON.stringify(entries.map(ocsfOf)));
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed.length).toBe(2);
      expect(parsed[0].api.operation).toBe("op1");
      expect(parsed[1].api.operation).toBe("op2");
    });
  });

  describe("Operation + layer context", () => {
    it("should use operation name from audit entry", () => {
      expect(
        ocsfOf(createTestEntry({ operation: "custom_operation_name" })).api.operation
      ).toBe("custom_operation_name");
    });

    it("should produce valid OCSF regardless of source layer", () => {
      for (const layer of ["l1", "l2", "l3", "l4"] as const) {
        const ocsf = ocsfOf(createTestEntry({ layer }));
        expect(ocsf.class_uid).toBe(3001);
        expect(ocsf.api).toBeDefined();
      }
    });
  });
});

// ── agentDecision unit ──────────────────────────────────────────────────

describe("agentDecision (2-valued, tier-free)", () => {
  const okView: AgentAuditView = {
    timestamp: "t",
    operation: "op",
    result: "success",
    has_details: true,
  };
  const failView: AgentAuditView = { ...okView, result: "failure" };

  it("maps deny/drop/block decisions to deny", () => {
    for (const d of ["deny", "deny_once", "drop", "block"]) {
      expect(agentDecision(okView, d)).toBe("deny");
    }
  });

  it("maps allow/approve/auto-allow decisions to allow", () => {
    for (const d of ["allow", "approve", "auto-allow"]) {
      expect(agentDecision(okView, d)).toBe("allow");
    }
  });

  it("falls back to result when no decision: failure→deny, success→allow", () => {
    expect(agentDecision(failView)).toBe("deny");
    expect(agentDecision(okView)).toBe("allow");
  });
});

// ── Cross-format consistency ─────────────────────────────────────────────

describe("Cross-format consistency (allowlist)", () => {
  it("represents the same coarse decision in both CEF and OCSF", () => {
    const entry = createTestEntry({
      result: "failure",
      details: { decision: "deny_once" },
    });
    expect(cefOf(entry)).toContain("outcome=deny");
    expect(ocsfOf(entry).disposition_id).toBe(2);
  });

  it("neither format leaks the agent DID", () => {
    const entry = createTestEntry({ details: { agent_did: "did:key:z6MkhaXg..." } });
    expect(cefOf(entry)).not.toContain("did:key:");
    expect(JSON.stringify(ocsfOf(entry))).not.toContain("did:key:");
  });

  it("represents the same operation in both formats", () => {
    const entry = createTestEntry({ operation: "state_delete" });
    expect(cefOf(entry)).toContain("act=state_delete");
    expect(ocsfOf(entry).api.operation).toBe("state_delete");
  });

  it("represents the same timestamp in both formats", () => {
    const testDate = new Date("2026-04-08T12:00:00Z");
    const entry = createTestEntry({ timestamp: testDate.toISOString() });
    expect(cefOf(entry)).toContain(`rt=${testDate.getTime()}`);
    expect(ocsfOf(entry).time).toBe(testDate.getTime());
  });
});

// ── Edge cases ──────────────────────────────────────────────────────────

describe("Edge cases", () => {
  it("should handle a missing details object gracefully", () => {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      layer: "l1",
      operation: "test",
      identity_id: "id",
      result: "success",
    };
    expect(cefOf(entry)).toMatch(/^CEF:/);
    expect(ocsfOf(entry).class_uid).toBe(3001);
  });

  it("should sanitize special characters in operation names for CEF signature ID", () => {
    expect(cefOf(createTestEntry({ operation: "state/create:v2" }))).toContain(
      "state_create_v2"
    );
  });

  it("never leaks even a very long DID value (it is not read at all)", () => {
    const longDid = "did:key:" + "z".repeat(100);
    const entry = createTestEntry({ details: { agent_did: longDid } });
    expect(cefOf(entry)).not.toContain(longDid);
    expect(JSON.stringify(ocsfOf(entry))).not.toContain(longDid);
  });

  it("should handle empty operation name", () => {
    const entry = createTestEntry({ operation: "" });
    expect(cefOf(entry)).toMatch(/^CEF:/);
    expect(ocsfOf(entry).api.operation).toBe("");
  });

  it("should handle null/undefined in details gracefully", () => {
    const entry = createTestEntry({
      details: { decision: null, tier: undefined } as unknown as Record<
        string,
        unknown
      >,
    });
    expect(cefOf(entry)).toMatch(/^CEF:/);
    expect(ocsfOf(entry).class_uid).toBe(3001);
  });
});
