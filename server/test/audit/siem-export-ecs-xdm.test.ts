/**
 * ECS and XDM SIEM export fixture parity.
 *
 * These tests prove the additive ECS/XDM formatters use the same redacted
 * audit view and coarse safe-decision projection as the existing CEF/OCSF
 * export path. The proof is schema and fixture coverage only; no live tenant
 * drill is claimed here.
 */

import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fingerprintIdentityId } from "../../src/agent-native/safety-base.js";
import { redactAuditEntryForAgent } from "../../src/operational/agent-audit-redaction.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  SIEM_ECS_FIELD_MAPPING,
  SIEM_XDM_FIELD_MAPPING,
  formatAsCEF,
  formatAsECS,
  formatAsOCSF,
  formatAsXDM,
} from "../../src/audit/siem-formatter.js";
import { createSIEMTools } from "../../src/audit/siem-tools.js";

type FlatRecord = Record<string, unknown>;

const FIXTURE_TIME = "2026-10-14T18:30:00.000Z";

function fixtureEntry(overrides: Partial<AuditEntry>): AuditEntry {
  return {
    timestamp: FIXTURE_TIME,
    layer: "l2",
    operation: "state_read",
    identity_id: "agent-fixture",
    result: "success",
    details: {
      decision: "allow",
      gate_decision: "approve",
      tier: 1,
      session_id: "sess-never-exported",
      agent_did: "did:key:zNeverExported",
      reason: "operator-only policy reason",
    },
    ...overrides,
  };
}

function flatten(value: unknown, prefix = ""): FlatRecord {
  if (Array.isArray(value)) {
    return { [prefix]: value };
  }
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).reduce<FlatRecord>(
      (acc, [key, child]) => ({
        ...acc,
        ...flatten(child, prefix ? `${prefix}.${key}` : key),
      }),
      {}
    );
  }
  return { [prefix]: value };
}

function cefDecision(line: string): "allow" | "deny" {
  return line.includes("outcome=deny") ? "deny" : "allow";
}

function cefTimestamp(line: string): number {
  const match = line.match(/\brt=(\d+)\b/);
  if (!match) throw new Error(`missing CEF rt field: ${line}`);
  return Number(match[1]);
}

function ocsfDecision(obj: ReturnType<typeof formatAsOCSF>): "allow" | "deny" {
  return obj.disposition_id === 2 ? "deny" : "allow";
}

function ecsDecision(obj: ReturnType<typeof formatAsECS>): "allow" | "deny" {
  return obj.sanctuary.audit.decision;
}

function xdmDecision(obj: ReturnType<typeof formatAsXDM>): "allow" | "deny" {
  return obj["sanctuary.audit.decision"];
}

describe("ECS and XDM SIEM export parity", () => {
  const entries: AuditEntry[] = [
    fixtureEntry({
      timestamp: "2026-10-14T18:30:00.000Z",
      layer: "l1",
      operation: "state_read",
      result: "success",
    }),
    fixtureEntry({
      timestamp: "2026-10-14T18:31:00.000Z",
      layer: "l2",
      operation: "identity_sign",
      result: "failure",
      details: { decision: "deny_once", tier: 1, agent_did: "did:key:zNope" },
    }),
    fixtureEntry({
      timestamp: "2026-10-14T18:32:00.000Z",
      layer: "l3",
      operation: "proof_reveal",
      result: "success",
      details: { decision: "auto-allow", tier: 3, session_id: "sess-nope" },
    }),
    fixtureEntry({
      timestamp: "2026-10-14T18:33:00.000Z",
      layer: "l4",
      operation: "reputation_import",
      result: "failure",
      details: { decision: "deny_once", reason: "policy-only reason" },
    }),
  ];

  it("keeps full-set event, decision, and time parity with CEF and OCSF", () => {
    const cef = entries.map((entry) => formatAsCEF(redactAuditEntryForAgent(entry)));
    const ocsf = entries.map((entry) => formatAsOCSF(redactAuditEntryForAgent(entry)));
    const ecs = entries.map((entry) => formatAsECS(redactAuditEntryForAgent(entry)));
    const xdm = entries.map((entry) => formatAsXDM(redactAuditEntryForAgent(entry)));

    expect(ecs).toHaveLength(cef.length);
    expect(xdm).toHaveLength(ocsf.length);

    entries.forEach((entry, index) => {
      const expectedTime = new Date(entry.timestamp).getTime();
      expect(ecs[index]?.event.action).toBe(entry.operation);
      expect(xdm[index]?.["xdm.event.operation"]).toBe(entry.operation);
      expect(ecsDecision(ecs[index]!)).toBe(cefDecision(cef[index]!));
      expect(xdmDecision(xdm[index]!)).toBe(ocsfDecision(ocsf[index]!));
      expect(new Date(ecs[index]!["@timestamp"]).getTime()).toBe(cefTimestamp(cef[index]!));
      expect(xdm[index]?._time).toBe(expectedTime);
      expect(ocsf[index]?.time).toBe(expectedTime);
    });
  });

  it("emits no ECS or XDM field outside the formatter mapping tables", () => {
    const ecsFields = new Set(Object.values(SIEM_ECS_FIELD_MAPPING));
    const xdmFields = new Set(Object.values(SIEM_XDM_FIELD_MAPPING));

    for (const entry of entries) {
      expect(Object.keys(flatten(formatAsECS(redactAuditEntryForAgent(entry)))).sort()).toEqual(
        [...ecsFields].sort()
      );
      expect(Object.keys(flatten(formatAsXDM(redactAuditEntryForAgent(entry)))).sort()).toEqual(
        [...xdmFields].sort()
      );
    }
  });

  it("reuses the safe decision projection so a failed entry never exports as allowed", () => {
    const deniedDespiteDetail = fixtureEntry({
      result: "failure",
      details: { decision: "allow", tier: 3 },
    });

    const ecs = formatAsECS(redactAuditEntryForAgent(deniedDespiteDetail));
    const xdm = formatAsXDM(redactAuditEntryForAgent(deniedDespiteDetail));

    expect(ecs.sanctuary.audit.decision).toBe("deny");
    expect(ecs.event.type).toContain("denied");
    expect(xdm["sanctuary.audit.decision"]).toBe("deny");
    expect(xdm["xdm.event.operation_sub_type"]).toBe("deny");
  });

  it("never emits raw policy, identity, session, or reason fields in ECS or XDM", () => {
    const entry = fixtureEntry({});
    const ecs = JSON.stringify(formatAsECS(redactAuditEntryForAgent(entry)));
    const xdm = JSON.stringify(formatAsXDM(redactAuditEntryForAgent(entry)));
    for (const body of [ecs, xdm]) {
      expect(body).not.toContain("did:key:");
      expect(body).not.toContain("tier");
      expect(body).not.toContain("sess-never-exported");
      expect(body).not.toContain("operator-only policy reason");
      expect(body).not.toContain("gate_decision");
    }
  });

  it("accepts ecs and xdm tool formats while still rejecting unknown formats", async () => {
    const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
    await auditLog.append("l2", "state_read", "agent-fixture", { decision: "allow" });
    await auditLog.append("l2", "state_delete", "agent-fixture", { decision: "deny" }, "failure");

    const { tools } = createSIEMTools(auditLog, () => ({
      identity_id: "agent-fixture",
      requester_identity_fingerprint: fingerprintIdentityId("agent-fixture"),
    }));
    const tool = tools.find((candidate) => candidate.name === "audit_export_siem");
    expect(tool).toBeDefined();

    for (const format of ["ecs", "xdm"] as const) {
      const result = await tool!.handler({ format });
      const metadata = JSON.parse(result.content[0].text);
      const body = JSON.parse(result.content[1].text);
      expect(metadata.format).toBe(format);
      expect(metadata.count).toBe(2);
      expect(body).toHaveLength(2);
    }

    const rejected = await tool!.handler({ format: "made-up" });
    expect(JSON.parse(rejected.content[0].text).error).toContain("cef");
  });
});
