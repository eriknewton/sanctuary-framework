/**
 * Castle Wall Observe / Learn Allow-List v1 -- audit-entry adapter tests.
 *
 * Bridges real, already-decrypted `AuditEntry` rows (as `AuditLog.query`
 * returns them) into the `FlowObservationEvent` shape `foldObservations`
 * consumes. This is the seam between the existing, already-shipped audit
 * rail and the new pure fold core.
 */

import { describe, it, expect } from "vitest";
import { flowEventsFromAuditEntries } from "../../../src/castle-wall/observe/adapter.js";
import type { AuditEntry } from "../../../src/operational/audit-log.js";

function blockedEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: "2026-07-07T10:00:00.000Z",
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "agent-1",
    result: "success",
    details: {
      agent: { id: "agent-1", template: "claude-code" },
      destination: { host: "new-tool.example.com", ip: "203.0.113.9", port: 443, protocol: "tcp", hostname_source: "sni" },
      decision: "drop",
      rule_id: null,
      source: "macos_extension",
    },
    ...overrides,
  };
}

describe("flowEventsFromAuditEntries", () => {
  it("extracts a well-formed denied flow from an egress_blocked entry", () => {
    const events = flowEventsFromAuditEntries([blockedEntry()]);
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({
      timestamp: "2026-07-07T10:00:00.000Z",
      agent: { id: "agent-1", template: "claude-code" },
      destination: { host: "new-tool.example.com", ip: "203.0.113.9", port: 443, protocol: "tcp" },
      hostname_source: "sni",
      disposition: "denied",
    });
  });

  it("ignores egress_allowed entries (already-allowed flows are never candidates)", () => {
    const entry = blockedEntry({ operation: "egress_allowed" });
    expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
  });

  it("ignores unrelated operations (e.g. filter_started, policy_loaded)", () => {
    const entry = blockedEntry({ operation: "filter_started", details: {} });
    expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
  });

  it("defaults hostname_source to null when the Linux daemon's generic destination shape omits it", () => {
    const entry = blockedEntry({
      details: {
        agent: { id: "agent-1", template: "claude-code" },
        destination: { host: "new-tool.example.com", ip: "203.0.113.9", port: 443, protocol: "tcp" },
      },
    });
    const events = flowEventsFromAuditEntries([entry]);
    expect(events[0]!.hostname_source).toBeNull();
  });

  it("skips an entry missing agent attribution", () => {
    const entry = blockedEntry({ details: { destination: { host: "x.example.com", ip: "1.2.3.4", port: 443, protocol: "tcp" } } });
    expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
  });

  it("skips an entry with no host and no ip", () => {
    const entry = blockedEntry({
      details: {
        agent: { id: "agent-1", template: "claude-code" },
        destination: { host: null, ip: "", port: 443, protocol: "tcp" },
      },
    });
    expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
  });

  it("skips an entry with an invalid protocol", () => {
    const entry = blockedEntry({
      details: {
        agent: { id: "agent-1", template: "claude-code" },
        destination: { host: "x.example.com", ip: "1.2.3.4", port: 443, protocol: "quic" },
      },
    });
    expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
  });

  it("skips an entry with no details at all", () => {
    const entry = blockedEntry({ details: undefined });
    expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
  });
});
