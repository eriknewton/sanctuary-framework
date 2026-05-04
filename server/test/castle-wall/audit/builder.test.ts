/**
 * Castle Wall audit-event builder tests.
 *
 * Asserts the layer field, schema version, and canonical-JSON byte-stability
 * required for cross-language vector tests in PR 6.
 */

import { describe, it, expect } from "vitest";
import {
  CASTLE_WALL_AUDIT_LAYER,
  CASTLE_WALL_SCHEMA_VERSION_V1,
} from "../../../src/castle-wall/constants.js";
import {
  buildAuditEvent,
  canonicalizeAuditEvent,
  canonicalizeAuditEventToBytes,
} from "../../../src/castle-wall/audit/builder.js";

describe("castle-wall/audit/builder : buildAuditEvent", () => {
  it("populates layer = l1 and schema_version = 1 by default", () => {
    const evt = buildAuditEvent({
      timestamp: "2026-05-03T12:00:00.000Z",
      fortress_id: "f-test",
      event_type: "egress_blocked",
    });
    expect(evt.layer).toBe(CASTLE_WALL_AUDIT_LAYER);
    expect(evt.schema_version).toBe(CASTLE_WALL_SCHEMA_VERSION_V1);
  });

  it("defaults agent / destination / decision / rule_id to null when unspecified", () => {
    const evt = buildAuditEvent({
      timestamp: "2026-05-03T12:00:00.000Z",
      fortress_id: "f-test",
      event_type: "policy_loaded",
    });
    expect(evt.agent).toBe(null);
    expect(evt.destination).toBe(null);
    expect(evt.decision).toBe(null);
    expect(evt.rule_id).toBe(null);
    expect(evt.details).toEqual({});
  });

  it("preserves explicit destination + agent + decision", () => {
    const evt = buildAuditEvent({
      timestamp: "2026-05-03T12:00:00.000Z",
      fortress_id: "f-test",
      event_type: "operator_decision",
      agent: { id: "agent-001", template: "claude-code" },
      destination: { host: "api.example.com", ip: "203.0.113.5", port: 443, protocol: "tcp" },
      decision: "allow_always",
      rule_id: "rule-xyz",
      details: { latency_ms: 1200 },
    });
    expect(evt.agent?.id).toBe("agent-001");
    expect(evt.destination?.host).toBe("api.example.com");
    expect(evt.decision).toBe("allow_always");
    expect(evt.rule_id).toBe("rule-xyz");
    expect(evt.details).toEqual({ latency_ms: 1200 });
  });

  it("supports every CastleWallEventType the v1 schema defines", () => {
    const types = [
      "egress_blocked",
      "egress_allowed",
      "operator_decision",
      "policy_loaded",
      "policy_validation_failed",
      "filter_started",
      "filter_stopped",
      "filter_crashed",
      "queue_saturated",
      "no_wall_engaged",
      "no_wall_expired",
      "wal_overflow",
      "external_firewall_clobber",
      "egress_metric_batch",
    ] as const;
    for (const t of types) {
      const evt = buildAuditEvent({
        timestamp: "2026-05-03T12:00:00.000Z",
        fortress_id: "f-test",
        event_type: t,
      });
      expect(evt.event_type).toBe(t);
      expect(evt.layer).toBe("l1");
    }
  });
});

describe("castle-wall/audit/builder : canonicalize", () => {
  it("produces byte-stable output across input-key permutations", () => {
    const a = buildAuditEvent({
      timestamp: "2026-05-03T12:00:00.000Z",
      fortress_id: "f-test",
      event_type: "egress_blocked",
      details: { foo: 1, bar: 2 },
    });
    const b = buildAuditEvent({
      timestamp: "2026-05-03T12:00:00.000Z",
      fortress_id: "f-test",
      event_type: "egress_blocked",
      details: { bar: 2, foo: 1 },
    });
    expect(canonicalizeAuditEvent(a)).toBe(canonicalizeAuditEvent(b));
  });

  it("emits UTF-8 bytes whose decoded string matches canonicalize()", () => {
    const evt = buildAuditEvent({
      timestamp: "2026-05-03T12:00:00.000Z",
      fortress_id: "f-test",
      event_type: "egress_allowed",
    });
    const str = canonicalizeAuditEvent(evt);
    const bytes = canonicalizeAuditEventToBytes(evt);
    expect(new TextDecoder().decode(bytes)).toBe(str);
  });

  it("includes layer:l1 in every canonical output", () => {
    const evt = buildAuditEvent({
      timestamp: "2026-05-03T12:00:00.000Z",
      fortress_id: "f-test",
      event_type: "egress_blocked",
    });
    expect(canonicalizeAuditEvent(evt)).toContain('"layer":"l1"');
  });
});
