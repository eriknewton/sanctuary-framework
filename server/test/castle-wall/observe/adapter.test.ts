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
      provenance: "macos",
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

  // ── #897 FLAT-SHAPE ARM: the Rust daemon writes flat `dest_*` + `agent_*`
  // fields (castle-wall-daemon/src/policy.rs build_audit_event_canonical_json),
  // preserved verbatim into entry.details by the audit-consumer. The original
  // reader knew only the nested shape and folded ZERO of these. ──
  describe("flat-shape (Linux daemon / producer-signed body)", () => {
    /** A Linux daemon egress_blocked body: flat dest_* + agent_* + the daemon's unconditional `decision_provenance` fingerprint. */
    function daemonFlatEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
      return {
        timestamp: "2026-07-07T11:00:00.000Z",
        layer: "l1",
        operation: "egress_blocked",
        identity_id: "agent-9",
        result: "failure",
        details: {
          agent_id: "agent-9",
          agent_template: "claude-code",
          dest_host: "flat-tool.example.com",
          dest_ip: "198.51.100.7",
          dest_port: 443,
          dest_protocol: "tcp",
          opaque: false,
          decision_provenance: "default_deny",
        },
        ...overrides,
      };
    }

    it("folds a Linux daemon FLAT-shape egress_blocked row (regression: was returning null, folding zero daemon events)", () => {
      const events = flowEventsFromAuditEntries([daemonFlatEntry()]);
      expect(events).toHaveLength(1);
      expect(events[0]).toEqual({
        timestamp: "2026-07-07T11:00:00.000Z",
        agent: { id: "agent-9", template: "claude-code" },
        destination: { host: "flat-tool.example.com", ip: "198.51.100.7", port: 443, protocol: "tcp" },
        hostname_source: null,
        disposition: "denied",
        provenance: "linux_daemon",
      });
    });

    it("tags a row carrying the daemon's decision_provenance fingerprint as provenance 'linux_daemon'", () => {
      const events = flowEventsFromAuditEntries([daemonFlatEntry()]);
      expect(events[0]!.provenance).toBe("linux_daemon");
    });

    it("folds an IP-only NFQUEUE flat row (no dest_host, agent_template 'unknown') and tags it linux_daemon", () => {
      const entry = daemonFlatEntry({
        details: {
          agent_id: "agent-9",
          agent_template: "unknown", // NFQUEUE hardcodes this (nfqueue.rs)
          dest_ip: "198.51.100.7",
          dest_port: 443,
          dest_protocol: "tcp",
          opaque: true,
          decision_provenance: "default_deny",
        },
      });
      const events = flowEventsFromAuditEntries([entry]);
      expect(events).toHaveLength(1);
      expect(events[0]!.destination.host).toBeNull();
      expect(events[0]!.destination.ip).toBe("198.51.100.7");
      expect(events[0]!.agent.template).toBe("unknown");
      expect(events[0]!.provenance).toBe("linux_daemon");
    });

    it("tags a macOS producer-signed FLAT body (source=macos_extension, NO decision_provenance) as provenance 'macos'", () => {
      // AuditProducerSigning.swift signedDetailsFor writes flat dest_* + a
      // `source: "macos_extension"` marker and NEVER `decision_provenance`.
      const entry = daemonFlatEntry({
        details: {
          agent_id: "agent-9",
          agent_template: "unknown",
          dest_ip: "198.51.100.7",
          dest_port: 443,
          dest_protocol: "tcp",
          decision: "block",
          source: "macos_extension",
        },
      });
      const events = flowEventsFromAuditEntries([entry]);
      expect(events).toHaveLength(1);
      expect(events[0]!.provenance).toBe("macos");
    });

    it("Codex gate finding 3: a flat row carrying BOTH decision_provenance AND source=macos_extension is tagged 'macos' (positive macОS marker overrides the daemon fingerprint -- fail safe)", () => {
      const entry = daemonFlatEntry({
        details: {
          agent_id: "agent-9",
          agent_template: "unknown",
          dest_ip: "198.51.100.7",
          dest_port: 443,
          dest_protocol: "tcp",
          decision_provenance: "default_deny", // daemon-looking...
          source: "macos_extension", // ...but positively macOS-sourced
        },
      });
      const events = flowEventsFromAuditEntries([entry]);
      expect(events).toHaveLength(1);
      expect(events[0]!.provenance).toBe("macos");
    });

    it("v1 scope (Codex gate finding 1): a flat row with a numeric-string dest_protocol (daemon non-TCP/UDP fallback) is DROPPED, exactly as the nested arm drops it -- the wall keeps denying, it is just not a candidate", () => {
      const entry = daemonFlatEntry({
        details: { agent_id: "a", agent_template: "t", dest_ip: "1.2.3.4", dest_port: 7, dest_protocol: "1", decision_provenance: "x" },
      });
      expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
    });

    it("skips a flat row missing dest_port", () => {
      const entry = daemonFlatEntry({
        details: { agent_id: "a", agent_template: "t", dest_ip: "1.2.3.4", dest_protocol: "tcp", decision_provenance: "x" },
      });
      expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
    });

    it("skips a flat row with an invalid dest_protocol", () => {
      const entry = daemonFlatEntry({
        details: { agent_id: "a", agent_template: "t", dest_ip: "1.2.3.4", dest_port: 443, dest_protocol: "quic", decision_provenance: "x" },
      });
      expect(flowEventsFromAuditEntries([entry])).toHaveLength(0);
    });
  });

  // ── ANTI-HONEYPOT EXCLUSION (must survive the flat arm): the credential
  // honeypot writes a flat `destination_host` (the FULL word) + `agent_id`
  // but NO `dest_port`/`dest_protocol`/`dest_*`, so it must NEVER fold. ──
  it("does NOT fold a credential-honeypot egress_blocked row (flat destination_host, no dest_* fields)", () => {
    const honeypot = blockedEntry({
      details: {
        event_type: "egress_blocked",
        fortress_id: "fortress-1",
        agent_id: "attacker-agent",
        destination_host: "honeypot-target.example.com",
        reason: "credential_honeypot_use_attempt",
        trap_id: "trap-1",
        fake_credential_name: "AWS_SECRET",
        credential_value_hash: "deadbeef",
        decision: "block",
      },
    });
    expect(flowEventsFromAuditEntries([honeypot])).toHaveLength(0);
  });
});
