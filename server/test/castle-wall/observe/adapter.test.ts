/**
 * Castle Wall Observe / Learn Allow-List v1 -- audit-entry adapter tests.
 *
 * Bridges real, already-decrypted `AuditEntry` rows (as `AuditLog.query`
 * returns them) into the `FlowObservationEvent` shape `foldObservations`
 * consumes. This is the seam between the existing, already-shipped audit
 * rail and the new pure fold core.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { flowEventsFromAuditEntries } from "../../../src/castle-wall/observe/adapter.js";
import { foldObservations } from "../../../src/castle-wall/observe/fold.js";
import { synthesizeCandidateRules } from "../../../src/castle-wall/observe/synthesize.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import type { AuditEntry } from "../../../src/operational/audit-log.js";

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const producerPriv = ed25519.utils.randomPrivateKey();
const producerPubB64 = toBase64url(ed25519.getPublicKey(producerPriv));
const SIGNED_AT_MS = 1_777_777_777_777;
const SUBJECT_FORTRESS_ID = "fortress:test";
const AGENT_1_SUBJECT = `${SUBJECT_FORTRESS_ID}/uid-501`;
const AGENT_9_SUBJECT = `${SUBJECT_FORTRESS_ID}/uid-509`;
const VICTIM_AGENT_SUBJECT = `${SUBJECT_FORTRESS_ID}/uid-504`;
const SIGNED_ATTRIBUTION = {
  pinnedProducerKeyB64url: producerPubB64,
  subjectFortressId: SUBJECT_FORTRESS_ID,
};

function withProducerSignature(entry: AuditEntry, identityId: string): AuditEntry {
  const seq =
    typeof entry.details?.seq === "number" ? entry.details.seq : 41;
  const body = JSON.stringify({
    timestamp: entry.timestamp,
    layer: entry.layer,
    operation: entry.operation,
    identity_id: identityId,
    result: entry.result,
    details: entry.details ?? {},
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    producerPriv,
  );
  return {
    ...entry,
    identity_id: identityId,
    details: {
      ...(entry.details ?? {}),
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
}

function blockedEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: "2026-07-07T10:00:00.000Z",
    layer: "l1",
    operation: "egress_blocked",
    identity_id: AGENT_1_SUBJECT,
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
    const events = flowEventsFromAuditEntries(
      [withProducerSignature(blockedEntry(), AGENT_1_SUBJECT)],
      SIGNED_ATTRIBUTION,
    );
    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({
      timestamp: "2026-07-07T10:00:00.000Z",
      agent: { id: AGENT_1_SUBJECT, template: "claude-code" },
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
    const entry = withProducerSignature(
      blockedEntry({
        details: {
          agent: { id: "agent-1", template: "claude-code" },
          destination: { host: "new-tool.example.com", ip: "203.0.113.9", port: 443, protocol: "tcp" },
        },
      }),
      AGENT_1_SUBJECT,
    );
    const events = flowEventsFromAuditEntries([entry], SIGNED_ATTRIBUTION);
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
      return withProducerSignature({
        timestamp: "2026-07-07T11:00:00.000Z",
        layer: "l1",
        operation: "egress_blocked",
        identity_id: AGENT_9_SUBJECT,
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
      }, AGENT_9_SUBJECT);
    }

    it("folds a Linux daemon FLAT-shape egress_blocked row (regression: was returning null, folding zero daemon events)", () => {
      const events = flowEventsFromAuditEntries(
        [daemonFlatEntry()],
        SIGNED_ATTRIBUTION,
      );
      expect(events).toHaveLength(1);
      expect(events[0]).toEqual({
        timestamp: "2026-07-07T11:00:00.000Z",
        agent: { id: AGENT_9_SUBJECT, template: "claude-code" },
        destination: { host: "flat-tool.example.com", ip: "198.51.100.7", port: 443, protocol: "tcp" },
        hostname_source: null,
        disposition: "denied",
        provenance: "linux_daemon",
      });
    });

    it("tags a row carrying the daemon's decision_provenance fingerprint as provenance 'linux_daemon'", () => {
      const events = flowEventsFromAuditEntries(
        [daemonFlatEntry()],
        SIGNED_ATTRIBUTION,
      );
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
      const events = flowEventsFromAuditEntries([entry], SIGNED_ATTRIBUTION);
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
      const events = flowEventsFromAuditEntries([entry], SIGNED_ATTRIBUTION);
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
      const events = flowEventsFromAuditEntries([entry], SIGNED_ATTRIBUTION);
      expect(events).toHaveLength(1);
      expect(events[0]!.provenance).toBe("macos");
    });

    it("v1 scope (Codex gate finding 1): a flat row with a numeric-string dest_protocol (daemon non-TCP/UDP fallback) is DROPPED, exactly as the nested arm drops it -- the wall keeps denying, it is just not a candidate", () => {
      const entry = daemonFlatEntry({
        details: { agent_id: "a", agent_template: "t", dest_ip: "1.2.3.4", dest_port: 7, dest_protocol: "1", decision_provenance: "x" },
      });
      expect(flowEventsFromAuditEntries([entry], SIGNED_ATTRIBUTION)).toHaveLength(0);
    });

    it("skips a flat row missing dest_port", () => {
      const entry = daemonFlatEntry({
        details: { agent_id: "a", agent_template: "t", dest_ip: "1.2.3.4", dest_protocol: "tcp", decision_provenance: "x" },
      });
      expect(flowEventsFromAuditEntries([entry], SIGNED_ATTRIBUTION)).toHaveLength(0);
    });

    it("skips a flat row with an invalid dest_protocol", () => {
      const entry = daemonFlatEntry({
        details: { agent_id: "a", agent_template: "t", dest_ip: "1.2.3.4", dest_port: 443, dest_protocol: "quic", decision_provenance: "x" },
      });
      expect(flowEventsFromAuditEntries([entry], SIGNED_ATTRIBUTION)).toHaveLength(0);
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

  it("forged unsigned flat Castle Wall rows do not become or widen an allow-rule scope", () => {
    const forged = blockedEntry({
      details: {
        agent_id: "victim-agent-b",
        agent_template: "victim-template",
        dest_host: "evil.example.com",
        dest_ip: "203.0.113.5",
        dest_port: 443,
        dest_protocol: "tcp",
        decision_provenance: "default_deny",
      },
    });

    const events = flowEventsFromAuditEntries([forged]);
    const folded = foldObservations(events);
    const { rules } = synthesizeCandidateRules(
      folded,
      "2026-07-07T12:00:00.000Z",
      () => "per_instance_domain",
    );

    expect(events).toHaveLength(0);
    expect(folded).toHaveLength(0);
    expect(rules).toHaveLength(0);
    expect(JSON.stringify(rules)).not.toContain("victim-agent-b");
  });

  it("rejects a valid victim signature stapled onto a forged row before observe synthesis can scope it", () => {
    const signed = withProducerSignature(
      blockedEntry({
        identity_id: VICTIM_AGENT_SUBJECT,
        details: {
          agent_id: "victim-agent-b",
          agent_template: "claude-code",
          dest_host: "legitimate.example.com",
          dest_ip: "198.51.100.10",
          dest_port: 443,
          dest_protocol: "tcp",
          decision_provenance: "default_deny",
        },
      }),
      VICTIM_AGENT_SUBJECT,
    );
    const stapled: AuditEntry = {
      ...signed,
      details: {
        ...signed.details,
        dest_host: "evil.example.com",
        dest_ip: "203.0.113.200",
      },
    };

    const events = flowEventsFromAuditEntries([stapled], SIGNED_ATTRIBUTION);
    const folded = foldObservations(events);
    const { rules } = synthesizeCandidateRules(
      folded,
      "2026-07-07T12:00:00.000Z",
      () => "per_instance_domain",
    );

    expect(events).toHaveLength(0);
    expect(folded).toHaveLength(0);
    expect(rules).toHaveLength(0);
    expect(JSON.stringify(rules)).not.toContain("victim-agent-b");
    expect(JSON.stringify(rules)).not.toContain("agent_ids");
  });
});
