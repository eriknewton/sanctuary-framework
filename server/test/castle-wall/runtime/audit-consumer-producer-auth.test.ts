/**
 * Slice L1: the audit consumer's producer-authenticity gate.
 *
 * The load-bearing safety property under test: when the consumer is configured
 * with a pinned producer public key, an enforcement-evidence event whose
 * producer signature does not verify against that key is NOT accepted as
 * enforcement evidence (fail closed). An in-process forger that can write the
 * `cw_source` marker still cannot produce a valid signature, so its event is
 * rejected and never persisted as evidence.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  AuditChainError,
  AuditConsumer,
  type AuditSink,
  type CriticalEventEnvelope,
} from "../../../src/castle-wall/runtime/audit-consumer.js";
import {
  buildAuditEvent,
} from "../../../src/castle-wall/audit/builder.js";
import { canonicalize } from "../../../src/castle-wall/../mesh/canonical-json.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import type { CastleWallAuditEvent } from "../../../src/castle-wall/audit/events.js";

class RecordingSink implements AuditSink {
  entries: Array<{
    operation: string;
    details?: Record<string, unknown>;
    result: "success" | "failure";
  }> = [];
  append(
    _layer: "l1",
    operation: string,
    _identityId: string,
    details?: Record<string, unknown>,
    result: "success" | "failure" = "success"
  ): void {
    this.entries.push({ operation, details, result });
  }
  async flush(): Promise<void> {}
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const daemonPriv = ed25519.utils.randomPrivateKey();
const daemonPubB64 = toBase64url(ed25519.getPublicKey(daemonPriv));

// Fixed clock so the freshness window is deterministic; signed events use a
// timestamp just inside the window.
const NOW = 1_750_000_000_000;
const SIGNED_TS = NOW - 1000;

const FORTRESS_ID = "f";
const SIGNED_AGENT_UID = 503;

function auditTokenForRuid(uid: number): string {
  const vals = [
    0xffffffff,
    uid,
    uid,
    uid,
    uid,
    0x00000269,
    0x000186ae,
    0x00000566,
  ];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}

const AGENT = { id: auditTokenForRuid(SIGNED_AGENT_UID), template: "tpl" };
const DEST = { host: "evil.example", ip: "9.9.9.9", port: 443, protocol: "tcp" as const };

/** Build a blocked-egress enforcement event at a given seq. */
function blockedEvent(seq: number, priorHash: string | null): CastleWallAuditEvent {
  return buildAuditEvent({
    timestamp: `2026-06-13T00:00:0${seq}Z`,
    fortress_id: FORTRESS_ID,
    event_type: "egress_blocked",
    agent: AGENT,
    destination: DEST,
    decision: "deny_once",
    details: { seq, prior_sha256_hex: priorHash },
  });
}

/**
 * Produce the daemon's WAL `AuditEntry`-shaped canonical JSON for an event —
 * the same shape `build_audit_event_canonical_json` emits in Rust. This is the
 * body the daemon actually signs (NOT the CastleWallAuditEvent shape).
 */
function walBodyFor(event: CastleWallAuditEvent): string {
  const details: Record<string, unknown> = {};
  if (event.agent) {
    details.agent_id = event.agent.id;
    details.agent_template = event.agent.template;
  }
  if (event.destination) {
    if (event.destination.host !== null) details.dest_host = event.destination.host;
    details.dest_ip = event.destination.ip;
    details.dest_port = event.destination.port;
    details.dest_protocol = event.destination.protocol;
  }
  const operation =
    event.event_type === "egress_blocked"
      ? "egress_blocked"
      : event.event_type === "egress_allowed"
        ? "egress_approved"
        : "egress_pending";
  return canonicalize({
    timestamp: event.timestamp,
    layer: "l1",
    operation,
    identity_id: event.agent?.id ?? "unknown",
    result: event.event_type === "egress_blocked" ? "blocked" : "success",
    details,
  });
}

function walBodyWithSubjectFields(input: {
  operation?: "egress_blocked" | "egress_approved";
  identityId?: string;
  agentId?: string;
}): string {
  return canonicalize({
    timestamp: "2026-06-13T00:00:00Z",
    layer: "l1",
    operation: input.operation ?? "egress_blocked",
    ...(input.identityId !== undefined ? { identity_id: input.identityId } : {}),
    result:
      input.operation === "egress_approved" ? "success" : "blocked",
    details:
      input.agentId !== undefined ? { agent_id: input.agentId } : {},
  });
}

/** Sign an event the way the daemon would: over the WAL canonical body bytes. */
function signedEnvelope(
  event: CastleWallAuditEvent,
  signer: Uint8Array,
  opts?: {
    overrideSeq?: number;
    overrideTs?: number;
    bodyOverride?: string;
    omitSubjectBinding?: boolean;
  }
): CriticalEventEnvelope {
  const canonical = opts?.bodyOverride ?? walBodyFor(event);
  const seq = opts?.overrideSeq ?? (event.details.seq as number);
  const ts = opts?.overrideTs ?? SIGNED_TS;
  const sig = ed25519.sign(producerSigningBytes(canonical, ts, seq), signer);
  return {
    event,
    ack: async () => {},
    producer: {
      eventCanonicalJson: canonical,
      capturedAtUnixMs: ts,
      seq,
      signatureB64url: toBase64url(sig),
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    },
    ...(opts?.omitSubjectBinding === true
      ? {}
      : {
          producerSubjectBinding: {
            kind: "macos_audit_token" as const,
            fortressId: FORTRESS_ID,
          },
        }),
  };
}

describe("audit-consumer producer-authenticity (pinned key configured)", () => {
  let sink: RecordingSink;
  let consumer: AuditConsumer;

  beforeEach(() => {
    sink = new RecordingSink();
    consumer = new AuditConsumer(sink, undefined, {
      pinnedProducerKeyB64url: daemonPubB64,
      now: () => NOW,
    });
  });

  it("reports enforcement is active", () => {
    expect(consumer.isProducerSignatureEnforced()).toBe(true);
  });

  it("accepts a daemon-signed enforcement event and PERSISTS its signature", async () => {
    const event = blockedEvent(0, null);
    const env = signedEnvelope(event, daemonPriv);
    await consumer.ingestCritical(env);

    const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(persisted).toBeDefined();
    expect(persisted!.result).toBe("failure");
    expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]).toBe(
      env.producer!.signatureB64url
    );
    expect(persisted!.details?.[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]).toBe(
      CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1
    );
    expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED
    );
    // Evidence is sourced from the SIGNED body, not the event.
    expect(persisted!.details?.agent_id).toBe(AGENT.id);
    expect(persisted!.details?.dest_host).toBe(DEST.host);
    expect(persisted!.details?.dest_port).toBe(DEST.port);
    expect(persisted!.details?.dest_protocol).toBe(DEST.protocol);
    expect(consumer.getStats().producerSignatureAccepted).toBe(1);
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
    expect(consumer.getWalChainState().lastAckedSeq).toBe(0);
  });

  it("R-1: PERSISTS the signed canonical bytes + captured_at so a reader can re-verify", async () => {
    const event = blockedEvent(0, null);
    const env = signedEnvelope(event, daemonPriv);
    await consumer.ingestCritical(env);

    const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(persisted).toBeDefined();
    // The verbatim signed canonical string is stored (NOT re-canonicalized), so
    // the reader can reconstruct the exact signed message.
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY],
    ).toBe(env.producer!.eventCanonicalJson);
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY],
    ).toBe(env.producer!.capturedAtUnixMs);
    // seq is preserved from the chain-authenticated event details.
    expect(persisted!.details?.seq).toBe(0);
    // Together with sig/kid, this is the full ProducerSignatureInput. Round-trip
    // it through the verifier to prove the persisted tuple actually re-verifies.
    const reBytes = producerSigningBytes(
      persisted!.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY] as string,
      persisted!.details?.[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY] as number,
      persisted!.details?.seq as number,
    );
    const sigBytes = (() => {
      const s = persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] as string;
      const std = s.replace(/-/g, "+").replace(/_/g, "/");
      const pad = (4 - (std.length % 4)) % 4;
      const bin = atob(std + "=".repeat(pad));
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    })();
    expect(
      ed25519.verify(sigBytes, reBytes, ed25519.getPublicKey(daemonPriv)),
    ).toBe(true);
  });

  it("REJECTS an enforcement event with NO signature (the load-bearing test)", async () => {
    const event = blockedEvent(0, null);
    let acked = false;
    const env: CriticalEventEnvelope = {
      event,
      ack: async () => {
        acked = true;
      },
      // No `producer` field — exactly what an in-process forger can produce: a
      // marked egress_blocked entry with no daemon signature.
    };
    await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(
      AuditChainError
    );
    // Not persisted as evidence; chain not advanced.
    expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
    expect(
      sink.entries.some((e) => e.operation === "producer_signature_rejected")
    ).toBe(true);
    expect(consumer.getWalChainState().lastAckedSeq).toBeNull();
    expect(consumer.getStats().producerSignatureRejections).toBe(1);
    // We ACK the permanently-refused packet so the daemon stops retrying.
    expect(acked).toBe(true);
  });

  it("REJECTS a verified producer-signed event that omits subject binding", async () => {
    const event = blockedEvent(0, null);
    const env = signedEnvelope(event, daemonPriv, {
      omitSubjectBinding: true,
    });
    await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(
      AuditChainError
    );
    expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
    const rejection = sink.entries.find(
      (e) => e.operation === "producer_signature_rejected"
    );
    expect(rejection?.details?.reason).toBe(
      "producer_signed_without_subject_binding"
    );
    expect(consumer.getStats().producerSignatureRejections).toBe(1);
    expect(consumer.getWalChainState().lastAckedSeq).toBeNull();
  });

  it("REJECTS macOS subject binding when the signed body omits agent_id", async () => {
    const event = blockedEvent(0, null);
    const env = signedEnvelope(event, daemonPriv, {
      bodyOverride: walBodyWithSubjectFields({ identityId: "signed-agent" }),
    });

    await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(
      AuditChainError,
    );

    const rejection = sink.entries.find(
      (e) => e.operation === "producer_signature_rejected",
    );
    expect(rejection?.details?.reason).toBe(
      "producer_signed_body_missing_agent_id",
    );
    expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
  });

  it("REJECTS macOS subject binding when signed agent_id cannot derive a uid subject", async () => {
    const event = blockedEvent(0, null);
    const env = signedEnvelope(event, daemonPriv, {
      bodyOverride: walBodyWithSubjectFields({
        identityId: "signed-agent",
        agentId: "agent-name-not-audit-token",
      }),
    });

    await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(
      AuditChainError,
    );

    const rejection = sink.entries.find(
      (e) => e.operation === "producer_signature_rejected",
    );
    expect(rejection?.details?.reason).toBe(
      "producer_signed_body_agent_subject_unresolvable",
    );
    expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
  });

  it("REJECTS signed-identity binding when the signed body omits identity_id", async () => {
    const event = blockedEvent(0, null);
    const env = signedEnvelope(event, daemonPriv, {
      bodyOverride: walBodyWithSubjectFields({ agentId: "agent-name" }),
    });
    env.producerSubjectBinding = { kind: "signed_identity_id" };

    await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(
      AuditChainError,
    );

    const rejection = sink.entries.find(
      (e) => e.operation === "producer_signature_rejected",
    );
    expect(rejection?.details?.reason).toBe(
      "producer_signed_body_missing_identity_id",
    );
    expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
  });

  it("REJECTS an enforcement event FORGED with a different key", async () => {
    const forgerPriv = ed25519.utils.randomPrivateKey();
    const event = blockedEvent(0, null);
    const env = signedEnvelope(event, forgerPriv); // signed by the wrong key
    await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(
      AuditChainError
    );
    expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
    expect(consumer.getStats().producerSignatureRejections).toBe(1);
  });

  it("DISCARDS fabricated event fields: persisted evidence comes from the SIGNED body", async () => {
    // Attacker has a genuine signed frame for agent-1 → evil.example tcp:443.
    // They staple that exact signature + signed body onto a fabricated event
    // with a different agent/host/port/protocol/rule, same seq + event_type.
    // Because the persist path sources evidence ENTIRELY from the signed body
    // (not the event), the fabricated fields are discarded — the stored entry
    // reflects what the daemon actually signed. This structurally defeats the
    // whole staple/strip/fabricate attack class. (codex L1 R2–R5.)
    const genuine = blockedEvent(0, null); // agent-1, evil.example, 9.9.9.9 tcp:443
    const genuineSigned = signedEnvelope(genuine, daemonPriv);

    const fabricated = buildAuditEvent({
      timestamp: "2026-06-13T00:00:00Z",
      fortress_id: FORTRESS_ID,
      event_type: "egress_blocked", // operation must still map; everything else lies
      agent: { id: "victim-agent", template: "fabricated-template" },
      destination: { host: "innocent.example", ip: "1.1.1.1", port: 22, protocol: "udp" },
      decision: "deny_once",
      rule_id: "fabricated-rule",
      details: { seq: 0, prior_sha256_hex: null },
    });
    await consumer.ingestCritical({
      event: fabricated,
      ack: async () => {},
      producer: genuineSigned.producer,
      producerSubjectBinding: {
        kind: "macos_audit_token",
        fortressId: FORTRESS_ID,
      },
    });

    const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(persisted).toBeDefined();
    expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED
    );
    // The SIGNED body's values are persisted; the fabricated ones are gone.
    expect(persisted!.details?.agent_id).toBe(AGENT.id);
    expect(persisted!.details?.dest_host).toBe(DEST.host);
    expect(persisted!.details?.dest_ip).toBe(DEST.ip);
    expect(persisted!.details?.dest_port).toBe(DEST.port);
    expect(persisted!.details?.dest_protocol).toBe(DEST.protocol);
    // The fabricated agent template / host never enter the stored entry.
    expect(persisted!.details?.agent).toBeUndefined();
    expect(persisted!.details?.dest_host).not.toBe("innocent.example");
  });

  it("REJECTS a signed body whose operation does not map to the event_type", async () => {
    // Daemon signed an egress_approved (allow) body, but the attacker presents
    // it as an egress_blocked event — the operation→event_type binding fails.
    const allowEvent = buildAuditEvent({
      timestamp: "2026-06-13T00:00:00Z",
      fortress_id: FORTRESS_ID,
      event_type: "egress_allowed",
      agent: AGENT,
      destination: DEST,
      decision: "allow_once",
      details: { seq: 0, prior_sha256_hex: null },
    });
    const allowBody = walBodyFor(allowEvent); // operation = egress_approved
    const blockEvent = blockedEvent(0, null); // event_type = egress_blocked
    const sig = ed25519.sign(producerSigningBytes(allowBody, SIGNED_TS, 0), daemonPriv);
    const mismatched: CriticalEventEnvelope = {
      event: blockEvent,
      ack: async () => {},
      producer: {
        eventCanonicalJson: allowBody,
        capturedAtUnixMs: SIGNED_TS,
        seq: 0,
        signatureB64url: toBase64url(sig),
        keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      },
    };
    await expect(consumer.ingestCritical(mismatched)).rejects.toBeInstanceOf(
      AuditChainError
    );
    const rej = sink.entries.find(
      (e) => e.operation === "producer_signature_rejected"
    );
    expect(rej?.details?.reason).toBe(
      "producer_signed_body_operation_event_type_mismatch"
    );
  });

  it("REJECTS a STALE genuine signed frame replayed after a restart (freshness)", async () => {
    // Simulate a captured genuine frame whose bound timestamp is well outside
    // the freshness window. Even with a fresh consumer (lastAckedSeq=null,
    // as after a process restart), the freshness gate rejects it so a captured
    // past frame cannot re-arm the wall. (codex L1 HIGH #3.)
    const fresh = new AuditConsumer(sink, undefined, {
      pinnedProducerKeyB64url: daemonPubB64,
      now: () => NOW,
      producerSigMaxAgeMs: 5 * 60 * 1000,
    });
    const oldTs = NOW - 10 * 60 * 1000; // 10 min old, window is 5 min
    const e0 = blockedEvent(0, null);
    const env = signedEnvelope(e0, daemonPriv, { overrideTs: oldTs });
    await expect(fresh.ingestCritical(env)).rejects.toBeInstanceOf(
      AuditChainError
    );
    const rejection = sink.entries.find(
      (e) => e.operation === "producer_signature_rejected"
    );
    expect(rejection?.details?.reason).toBe("producer_signature_stale");
    expect(fresh.getStats().producerSignatureRejections).toBe(1);
  });

  it("does NOT gate non-enforcement control events on a signature", async () => {
    // A policy_loaded control event with no producer signature is still
    // accepted (it is not enforcement evidence) and stamped channel-unsigned.
    const event = buildAuditEvent({
      timestamp: "2026-06-13T00:00:00Z",
      fortress_id: "f",
      event_type: "policy_loaded",
      details: { seq: 0, prior_sha256_hex: null },
    });
    await consumer.ingestCritical({ event, ack: async () => {} });
    const persisted = sink.entries.find((e) => e.operation === "policy_loaded");
    expect(persisted).toBeDefined();
    expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED
    );
  });
});

describe("audit-consumer producer-authenticity (NO pinned key — legacy basis)", () => {
  it("accepts unsigned enforcement events and stamps channel-unsigned basis", async () => {
    const sink = new RecordingSink();
    const consumer = new AuditConsumer(sink); // no pinned key
    expect(consumer.isProducerSignatureEnforced()).toBe(false);
    const event = blockedEvent(0, null);
    await consumer.ingestCritical({ event, ack: async () => {} });
    const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(persisted).toBeDefined();
    expect(persisted!.result).toBe("success");
    expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED
    );
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]
    ).toBeUndefined();
  });

  it("strips a FORGED cw_producer_sig from an unsigned event's details", async () => {
    const sink = new RecordingSink();
    const consumer = new AuditConsumer(sink);
    // Forger pre-stuffs a fake producer signature into details, hoping it
    // survives into the stored entry and fools a Slice-R reader.
    const event = buildAuditEvent({
      timestamp: "2026-06-13T00:00:00Z",
      fortress_id: "f",
      event_type: "egress_blocked",
      details: {
        seq: 0,
        prior_sha256_hex: null,
        [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: "FORGED",
        [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
        // R-1 re-verification inputs the forger plants, hoping a Slice-R reader
        // mistakes them for a verifiable signature.
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: "{\"forged\":true}",
        [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: 123,
      },
    });
    await consumer.ingestCritical({ event, ack: async () => {} });
    const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(persisted).toBeDefined();
    // The forged signature must NOT survive, and the basis must be honest.
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]
    ).toBeUndefined();
    // R-1: the planted re-verification inputs must be stripped too, so a reader
    // never treats this channel-basis entry as a verifiable producer signature.
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]
    ).toBeUndefined();
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]
    ).toBeUndefined();
    expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED
    );
  });
});
