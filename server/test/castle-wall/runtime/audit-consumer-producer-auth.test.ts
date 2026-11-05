/**
 * The audit consumer verifies producer evidence before durable admission and inbox projection.
 * S1
 */
// fail-before-exempt: these assertions witness behavior the source already has; each is proven by a named mutation that fails it, so the file passes against unchanged source by construction.

import { describe, it, expect, beforeEach } from "vitest";
import { createHash } from "node:crypto";
import { readConsumerMintedBlockedEgress } from "../../../src/castle-wall/runtime/blocked-egress-attribution.js";
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
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN,
  CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
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
 * Produce the daemon's WAL `AuditEntry`-shaped canonical JSON for an event -
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
    expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]).toBe(
      CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN,
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
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY],
    ).toBe(CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN);
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
      // No `producer` field - exactly what an in-process forger can produce: a
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
    // (not the event), the fabricated fields are discarded - the stored entry
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
    expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]).toBe(
      CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN,
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
    // it as an egress_blocked event - the operation→event_type binding fails.
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

describe("audit-consumer producer-authenticity (NO pinned key - legacy basis)", () => {
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
        [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]:
          CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
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
    expect(
      persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY],
    ).toBeUndefined();
    expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED
    );
  });
});

// The real bridge exercises the consumer-to-producer-to-cache handoff.
import { BLOCKED_EGRESS_SUBJECT_MAX_CHARS } from "../../../src/contracts/v1.1/index.js";
import { UnifiedInboxBridge } from "../../../src/principal-policy/unified-inbox-bridge.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { vi } from "vitest";

function structuredBridge() {
  // 32 bytes is the AES-256 fixture key length; storage is isolated per test.
  return new UnifiedInboxBridge({
    auditLog: new AuditLog(new MemoryStorage(), new Uint8Array(32)),
    identityId: FORTRESS_ID, fortressId: FORTRESS_ID, now: () => new Date("2026-06-14T00:00:00Z"),
  });
}

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

const verifiedAttribution = { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "verified" } as const;
const unsignedAttribution = { ...verifiedAttribution, state: "unverified" } as const;
const verifiedMetadata = { destination_host: DEST.host, destination_ip: DEST.ip, subject: `${FORTRESS_ID}/uid-${SIGNED_AGENT_UID}`, attribution: verifiedAttribution };

describe("structured blocked-egress producer evidence", () => {
  it.each(["macos_audit_token", "signed_identity_id"] as const)("keeps signed destinations and subject for %s", async (binding) => {
    const sink = new RecordingSink();
    const bridge = structuredBridge();
    const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    const env = signedEnvelope(blockedEvent(0, null), daemonPriv);
    if (binding === "signed_identity_id") env.producerSubjectBinding = { kind: binding };

    await consumer.ingestCritical(env);
    expect(bridge.list()[0]?.blocked_egress).toEqual({
      destination_host: DEST.host, destination_ip: DEST.ip,
      subject: binding === "signed_identity_id" ? AGENT.id : `${FORTRESS_ID}/uid-${SIGNED_AGENT_UID}`,
      attribution: { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "verified" },
    });
  });

  it.each(["host", "ip", "unavailable"])("keeps verified attribution with %s destination", async (mode) => {
    const bridge = structuredBridge();
    const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    const body = JSON.parse(walBodyFor(blockedEvent(0, null)));
    if (mode !== "host") body.details.dest_host = "bad/host";
    if (mode === "unavailable") body.details.dest_ip = "bad/ip";
    const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
    env.event = { ...env.event, destination: null, agent: null };
    env.producerSubjectBinding = { kind: "signed_identity_id" };
    await consumer.ingestCritical(env);
    const metadata = bridge.list()[0]?.blocked_egress;
    expect(metadata).toEqual({
      attribution: verifiedAttribution, subject: AGENT.id,
      ...(mode === "host" ? { destination_host: DEST.host } : {}),
      ...(mode !== "unavailable" ? { destination_ip: DEST.ip } : {}),
    });
    expect(metadata?.destination_host).toBe(mode === "host" ? DEST.host : undefined);
    expect(metadata?.destination_ip).toBe(mode === "unavailable" ? undefined : DEST.ip);
    const destination = mode === "host" ? DEST.host : mode === "ip" ? DEST.ip : "unknown";
    expect(bridge.list()[0]?.summary).toBe(`Egress to ${destination} blocked: other (agent ${AGENT.id})`);
  });

  it("mints unsigned attribution independently of a success row or claimed details", async () => {
    const sink = new RecordingSink();
    const bridge = structuredBridge();
    const event = blockedEvent(0, null);
    event.details.attribution = { state: "verified" };
    event.details.subject = "claimed-subject";
    await new AuditConsumer(sink, bridge).ingestCritical({ event, ack: async () => {} });
    expect(sink.entries.find((entry) => entry.operation === "egress_blocked")?.result).toBe("success");
    expect(bridge.list()[0]?.blocked_egress).toEqual({
      destination_host: DEST.host, destination_ip: DEST.ip,
      attribution: { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "unverified" },
    });
  });

  it("publishes only accepted signatures and preserves the accepted metadata", async () => {
    const bridge = structuredBridge();
    const ingest = vi.spyOn(bridge, "ingestBlockedEgress");
    const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    const bad = signedEnvelope(blockedEvent(0, null), daemonPriv);
    bad.producer!.signatureB64url = "invalid";
    await expect(consumer.ingestCritical(bad)).rejects.toBeInstanceOf(AuditChainError);
    expect(ingest).not.toHaveBeenCalled();
    await consumer.ingestCritical(signedEnvelope(blockedEvent(0, null), daemonPriv));
    expect(bridge.list()[0]?.blocked_egress).toEqual(verifiedMetadata);
  });

  it.each(["append", "flush"] as const)("waits for %s before publishing structured evidence", async (stage) => {
    const bridge = structuredBridge();
    const sink = new RecordingSink();
    const entered = deferred();
    const release = deferred();
    const order: string[] = [];
    const append = sink.append.bind(sink);
    sink.append = async (...args) => {
      if (stage === "append" && args[1] === "egress_blocked") { entered.resolve(); await release.promise; }
      append(...args);
    };
    sink.flush = async () => {
      if (stage === "flush") { entered.resolve(); await release.promise; }
      order.push("flushed");
    };
    bridge.onEvent(() => order.push("published"));
    const pending = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(signedEnvelope(blockedEvent(0, null), daemonPriv));
    await entered.promise;
    expect(bridge.list()).toEqual([]);
    release.resolve();
    await pending;
    expect(order).toEqual(["flushed", "published"]);
    expect(bridge.list()[0]?.blocked_egress).toEqual(verifiedMetadata);
  });

  it.each(["append", "flush"] as const)("withholds publication on %s failure and publishes after a successful retry", async (stage) => {
    const sink = new RecordingSink();
    const bridge = structuredBridge();
    const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    const fail = vi.spyOn(sink, stage).mockImplementationOnce(() => { throw new Error("isolated sink failure"); });
    const env = { ...signedEnvelope(blockedEvent(0, null), daemonPriv), ack: vi.fn(async () => {}) };
    await expect(consumer.ingestCritical(env)).rejects.toThrow("isolated sink failure");
    expect(bridge.list()).toEqual([]);
    expect(env.ack).not.toHaveBeenCalled();
    fail.mockRestore();
    await consumer.ingestCritical(env);
    expect(bridge.list()[0]?.blocked_egress).toEqual(verifiedMetadata);
    expect(env.ack).toHaveBeenCalled();
  });

  it("counts projection failure without payload and does not re-project redelivery", async () => {
    const sink = new RecordingSink();
    const bridge = structuredBridge();
    const ingest = vi.spyOn(bridge, "ingestBlockedEgress").mockImplementationOnce(() => { throw new Error("secret error host subject payload"); });
    const log = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
      const env = { ...signedEnvelope(blockedEvent(0, null), daemonPriv), ack: vi.fn(async () => {}) };
      await consumer.ingestCritical(env);
      expect(consumer.getStats().blockedEgressProjectionFailures).toBe(1);
      expect(log.mock.calls).toEqual([["Castle Wall blocked-egress inbox projection failed"]]);
      expect(consumer.getWalChainState().lastAckedSeq).toBe(0);
      expect(sink.entries.find((entry) => entry.operation === "egress_blocked")?.result).toBe("failure");
      expect(sink.entries.find((entry) => entry.operation === "castle_wall_blocked_egress")?.details?.projection_status).toBe("pending");
      await consumer.ingestCritical(env);
      expect(env.ack).toHaveBeenCalledTimes(2);
      expect(ingest).toHaveBeenCalledTimes(1);
      expect(bridge.list()).toEqual([]);
      expect(consumer.getStats().blockedEgressProjectionFailures).toBe(1);
      expect(consumer.getStats().duplicatesDropped).toBe(1);
    } finally { log.mockRestore(); }
  });

  it.each(["host", "ip"] as const)("suppresses a disagreeing envelope %s while preserving audit ACK and chain", async (field) => {
    const sink = new RecordingSink();
    const flush = vi.spyOn(sink, "flush");
    const bridge = structuredBridge();
    const ingest = vi.spyOn(bridge, "ingestBlockedEgress");
    const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    const env = { ...signedEnvelope(blockedEvent(0, null), daemonPriv), ack: vi.fn(async () => {}) };
    const destination = { ...DEST, [field]: field === "host" ? "envelope.example" : "192.0.2.1" };
    env.event = { ...env.event, destination, agent: { id: "envelope-agent", template: "tpl" }, timestamp: "2026-06-14T00:00:00Z",
      details: { ...env.event.details, reason: "envelope reason" } };
    const log = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await consumer.ingestCritical(env);
      expect(bridge.list()).toEqual([]);
      expect(ingest).not.toHaveBeenCalled();
      expect(consumer.getStats().blockedEgressDestinationConflicts).toBe(1);
      expect(consumer.getStats().blockedEgressProjectionFailures).toBe(0);
      expect(log.mock.calls).toEqual([["Castle Wall blocked-egress inbox destination conflict"]]);
      expect(env.ack).toHaveBeenCalledTimes(1);
      expect(consumer.getWalChainState()).toMatchObject({
        lastAckedSeq: 0,
        lastEventChainHash: createHash("sha256").update(env.producer!.eventCanonicalJson).digest("hex"),
      });
      expect(sink.entries.find((entry) => entry.operation === "egress_blocked")?.result).toBe("failure");
      expect(sink.entries.find((entry) => entry.operation === "castle_wall_blocked_egress")?.details?.projection_status).toBe("pending");
      expect(flush).toHaveBeenCalledTimes(1);
      await consumer.ingestCritical(env);
      expect(env.ack).toHaveBeenCalledTimes(2);
      expect(consumer.getStats().blockedEgressDestinationConflicts).toBe(1);
      expect(log).toHaveBeenCalledTimes(1);
    } finally { log.mockRestore(); }
  });

  it.each([undefined, null, false])("mints unverified without a string signed agent_id (%s)", async (agentId) => {
    const bridge = structuredBridge();
    const body = JSON.parse(walBodyFor(blockedEvent(0, null)));
    if (agentId === undefined) delete body.details.agent_id;
    else body.details.agent_id = agentId;
    const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
    env.producerSubjectBinding = { kind: "signed_identity_id" };
    const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    await consumer.ingestCritical(env);
    expect(consumer.getStats().producerSignatureAccepted).toBe(1);
    expect(bridge.list()).toHaveLength(1);
    expect(bridge.list()[0]?.blocked_egress).toEqual({
      destination_host: DEST.host, destination_ip: DEST.ip, attribution: unsignedAttribution,
    });
    expect(bridge.list()[0]?.blocked_egress).not.toHaveProperty("subject");
  });

  it("consumes a consumer token on its first read", async () => {
    const bridge = structuredBridge();
    const reads: Array<ReturnType<typeof readConsumerMintedBlockedEgress>> = [];
    const ingest = vi.spyOn(bridge, "ingestBlockedEgress").mockImplementation((_input, token) => {
      reads.push(readConsumerMintedBlockedEgress(token), readConsumerMintedBlockedEgress(token));
      return null;
    });
    await new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW })
      .ingestCritical(signedEnvelope(blockedEvent(0, null), daemonPriv));
    expect(ingest).toHaveBeenCalledTimes(1);
    expect(reads).toHaveLength(2);
    expect(reads[0]?.metadata).toEqual(verifiedMetadata);
    expect(reads[1]).toBeUndefined();
  });

  it("saturates destination conflict accounting across repeated admissions even if logging throws", async () => {
    const bridge = structuredBridge();
    const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    // Seed just below the numeric ceiling to exercise saturation without an impractical event history.
    (consumer as unknown as { stats: { blockedEgressDestinationConflicts: number } }).stats.blockedEgressDestinationConflicts = Number.MAX_SAFE_INTEGER - 1;
    const log = vi.spyOn(console, "warn").mockImplementation(() => { throw new Error("isolated log failure"); });
    let prior: string | null = null;
    try {
      for (const seq of [0, 1]) {
        const env: CriticalEventEnvelope = { ...signedEnvelope(blockedEvent(seq, prior), daemonPriv), ack: vi.fn(async () => {}) };
        env.event = { ...env.event, destination: { ...DEST, host: "envelope.example" } };
        await consumer.ingestCritical(env);
        expect(env.ack).toHaveBeenCalledTimes(1);
        expect(consumer.getWalChainState().lastAckedSeq).toBe(seq);
        expect(consumer.getStats().blockedEgressDestinationConflicts).toBe(Number.MAX_SAFE_INTEGER);
        prior = createHash("sha256").update(env.producer!.eventCanonicalJson).digest("hex");
      }
      expect(bridge.list()).toEqual([]);
      expect(consumer.getStats().blockedEgressProjectionFailures).toBe(0);
      expect(log.mock.calls).toEqual(Array.from({ length: 2 }, () => ["Castle Wall blocked-egress inbox destination conflict"]));
    } finally { log.mockRestore(); }
  });

  it("uses signed display fields but unsigned envelope reason on a verified entry", async () => {
    const bridge = structuredBridge();
    const event = blockedEvent(0, null);
    const body = JSON.parse(walBodyFor(event));
    body.details.reason = "signed reason";
    const env = signedEnvelope(event, daemonPriv, { bodyOverride: canonicalize(body) });
    env.event = { ...env.event, destination: null, agent: { id: "envelope-agent", template: "tpl" }, timestamp: "2026-06-14T00:00:00Z",
      details: { ...env.event.details, reason: "envelope reason", block_reason_class: "lockdown_active" } };
    await new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(env);
    const entry = bridge.list()[0]!;
    expect(entry.blocked_egress).toEqual(verifiedMetadata);
    expect(entry.summary).toBe(`Egress to ${DEST.host} blocked: envelope reason (agent ${AGENT.id})`);
    expect(entry.agent_id).toBe(AGENT.id);
    expect(entry.observed_at).toBe(event.timestamp);
    expect(entry.source_event_id).toBe(`${event.timestamp}:0`);
  });

  it.each(["bad\0subject", "bad\nsubject", "<subject>", "a".repeat(BLOCKED_EGRESS_SUBJECT_MAX_CHARS + 1)])("downgrades rejected display subject %j", async (subject) => {
    const bridge = structuredBridge();
    const body = JSON.parse(walBodyFor(blockedEvent(0, null)));
    body.identity_id = subject;
    const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
    env.producerSubjectBinding = { kind: "signed_identity_id" };
    await new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(env);
    expect(bridge.list()[0]?.blocked_egress).toEqual({ destination_host: DEST.host, destination_ip: DEST.ip, attribution: unsignedAttribution });
  });

  it.each([false, true])("never calls the bridge for a rejected subject binding (durable: %s)", async (durable) => {
    const bridge = structuredBridge();
    const ingest = vi.spyOn(bridge, "ingestBlockedEgress");
    const env = signedEnvelope(blockedEvent(0, null), daemonPriv);
    env.producerSubjectBinding = undefined;
    env.producerDelivery = durable ? "durable_wal" : undefined;
    const ack = vi.fn(async () => {}); env.ack = ack;
    await expect(new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(env)).rejects.toThrow("producer_signed_without_subject_binding");
    expect(ingest).not.toHaveBeenCalled();
    expect(ack).toHaveBeenCalledTimes(durable ? 0 : 1);
  });

  it("counts mint failures under the same projection diagnostic", async () => {
    const bridge = structuredBridge();
    const body = JSON.parse(walBodyFor(blockedEvent(0, null))); delete body.timestamp;
    const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
    const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
    const log = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await consumer.ingestCritical(env);
      expect(bridge.list()).toEqual([]);
      expect(consumer.getStats().blockedEgressProjectionFailures).toBe(1);
      expect(log.mock.calls).toEqual([["Castle Wall blocked-egress inbox projection failed"]]);
      expect(consumer.getWalChainState().lastAckedSeq).toBe(0);
    } finally { log.mockRestore(); }
  });
  it.each([false, true])("keeps a signed and an unsigned event that share a source id as separate records (verified first: %s)", async (verifiedFirst) => {
    const bridge = structuredBridge();
    let first: ReturnType<typeof bridge.list>[number] | undefined;
    for (const verified of [verifiedFirst, !verifiedFirst]) {
      const consumer = new AuditConsumer(new RecordingSink(), bridge, { now: () => NOW,
        ...(verified ? { pinnedProducerKeyB64url: daemonPubB64 } : {}) });
      await consumer.ingestCritical(verified ? signedEnvelope(blockedEvent(0, null), daemonPriv) : { event: blockedEvent(0, null), ack: async () => {} });
      if (!first) first = structuredClone(bridge.list()[0]!);
    }
    expect(bridge.list()).toHaveLength(2);
    const verified = bridge.list().find(e => e.blocked_egress?.attribution.state === "verified")!;
    const unsigned = bridge.list().find(e => e.blocked_egress?.attribution.state === "unverified")!;
    expect(verified.blocked_egress).toEqual(verifiedMetadata);
    expect(verified.blocked_egress_admission?.origin).toBe(`subject:${verifiedMetadata.subject}`);
    expect(unsigned.blocked_egress).toEqual({ destination_host: DEST.host, destination_ip: DEST.ip, attribution: unsignedAttribution });
    expect(unsigned.blocked_egress_admission?.origin).toBe("unsigned");
    expect(bridge.get(first!.inbox_id)).toEqual(first);
  });

});

describe("signed blocked-egress admission identity", () => {
  it("retains distinct enrolled keys at one sequence and assigns minted subject origins", async () => {
    const bridge = structuredBridge();
    const secondKey = ed25519.utils.randomPrivateKey();
    for (const [key, uid] of [[daemonPriv, SIGNED_AGENT_UID], [secondKey, SIGNED_AGENT_UID + 1]] as const) {
      const event = blockedEvent(0, null);
      event.agent = { ...AGENT, id: auditTokenForRuid(uid) };
      const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(key)), now: () => NOW });
      await consumer.ingestCritical(signedEnvelope(event, key));
    }
    const entries = bridge.list();
    expect(entries).toHaveLength(2);
    expect(new Set(entries.map(e => e.blocked_egress_admission?.origin))).toEqual(new Set([
      `subject:${FORTRESS_ID}/uid-${SIGNED_AGENT_UID}`, `subject:${FORTRESS_ID}/uid-${SIGNED_AGENT_UID + 1}`,
    ]));
    expect(entries.every(e => e.blocked_egress?.attribution.state === "verified")).toBe(true);
    expect(new Set(entries.map(e => JSON.stringify(e.blocked_egress_admission?.identity))).size).toBe(2);
  });
});

import { describe as parityDescribe, it as parityIt, expect as parityExpect } from "vitest";
import { AuditConsumer as ParityBaseConsumer } from "../../../src/castle-wall/runtime/audit-consumer.js";
import { MacOSFlowEventConsumer as ParityFlowConsumer } from "../../../src/castle-wall/runtime/macos-flow-events.js";
parityDescribe("consumer admission with counted-window configuration", () => {
  const paritySecondKey = ed25519.utils.randomPrivateKey();
  let enabled = false;
  let invocationCount = 0;
  let countedInvocations = new Set<number>();
  let trace: unknown[] = [];
  let instances: ParityBaseConsumer[] = [];
  let hooks: Array<() => unknown> = [];
  let helper: typeof import("../../../src/castle-wall/runtime/macos-flow-coalescing.js") | null = null;
  class AuditConsumer extends ParityBaseConsumer {
    constructor(...args: ConstructorParameters<typeof ParityBaseConsumer>) {
      const sink = args[0];
      const append = sink.append.bind(sink), flush = sink.flush.bind(sink);
      sink.append = (...call) => { trace.push(["append", JSON.stringify(call)]); return append(...call); };
      sink.flush = () => { trace.push(["flush"]); return flush(); };
      super(sink, args[1], { ...args[2], ...(enabled ? { liveFlowCoalescer: new helper!.FlowCoalescer("parity-instance", () => 0) } : {}) });
      instances.push(this);
    }
    override async ingestCritical(envelope: Parameters<ParityBaseConsumer["ingestCritical"]>[0]): Promise<void> {
      const ack = envelope.ack;
      const invocation = invocationCount++;
      trace.push(["begin", invocation]);
      try {
        await super.ingestCritical({ ...envelope, ack: async () => { trace.push(["ACK", envelope.event.details?.seq]); return ack(); } }, { classify(kind) { if (kind === "coalesced") countedInvocations.add(invocation); } });
        trace.push(["fulfilled"]);
      } catch (error) { trace.push(["thrown", error instanceof Error ? [error.constructor.name, error.name, error.message] : String(error)]); throw error; }
      finally { trace.push(["end", invocation]); }
    }
  }
  function describe(title: string, register: () => void) {
    const previous = hooks; hooks = [...hooks]; parityDescribe(title, register); hooks = previous;
  }
  function beforeEach(hook: () => unknown) { hooks.push(hook); }
  function variant(callback: (...args: any[]) => unknown) {
    const setup = [...hooks];
    return async (...args: any[]) => {
      const consumer = new ParityFlowConsumer({ fortressId: "parity", defaultApprovalTimeoutSeconds: 30,
        auditSink: { append() {}, async flush() {} }, approvalQueue: { async enqueue() {} },
        manifestProvider: { currentSnapshot() { throw new Error("unused"); } } });
      parityExpect(consumer.flushCoalescedFlowSummaries).toBeTypeOf("function");
      const path = "../../../src/castle-wall/runtime/macos-flow-coalescing.js";
      helper = await import(path).catch(() => null); parityExpect(helper).not.toBeNull();
      const results: unknown[] = [];
      for (const mode of [false, true]) {
        enabled = mode; trace = []; instances = []; invocationCount = 0; countedInvocations = new Set();
        for (const hook of setup) await hook();
        await callback(...args);
        results.push({ counted: [...countedInvocations], trace: structuredClone(trace), consumers: instances.map(item => ({ stats: item.getStats(), state: item.getWalChainState() })) });
      }
      const [control, counted] = results as Array<{ counted: number[]; trace: any[]; consumers: Array<{ stats: ReturnType<ParityBaseConsumer["getStats"]>; state: unknown }> }>;
      const omitted = new Set(counted!.counted);
      let invocation = -1, beforeAck = false;
      const expectedTrace = control!.trace.filter(call => {
        if (call[0] === "begin") { invocation = call[1]; beforeAck = true; }
        if (call[0] === "ACK") beforeAck = false;
        // Only an admitted counted frame omits its primary/projection transaction; rejection bytes remain exact.
        return !(omitted.has(invocation) && beforeAck && (call[0] === "append" || call[0] === "flush"));
      });
      parityExpect(counted!.trace, "ordered evidence bytes, outcomes and ACKs match after admitted write omission").toEqual(expectedTrace);
      for (let index = 0; index < control!.consumers.length; index++) {
        const left = control!.consumers[index]!, right = counted!.consumers[index]!;
        const { acceptedCriticalEvents: primaryLeft, coalescedCriticalEvents: countLeft, ...statsLeft } = left.stats;
        const { acceptedCriticalEvents: primaryRight, coalescedCriticalEvents: countRight, ...statsRight } = right.stats;
        parityExpect(primaryRight + countRight, "accepted primaries and counted admissions remain separate").toBe(primaryLeft + countLeft);
        parityExpect({ stats: statsRight, state: right.state }, "refusal diagnostics and committed chain state remain identical").toEqual({ stats: statsLeft, state: left.state });
      }
    };
  }
  const it = Object.assign((title: string, callback: (...args: any[]) => unknown) => parityIt(title + " with coalescer attached", variant(callback)), {
    each: (cases: readonly any[]) => (title: string, callback: (...args: any[]) => unknown) => parityIt.each(cases)(title + " with coalescer attached", variant(callback)),
  });
class RecordingSink implements AuditSink {
    entries: Array<{
        operation: string;
        details?: Record<string, unknown>;
        result: "success" | "failure";
    }> = [];
    append(_layer: "l1", operation: string, _identityId: string, details?: Record<string, unknown>, result: "success" | "failure" = "success"): void {
        this.entries.push({ operation, details, result });
    }
    async flush(): Promise<void> { }
}
function toBase64url(bytes: Uint8Array): string {
    let bin = "";
    for (const b of bytes)
        bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const daemonPriv = ed25519.utils.randomPrivateKey();
const daemonPubB64 = toBase64url(ed25519.getPublicKey(daemonPriv));
const NOW = 1750000000000; // Fixed Unix milliseconds keep signed freshness deterministic.
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
function walBodyFor(event: CastleWallAuditEvent): string {
    const details: Record<string, unknown> = { decision: event.event_type === "egress_blocked" ? "drop" : "allow" };
    if (event.agent) {
        details.agent_id = event.agent.id;
        details.agent_template = event.agent.template;
    }
    if (event.destination) {
        if (event.destination.host !== null)
            details.dest_host = event.destination.host;
        details.dest_ip = event.destination.ip;
        details.dest_port = event.destination.port;
        details.dest_protocol = event.destination.protocol;
    }
    const operation = event.event_type === "egress_blocked"
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
        result: input.operation === "egress_approved" ? "success" : "blocked",
        details: input.agentId !== undefined ? { agent_id: input.agentId } : {},
    });
}
function signedEnvelope(event: CastleWallAuditEvent, signer: Uint8Array, opts?: {
    overrideSeq?: number;
    overrideTs?: number;
    bodyOverride?: string;
    omitSubjectBinding?: boolean;
}): CriticalEventEnvelope {
    const canonical = opts?.bodyOverride ?? walBodyFor(event);
    const seq = opts?.overrideSeq ?? (event.details.seq as number);
    const ts = opts?.overrideTs ?? SIGNED_TS;
    const sig = ed25519.sign(producerSigningBytes(canonical, ts, seq), signer);
    return {
        event,
        producerDelivery: "live",
        ack: async () => { },
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
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]).toBe(env.producer!.signatureB64url);
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]).toBe(CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1);
        expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED);
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]).toBe(CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN);
        expect(persisted!.details?.agent_id).toBe(AGENT.id);
        expect(persisted!.details?.dest_host).toBe(DEST.host);
        expect(persisted!.details?.dest_port).toBe(DEST.port);
        expect(persisted!.details?.dest_protocol).toBe(DEST.protocol);
        expect(consumer.getStats().producerSignatureAccepted).toBe(1);
        expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
        expect(consumer.getWalChainState().lastAckedSeq).toBe(0);
    });
    it("PERSISTS the signed canonical bytes and captured_at so a reader can re-verify", async () => {
        const event = blockedEvent(0, null);
        const env = signedEnvelope(event, daemonPriv);
        await consumer.ingestCritical(env);
        const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
        expect(persisted).toBeDefined();
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]).toBe(env.producer!.eventCanonicalJson);
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]).toBe(env.producer!.capturedAtUnixMs);
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]).toBe(CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN);
        expect(persisted!.details?.seq).toBe(0);
        const reBytes = producerSigningBytes(persisted!.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY] as string, persisted!.details?.[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY] as number, persisted!.details?.seq as number);
        const sigBytes = (() => {
            const s = persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY] as string;
            const std = s.replace(/-/g, "+").replace(/_/g, "/");
            const pad = (4 - (std.length % 4)) % 4;
            const bin = atob(std + "=".repeat(pad));
            const out = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++)
                out[i] = bin.charCodeAt(i);
            return out;
        })();
        expect(ed25519.verify(sigBytes, reBytes, ed25519.getPublicKey(daemonPriv))).toBe(true);
    });
    it("REJECTS an enforcement event with NO signature", async () => {
        const event = blockedEvent(0, null);
        let acked = false;
        const env: CriticalEventEnvelope = {
            event,
            ack: async () => {
                acked = true;
            },
        };
        await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(AuditChainError);
        expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
        expect(sink.entries.some((e) => e.operation === "producer_signature_rejected")).toBe(true);
        expect(consumer.getWalChainState().lastAckedSeq).toBeNull();
        expect(consumer.getStats().producerSignatureRejections).toBe(1);
        expect(acked).toBe(true);
    });
    it("REJECTS a verified producer-signed event that omits subject binding", async () => {
        const event = blockedEvent(0, null);
        const env = signedEnvelope(event, daemonPriv, {
            omitSubjectBinding: true,
        });
        await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(AuditChainError);
        expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
        const rejection = sink.entries.find((e) => e.operation === "producer_signature_rejected");
        expect(rejection?.details?.reason).toBe("producer_signed_without_subject_binding");
        expect(consumer.getStats().producerSignatureRejections).toBe(1);
        expect(consumer.getWalChainState().lastAckedSeq).toBeNull();
    });
    it("REJECTS macOS subject binding when the signed body omits agent_id", async () => {
        const event = blockedEvent(0, null);
        const env = signedEnvelope(event, daemonPriv, {
            bodyOverride: walBodyWithSubjectFields({ identityId: "signed-agent" }),
        });
        await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(AuditChainError);
        const rejection = sink.entries.find((e) => e.operation === "producer_signature_rejected");
        expect(rejection?.details?.reason).toBe("producer_signed_body_missing_agent_id");
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
        await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(AuditChainError);
        const rejection = sink.entries.find((e) => e.operation === "producer_signature_rejected");
        expect(rejection?.details?.reason).toBe("producer_signed_body_agent_subject_unresolvable");
        expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
    });
    it("REJECTS signed-identity binding when the signed body omits identity_id", async () => {
        const event = blockedEvent(0, null);
        const env = signedEnvelope(event, daemonPriv, {
            bodyOverride: walBodyWithSubjectFields({ agentId: "agent-name" }),
        });
        env.producerSubjectBinding = { kind: "signed_identity_id" };
        await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(AuditChainError);
        const rejection = sink.entries.find((e) => e.operation === "producer_signature_rejected");
        expect(rejection?.details?.reason).toBe("producer_signed_body_missing_identity_id");
        expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
    });
    it("REJECTS an enforcement event FORGED with a different key", async () => {
        const forgerPriv = ed25519.utils.randomPrivateKey();
        const event = blockedEvent(0, null);
        const env = signedEnvelope(event, forgerPriv);
        await expect(consumer.ingestCritical(env)).rejects.toBeInstanceOf(AuditChainError);
        expect(sink.entries.some((e) => e.operation === "egress_blocked")).toBe(false);
        expect(consumer.getStats().producerSignatureRejections).toBe(1);
    });
    it("DISCARDS fabricated event fields: persisted evidence comes from the SIGNED body", async () => {
        const genuine = blockedEvent(0, null);
        const genuineSigned = signedEnvelope(genuine, daemonPriv);
        const fabricated = buildAuditEvent({
            timestamp: "2026-06-13T00:00:00Z",
            fortress_id: FORTRESS_ID,
            event_type: "egress_blocked",
            agent: { id: "victim-agent", template: "fabricated-template" },
            destination: { host: "innocent.example", ip: "1.1.1.1", port: 22, protocol: "udp" },
            decision: "deny_once",
            rule_id: "fabricated-rule",
            details: { seq: 0, prior_sha256_hex: null },
        });
        await consumer.ingestCritical({
            event: fabricated,
            ack: async () => { },
            producer: genuineSigned.producer,
            producerSubjectBinding: {
                kind: "macos_audit_token",
                fortressId: FORTRESS_ID,
            },
        });
        const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
        expect(persisted).toBeDefined();
        expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED);
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]).toBe(CASTLE_WALL_PRODUCER_SUBJECT_BINDING_MACOS_AUDIT_TOKEN);
        expect(persisted!.details?.agent_id).toBe(AGENT.id);
        expect(persisted!.details?.dest_host).toBe(DEST.host);
        expect(persisted!.details?.dest_ip).toBe(DEST.ip);
        expect(persisted!.details?.dest_port).toBe(DEST.port);
        expect(persisted!.details?.dest_protocol).toBe(DEST.protocol);
        expect(persisted!.details?.agent).toBeUndefined();
        expect(persisted!.details?.dest_host).not.toBe("innocent.example");
    });
    it("REJECTS a signed body whose operation does not map to the event_type", async () => {
        const allowEvent = buildAuditEvent({
            timestamp: "2026-06-13T00:00:00Z",
            fortress_id: FORTRESS_ID,
            event_type: "egress_allowed",
            agent: AGENT,
            destination: DEST,
            decision: "allow_once",
            details: { seq: 0, prior_sha256_hex: null },
        });
        const allowBody = walBodyFor(allowEvent);
        const blockEvent = blockedEvent(0, null);
        const sig = ed25519.sign(producerSigningBytes(allowBody, SIGNED_TS, 0), daemonPriv);
        const mismatched: CriticalEventEnvelope = {
            event: blockEvent,
            ack: async () => { },
            producer: {
                eventCanonicalJson: allowBody,
                capturedAtUnixMs: SIGNED_TS,
                seq: 0,
                signatureB64url: toBase64url(sig),
                keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
            },
        };
        await expect(consumer.ingestCritical(mismatched)).rejects.toBeInstanceOf(AuditChainError);
        const rej = sink.entries.find((e) => e.operation === "producer_signature_rejected");
        expect(rej?.details?.reason).toBe("producer_signed_body_operation_event_type_mismatch");
    });
    it("REJECTS a STALE genuine signed frame replayed after a restart", async () => {
        const fresh = new AuditConsumer(sink, undefined, {
            pinnedProducerKeyB64url: daemonPubB64,
            now: () => NOW,
            producerSigMaxAgeMs: 5 * 60 * 1000,
        });
        const oldTs = NOW - 10 * 60 * 1000;
        const e0 = blockedEvent(0, null);
        const env = signedEnvelope(e0, daemonPriv, { overrideTs: oldTs });
        await expect(fresh.ingestCritical(env)).rejects.toBeInstanceOf(AuditChainError);
        const rejection = sink.entries.find((e) => e.operation === "producer_signature_rejected");
        expect(rejection?.details?.reason).toBe("producer_signature_stale");
        expect(fresh.getStats().producerSignatureRejections).toBe(1);
    });
    it("does NOT gate non-enforcement control events on a signature", async () => {
        const event = buildAuditEvent({
            timestamp: "2026-06-13T00:00:00Z",
            fortress_id: "f",
            event_type: "policy_loaded",
            details: { seq: 0, prior_sha256_hex: null },
        });
        await consumer.ingestCritical({ event, ack: async () => { } });
        const persisted = sink.entries.find((e) => e.operation === "policy_loaded");
        expect(persisted).toBeDefined();
        expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED);
    });
});
describe("audit-consumer producer-authenticity (NO pinned key - legacy basis)", () => {
    it("accepts unsigned enforcement events and stamps channel-unsigned basis", async () => {
        const sink = new RecordingSink();
        const consumer = new AuditConsumer(sink);
        expect(consumer.isProducerSignatureEnforced()).toBe(false);
        const event = blockedEvent(0, null);
        await consumer.ingestCritical({ event, ack: async () => { } });
        const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
        expect(persisted).toBeDefined();
        expect(persisted!.result).toBe("success");
        expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED);
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]).toBeUndefined();
    });
    it("strips a FORGED cw_producer_sig from an unsigned event's details", async () => {
        const sink = new RecordingSink();
        const consumer = new AuditConsumer(sink);
        const event = buildAuditEvent({
            timestamp: "2026-06-13T00:00:00Z",
            fortress_id: "f",
            event_type: "egress_blocked",
            details: {
                seq: 0,
                prior_sha256_hex: null,
                [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: "FORGED",
                [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
                [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: "{\"forged\":true}",
                [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: 123,
                [CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]: CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
            },
        });
        await consumer.ingestCritical({ event, ack: async () => { } });
        const persisted = sink.entries.find((e) => e.operation === "egress_blocked");
        expect(persisted).toBeDefined();
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]).toBeUndefined();
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]).toBeUndefined();
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]).toBeUndefined();
        expect(persisted!.details?.[CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]).toBeUndefined();
        expect(persisted!.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(CASTLE_WALL_EVIDENCE_BASIS_CHANNEL_UNSIGNED);
    });
});
function structuredBridge() {
    return new UnifiedInboxBridge({
        auditLog: new AuditLog(new MemoryStorage(), new Uint8Array(32)),
        identityId: FORTRESS_ID, fortressId: FORTRESS_ID, now: () => new Date("2026-06-14T00:00:00Z"),
    });
}
function deferred() {
    let resolve!: () => void;
    const promise = new Promise<void>((done) => { resolve = done; });
    return { promise, resolve };
}
const verifiedAttribution = { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "verified" } as const;
const unsignedAttribution = { ...verifiedAttribution, state: "unverified" } as const;
const verifiedMetadata = { destination_host: DEST.host, destination_ip: DEST.ip, subject: `${FORTRESS_ID}/uid-${SIGNED_AGENT_UID}`, attribution: verifiedAttribution };
describe("structured blocked-egress producer evidence", () => {
    it.each(["macos_audit_token", "signed_identity_id"] as const)("keeps signed destinations and subject for %s", async (binding) => {
        const sink = new RecordingSink();
        const bridge = structuredBridge();
        const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        const env = signedEnvelope(blockedEvent(0, null), daemonPriv);
        if (binding === "signed_identity_id")
            env.producerSubjectBinding = { kind: binding };
        await consumer.ingestCritical(env);
        expect(bridge.list()[0]?.blocked_egress).toEqual({
            destination_host: DEST.host, destination_ip: DEST.ip,
            subject: binding === "signed_identity_id" ? AGENT.id : `${FORTRESS_ID}/uid-${SIGNED_AGENT_UID}`,
            attribution: { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "verified" },
        });
    });
    it.each(["host", "ip", "unavailable"])("keeps verified attribution with %s destination", async (mode) => {
        const bridge = structuredBridge();
        const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        const body = JSON.parse(walBodyFor(blockedEvent(0, null)));
        if (mode !== "host")
            body.details.dest_host = "bad/host";
        if (mode === "unavailable")
            body.details.dest_ip = "bad/ip";
        const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
        env.event = { ...env.event, destination: null, agent: null };
        env.producerSubjectBinding = { kind: "signed_identity_id" };
        await consumer.ingestCritical(env);
        const metadata = bridge.list()[0]?.blocked_egress;
        expect(metadata).toEqual({
            attribution: verifiedAttribution, subject: AGENT.id,
            ...(mode === "host" ? { destination_host: DEST.host } : {}),
            ...(mode !== "unavailable" ? { destination_ip: DEST.ip } : {}),
        });
        expect(metadata?.destination_host).toBe(mode === "host" ? DEST.host : undefined);
        expect(metadata?.destination_ip).toBe(mode === "unavailable" ? undefined : DEST.ip);
        const destination = mode === "host" ? DEST.host : mode === "ip" ? DEST.ip : "unknown";
        expect(bridge.list()[0]?.summary).toBe(`Egress to ${destination} blocked: other (agent ${AGENT.id})`);
    });
    it("mints unsigned attribution independently of a success row or claimed details", async () => {
        const sink = new RecordingSink();
        const bridge = structuredBridge();
        const event = blockedEvent(0, null);
        event.details.attribution = { state: "verified" };
        event.details.subject = "claimed-subject";
        await new AuditConsumer(sink, bridge).ingestCritical({ event, ack: async () => { } });
        expect(sink.entries.find((entry) => entry.operation === "egress_blocked")?.result).toBe("success");
        expect(bridge.list()[0]?.blocked_egress).toEqual({
            destination_host: DEST.host, destination_ip: DEST.ip,
            attribution: { subject: "castle_wall_producer", evidence_source: "producer_signature", verifier: "castle_wall_audit_consumer", state: "unverified" },
        });
    });
    it("publishes only accepted signatures and preserves the accepted metadata", async () => {
        const bridge = structuredBridge();
        const ingest = vi.spyOn(bridge, "ingestBlockedEgress");
        const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        const bad = signedEnvelope(blockedEvent(0, null), daemonPriv);
        bad.producer!.signatureB64url = "invalid";
        await expect(consumer.ingestCritical(bad)).rejects.toBeInstanceOf(AuditChainError);
        expect(ingest).not.toHaveBeenCalled();
        await consumer.ingestCritical(signedEnvelope(blockedEvent(0, null), daemonPriv));
        expect(bridge.list()[0]?.blocked_egress).toEqual(verifiedMetadata);
    });
    it.each(["append", "flush"] as const)("waits for %s before publishing structured evidence", async (stage) => {
        const bridge = structuredBridge();
        const sink = new RecordingSink();
        const entered = deferred();
        const release = deferred();
        const order: string[] = [];
        const append = sink.append.bind(sink);
        sink.append = async (...args) => {
            if (stage === "append" && args[1] === "egress_blocked") {
                entered.resolve();
                await release.promise;
            }
            append(...args);
        };
        sink.flush = async () => {
            if (stage === "flush") {
                entered.resolve();
                await release.promise;
            }
            order.push("flushed");
        };
        bridge.onEvent(() => order.push("published"));
        const pending = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(signedEnvelope(blockedEvent(0, null), daemonPriv));
        await entered.promise;
        expect(bridge.list()).toEqual([]);
        release.resolve();
        await pending;
        expect(order).toEqual(["flushed", "published"]);
        expect(bridge.list()[0]?.blocked_egress).toEqual(verifiedMetadata);
    });
    it.each(["append", "flush"] as const)("withholds publication on %s failure and publishes after a successful retry", async (stage) => {
        const sink = new RecordingSink();
        const bridge = structuredBridge();
        const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        const fail = vi.spyOn(sink, stage).mockImplementationOnce(() => { throw new Error("isolated sink failure"); });
        const env = { ...signedEnvelope(blockedEvent(0, null), daemonPriv), ack: vi.fn(async () => { }) };
        await expect(consumer.ingestCritical(env)).rejects.toThrow("isolated sink failure");
        expect(bridge.list()).toEqual([]);
        expect(env.ack).not.toHaveBeenCalled();
        fail.mockRestore();
        await consumer.ingestCritical(env);
        expect(bridge.list()[0]?.blocked_egress).toEqual(verifiedMetadata);
        expect(env.ack).toHaveBeenCalled();
    });
    it("counts projection failure without payload and does not re-project redelivery", async () => {
        const sink = new RecordingSink();
        const bridge = structuredBridge();
        const ingest = vi.spyOn(bridge, "ingestBlockedEgress").mockImplementationOnce(() => { throw new Error("secret error host subject payload"); });
        const log = vi.spyOn(console, "warn").mockImplementation(() => { });
        try {
            const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
            const env = { ...signedEnvelope(blockedEvent(0, null), daemonPriv), ack: vi.fn(async () => { }) };
            await consumer.ingestCritical(env);
            expect(consumer.getStats().blockedEgressProjectionFailures).toBe(1);
            expect(log.mock.calls).toEqual([["Castle Wall blocked-egress inbox projection failed"]]);
            expect(consumer.getWalChainState().lastAckedSeq).toBe(0);
            expect(sink.entries.find((entry) => entry.operation === "egress_blocked")?.result).toBe("failure");
            expect(sink.entries.find((entry) => entry.operation === "castle_wall_blocked_egress")?.details?.projection_status).toBe("pending");
            await consumer.ingestCritical(env);
            expect(env.ack).toHaveBeenCalledTimes(2);
            expect(ingest).toHaveBeenCalledTimes(1);
            expect(bridge.list()).toEqual([]);
            expect(consumer.getStats().blockedEgressProjectionFailures).toBe(1);
            expect(consumer.getStats().duplicatesDropped).toBe(1);
        }
        finally {
            log.mockRestore();
        }
    });
    it.each(["host", "ip"] as const)("suppresses a disagreeing envelope %s while preserving audit ACK and chain", async (field) => {
        const sink = new RecordingSink();
        const flush = vi.spyOn(sink, "flush");
        const bridge = structuredBridge();
        const ingest = vi.spyOn(bridge, "ingestBlockedEgress");
        const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        const env = { ...signedEnvelope(blockedEvent(0, null), daemonPriv), ack: vi.fn(async () => { }) };
        const destination = { ...DEST, [field]: field === "host" ? "envelope.example" : "192.0.2.1" };
        env.event = { ...env.event, destination, agent: { id: "envelope-agent", template: "tpl" }, timestamp: "2026-06-14T00:00:00Z",
            details: { ...env.event.details, reason: "envelope reason" } };
        const log = vi.spyOn(console, "warn").mockImplementation(() => { });
        try {
            await consumer.ingestCritical(env);
            expect(bridge.list()).toEqual([]);
            expect(ingest).not.toHaveBeenCalled();
            expect(consumer.getStats().blockedEgressDestinationConflicts).toBe(1);
            expect(consumer.getStats().blockedEgressProjectionFailures).toBe(0);
            expect(log.mock.calls).toEqual([["Castle Wall blocked-egress inbox destination conflict"]]);
            expect(env.ack).toHaveBeenCalledTimes(1);
            expect(consumer.getWalChainState()).toMatchObject({
                lastAckedSeq: 0,
                lastEventChainHash: createHash("sha256").update(env.producer!.eventCanonicalJson).digest("hex"),
            });
            expect(sink.entries.find((entry) => entry.operation === "egress_blocked")?.result).toBe("failure");
            expect(sink.entries.find((entry) => entry.operation === "castle_wall_blocked_egress")?.details?.projection_status).toBe("pending");
            expect(flush).toHaveBeenCalledTimes(1);
            await consumer.ingestCritical(env);
            expect(env.ack).toHaveBeenCalledTimes(2);
            expect(consumer.getStats().blockedEgressDestinationConflicts).toBe(1);
            expect(log).toHaveBeenCalledTimes(1);
        }
        finally {
            log.mockRestore();
        }
    });
    it.each([undefined, null, false])("mints unverified without a string signed agent_id (%s)", async (agentId) => {
        const bridge = structuredBridge();
        const body = JSON.parse(walBodyFor(blockedEvent(0, null)));
        if (agentId === undefined)
            delete body.details.agent_id;
        else
            body.details.agent_id = agentId;
        const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
        env.producerSubjectBinding = { kind: "signed_identity_id" };
        const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        await consumer.ingestCritical(env);
        expect(consumer.getStats().producerSignatureAccepted).toBe(1);
        expect(bridge.list()).toHaveLength(1);
        expect(bridge.list()[0]?.blocked_egress).toEqual({
            destination_host: DEST.host, destination_ip: DEST.ip, attribution: unsignedAttribution,
        });
        expect(bridge.list()[0]?.blocked_egress).not.toHaveProperty("subject");
    });
    it("consumes a consumer token on its first read", async () => {
        const bridge = structuredBridge();
        const reads: Array<ReturnType<typeof readConsumerMintedBlockedEgress>> = [];
        const ingest = vi.spyOn(bridge, "ingestBlockedEgress").mockImplementation((_input, token) => {
            reads.push(readConsumerMintedBlockedEgress(token), readConsumerMintedBlockedEgress(token));
            return null;
        });
        await new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW })
            .ingestCritical(signedEnvelope(blockedEvent(0, null), daemonPriv));
        expect(ingest).toHaveBeenCalledTimes(1);
        expect(reads).toHaveLength(2);
        expect(reads[0]?.metadata).toEqual(verifiedMetadata);
        expect(reads[1]).toBeUndefined();
    });
    it("saturates destination conflict accounting across repeated admissions even if logging throws", async () => {
        const bridge = structuredBridge();
        const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        (consumer as unknown as {
            stats: {
                blockedEgressDestinationConflicts: number;
            };
        }).stats.blockedEgressDestinationConflicts = Number.MAX_SAFE_INTEGER - 1;
        const log = vi.spyOn(console, "warn").mockImplementation(() => { throw new Error("isolated log failure"); });
        let prior: string | null = null;
        try {
            for (const seq of [0, 1]) {
                const env: CriticalEventEnvelope = { ...signedEnvelope(blockedEvent(seq, prior), daemonPriv), ack: vi.fn(async () => { }) };
                env.event = { ...env.event, destination: { ...DEST, host: "envelope.example" } };
                await consumer.ingestCritical(env);
                expect(env.ack).toHaveBeenCalledTimes(1);
                expect(consumer.getWalChainState().lastAckedSeq).toBe(seq);
                expect(consumer.getStats().blockedEgressDestinationConflicts).toBe(Number.MAX_SAFE_INTEGER);
                prior = createHash("sha256").update(env.producer!.eventCanonicalJson).digest("hex");
            }
            expect(bridge.list()).toEqual([]);
            expect(consumer.getStats().blockedEgressProjectionFailures).toBe(0);
            expect(log.mock.calls).toEqual(Array.from({ length: enabled ? 1 : 2 }, () => ["Castle Wall blocked-egress inbox destination conflict"]));
        }
        finally {
            log.mockRestore();
        }
    });
    it("uses signed display fields but unsigned envelope reason on a verified entry", async () => {
        const bridge = structuredBridge();
        const event = blockedEvent(0, null);
        const body = JSON.parse(walBodyFor(event));
        body.details.reason = "signed reason";
        const env = signedEnvelope(event, daemonPriv, { bodyOverride: canonicalize(body) });
        env.event = { ...env.event, destination: null, agent: { id: "envelope-agent", template: "tpl" }, timestamp: "2026-06-14T00:00:00Z",
            details: { ...env.event.details, reason: "envelope reason", block_reason_class: "lockdown_active" } };
        await new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(env);
        const entry = bridge.list()[0]!;
        expect(entry.blocked_egress).toEqual(verifiedMetadata);
        expect(entry.summary).toBe(`Egress to ${DEST.host} blocked: envelope reason (agent ${AGENT.id})`);
        expect(entry.agent_id).toBe(AGENT.id);
        expect(entry.observed_at).toBe(event.timestamp);
        expect(entry.source_event_id).toBe(`${event.timestamp}:0`);
    });
    it.each(["bad\0subject", "bad\nsubject", "<subject>", "a".repeat(BLOCKED_EGRESS_SUBJECT_MAX_CHARS + 1)])("downgrades rejected display subject %j", async (subject) => {
        const bridge = structuredBridge();
        const body = JSON.parse(walBodyFor(blockedEvent(0, null)));
        body.identity_id = subject;
        const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
        env.producerSubjectBinding = { kind: "signed_identity_id" };
        await new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(env);
        expect(bridge.list()[0]?.blocked_egress).toEqual({ destination_host: DEST.host, destination_ip: DEST.ip, attribution: unsignedAttribution });
    });
    it.each([false, true])("never calls the bridge for a rejected subject binding (durable: %s)", async (durable) => {
        const bridge = structuredBridge();
        const ingest = vi.spyOn(bridge, "ingestBlockedEgress");
        const env = signedEnvelope(blockedEvent(0, null), daemonPriv);
        env.producerSubjectBinding = undefined;
        env.producerDelivery = durable ? "durable_wal" : undefined;
        const ack = vi.fn(async () => { });
        env.ack = ack;
        await expect(new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW }).ingestCritical(env)).rejects.toThrow("producer_signed_without_subject_binding");
        expect(ingest).not.toHaveBeenCalled();
        expect(ack).toHaveBeenCalledTimes(durable ? 0 : 1);
    });
    it("counts mint failures under the same projection diagnostic", async () => {
        const bridge = structuredBridge();
        const body = JSON.parse(walBodyFor(blockedEvent(0, null)));
        delete body.timestamp;
        const env = signedEnvelope(blockedEvent(0, null), daemonPriv, { bodyOverride: canonicalize(body) });
        const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: daemonPubB64, now: () => NOW });
        const log = vi.spyOn(console, "warn").mockImplementation(() => { });
        try {
            await consumer.ingestCritical(env);
            expect(bridge.list()).toEqual([]);
            expect(consumer.getStats().blockedEgressProjectionFailures).toBe(1);
            expect(log.mock.calls).toEqual([["Castle Wall blocked-egress inbox projection failed"]]);
            expect(consumer.getWalChainState().lastAckedSeq).toBe(0);
        }
        finally {
            log.mockRestore();
        }
    });
    it.each([false, true])("keeps a signed and an unsigned event that share a source id as separate records (verified first: %s)", async (verifiedFirst) => {
        const bridge = structuredBridge();
        let first: ReturnType<typeof bridge.list>[number] | undefined;
        for (const verified of [verifiedFirst, !verifiedFirst]) {
            const consumer = new AuditConsumer(new RecordingSink(), bridge, { now: () => NOW,
                ...(verified ? { pinnedProducerKeyB64url: daemonPubB64 } : {}) });
            await consumer.ingestCritical(verified ? signedEnvelope(blockedEvent(0, null), daemonPriv) : { event: blockedEvent(0, null), ack: async () => { } });
            if (!first)
                first = structuredClone(bridge.list()[0]!);
        }
        expect(bridge.list()).toHaveLength(2);
        const verified = bridge.list().find(e => e.blocked_egress?.attribution.state === "verified")!;
        const unsigned = bridge.list().find(e => e.blocked_egress?.attribution.state === "unverified")!;
        expect(verified.blocked_egress).toEqual(verifiedMetadata);
        expect(verified.blocked_egress_admission?.origin).toBe(`subject:${verifiedMetadata.subject}`);
        expect(unsigned.blocked_egress).toEqual({ destination_host: DEST.host, destination_ip: DEST.ip, attribution: unsignedAttribution });
        expect(unsigned.blocked_egress_admission?.origin).toBe("unsigned");
        expect(bridge.get(first!.inbox_id)).toEqual(first);
    });
});
describe("signed blocked-egress admission identity", () => {
    it("retains distinct enrolled keys at one sequence and assigns minted subject origins", async () => {
        const bridge = structuredBridge();
        const secondKey = paritySecondKey;
        for (const [key, uid] of [[daemonPriv, SIGNED_AGENT_UID], [secondKey, SIGNED_AGENT_UID + 1]] as const) {
            const event = blockedEvent(0, null);
            event.agent = { ...AGENT, id: auditTokenForRuid(uid) };
            const consumer = new AuditConsumer(new RecordingSink(), bridge, { pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(key)), now: () => NOW });
            await consumer.ingestCritical(signedEnvelope(event, key));
        }
        const entries = bridge.list();
        expect(entries).toHaveLength(2);
        expect(new Set(entries.map(e => e.blocked_egress_admission?.origin))).toEqual(new Set([
            `subject:${FORTRESS_ID}/uid-${SIGNED_AGENT_UID}`, `subject:${FORTRESS_ID}/uid-${SIGNED_AGENT_UID + 1}`,
        ]));
        expect(entries.every(e => e.blocked_egress?.attribution.state === "verified")).toBe(true);
        expect(new Set(entries.map(e => JSON.stringify(e.blocked_egress_admission?.identity))).size).toBe(2);
    });
});
});

const FLOW_NOW = Date.parse("2026-11-04T00:00:00Z");
const FLOW_UID = 501; // Ordinary fixture principal.
const FLOW_TOKEN = Buffer.from(new Uint32Array([0, FLOW_UID, FLOW_UID, FLOW_UID, FLOW_UID, 123, 1, 1]).buffer).toString("hex");
const flowKey = ed25519.utils.randomPrivateKey();
const flowPin = Buffer.from(ed25519.getPublicKey(flowKey)).toString("base64url");
const flowHash = (body: string) => createHash("sha256").update(body).digest("hex");
function liveEnvelope(seq: number, prior: string | null, ip = "192.0.2.1") {
  const timestamp = new Date(FLOW_NOW).toISOString();
  const body = canonicalize({ timestamp, layer: "l1", operation: "egress_blocked", identity_id: FLOW_TOKEN, result: "blocked",
    details: { agent_id: FLOW_TOKEN, dest_ip: ip, dest_port: 443, dest_protocol: "tcp", decision: "drop", seq, prior_sha256_hex: prior } });
  return { event: buildAuditEvent({ timestamp, fortress_id: "fixture", event_type: "egress_blocked",
    agent: { id: FLOW_TOKEN, template: "fixture" }, destination: { host: null, ip, port: 443, protocol: "tcp" }, details: { seq, prior_sha256_hex: prior } }),
    ack: async () => {}, producerDelivery: "live" as "live" | "durable_wal",
    producerSubjectBinding: { kind: "macos_audit_token" as const, fortressId: "fixture" },
    producer: { eventCanonicalJson: body, capturedAtUnixMs: FLOW_NOW, seq, keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      signatureB64url: Buffer.from(ed25519.sign(producerSigningBytes(body, FLOW_NOW, seq), flowKey)).toString("base64url") } };
}
async function countedConsumer(sink: AuditSink) {
  const path = "../../../src/castle-wall/runtime/macos-flow-coalescing.js";
  const module = await import(path).catch(() => null) as typeof import("../../../src/castle-wall/runtime/macos-flow-coalescing.js") | null;
  expect(module, "counted-flow helper is available").not.toBeNull();
  const coalescer = new module!.FlowCoalescer("fixture-instance", () => FLOW_NOW);
  const consumer = new AuditConsumer(sink, undefined, { pinnedProducerKeyB64url: flowPin, now: () => FLOW_NOW, chainContinuity: "producer_subset", liveFlowCoalescer: coalescer });
  return { consumer, coalescer };
}

it("coalescer key comes from the signed body", async () => {
  const sink = new RecordingSink(); const f = await countedConsumer(sink);
  const zero = liveEnvelope(0, null), one = liveEnvelope(1, flowHash(zero.producer.eventCanonicalJson));
  await f.consumer.ingestCritical(zero);
  one.event.agent = { id: "envelope-subject", template: "fixture" };
  one.event.destination = { ip: "198.51.100.2", port: 22, protocol: "udp", host: "envelope.example" };
  await f.consumer.ingestCritical(one);
  expect(f.consumer.getStats().coalescedCriticalEvents, "unsigned envelope metadata cannot change the admitted key").toBe(1);
  f.coalescer.closeWindows(); const summary = [...f.coalescer.reservations()][0]?.record;
  expect(summary).toMatchObject({ subject: "fixture/uid-501", destination: { ip: "192.0.2.1", port: 443, protocol: "tcp", host: null }, decision: "drop" });
});

it("unsupported signed operation and verdict pairs retain primary persistence", async () => {
  const sink = new RecordingSink(); const f = await countedConsumer(sink);
  let prior: string | null = null;
  for (const seq of [0, 1]) {
    const envelope = liveEnvelope(seq, prior);
    const body = JSON.parse(envelope.producer.eventCanonicalJson);
    body.details.decision = "allow";
    envelope.producer.eventCanonicalJson = canonicalize(body);
    envelope.producer.signatureB64url = Buffer.from(ed25519.sign(producerSigningBytes(envelope.producer.eventCanonicalJson, FLOW_NOW, seq), flowKey)).toString("base64url");
    prior = flowHash(envelope.producer.eventCanonicalJson);
    await f.consumer.ingestCritical(envelope);
  }
  expect(f.consumer.getStats()).toMatchObject({ acceptedCriticalEvents: 2, coalescedCriticalEvents: 0 });
  expect(f.coalescer.snapshot().keys).toBe(0);
});

const signedWindowCases = [
  ["active enforcement", "active"], ["persisted signature", "accepted"],
  ["persisted canonical bytes", "accepted"], ["required signature", "no-signature"],
  ["required subject binding", "no-binding"], ["required signed agent", "no-agent"],
  ["uid subject derivation", "bad-agent"], ["required signed identity", "no-identity"],
  ["pinned producer key", "wrong-key"], ["signed evidence fields", "substitution"],
  ["operation correspondence", "operation"], ["fresh signed evidence", "stale"],
  ["unsigned control events", "control"], ["accepted projection metadata", "accepted"],
  ["projection exception commit and ACK", "projection"], ["single read projection token", "token"],
  ["saturating destination conflicts", "conflict"], ["signed display and envelope reason", "display"],
  ["mint exception commit and ACK", "mint"], ["distinct enrolled subjects", "subjects"],
] as const;
for (const [label, scenario] of signedWindowCases) it(`established signed window preserves ${label}`, async () => {
  const module = await import("../../../src/castle-wall/runtime/macos-flow-coalescing.js").catch(() => null);
  expect(module).not.toBeNull();
  const results = [];
  const warnings = vi.spyOn(console, "warn").mockImplementation(() => {});
  try { for (const enabled of [false, true]) {
    const trace: unknown[][] = []; let invocation = 0;
    const counted = new Set<number>(); const errors: unknown[] = [];
    const sink: AuditSink = { append(...args) { trace.push(["append", invocation, JSON.stringify(args)]); }, async flush() { trace.push(["flush", invocation]); } };
    const coalescer = new module!.FlowCoalescer("signed-window", () => FLOW_NOW);
    const bridge = new UnifiedInboxBridge({
      auditLog: new AuditLog(new MemoryStorage(), new Uint8Array(32)), // AES-256 fixture key length.
      identityId: "fixture", fortressId: "fixture", now: () => new Date(FLOW_NOW),
    });
    const consumer = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: flowPin, now: () => FLOW_NOW,
      chainContinuity: "producer_subset", ...(enabled ? { liveFlowCoalescer: coalescer } : {}) });
    const head = liveEnvelope(0, null); await consumer.ingestCritical(head);
    expect(consumer.getWalChainState().lastAckedSeq, "the signed setup head is settled").toBe(0);
    if (enabled) expect(coalescer.snapshot().keys, "the verified live subject owns an open window").toBe(1);
    const needsProjection = ["projection", "conflict", "mint"].includes(scenario);
    const envelope: CriticalEventEnvelope = liveEnvelope(1, flowHash(head.producer.eventCanonicalJson), needsProjection ? "192.0.2.2" : "192.0.2.1");
    const body = JSON.parse(envelope.producer!.eventCanonicalJson);
    let signingKey = flowKey;
    switch (scenario) {
      case "no-agent": delete body.details.agent_id; break;
      case "bad-agent": body.details.agent_id = "non-token-subject"; break;
      case "no-identity": delete body.identity_id; envelope.producerSubjectBinding = { kind: "signed_identity_id" }; break;
      case "wrong-key": signingKey = ed25519.utils.randomPrivateKey(); break;
      case "operation": body.operation = "egress_allowed"; break;
      case "mint": delete body.timestamp; break;
    }
    envelope.producer!.eventCanonicalJson = canonicalize(body);
    if (scenario === "stale") envelope.producer!.capturedAtUnixMs = FLOW_NOW - 10 * 60_000; // Ten minutes is beyond the five-minute live freshness bound.
    envelope.producer!.signatureB64url = Buffer.from(ed25519.sign(producerSigningBytes(envelope.producer!.eventCanonicalJson, envelope.producer!.capturedAtUnixMs, envelope.producer!.seq), signingKey)).toString("base64url");
    if (scenario === "no-signature") envelope.producer = undefined;
    if (scenario === "no-binding") envelope.producerSubjectBinding = undefined;
    if (scenario === "substitution") envelope.event.agent = { id: "envelope-subject", template: "fixture" };
    if (scenario === "display") { envelope.event.destination = null; envelope.event.details.reason = "envelope reason"; }
    if (scenario === "control") { envelope.producer = undefined; envelope.event.event_type = "policy_loaded"; }
    if (scenario === "conflict") {
      envelope.event.destination = { ...envelope.event.destination!, host: "envelope.example" };
      (consumer as unknown as { stats: { blockedEgressDestinationConflicts: number } }).stats.blockedEgressDestinationConflicts = Number.MAX_SAFE_INTEGER - 1;
      warnings.mockImplementation(() => { throw new Error("fixture logging unavailable"); });
    }
    const projection = vi.spyOn(bridge, "ingestBlockedEgress");
    const reads: Array<ReturnType<typeof readConsumerMintedBlockedEgress>> = [];
    if (scenario === "projection") projection.mockImplementation(() => { throw new Error("fixture projection unavailable"); });
    if (scenario === "token") projection.mockImplementation((_input, token) => { reads.push(readConsumerMintedBlockedEgress(token), readConsumerMintedBlockedEgress(token)); return null; });
    const before = consumer.getStats(); trace.length = 0;
    const deliver = async (env: CriticalEventEnvelope, target = consumer) => {
      invocation++;
      try {
        await target.ingestCritical({ ...env, ack: async () => { trace.push(["ACK", invocation]); } }, { classify(kind) { if (kind === "coalesced") counted.add(invocation); } });
        trace.push(["fulfilled", invocation]);
      } catch (error) { errors.push(error); trace.push(["thrown", invocation, error instanceof Error ? [error.constructor.name, error.name, error.message] : String(error)]); }
    };
    await deliver(envelope);
    if (scenario === "subjects") {
      const secondKey = new Uint8Array(32).fill(7); // Deterministic Ed25519 fixture seed, separate from the first producer.
      const uid = FLOW_UID + 1; // A second enrolled principal owns its own key and window.
      const subjectToken = Buffer.from(new Uint32Array([0, uid, uid, uid, uid, 123, 1, 1]).buffer).toString("hex");
      const secondCoalescer = new module!.FlowCoalescer("second-signed-window", () => FLOW_NOW);
      const second = new AuditConsumer(sink, bridge, { pinnedProducerKeyB64url: Buffer.from(ed25519.getPublicKey(secondKey)).toString("base64url"), now: () => FLOW_NOW,
        ...(enabled ? { liveFlowCoalescer: secondCoalescer } : {}) });
      const signedSubject = (seq: number, prior: string | null) => {
        const env = liveEnvelope(seq, prior), body = JSON.parse(env.producer.eventCanonicalJson);
        body.details.agent_id = subjectToken; body.identity_id = subjectToken;
        env.event.agent = { id: subjectToken, template: "fixture" };
        env.producer.eventCanonicalJson = canonicalize(body);
        env.producer.signatureB64url = Buffer.from(ed25519.sign(producerSigningBytes(env.producer.eventCanonicalJson, FLOW_NOW, seq), secondKey)).toString("base64url");
        return env;
      };
      const secondHead = signedSubject(0, null), traceLength = trace.length;
      await second.ingestCritical(secondHead); trace.splice(traceLength);
      expect(second.getWalChainState().lastAckedSeq).toBe(0);
      if (enabled) expect(secondCoalescer.snapshot().keys).toBe(1);
      const next = signedSubject(1, flowHash(secondHead.producer.eventCanonicalJson));
      await deliver(next, second);
      expect(second.getStats()).toMatchObject({ acceptedCriticalEvents: enabled ? 1 : 2, coalescedCriticalEvents: enabled ? 1 : 0 });
      expect(second.getWalChainState().lastEventChainHash).toBe(flowHash(next.producer.eventCanonicalJson));
      expect(new Set(bridge.list().map(entry => entry.blocked_egress_admission?.origin))).toEqual(new Set([
        `subject:fixture/uid-${FLOW_UID}`, `subject:fixture/uid-${uid}`,
      ]));
    }
    if (scenario === "projection") await deliver(envelope);
    if (scenario === "conflict") {
      const next = liveEnvelope(2, flowHash(envelope.producer!.eventCanonicalJson), "192.0.2.3");
      next.event.destination = { ...next.event.destination!, host: "envelope.example" };
      await deliver(next);
      expect(consumer.getStats().blockedEgressDestinationConflicts, "each conflicting head commits with saturated accounting").toBe(Number.MAX_SAFE_INTEGER);
      expect(projection).not.toHaveBeenCalled();
    }
    if (scenario === "projection" || scenario === "mint") expect(consumer.getStats().blockedEgressProjectionFailures - before.blockedEgressProjectionFailures).toBe(1);
    if (scenario === "token") {
      expect(reads).toHaveLength(enabled ? 0 : 2);
      if (!enabled) { expect(reads[0]).toBeDefined(); expect(reads[1]).toBeUndefined(); }
    }
    const stats = consumer.getStats();
    const delta = Object.fromEntries(Object.entries(stats).map(([key, value]) => [key, value - before[key as keyof typeof before]]));
    if (enabled && ["active", "accepted", "substitution", "token", "display", "subjects"].includes(scenario)) expect(delta.coalescedCriticalEvents, "the signed same-key trigger is counted").toBe(1);
    const reasons: Record<string, string> = {
      "no-signature": "producer_signature_absent", "no-binding": "producer_signed_without_subject_binding",
      "no-agent": "producer_signed_body_missing_agent_id", "bad-agent": "producer_signed_body_agent_subject_unresolvable",
      "no-identity": "producer_signed_body_missing_identity_id", "wrong-key": "producer_signature_verification_failed",
      operation: "producer_signed_body_operation_event_type_mismatch", stale: "producer_signature_stale",
    };
    const records = trace.filter(call => call[0] === "append").map(call => JSON.parse(String(call[2])) as [string, string, string, Record<string, unknown>]);
    const operations = records.map(record => record[1]);
    const acks = trace.filter(call => call[0] === "ACK");
    const reason = reasons[scenario];
    if (reason) {
      expect(records.map(record => [record[1], record[3].reason])).toEqual([["producer_signature_rejected", reason]]);
      expect(errors).toHaveLength(1); expect(errors[0]).toMatchObject({ name: "AuditChainError", reason });
      expect(delta.producerSignatureRejections).toBe(1);
      expect(delta.producerSignatureAccepted).toBe(["no-binding", "no-agent", "bad-agent", "no-identity"].includes(scenario) ? 1 : 0);
      expect(delta.acceptedCriticalEvents! + delta.coalescedCriticalEvents!).toBe(0);
      expect(consumer.getWalChainState()).toEqual({ lastAckedSeq: 0, lastEventChainHash: flowHash(head.producer.eventCanonicalJson) });
      expect(acks).toHaveLength(1);
      expect(trace.findIndex(call => call[0] === "flush")).toBeLessThan(trace.findIndex(call => call[0] === "ACK"));
    } else {
      expect(errors).toEqual([]); expect(delta.producerSignatureRejections).toBe(0); expect(delta.rejectedEvents).toBe(0);
      expect(operations).not.toContain("wal_chain_verification_failed"); expect(acks.length).toBeGreaterThan(0);
      const primaries = records.filter(record => record[1] === "egress_blocked");
      if (["active", "accepted", "substitution", "token", "display"].includes(scenario)) {
        expect(primaries).toHaveLength(enabled ? 0 : 1);
        expect(delta.acceptedCriticalEvents! + delta.coalescedCriticalEvents!).toBe(1);
        expect(consumer.getWalChainState().lastEventChainHash).toBe(flowHash(envelope.producer!.eventCanonicalJson));
        if (!enabled) {
          expect(primaries[0]![3]).toMatchObject({ cw_producer_signed_canonical: envelope.producer!.eventCanonicalJson, cw_producer_sig: envelope.producer!.signatureB64url });
          expect(trace.findIndex(call => call[0] === "flush")).toBeLessThan(trace.findIndex(call => call[0] === "ACK"));
        }
      }
      if (scenario === "control") {
        expect(operations).toEqual(["policy_loaded"]);
        expect(records[0]![3].cw_evidence_basis).toBe("channel_authenticated_unsigned");
        expect(delta.acceptedCriticalEvents).toBe(1); expect(delta.coalescedCriticalEvents).toBe(0);
        expect(consumer.getWalChainState()).toEqual({ lastAckedSeq: 1, lastEventChainHash: flowHash(canonicalize(envelope.event)) });
        expect(acks).toHaveLength(1);
        expect(trace.findIndex(call => call[0] === "flush")).toBeLessThan(trace.findIndex(call => call[0] === "ACK"));
      }
      if (scenario === "subjects") {
        expect(delta.acceptedCriticalEvents! + delta.coalescedCriticalEvents!).toBe(1);
        expect(consumer.getWalChainState().lastEventChainHash).toBe(flowHash(envelope.producer!.eventCanonicalJson));
      }
      if (scenario === "projection" || scenario === "mint") {
        expect(delta.acceptedCriticalEvents).toBe(1); expect(delta.coalescedCriticalEvents).toBe(0);
        expect(consumer.getWalChainState().lastEventChainHash).toBe(flowHash(envelope.producer!.eventCanonicalJson));
        expect(primaries).toHaveLength(1); expect(acks).toHaveLength(scenario === "projection" ? 2 : 1);
        expect(projection).toHaveBeenCalledTimes(scenario === "projection" ? 1 : 0);
        if (scenario === "projection") { expect(delta.duplicatesDropped).toBe(1); expect(operations).toContain("critical_event_duplicate_dropped"); }
      }
      if (scenario === "conflict") {
        expect(primaries).toHaveLength(2); expect(acks).toHaveLength(primaries.length);
        expect(delta.blockedEgressProjectionFailures).toBe(0);
      }
    }
    results.push({ trace, counted, delta, state: consumer.getWalChainState() });
    projection.mockRestore(); warnings.mockImplementation(() => {});
  } } finally { warnings.mockRestore(); }
  const [control, counted] = results;
  expect(counted!.trace, "ordered signed trigger evidence preserves only the coalesced write omission").toEqual(control!.trace.filter(call => !(counted!.counted.has(call[1] as number) && (call[0] === "append" || call[0] === "flush"))));
  const counters = (result: typeof control) => {
    const { acceptedCriticalEvents, coalescedCriticalEvents, ...other } = result!.delta;
    return { ...other, admissions: acceptedCriticalEvents! + coalescedCriticalEvents! };
  };
  expect(counters(counted)).toEqual(counters(control)); expect(counted!.state).toEqual(control!.state);
});
