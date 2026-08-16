/**
 * #1096 rebuild: shared chain basis + one-time LOCAL anchor migration.
 *
 * Three suites:
 *
 *  1. BASIS VECTORS — for each producer writer (Rust WAL via the real drain
 *     envelope builder, macOS flow-decision shape), the consumer's chain head
 *     after event 1 must equal the producer's `prior_sha256_hex` for event 2:
 *     `sha256(utf8(eventCanonicalJson))`, never a hash of the locally
 *     reconstructed CastleWallAuditEvent (which no producer hashes — the
 *     #1096 root cause).
 *
 *     The Rust side is covered by the captured cross-language fixture in
 *     `producer-sig-cross-lang.test.ts`; the macOS Swift flow-decision path is
 *     covered below by `swift-flow-decision-vector.json`, which is regenerated
 *     and checked on the Swift side by `SwiftFlowDecisionFixtureTests`.
 *
 *  2. CONTINUITY MODES — the Linux drain consumes the daemon's COMPLETE WAL
 *     chain, so a prior-hash mismatch is a hard fork (stop, loud, no
 *     self-heal). The macOS flow consumer receives only a SUBSET of the
 *     extension's shared chain (availability reports interleave in the same
 *     seq/prior space on their own delivery path), so continuity there is
 *     verified signature + strict seq monotonicity, with the un-assertable
 *     prior recorded honestly as `cw_chain_prior_unconsumed`.
 *
 *  3. ANCHOR RESTORE + MIGRATION — at startup the consumer re-anchors from
 *     its OWN last persisted signed canonical body (zero incoming-event
 *     trust), migrating old-basis history exactly once via the STORED
 *     `cw_chain_basis` fact, and latching a loud stuck state when local
 *     recomputation is impossible (unsigned last entry / integrity findings).
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, it, expect, beforeEach } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import {
  AuditConsumer,
  AuditChainError,
  buildChainAnchorSourceFromAuditLog,
  type AuditSink,
  type ChainAnchorSource,
  type CriticalEventEnvelope,
} from "../../../src/castle-wall/runtime/audit-consumer.js";
import { buildCriticalEnvelopeFromDrainEvent } from "../../../src/castle-wall/runtime/linux-audit-drain.js";
import {
  producerSigningBytes,
  verifyProducerSignature,
} from "../../../src/castle-wall/runtime/producer-signature.js";
import { buildAuditEvent } from "../../../src/castle-wall/audit/builder.js";
import type { CastleWallAuditEvent } from "../../../src/castle-wall/audit/events.js";
import type { AuditDrainEvent } from "../../../src/castle-wall/ipc/messages.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY,
  CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL,
  CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
  CASTLE_WALL_CHAIN_PRIOR_UNCONSUMED_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../../src/castle-wall/constants.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import type { AuditChainVerdict } from "../../../src/operational/audit-log.js";

/** Sink that records entries AND the flush count each append happened after. */
class RecordingSink implements AuditSink {
  entries: Array<{
    operation: string;
    identityId: string;
    details?: Record<string, unknown>;
    result: "success" | "failure";
    flushesBeforeAppend: number;
  }> = [];
  flushes = 0;
  append(
    _layer: "l1",
    operation: string,
    identityId: string,
    details?: Record<string, unknown>,
    result: "success" | "failure" = "success",
  ): void {
    this.entries.push({
      operation,
      identityId,
      details,
      result,
      flushesBeforeAppend: this.flushes,
    });
  }
  async flush(): Promise<void> {
    this.flushes += 1;
  }
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sha256Hex(utf8: string): string {
  return createHash("sha256").update(utf8, "utf8").digest("hex");
}

const daemonPriv = ed25519.utils.randomPrivateKey();
const daemonPubB64 = toBase64url(ed25519.getPublicKey(daemonPriv));

const NOW = 1_750_000_000_000;
const SIGNED_TS = NOW - 1000;
const FORTRESS_ID = "f";

interface SwiftFlowDecisionVector {
  pubkey_b64url: string;
  canonical: string;
  canonical_sha256_hex: string;
  captured_at_unix_ms: number;
  seq: number;
  prior_sha256_hex: string | null;
  key_id: string;
  sig_b64url: string;
  flow: {
    fortress_id: string;
    event_type: "egress_blocked" | "egress_allowed";
    agent_id: string;
    agent_template: string;
    dest_host: string | null;
    dest_ip: string;
    dest_port: number;
    dest_protocol: "tcp" | "udp";
    decision: "drop" | "allow";
    matched_rule_id: string | null;
    recorded_at: string;
  };
}

function loadSwiftFlowDecisionVector(): SwiftFlowDecisionVector {
  const here = dirname(fileURLToPath(import.meta.url));
  const fixturePath = join(
    here,
    "..",
    "fixtures",
    "swift-flow-decision-vector.json",
  );
  return JSON.parse(readFileSync(fixturePath, "utf8")) as SwiftFlowDecisionVector;
}

/** Valid macOS audit_token_t hex for a non-root uid (mirrors producer-auth tests). */
function auditTokenForRuid(uid: number): string {
  const vals = [0xffffffff, uid, uid, uid, uid, 0x269, 0x186ae, 0x566];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}
const AGENT_ID = auditTokenForRuid(503);

/** Rust daemon WAL body (AuditEntry canonical shape from policy.rs). */
function rustWalBody(input: {
  seq: number;
  prior: string | null;
  timestamp: string;
}): string {
  return canonicalize({
    timestamp: input.timestamp,
    layer: "l1",
    operation: "egress_blocked",
    identity_id: "agent-a",
    result: "blocked",
    details: {
      agent_id: "agent-a",
      dest_host: "api.example.test",
      dest_ip: "203.0.113.10",
      dest_port: 443,
      dest_protocol: "tcp",
      seq: input.seq,
      prior_sha256_hex: input.prior,
    },
  });
}

function signBody(canonical: string, seq: number, ts = SIGNED_TS): string {
  return toBase64url(
    ed25519.sign(producerSigningBytes(canonical, ts, seq), daemonPriv),
  );
}

/** Envelope exactly as the Linux drain builds it from a daemon WAL entry. */
function rustDrainEnvelope(input: {
  canonical: string;
  seq: number;
  prior: string | null;
  ack?: () => Promise<void>;
}): CriticalEventEnvelope {
  const drained: AuditDrainEvent = {
    seq: input.seq,
    captured_at_unix_ms: SIGNED_TS,
    prior_sha256_hex: input.prior,
    event_canonical_json: input.canonical,
    critical: true,
    producer_signature_b64url: signBody(input.canonical, input.seq),
    producer_key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  };
  const built = buildCriticalEnvelopeFromDrainEvent(
    drained,
    input.ack ?? (async () => {}),
  );
  if (built.kind === "error") throw new Error(built.reason);
  return built.envelope;
}

/**
 * macOS flow-decision signed body, mirroring `signedDetailsFor` +
 * `buildPendingDecisionLocked` in AuditProducerSigning.swift (field set and
 * operation names must track that file).
 */
function macFlowBody(input: {
  seq: number;
  prior: string | null;
  timestamp: string;
  decision?: "drop" | "allow";
}): string {
  const decision = input.decision ?? "drop";
  return canonicalize({
    timestamp: input.timestamp,
    layer: "l1",
    operation: decision === "drop" ? "egress_blocked" : "egress_approved",
    identity_id: AGENT_ID,
    result: decision === "drop" ? "blocked" : "success",
    details: {
      agent_id: AGENT_ID,
      agent_template: "tpl",
      dest_ip: "203.0.113.9",
      dest_port: 443,
      dest_protocol: "tcp",
      decision,
      prior_sha256_hex: input.prior,
      rule_id: null,
      seq: input.seq,
      source: "macos_extension",
    },
  });
}

/**
 * macOS availability-report signed body — advances the extension's SHARED
 * chain but is NEVER delivered to the flow chain consumer (it goes to the
 * enforcement-availability store). Used to model the interleave gap.
 */
function macAvailabilityBody(input: {
  seq: number;
  prior: string | null;
  timestamp: string;
}): string {
  return canonicalize({
    timestamp: input.timestamp,
    layer: "l1",
    operation: "enforcement_availability_report",
    identity_id: FORTRESS_ID,
    result: "success",
    details: { seq: input.seq, prior_sha256_hex: input.prior },
  });
}

/** Envelope exactly as macos-flow-events builds it for a flow decision. */
function macFlowEnvelope(input: {
  canonical: string;
  seq: number;
  prior: string | null;
  eventType?: "egress_blocked" | "egress_allowed";
}): CriticalEventEnvelope {
  const event: CastleWallAuditEvent = buildAuditEvent({
    timestamp: new Date(SIGNED_TS).toISOString(),
    fortress_id: FORTRESS_ID,
    event_type: input.eventType ?? "egress_blocked",
    agent: { id: AGENT_ID, template: "tpl" },
    destination: { host: null, ip: "203.0.113.9", port: 443, protocol: "tcp" },
    decision: null,
    rule_id: null,
    details: { seq: input.seq, prior_sha256_hex: input.prior },
  });
  return {
    event,
    ack: async () => {},
    producer: {
      eventCanonicalJson: input.canonical,
      capturedAtUnixMs: SIGNED_TS,
      seq: input.seq,
      signatureB64url: signBody(input.canonical, input.seq),
      keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
    },
    producerSubjectBinding: { kind: "macos_audit_token", fortressId: FORTRESS_ID },
  };
}

function swiftFixtureFlowEnvelope(v: SwiftFlowDecisionVector): CriticalEventEnvelope {
  const event: CastleWallAuditEvent = buildAuditEvent({
    timestamp: v.flow.recorded_at,
    fortress_id: v.flow.fortress_id,
    event_type: v.flow.event_type,
    agent: { id: v.flow.agent_id, template: v.flow.agent_template },
    destination: {
      host: v.flow.dest_host,
      ip: v.flow.dest_ip,
      port: v.flow.dest_port,
      protocol: v.flow.dest_protocol,
    },
    decision: null,
    rule_id: v.flow.matched_rule_id,
    details: { seq: v.seq, prior_sha256_hex: v.prior_sha256_hex },
  });
  return {
    event,
    ack: async () => {},
    producer: {
      eventCanonicalJson: v.canonical,
      capturedAtUnixMs: v.captured_at_unix_ms,
      seq: v.seq,
      signatureB64url: v.sig_b64url,
      keyId: v.key_id,
    },
    producerSubjectBinding: {
      kind: "macos_audit_token",
      fortressId: v.flow.fortress_id,
    },
  };
}

function completeConsumer(
  sink: AuditSink,
  extra?: ConstructorParameters<typeof AuditConsumer>[2],
): AuditConsumer {
  return new AuditConsumer(sink, undefined, {
    pinnedProducerKeyB64url: daemonPubB64,
    now: () => NOW,
    ...extra,
  });
}

function subsetConsumer(
  sink: AuditSink,
  extra?: ConstructorParameters<typeof AuditConsumer>[2],
): AuditConsumer {
  return completeConsumer(sink, {
    chainContinuity: "producer_subset",
    ...extra,
  });
}

describe("chain basis vectors: consumer head == producer next-prior", () => {
  it("Rust WAL writer (real drain envelope): head after event 1 is sha256(signed body 1)", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink);
    const body1 = rustWalBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    const nextPrior = sha256Hex(body1);
    await consumer.ingestCritical(
      rustDrainEnvelope({ canonical: body1, seq: 0, prior: null }),
    );
    expect(consumer.getWalChainState().lastEventChainHash).toBe(nextPrior);
    // Event 2 chained by the producer over the SIGNED body of event 1 is
    // accepted with strict (complete-chain) contiguity.
    const body2 = rustWalBody({ seq: 1, prior: nextPrior, timestamp: "2026-08-05T00:00:01Z" });
    await expect(
      consumer.ingestCritical(
        rustDrainEnvelope({ canonical: body2, seq: 1, prior: nextPrior }),
      ),
    ).resolves.toBeUndefined();
    expect(consumer.getStats().acceptedCriticalEvents).toBe(2);
  });

  it("Rust WAL writer: a prior computed over the RECONSTRUCTED event (old basis) forks", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink);
    const body1 = rustWalBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    const env1 = rustDrainEnvelope({ canonical: body1, seq: 0, prior: null });
    await consumer.ingestCritical(env1);
    // The old consumer basis: hash of the locally reconstructed event shape.
    const oldBasisPrior = sha256Hex(canonicalize(env1.event));
    expect(oldBasisPrior).not.toBe(sha256Hex(body1));
    const body2 = rustWalBody({ seq: 1, prior: oldBasisPrior, timestamp: "2026-08-05T00:00:01Z" });
    await expect(
      consumer.ingestCritical(
        rustDrainEnvelope({ canonical: body2, seq: 1, prior: oldBasisPrior }),
      ),
    ).rejects.toThrow("wal_chain_verification_failed");
  });

  it("macOS Swift fixture: TS verifies and chains over the exact Swift-emitted body", async () => {
    const fixture = loadSwiftFlowDecisionVector();
    expect(fixture.key_id).toBe(CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1);
    expect(sha256Hex(fixture.canonical)).toBe(fixture.canonical_sha256_hex);
    expect(
      verifyProducerSignature(
        {
          eventCanonicalJson: fixture.canonical,
          capturedAtUnixMs: fixture.captured_at_unix_ms,
          seq: fixture.seq,
          signatureB64url: fixture.sig_b64url,
          keyId: fixture.key_id,
        },
        fixture.pubkey_b64url,
      ),
    ).toEqual({ ok: true });

    const sink = new RecordingSink();
    const consumer = subsetConsumer(sink, {
      pinnedProducerKeyB64url: fixture.pubkey_b64url,
    });
    await consumer.ingestCritical(swiftFixtureFlowEnvelope(fixture));

    expect(consumer.getWalChainState().lastEventChainHash).toBe(
      fixture.canonical_sha256_hex,
    );
    const accepted = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(accepted?.details?.[CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
    );
    expect(
      accepted?.details?.[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY],
    ).toBe(fixture.canonical);
  });

  it("macOS flow writer: head after decision 1 is sha256(signed body 1); adjacent decision 2 chains", async () => {
    const sink = new RecordingSink();
    const consumer = subsetConsumer(sink);
    const body1 = macFlowBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    const nextPrior = sha256Hex(body1);
    await consumer.ingestCritical(
      macFlowEnvelope({ canonical: body1, seq: 0, prior: null }),
    );
    expect(consumer.getWalChainState().lastEventChainHash).toBe(nextPrior);
    const body2 = macFlowBody({ seq: 1, prior: nextPrior, timestamp: "2026-08-05T00:00:01Z" });
    await consumer.ingestCritical(
      macFlowEnvelope({ canonical: body2, seq: 1, prior: nextPrior }),
    );
    expect(consumer.getStats().acceptedCriticalEvents).toBe(2);
    // Adjacent accept must NOT carry the unconsumed-prior marker.
    const accepted = sink.entries.filter((e) => e.operation === "egress_blocked");
    expect(accepted).toHaveLength(2);
    expect(
      accepted[1]!.details?.[CASTLE_WALL_CHAIN_PRIOR_UNCONSUMED_DETAIL_KEY],
    ).toBeUndefined();
  });
});

describe("continuity modes: complete vs producer_subset", () => {
  it("subset mode: a flow decision after an interleaved availability event is accepted with the honesty marker", async () => {
    const sink = new RecordingSink();
    const consumer = subsetConsumer(sink);
    const flow1 = macFlowBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      macFlowEnvelope({ canonical: flow1, seq: 0, prior: null }),
    );
    // The extension signs an availability report into the SHARED chain at seq
    // 1; the flow consumer never receives it.
    const avail = macAvailabilityBody({
      seq: 1,
      prior: sha256Hex(flow1),
      timestamp: "2026-08-05T00:00:01Z",
    });
    const flow2 = macFlowBody({
      seq: 2,
      prior: sha256Hex(avail),
      timestamp: "2026-08-05T00:00:02Z",
    });
    await expect(
      consumer.ingestCritical(
        macFlowEnvelope({ canonical: flow2, seq: 2, prior: sha256Hex(avail) }),
      ),
    ).resolves.toBeUndefined();
    expect(consumer.getStats().acceptedCriticalEvents).toBe(2);
    const accepted = sink.entries.filter((e) => e.operation === "egress_blocked");
    expect(
      accepted[1]!.details?.[CASTLE_WALL_CHAIN_PRIOR_UNCONSUMED_DETAIL_KEY],
    ).toBe(true);
    // The head advanced to the accepted event's own signed-body hash.
    expect(consumer.getWalChainState().lastEventChainHash).toBe(sha256Hex(flow2));
  });

  it("complete mode: the same gap is a hard fork (no self-heal)", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink);
    const body1 = rustWalBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      rustDrainEnvelope({ canonical: body1, seq: 0, prior: null }),
    );
    const foreignPrior = sha256Hex("some body the consumer never saw");
    const body2 = rustWalBody({ seq: 2, prior: foreignPrior, timestamp: "2026-08-05T00:00:02Z" });
    await expect(
      consumer.ingestCritical(
        rustDrainEnvelope({ canonical: body2, seq: 2, prior: foreignPrior }),
      ),
    ).rejects.toThrow("wal_chain_verification_failed");
    // And it STAYS stuck: the same delivery keeps failing — no counter, no
    // threshold, no re-anchor.
    await expect(
      consumer.ingestCritical(
        rustDrainEnvelope({ canonical: body2, seq: 2, prior: foreignPrior }),
      ),
    ).rejects.toThrow("wal_chain_verification_failed");
    expect(
      sink.entries.filter((e) => e.operation === "wal_chain_verification_failed"),
    ).toHaveLength(2);
    expect(sink.entries.some((e) => e.operation === "chain_reanchored")).toBe(false);
  });

  it("subset mode: seq regression is still rejected (replay floor holds)", async () => {
    const sink = new RecordingSink();
    const consumer = subsetConsumer(sink);
    const flow1 = macFlowBody({ seq: 5, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      macFlowEnvelope({ canonical: flow1, seq: 5, prior: null }),
    );
    // A captured earlier frame replayed after acceptance: seq 3 <= floor 5.
    const old = macFlowBody({ seq: 3, prior: sha256Hex("x"), timestamp: "2026-08-05T00:00:01Z" });
    await expect(
      consumer.ingestCritical(
        macFlowEnvelope({ canonical: old, seq: 3, prior: sha256Hex("x") }),
      ),
    ).rejects.toThrow("seq_regression");
  });

  it("subset mode: an UNSIGNED gap claim is refused (gap acceptance is signature-gated)", async () => {
    const sink = new RecordingSink();
    const consumer = subsetConsumer(sink);
    const flow1 = macFlowBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      macFlowEnvelope({ canonical: flow1, seq: 0, prior: null }),
    );
    // Enforcement evidence without a producer block: rejected before the
    // chain decision (fail closed), so the gap path is unreachable unsigned.
    const bare: CriticalEventEnvelope = {
      event: buildAuditEvent({
        timestamp: new Date(SIGNED_TS).toISOString(),
        fortress_id: FORTRESS_ID,
        event_type: "egress_blocked",
        agent: { id: AGENT_ID, template: "tpl" },
        destination: { host: null, ip: "203.0.113.9", port: 443, protocol: "tcp" },
        decision: null,
        rule_id: null,
        details: { seq: 2, prior_sha256_hex: sha256Hex("unseen") },
      }),
      ack: async () => {},
    };
    await expect(consumer.ingestCritical(bare)).rejects.toThrow(
      "producer_signature_absent",
    );
  });
});

describe("strict signed-operation binding", () => {
  it("a signed body with an unmapped operation is rejected for a non-enforcement event type", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink);
    // Availability-report bodies are signed by the producer but NEVER accepted
    // through ingestCritical: stapling one onto a non-enforcement event type
    // must be refused, not accepted-as-unsigned (the #1096-branch regression).
    const avail = macAvailabilityBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    const event: CastleWallAuditEvent = buildAuditEvent({
      timestamp: new Date(SIGNED_TS).toISOString(),
      fortress_id: FORTRESS_ID,
      event_type: "filter_started",
      details: { seq: 0, prior_sha256_hex: null },
    });
    const envelope: CriticalEventEnvelope = {
      event,
      ack: async () => {},
      producer: {
        eventCanonicalJson: avail,
        capturedAtUnixMs: SIGNED_TS,
        seq: 0,
        signatureB64url: signBody(avail, 0),
        keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      },
      producerSubjectBinding: { kind: "signed_identity_id" },
    };
    await expect(consumer.ingestCritical(envelope)).rejects.toThrow(
      "producer_signed_body_operation_event_type_mismatch",
    );
    expect(
      sink.entries.some((e) => e.operation === "producer_signature_rejected"),
    ).toBe(true);
  });

  it("accepted verified entries record the chain basis as a stored fact", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink);
    const body1 = rustWalBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      rustDrainEnvelope({ canonical: body1, seq: 0, prior: null }),
    );
    const accepted = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(accepted?.details?.[CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
    );
  });

  it("unsigned accepted entries record the legacy event_canonical basis", async () => {
    const sink = new RecordingSink();
    // No pinned key: channel basis.
    const consumer = new AuditConsumer(sink, undefined, { now: () => NOW });
    const event = buildAuditEvent({
      timestamp: new Date(SIGNED_TS).toISOString(),
      fortress_id: FORTRESS_ID,
      event_type: "filter_started",
      details: { seq: 0, prior_sha256_hex: null },
    });
    await consumer.ingestCritical({ event, ack: async () => {} });
    const accepted = sink.entries.find((e) => e.operation === "filter_started");
    expect(accepted?.details?.[CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL,
    );
  });
});

describe("anchor restore + one-time basis migration", () => {
  const anchorBody = rustWalBody({
    seq: 41,
    prior: sha256Hex("older"),
    timestamp: "2026-08-04T00:00:00Z",
  });
  const anchorHash = sha256Hex(anchorBody);

  /** A persisted anchor carrying VALID producer signature material. */
  function signedAnchor(over: Partial<{
    seq: number;
    signedCanonicalJson: string | null;
    signatureB64url: string | null;
    keyId: string | null;
    capturedAtUnixMs: number | null;
    chainBasis: string | null;
    identityId: string;
  }> = {}) {
    const seq = over.seq ?? 41;
    const body =
      over.signedCanonicalJson !== undefined
        ? over.signedCanonicalJson
        : anchorBody;
    return {
      kind: "persisted" as const,
      seq,
      signedCanonicalJson: body,
      signatureB64url:
        over.signatureB64url !== undefined
          ? over.signatureB64url
          : body === null
            ? null
            : signBody(body, seq),
      keyId: over.keyId !== undefined ? over.keyId : CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      capturedAtUnixMs:
        over.capturedAtUnixMs !== undefined ? over.capturedAtUnixMs : SIGNED_TS,
      chainBasis: over.chainBasis !== undefined ? over.chainBasis : null,
      identityId: over.identityId ?? "agent-a",
    };
  }

  function sourceReturning(
    value: Awaited<ReturnType<ChainAnchorSource>>,
  ): ChainAnchorSource {
    return async () => value;
  }

  it("old-basis history (no stored basis) migrates exactly once, record flushed BEFORE use", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      chainAnchorSource: sourceReturning(signedAnchor()),
    });
    const body42 = rustWalBody({ seq: 42, prior: anchorHash, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      rustDrainEnvelope({ canonical: body42, seq: 42, prior: anchorHash }),
    );
    const migrations = sink.entries.filter(
      (e) => e.operation === "chain_basis_migrated",
    );
    expect(migrations).toHaveLength(1);
    expect(migrations[0]!.details).toMatchObject({
      previous_basis: CASTLE_WALL_CHAIN_BASIS_EVENT_CANONICAL,
      new_basis: CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
      anchor_seq: 41,
      anchor_sha256_hex: anchorHash,
    });
    // Flushed BEFORE the anchor is used: the acceptance append must observe at
    // least one more completed flush than the migration record did.
    const acceptedEntry = sink.entries.find((e) => e.operation === "egress_blocked");
    expect(acceptedEntry).toBeDefined();
    expect(migrations[0]!.flushesBeforeAppend).toBeLessThan(
      acceptedEntry!.flushesBeforeAppend,
    );
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
  });

  it("new-basis history restores silently (no second migration) and closes the restart replay hole", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      chainAnchorSource: sourceReturning(
        signedAnchor({ chainBasis: CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY }),
      ),
    });
    // A captured OLD signed frame replayed into the "fresh" consumer: without
    // the restore this would bootstrap-accept; with it, the restored seq floor
    // rejects it as a regression.
    const oldBody = rustWalBody({ seq: 7, prior: sha256Hex("ancient"), timestamp: "2026-08-01T00:00:00Z" });
    await expect(
      consumer.ingestCritical(
        rustDrainEnvelope({ canonical: oldBody, seq: 7, prior: sha256Hex("ancient") }),
      ),
    ).rejects.toThrow("seq_regression");
    expect(
      sink.entries.filter((e) => e.operation === "chain_basis_migrated"),
    ).toHaveLength(0);
    // The genuine next event chains off the restored anchor.
    const body42 = rustWalBody({ seq: 42, prior: anchorHash, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      rustDrainEnvelope({ canonical: body42, seq: 42, prior: anchorHash }),
    );
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
  });

  it("an unsigned last entry latches chain_migration_unavailable: loud once, stuck, never ACKed", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      chainAnchorSource: sourceReturning(
        signedAnchor({ signedCanonicalJson: null }),
      ),
    });
    let acked = 0;
    const body = rustWalBody({ seq: 42, prior: sha256Hex("whatever"), timestamp: "2026-08-05T00:00:00Z" });
    const envelope = rustDrainEnvelope({
      canonical: body,
      seq: 42,
      prior: sha256Hex("whatever"),
      ack: async () => {
        acked += 1;
      },
    });
    await expect(consumer.ingestCritical(envelope)).rejects.toThrow(
      "chain_migration_unavailable",
    );
    await expect(consumer.ingestCritical(envelope)).rejects.toThrow(
      "chain_migration_unavailable",
    );
    // One durable latch record, not one per refused event; the refusals are
    // UNSETTLED (no ACK — an ACK would truncate the daemon WAL through
    // evidence we never accepted).
    expect(
      sink.entries.filter((e) => e.operation === "chain_migration_unavailable"),
    ).toHaveLength(1);
    expect(acked).toBe(0);
    expect(consumer.getStats().acceptedCriticalEvents).toBe(0);
  });


  it("REGRESSION (gate #1103 R1): a persisted anchor with an INVALID signature is refused, not adopted", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      // A row planted by some other writer: plausible shape, bogus signature.
      chainAnchorSource: sourceReturning(
        signedAnchor({
          seq: 9_000,
          signatureB64url: signBody(rustWalBody({
            seq: 9_000,
            prior: null,
            timestamp: "2026-08-04T00:00:00Z",
          }), 9_000),
        }),
      ),
    });
    const body = rustWalBody({ seq: 42, prior: anchorHash, timestamp: "2026-08-05T00:00:00Z" });
    await expect(
      consumer.ingestCritical(rustDrainEnvelope({ canonical: body, seq: 42, prior: anchorHash })),
    ).rejects.toThrow("chain_migration_unavailable");
    const latch = sink.entries.find((e) => e.operation === "chain_migration_unavailable");
    expect(String(latch?.details?.reason)).toContain("persisted_anchor_signature_invalid");
  });

  it("REGRESSION: a genuine signed body re-filed under a CHOSEN seq is refused (seq must be signature-bound)", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      // anchorBody's signed details say seq 41; the row claims seq 9000, and
      // the signature is recomputed over the chosen seq so it verifies.
      chainAnchorSource: sourceReturning(signedAnchor({ seq: 9_000 })),
    });
    const body = rustWalBody({ seq: 9_001, prior: anchorHash, timestamp: "2026-08-05T00:00:00Z" });
    await expect(
      consumer.ingestCritical(rustDrainEnvelope({ canonical: body, seq: 9_001, prior: anchorHash })),
    ).rejects.toThrow("chain_migration_unavailable");
    expect(
      sink.entries.find((e) => e.operation === "chain_migration_unavailable")?.details?.reason,
    ).toBe("persisted_anchor_seq_not_signature_bound");
  });

  it("REGRESSION: signature material stripped from the row is refused, never adopted unverified", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      chainAnchorSource: sourceReturning(signedAnchor({ signatureB64url: null })),
    });
    const body = rustWalBody({ seq: 42, prior: anchorHash, timestamp: "2026-08-05T00:00:00Z" });
    await expect(
      consumer.ingestCritical(rustDrainEnvelope({ canonical: body, seq: 42, prior: anchorHash })),
    ).rejects.toThrow("chain_migration_unavailable");
    expect(
      sink.entries.find((e) => e.operation === "chain_migration_unavailable")?.details?.reason,
    ).toBe("persisted_anchor_signature_material_missing");
  });

  it("audit-log integrity findings latch the unavailable state", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      chainAnchorSource: sourceReturning({
        kind: "unavailable",
        reason: "audit_log_integrity_findings",
      }),
    });
    const body = rustWalBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await expect(
      consumer.ingestCritical(rustDrainEnvelope({ canonical: body, seq: 0, prior: null })),
    ).rejects.toThrow("chain_migration_unavailable");
    expect(
      sink.entries.find((e) => e.operation === "chain_migration_unavailable")
        ?.details?.reason,
    ).toBe("audit_log_integrity_findings");
  });

  it("no history at all is a genuine genesis bootstrap", async () => {
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink, {
      chainAnchorSource: sourceReturning(null),
    });
    const body = rustWalBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      rustDrainEnvelope({ canonical: body, seq: 0, prior: null }),
    );
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
    expect(
      sink.entries.some(
        (e) =>
          e.operation === "chain_basis_migrated" ||
          e.operation === "chain_migration_unavailable",
      ),
    ).toBe(false);
  });

  it("a transient reader fault fails closed and is RETRIED, not latched", async () => {
    const sink = new RecordingSink();
    let calls = 0;
    const consumer = completeConsumer(sink, {
      chainAnchorSource: async () => {
        calls += 1;
        if (calls === 1) throw new Error("storage momentarily unreadable");
        return null;
      },
    });
    const body = rustWalBody({ seq: 0, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    const envelope = rustDrainEnvelope({ canonical: body, seq: 0, prior: null });
    await expect(consumer.ingestCritical(envelope)).rejects.toThrow(
      "storage momentarily unreadable",
    );
    // Second ingest retries the source and proceeds normally.
    await consumer.ingestCritical(envelope);
    expect(calls).toBe(2);
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
  });

  it("no pinned key: the restore is disabled and the source is never consulted", async () => {
    const sink = new RecordingSink();
    let calls = 0;
    const consumer = new AuditConsumer(sink, undefined, {
      now: () => NOW,
      chainAnchorSource: async () => {
        calls += 1;
        return null;
      },
    });
    const event = buildAuditEvent({
      timestamp: new Date(SIGNED_TS).toISOString(),
      fortress_id: FORTRESS_ID,
      event_type: "filter_started",
      details: { seq: 0, prior_sha256_hex: null },
    });
    await consumer.ingestCritical({ event, ack: async () => {} });
    expect(calls).toBe(0);
    expect(consumer.getStats().acceptedCriticalEvents).toBe(1);
  });
});

describe("buildChainAnchorSourceFromAuditLog", () => {
  function fakeLog(
    entries: Array<{
      operation: string;
      identity_id: string;
      details?: Record<string, unknown>;
    }>,
    verdictStatus: "verified" | "verified_suffix_only" | "findings" = "verified",
  ) {
    return {
      async query() {
        return { entries, total: entries.length };
      },
      async getAuditChainVerdict() {
        return { status: verdictStatus } as AuditChainVerdict;
      },
    };
  }

  it("round-trips a REAL consumer-persisted entry (not a hand-built fixture)", async () => {
    // Drive the real consumer to persist an accepted signed entry, then feed
    // the captured entries back through the source: what the producer of the
    // persisted shape actually emits is what the restore consumes.
    const sink = new RecordingSink();
    const consumer = completeConsumer(sink);
    const body = rustWalBody({ seq: 9, prior: null, timestamp: "2026-08-05T00:00:00Z" });
    await consumer.ingestCritical(
      rustDrainEnvelope({ canonical: body, seq: 9, prior: null }),
    );
    const source = buildChainAnchorSourceFromAuditLog(
      fakeLog(
        sink.entries.map((e) => ({
          operation: e.operation,
          identity_id: e.identityId,
          details: e.details,
        })),
      ),
    );
    const anchor = await source();
    expect(anchor).toMatchObject({
      kind: "persisted",
      seq: 9,
      signedCanonicalJson: body,
      chainBasis: CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
    });
  });

  it("skips trailing non-chain entries (rejections, metric batches) to find the anchor", async () => {
    const chainEntry = {
      operation: "egress_blocked",
      identity_id: "agent-a",
      details: {
        seq: 12,
        prior_sha256_hex: sha256Hex("prev"),
        [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: anchorBodyFor(12),
        [CASTLE_WALL_CHAIN_BASIS_DETAIL_KEY]:
          CASTLE_WALL_CHAIN_BASIS_PRODUCER_SIGNED_BODY,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
    };
    const source = buildChainAnchorSourceFromAuditLog(
      fakeLog([
        chainEntry,
        // Rejection diagnostic: operation not an accepted event type.
        {
          operation: "producer_signature_rejected",
          identity_id: "unknown",
          details: { reason: "producer_signature_stale", seq: 13 },
        },
        // Metric batch: accepted operation but no chain bookkeeping/provenance.
        {
          operation: "egress_metric_batch",
          identity_id: FORTRESS_ID,
          details: { window_start: "2026-08-05T00:00:00Z" },
        },
      ]),
    );
    const anchor = await source();
    expect(anchor).toMatchObject({ kind: "persisted", seq: 12 });
  });

  it("returns null on an empty log and unavailable on integrity findings", async () => {
    expect(await buildChainAnchorSourceFromAuditLog(fakeLog([]))()).toBeNull();
    const source = buildChainAnchorSourceFromAuditLog(
      fakeLog(
        [
          {
            operation: "egress_blocked",
            identity_id: "agent-a",
            details: {
              seq: 1,
              prior_sha256_hex: null,
              [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
            },
          },
        ],
        "findings",
      ),
    );
    expect(await source()).toMatchObject({
      kind: "unavailable",
      reason: "audit_log_integrity_findings",
    });
  });


  it("a sealed-region tamper the routine findings would MISS still blocks the anchor", async () => {
    // The routine integrity findings deliberately skip the sealed-region crypto
    // verdict; reading them directly would call this log clean and adopt an
    // anchor out of a tampered history. The shared verdict catches it.
    const source = buildChainAnchorSourceFromAuditLog(
      fakeLog(
        [
          {
            operation: "egress_blocked",
            identity_id: "agent-a",
            details: {
              seq: 5,
              prior_sha256_hex: null,
              [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
            },
          },
        ],
        "findings",
      ),
    );
    expect(await source()).toMatchObject({
      kind: "unavailable",
      reason: "audit_log_integrity_findings",
    });
  });

  it("verified_suffix_only (sealed unreadable at this privilege) does NOT wedge the chain", async () => {
    // An armed box's daemon uid cannot read the root-owned sealed region. That
    // is not tamper, and treating it as such would leave every armed fortress
    // permanently stuck after a restart.
    const source = buildChainAnchorSourceFromAuditLog(
      fakeLog(
        [
          {
            operation: "egress_blocked",
            identity_id: "agent-a",
            details: {
              seq: 5,
              prior_sha256_hex: null,
              [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
            },
          },
        ],
        "verified_suffix_only",
      ),
    );
    expect(await source()).toMatchObject({ kind: "persisted", seq: 5 });
  });

  it("an unsigned last accepted entry surfaces signedCanonicalJson: null", async () => {
    const source = buildChainAnchorSourceFromAuditLog(
      fakeLog([
        {
          operation: "filter_started",
          identity_id: FORTRESS_ID,
          details: {
            seq: 3,
            prior_sha256_hex: null,
            [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
          },
        },
      ]),
    );
    expect(await source()).toMatchObject({
      kind: "persisted",
      seq: 3,
      signedCanonicalJson: null,
      chainBasis: null,
    });
  });

  function anchorBodyFor(seq: number): string {
    return rustWalBody({
      seq,
      prior: sha256Hex("prev"),
      timestamp: "2026-08-05T00:00:00Z",
    });
  }
});
