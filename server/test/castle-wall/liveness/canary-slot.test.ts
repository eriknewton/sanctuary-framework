/** The canary drop-recording slot: its named states, and admission through a real AuditConsumer with a live flow coalescer. */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import { buildAuditEvent } from "../../../src/castle-wall/audit/builder.js";
import { CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1 } from "../../../src/castle-wall/constants.js";
import { CANARY_IP, CANARY_PORT, CANARY_PROTOCOL, CANARY_SETTLE, CANARY_SLOT_REARM, DAY, SECOND } from "../../../src/castle-wall/liveness/constants.js";
import { CanaryRecordingSlot, type CanaryCandidate, type CanaryOriginSubjects } from "../../../src/castle-wall/liveness/recorder.js";
import { AuditConsumer, type AuditSink } from "../../../src/castle-wall/runtime/audit-consumer.js";
import { FlowCoalescer } from "../../../src/castle-wall/runtime/macos-flow-coalescing.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { protectionSubjectForUid } from "../../../src/castle-wall/subject-binding.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";

const FORTRESS = "fixture";
const OPERATOR_UID = 501;
const AGENT_UID = 502;
const GATE_UID = 503;
const START = Date.parse("2026-11-09T12:00:00.000Z");
const UID_ORIGIN: CanaryOriginSubjects = {
  adapter: "uid", agentUid: AGENT_UID, gateUid: GATE_UID,
  agentSubject: protectionSubjectForUid(FORTRESS, AGENT_UID), gateSubject: protectionSubjectForUid(FORTRESS, GATE_UID),
};
const NAT_ORIGIN: CanaryOriginSubjects = { adapter: "unsupported", agentUid: null, gateUid: null, agentSubject: null, gateSubject: null };
const candidate = (seq: number, capturedAtMs: number): CanaryCandidate => ({ seq, capturedAtMs, subjectUid: AGENT_UID, destIp: CANARY_IP, destPort: CANARY_PORT, destProtocol: CANARY_PROTOCOL });

describe("slot states", () => {
  function slot() {
    let now = START;
    const s = new CanaryRecordingSlot(() => UID_ORIGIN, () => now);
    return { s, advance: (ms: number) => { now += ms; }, now: () => now };
  }

  it("moves IDLE to PENDING to COOLDOWN on a confirmation and re-arms CANARY_SLOT_REARM after admission", () => {
    const { s, advance } = slot();
    expect(s.currentState()).toBe("canary_IDLE");
    expect(s.admit(candidate(1, START - SECOND))).toBe(true);
    expect(s.currentState()).toBe("canary_PENDING");
    advance(SECOND);
    s.settled(true);
    expect(s.currentState()).toBe("canary_COOLDOWN");
    expect(s.evidence().last_confirmation).toEqual({ seq: 1, captured_at_ms: START - SECOND, confirmed_at_ms: START + SECOND, subject_uid: AGENT_UID, dest_ip: CANARY_IP, dest_port: CANARY_PORT, dest_protocol: CANARY_PROTOCOL, delivery: "live" });
    expect(s.admit(candidate(2, START))).toBe(false);
    advance(CANARY_SLOT_REARM - 2 * SECOND);
    expect(s.currentState()).toBe("canary_COOLDOWN");
    advance(SECOND);
    expect(s.currentState()).toBe("canary_IDLE");
  });

  it("records a failure on settled(false)", () => {
    const { s } = slot();
    s.admit(candidate(1, START));
    s.settled(false);
    expect(s.currentState()).toBe("canary_COOLDOWN");
    expect(s.evidence()).toMatchObject({ last_confirmation: null, last_failure: { seq: 1, admitted_at_ms: START, failed_at_ms: START }, failure_count: 1 });
  });

  it("expires past CANARY_SETTLE, refuses replacement, and records a later settlement as late, never as a confirmation", () => {
    const { s, advance } = slot();
    s.admit(candidate(1, START));
    advance(CANARY_SETTLE + 1);
    expect(s.currentState()).toBe("canary_EXPIRED");
    expect(s.admit(candidate(2, START))).toBe(false);
    s.settled(true);
    expect(s.evidence()).toMatchObject({ last_confirmation: null, last_late: { seq: 1, admitted_at_ms: START }, late_count: 1 });
    expect(s.currentState()).toBe("canary_COOLDOWN");
  });

  it("a slot that is never settled stays EXPIRED and never re-arms", () => {
    const { s, advance } = slot();
    s.admit(candidate(1, START));
    advance(DAY);
    expect(s.currentState()).toBe("canary_EXPIRED");
    expect(s.admit(candidate(2, START + DAY))).toBe(false);
    expect(s.admissionCount()).toBe(1);
  });

  it("settles as a failure on stop and ignores every later settlement and admission", () => {
    const { s } = slot();
    s.admit(candidate(1, START));
    s.stop();
    s.settled(true);
    expect(s.evidence()).toMatchObject({ last_confirmation: null, failure_count: 1 });
    expect(s.admit(candidate(2, START))).toBe(false);
  });

  it("a null candidate never admits and a NAT origin publishes the unsupported adapter", () => {
    expect(slot().s.admit(null)).toBe(false);
    const nat = new CanaryRecordingSlot(() => NAT_ORIGIN, () => START);
    expect(nat.evidence().adapter).toBe("unsupported");
  });
});

// ---------------------------------------------------------------------------
// Through a real AuditConsumer.
// ---------------------------------------------------------------------------
class RecordingSink implements AuditSink {
  entries: Array<{ operation: string; identityId: string; details?: Record<string, unknown> }> = [];
  append(_layer: "l1", operation: string, identityId: string, details?: Record<string, unknown>): void {
    this.entries.push({ operation, identityId, details });
  }
  async flush(): Promise<void> {}
}

const signingKey = ed25519.utils.randomPrivateKey();
const pin = Buffer.from(ed25519.getPublicKey(signingKey)).toString("base64url");
const hashOf = (body: string) => createHash("sha256").update(body).digest("hex");
/** An audit token whose real uid is `uid`; the subject binding reads it as `<fortress>/uid-<uid>`. */
const tokenFor = (uid: number) => Buffer.from(new Uint32Array([0, uid, uid, uid, uid, 123, 1, 1]).buffer).toString("hex");

interface FlowSpec {
  uid?: number;
  ip?: string;
  port?: number;
  protocol?: "tcp" | "udp";
  host?: string | null;
  kind?: "drop" | "allow";
  delivery?: "live" | "durable_wal";
}

function harness(origin: CanaryOriginSubjects = UID_ORIGIN) {
  let now = START;
  let seq = 0;
  let prior: string | null = null;
  const sink = new RecordingSink();
  const slot = new CanaryRecordingSlot(() => origin, () => now);
  const coalescer = new FlowCoalescer("fixture-instance", () => now);
  const consumer = new AuditConsumer(sink, undefined, { pinnedProducerKeyB64url: pin, now: () => now, chainContinuity: "producer_subset", liveFlowCoalescer: coalescer, canarySlot: slot });
  function envelope(spec: FlowSpec = {}, options: { seq?: number; prior?: string | null; tamper?: boolean } = {}) {
    const flowSeq = options.seq ?? seq++;
    const flowPrior = options.prior !== undefined ? options.prior : prior;
    const token = tokenFor(spec.uid ?? AGENT_UID);
    const ip = spec.ip ?? CANARY_IP, port = spec.port ?? CANARY_PORT, protocol = spec.protocol ?? CANARY_PROTOCOL;
    const host = spec.host ?? null;
    const kind = spec.kind ?? "drop";
    const timestamp = new Date(now).toISOString();
    const details: Record<string, unknown> = { agent_id: token, dest_ip: ip, dest_port: port, dest_protocol: protocol, decision: kind, seq: flowSeq, prior_sha256_hex: flowPrior };
    if (host !== null) details.dest_host = host;
    const body = canonicalize({ timestamp, layer: "l1", operation: kind === "drop" ? "egress_blocked" : "egress_approved", identity_id: token, result: kind === "drop" ? "blocked" : "success", details });
    if (options.seq === undefined) prior = hashOf(body);
    const signature = ed25519.sign(producerSigningBytes(body, now, flowSeq), signingKey);
    if (options.tamper) signature[0] = signature[0]! ^ 1;
    return {
      event: buildAuditEvent({ timestamp, fortress_id: FORTRESS, event_type: kind === "drop" ? "egress_blocked" : "egress_allowed",
        agent: { id: token, template: "fixture" }, destination: { host, ip, port, protocol }, details: { seq: flowSeq, prior_sha256_hex: flowPrior } }),
      ack: async () => {},
      producerDelivery: spec.delivery ?? "live",
      producerSubjectBinding: { kind: "macos_audit_token" as const, fortressId: FORTRESS },
      producer: { eventCanonicalJson: body, capturedAtUnixMs: now, seq: flowSeq, keyId: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1, signatureB64url: Buffer.from(signature).toString("base64url") },
      body,
    };
  }
  const primaries = (ip = CANARY_IP) => sink.entries.filter(entry => entry.operation === "egress_blocked" && entry.details?.dest_ip === ip).length;
  return {
    sink, slot, consumer, coalescer, envelope, primaries,
    advance: (ms: number) => { now += ms; },
    ingest: async (spec: FlowSpec = {}) => { const e = envelope(spec); await consumer.ingestCritical(e); return e; },
  };
}

describe("canary admission through the audit consumer", () => {
  it("a verified live agent-subject drop for the exact tuple is admitted, goes primary and confirms", async () => {
    const h = harness();
    const first = await h.ingest();
    expect(h.slot.admissionCount()).toBe(1);
    expect(h.primaries()).toBe(1);
    expect(h.slot.evidence().last_confirmation).toMatchObject({ seq: first.producer.seq, subject_uid: AGENT_UID, dest_ip: CANARY_IP, dest_port: CANARY_PORT, dest_protocol: CANARY_PROTOCOL, delivery: "live" });
  });

  it("forces the canary primary while a coalescing window for its key exists, and canaries inside the rearm interval coalesce as ordinary flows", async () => {
    const h = harness();
    const first = await h.ingest();
    // Inside CANARY_SLOT_REARM the slot is not IDLE, so the same tuple takes ordinary coalescing: a head opens the window, then a counted arrival.
    await h.ingest();
    const third = await h.ingest();
    expect(h.consumer.getStats().coalescedCriticalEvents, "a canary inside CANARY_SLOT_REARM coalesces").toBe(1);
    expect(h.slot.evidence().last_confirmation!.seq, "ordinary coalescing is never canary evidence").toBe(first.producer.seq);
    expect(third.producer.seq).not.toBe(first.producer.seq);
    h.advance(CANARY_SLOT_REARM);
    const fourth = await h.ingest();
    expect(h.primaries(), "the window for this key is still open, yet the admitted canary is primary").toBe(3);
    expect(h.slot.evidence().last_confirmation!.seq).toBe(fourth.producer.seq);
    expect(h.consumer.getStats().coalescedCriticalEvents).toBe(1);
    expect(h.slot.admissionCount()).toBe(2);
  });

  it("leaves a non-canary flow's coalescing unchanged", async () => {
    const h = harness();
    await h.ingest({ ip: "198.51.100.7", port: 443 });
    await h.ingest({ ip: "198.51.100.7", port: 443 });
    h.advance(CANARY_SLOT_REARM);
    await h.ingest({ ip: "198.51.100.7", port: 443 });
    expect(h.primaries("198.51.100.7")).toBe(1);
    expect(h.consumer.getStats().coalescedCriticalEvents).toBe(2);
    expect(h.slot.admissionCount()).toBe(0);
  });

  it("a NAT origin never admits and publishes the unsupported adapter", async () => {
    const h = harness(NAT_ORIGIN);
    await h.ingest();
    await h.ingest();
    expect(h.slot.admissionCount()).toBe(0);
    expect(h.consumer.getStats().coalescedCriticalEvents).toBe(1);
    expect(h.slot.evidence().adapter).toBe("unsupported");
  });

  it.each([
    ["an allow from the agent", { kind: "allow" }],
    ["the operator subject", { uid: OPERATOR_UID }],
    ["another uid", { uid: 9999 }],
    ["the gate subject", { uid: GATE_UID }],
    ["another ip", { ip: "192.0.2.253" }],
    ["another port", { port: 10 }],
    ["another protocol", { protocol: "udp" }],
    ["a non-null host", { host: "canary.example" }],
    ["durable_wal delivery", { delivery: "durable_wal" }],
  ] as const)("never admits %s", async (_name, spec) => {
    const h = harness();
    await h.ingest(spec as FlowSpec);
    expect(h.slot.admissionCount()).toBe(0);
    expect(h.slot.currentState()).toBe("canary_IDLE");
    expect(h.slot.evidence().last_confirmation).toBeNull();
  });

  it("an allow never force-primes: a later same-key allow still coalesces", async () => {
    const h = harness();
    await h.ingest({ kind: "allow", uid: OPERATOR_UID });
    await h.ingest({ kind: "allow", uid: OPERATOR_UID });
    expect(h.consumer.getStats().coalescedCriticalEvents).toBe(1);
    expect(h.slot.admissionCount()).toBe(0);
  });

  it("never admits a rejected or duplicate delivery", async () => {
    const h = harness();
    const rejected = h.envelope({}, { tamper: true, seq: 0, prior: null });
    await h.consumer.ingestCritical(rejected).catch(() => undefined);
    expect(h.slot.admissionCount()).toBe(0);
    const first = h.envelope({}, { seq: 0, prior: null });
    await h.consumer.ingestCritical(first);
    expect(h.slot.admissionCount()).toBe(1);
    h.advance(CANARY_SLOT_REARM);
    await h.consumer.ingestCritical(first).catch(() => undefined);
    expect(h.slot.admissionCount(), "an identical replay is a duplicate and never evidence").toBe(1);
    expect(h.sink.entries.at(-1)?.operation).toBe("critical_event_duplicate_dropped");
  });

  it("settles the slot as a failure when the primary append fails", async () => {
    const h = harness();
    h.sink.append = (_layer, operation) => { if (operation === "egress_blocked") throw new Error("fixture primary failure"); };
    await expect(h.ingest()).rejects.toThrow("fixture primary failure");
    expect(h.slot.evidence()).toMatchObject({ last_confirmation: null, failure_count: 1 });
    expect(h.slot.currentState()).toBe("canary_COOLDOWN");
  });

  it("closing flow admission settles a pending slot as a failure", () => {
    const h = harness();
    h.slot.admit(candidate(9, START));
    h.consumer.closeFlowAdmission();
    expect(h.slot.evidence()).toMatchObject({ last_confirmation: null, failure_count: 1 });
  });
});

describe("allow sightings", () => {
  it("ignores an operator-uid allow to the canary tuple: no sighting and no satisfaction", async () => {
    const h = harness();
    await h.ingest({ kind: "allow", uid: OPERATOR_UID });
    expect(h.slot.evidence().last_destination_allowed).toBeNull();
    expect(h.slot.evidence().last_confirmation).toBeNull();
  });

  it.each([["agent", AGENT_UID], ["gate", GATE_UID]] as const)("records a %s-uid allow to the canary tuple", async (principal, uid) => {
    const h = harness();
    await h.ingest({ kind: "allow", uid });
    expect(h.slot.evidence().last_destination_allowed).toEqual({ captured_at_ms: START, principal });
  });

  it("ignores an agent allow to another destination", async () => {
    const h = harness();
    await h.ingest({ kind: "allow", ip: "198.51.100.7", port: 443 });
    expect(h.slot.evidence().last_destination_allowed).toBeNull();
  });
});

describe("producer-flows.json", () => {
  type ProducerFlow = { name: string; flow: FlowSpec & { principal?: "agent" | "gate" | "operator"; tamper?: boolean; replay?: boolean; after_primary?: boolean }; expect: { admitted: boolean; confirmed: boolean; allow_sighting: "agent" | "gate" | null; coalesced?: boolean } };
  const FLOWS = (JSON.parse(readFileSync(join(__dirname, "fixtures", "producer-flows.json"), "utf8")) as { flows: ProducerFlow[] }).flows;
  const PRINCIPAL_UID = { agent: AGENT_UID, gate: GATE_UID, operator: OPERATOR_UID } as const;

  it("names every required case", () => {
    expect(FLOWS.map(flow => flow.name).filter(name => /model-only valid denied|operator allow|wrong uid|unsigned|replay|coalesced/.test(name))).toHaveLength(6);
    expect(new Set(FLOWS.map(flow => flow.name)).size).toBe(FLOWS.length);
  });

  it.each(FLOWS.map(flow => [flow.name, flow] as const))("%s", async (_name, { flow, expect: expected }) => {
    const h = harness();
    const spec: FlowSpec = { ...flow, uid: flow.uid ?? PRINCIPAL_UID[flow.principal ?? "agent"] };
    let admissionsBefore = 0;
    if (flow.after_primary || flow.replay) {
      // A first canary takes the slot, so the case under test is the one that follows it.
      const first = await h.ingest();
      admissionsBefore = h.slot.admissionCount();
      if (flow.replay) {
        h.advance(CANARY_SLOT_REARM);
        await h.consumer.ingestCritical(first).catch(() => undefined);
      } else {
        await h.ingest(spec);
        await h.ingest(spec);
      }
    } else if (flow.tamper) {
      await h.consumer.ingestCritical(h.envelope(spec, { tamper: true, seq: 0, prior: null })).catch(() => undefined);
    } else {
      await h.ingest(spec);
    }
    const evidence = h.slot.evidence();
    expect(h.slot.admissionCount() - admissionsBefore > 0, "admitted").toBe(expected.admitted);
    if (!flow.after_primary && !flow.replay) expect(evidence.last_confirmation !== null, "confirmed").toBe(expected.confirmed);
    else expect(evidence.last_confirmation?.seq, "only the first canary is evidence").toBe(0);
    expect(evidence.last_destination_allowed?.principal ?? null).toBe(expected.allow_sighting);
    if (expected.coalesced) expect(h.consumer.getStats().coalescedCriticalEvents).toBe(1);
  });
});
