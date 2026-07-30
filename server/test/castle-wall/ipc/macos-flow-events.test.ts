/**
 * Castle Wall macOS flow event consumer tests.
 *
 * Drives the new IPC message types added in Castle Wall macOS Phase 1
 * Alpha-2: `manifest_subscribe`, `manifest_updated`, `flow_decision_recorded`,
 * and `flow_pending_approval`. Mocks the audit sink and approval queue;
 * asserts:
 *   - manifest_subscribe causes an immediate manifest_updated emit
 *     to the requesting subscriber with the current snapshot.
 *   - broadcastManifestUpdate fans out to every registered subscriber.
 *   - flow_decision_recorded translates `allow` to egress_allowed and
 *     `drop` to egress_blocked on the audit sink.
 *   - malformed flow_decision_recorded notifications append a rejected
 *     entry without translating into an egress event.
 *   - flow_pending_approval enqueues into the approval queue.
 *   - flow_pending_approval clamps non-positive expires_in_seconds to
 *     the configured default.
 *   - malformed flow_pending_approval notifications append a rejected
 *     entry without enqueueing.
 *   - register/unregister keep the subscriber count consistent.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import type {
  AuditEmitNotification,
  FlowDecisionRecordedNotification,
  FlowPendingApprovalNotification,
  ManifestSubscribeRequest,
  ManifestUpdatedNotification,
} from "../../../src/castle-wall/ipc/messages.js";
import { canonicalize } from "../../../src/mesh/canonical-json.js";
import {
  MacOSFlowEventConsumer,
  validateFlowDecisionRecorded,
  validateFlowPendingApproval,
  type AuditSink,
  type MacOSApprovalQueue,
  type MacOSManifestProvider,
  type MacOSSubscriber,
} from "../../../src/castle-wall/runtime/index.js";
import type { EmissionLivenessNotes } from "../../../src/castle-wall/audit/emission-liveness.js";
import { producerSigningBytes } from "../../../src/castle-wall/runtime/producer-signature.js";
import { protectionSubjectForUid } from "../../../src/castle-wall/subject-binding.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { SignedManifest } from "../../../src/castle-wall/allowlist/manifest.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../../../src/castle-wall/constants.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { buildCastleWallPosture } from "../../../src/principal-policy/posture.js";

const SAMPLE_RULE: AllowlistRule = {
  id: "rule-anthropic",
  schema_version: 1,
  created_at: "2026-05-11T00:00:00Z",
  match: { host: "api.anthropic.com", port: 443, protocol: "tcp" },
  scope: { template_ids: ["coding-assistant"] },
  disposition: "allow",
};

interface FakeAuditEntry {
  layer: "l1";
  operation: string;
  identityId: string;
  details?: Record<string, unknown>;
  result?: "success" | "failure";
}

function makeAuditSink(): { sink: AuditSink; entries: FakeAuditEntry[]; flushes: number } {
  const entries: FakeAuditEntry[] = [];
  let flushes = 0;
  const sink: AuditSink = {
    append(layer, operation, identityId, details, result) {
      entries.push({ layer, operation, identityId, details, result });
    },
    async flush() {
      flushes += 1;
    },
  };
  return {
    sink,
    entries,
    get flushes() {
      return flushes;
    },
  };
}

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makeApprovalQueue(): {
  queue: MacOSApprovalQueue;
  enqueued: Array<{
    requestId: string;
    expiresInSeconds: number;
    agentId: string;
    destinationHost: string | null;
  }>;
} {
  const enqueued: Array<{
    requestId: string;
    expiresInSeconds: number;
    agentId: string;
    destinationHost: string | null;
  }> = [];
  const queue: MacOSApprovalQueue = {
    async enqueue(input) {
      enqueued.push({
        requestId: input.requestId,
        expiresInSeconds: input.expiresInSeconds,
        agentId: input.agent.id,
        destinationHost: input.destination.host ?? null,
      });
    },
  };
  return { queue, enqueued };
}

function makeManifestProvider(rules: AllowlistRule[], signature: string | null = "sigA"): MacOSManifestProvider {
  return {
    currentSnapshot() {
      return {
        signed_manifest: makeSignedManifest(rules, signature ?? ""),
        rules,
      };
    },
  };
}

function makeSignedManifest(rules: AllowlistRule[], signature: string): SignedManifest {
  return {
    manifest: {
      schema_version: 1,
      fortress_id: "fortress-test",
      issued_at: "2026-05-14T00:00:00Z",
      rules: rules.map((rule) => ({
        rule_id: rule.id,
        file: `${rule.id}.json`,
        sha256: "0".repeat(64),
      })),
    },
    signature: {
      signature_scheme: "ed25519-v1",
      signing_key_id: "test-key",
      signature_b64url: signature,
    },
  };
}

function makeSubscriber(id: string): {
  subscriber: MacOSSubscriber;
  emitted: ManifestUpdatedNotification[];
} {
  const emitted: ManifestUpdatedNotification[] = [];
  const subscriber: MacOSSubscriber = {
    subscriberId: id,
    async emitManifestUpdate(notification) {
      emitted.push(notification);
    },
  };
  return { subscriber, emitted };
}

function buildConsumer(args?: {
  rules?: AllowlistRule[];
  signature?: string | null;
  defaultApprovalTimeoutSeconds?: number;
  pinnedProducerKeyB64url?: string | null;
  now?: () => number;
  fortressId?: string;
}) {
  const auditSinkBundle = makeAuditSink();
  const queueBundle = makeApprovalQueue();
  const manifestProvider = makeManifestProvider(
    args?.rules ?? [SAMPLE_RULE],
    args?.signature ?? "sigA"
  );
  const consumer = new MacOSFlowEventConsumer({
    manifestProvider,
    approvalQueue: queueBundle.queue,
    auditSink: auditSinkBundle.sink,
    defaultApprovalTimeoutSeconds: args?.defaultApprovalTimeoutSeconds ?? 30,
    pinnedProducerKeyB64url: args?.pinnedProducerKeyB64url ?? null,
    ...(args?.fortressId ? { fortressId: args.fortressId } : {}),
    ...(args?.now ? { now: args.now } : {}),
  });
  return { consumer, auditSinkBundle, queueBundle, manifestProvider };
}

function subjectForUid(fortressId: string, uid: number): string {
  const subject = protectionSubjectForUid(fortressId, uid);
  if (subject === null) throw new Error("test subject could not be derived");
  return subject;
}

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

function signedMacOSProducerFor(
  notification: FlowDecisionRecordedNotification,
  privateKey: Uint8Array,
  opts?: { seq?: number; priorSha256Hex?: string | null; capturedAtUnixMs?: number }
): NonNullable<FlowDecisionRecordedNotification["producer"]> {
  const seq = opts?.seq ?? 0;
  const capturedAtUnixMs = opts?.capturedAtUnixMs ?? Date.parse(notification.recorded_at);
  const operation =
    notification.decision === "allow" ? "egress_approved" : "egress_blocked";
  const result = notification.decision === "allow" ? "success" : "blocked";
  const details: Record<string, unknown> = {
    agent_id: notification.agent.id,
    agent_template: notification.agent.template,
    dest_ip: notification.destination.ip,
    dest_port: notification.destination.port,
    dest_protocol: notification.destination.protocol,
    decision: notification.decision,
    prior_sha256_hex: opts?.priorSha256Hex ?? null,
    rule_id: notification.matched_rule_id ?? null,
    seq,
    source: "macos_extension",
  };
  if (notification.destination.host !== null) {
    details.dest_host = notification.destination.host;
  }
  const eventCanonicalJson = canonicalize({
    timestamp: notification.recorded_at,
    layer: "l1",
    operation,
    identity_id: notification.agent.id,
    result,
    details,
  });
  const signature = ed25519.sign(
    producerSigningBytes(eventCanonicalJson, capturedAtUnixMs, seq),
    privateKey,
  );
  return {
    event_canonical_json: eventCanonicalJson,
    captured_at_unix_ms: capturedAtUnixMs,
    seq,
    prior_sha256_hex: opts?.priorSha256Hex ?? null,
    signature_b64url: toBase64url(signature),
    key_id: CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  };
}

describe("MacOSFlowEventConsumer : manifest subscribe + broadcast", () => {
  it("emits an immediate manifest_updated snapshot on subscribe", async () => {
    const { consumer } = buildConsumer({ rules: [SAMPLE_RULE], signature: "sigA" });
    const { subscriber, emitted } = makeSubscriber("ext-1");
    consumer.registerSubscriber(subscriber);

    const request: ManifestSubscribeRequest = {
      type: "manifest_subscribe",
      request_id: "abc123",
    };
    const notification = await consumer.handleManifestSubscribe(request, "ext-1");

    expect(notification.type).toBe("manifest_updated");
    expect(notification.signature.signature_b64url).toBe("sigA");
    expect(notification.rules).toEqual([SAMPLE_RULE]);
    expect(emitted).toHaveLength(1);
    expect(emitted[0]).toEqual(notification);
    expect(consumer.getStats().manifestSnapshotsEmitted).toBe(1);
    expect(consumer.getStats().subscribers).toBe(1);
  });

  it("rejects manifest_subscribe from an unregistered subscriber", async () => {
    const { consumer } = buildConsumer();
    const request: ManifestSubscribeRequest = {
      type: "manifest_subscribe",
      request_id: "abc123",
    };
    await expect(
      consumer.handleManifestSubscribe(request, "no-such-subscriber")
    ).rejects.toThrow(/unregistered/);
  });

  it("broadcasts manifest_updated to every registered subscriber", async () => {
    const { consumer } = buildConsumer({ rules: [SAMPLE_RULE], signature: "sigB" });
    const a = makeSubscriber("ext-a");
    const b = makeSubscriber("ext-b");
    consumer.registerSubscriber(a.subscriber);
    consumer.registerSubscriber(b.subscriber);

    const emittedCount = await consumer.broadcastManifestUpdate();
    expect(emittedCount).toBe(2);
    expect(a.emitted).toHaveLength(1);
    expect(b.emitted).toHaveLength(1);
    expect(a.emitted[0]?.signature.signature_b64url).toBe("sigB");
    expect(b.emitted[0]?.rules).toEqual([SAMPLE_RULE]);
  });

  it("unregisterSubscriber removes the subscriber from broadcasts", async () => {
    const { consumer } = buildConsumer();
    const a = makeSubscriber("ext-a");
    const b = makeSubscriber("ext-b");
    consumer.registerSubscriber(a.subscriber);
    consumer.registerSubscriber(b.subscriber);
    consumer.unregisterSubscriber("ext-a");

    expect(consumer.getStats().subscribers).toBe(1);
    const emittedCount = await consumer.broadcastManifestUpdate();
    expect(emittedCount).toBe(1);
    expect(a.emitted).toHaveLength(0);
    expect(b.emitted).toHaveLength(1);
  });
});

describe("MacOSFlowEventConsumer : flow_decision_recorded", () => {
  it("translates allow to egress_allowed audit event", async () => {
    const { consumer, auditSinkBundle } = buildConsumer();
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00Z",
    };
    await consumer.handleFlowDecisionRecorded(notification);

    expect(auditSinkBundle.entries).toHaveLength(1);
    const entry = auditSinkBundle.entries[0];
    expect(entry?.layer).toBe("l1");
    expect(entry?.operation).toBe("egress_allowed");
    expect(entry?.identityId).toBe(subjectForUid("fortress-test", 503));
    expect(entry?.result).toBe("success");
    // #381: the matched rule id is written into the stored entry so the
    // operator can attribute the flow. Property #11 (no agent leak) is enforced
    // at the agent-facing read boundary (monitor_audit_log redaction), not by
    // dropping the id at write time -- see cred-return-hardening.test.ts.
    expect(entry?.details?.rule_id).toBe("rule-anthropic");
    expect(entry?.details?.source).toBe("macos_extension");
    // 2026-06-17 provenance fix: the macOS writer must stamp the Castle Wall
    // provenance marker so the honest posture readers count this as real
    // enforcement evidence (without it, an enforcing macOS wall reads amber).
    expect(entry?.details?.[CASTLE_WALL_AUDIT_PROVENANCE_KEY]).toBe(
      CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    );
    expect(consumer.getStats().decisionsRecorded).toBe(1);
    expect(consumer.getStats().decisionsRejected).toBe(0);
  });

  it("derives the persisted macOS evidence subject from audit_token ruid on the channel path", async () => {
    const fortressId = "fortress-test";
    const agentUid = 503;
    const token = auditTokenForRuid(agentUid);
    const { consumer, auditSinkBundle } = buildConsumer({ fortressId });
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: token, template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00Z",
    };

    await consumer.handleFlowDecisionRecorded(notification);

    const entry = auditSinkBundle.entries[0];
    expect(entry?.identityId).toBe(subjectForUid(fortressId, agentUid));
    expect(entry?.details?.agent_id).toBe(token);
    expect(entry?.details?.agent_template).toBe("coding-assistant");
  });

  it("rejects a forged canonical-looking agent.id instead of stamping it as evidence", async () => {
    const forgedSubject = "fortress-malformed-drive/uid-503";
    const { consumer, auditSinkBundle } = buildConsumer({
      fortressId: "fortress-malformed-drive",
    });
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: forgedSubject, template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00Z",
    };

    await consumer.handleFlowDecisionRecorded(notification);

    expect(
      auditSinkBundle.entries.some(
        (entry) =>
          entry.operation === "egress_allowed" &&
          entry.identityId === forgedSubject,
      ),
    ).toBe(false);
    expect(auditSinkBundle.entries).toHaveLength(1);
    expect(auditSinkBundle.entries[0]?.operation).toBe("flow_decision_rejected");
    expect(auditSinkBundle.entries[0]?.details?.reason).toMatch(
      /audit_token_t/,
    );
    expect(consumer.getStats().decisionsRecorded).toBe(0);
    expect(consumer.getStats().decisionsRejected).toBe(1);
  });

  it("a REAL allow flow arms buildCastleWallPosture (end-to-end, marker from the writer not the test)", async () => {
    // The gold regression for the 2026-06-17 macOS under-claim: run the actual
    // writer into a real AuditLog (so cw_source is stamped by the writer, NOT
    // pre-set by the test), then prove the honest posture reader arms from it.
    // Before the fix this returned arm_state "unknown" on a genuinely-enforcing
    // macOS wall (the demo platform).
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE], "sigA"),
      approvalQueue: makeApprovalQueue().queue,
      auditSink: log as unknown as AuditSink,
      defaultApprovalTimeoutSeconds: 30,
    });
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: new Date().toISOString(),
    };
    await consumer.handleFlowDecisionRecorded(notification);
    await log.flush();

    const posture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: "fortress-test",
      platform: "linux",
      protectionClaimSubject: subjectForUid("fortress-test", 503),
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.evidence_basis).toBe("fresh_enforcement_evidence");
  });

  it("accepts a producer-signed macOS allow verdict when the audit-producer key is pinned", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const capturedAtUnixMs = 1_760_000_000_000;
    const { consumer, auditSinkBundle } = buildConsumer({
      pinnedProducerKeyB64url: publicKeyB64url,
      now: () => capturedAtUnixMs + 1000,
    });
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00.000Z",
    };
    notification.producer = signedMacOSProducerFor(notification, privateKey, {
      capturedAtUnixMs,
    });

    await consumer.handleFlowDecisionRecorded(notification);

    const entry = auditSinkBundle.entries.find((e) => e.operation === "egress_allowed");
    expect(entry).toBeDefined();
    expect(entry?.details?.[CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]).toBe(
      CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    );
    expect(entry?.details?.[CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]).toBe(
      notification.producer.signature_b64url,
    );
    expect(entry?.details?.dest_host).toBe("api.anthropic.com");
    expect(entry?.details?.rule_id).toBe("rule-anthropic");
    expect(entry?.details?.[CASTLE_WALL_AUDIT_PROVENANCE_KEY]).toBe(
      CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    );
    expect(consumer.getStats().decisionsRecorded).toBe(1);
    expect(consumer.getStats().decisionsRejected).toBe(0);
  });

  it("producer-signed evidence arms only the independently derived matching claim subject", async () => {
    const fortressId = "fortress-test";
    const agentUid = 503;
    const token = auditTokenForRuid(agentUid);
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const capturedAtUnixMs = Date.now();
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE], "sigA"),
      approvalQueue: makeApprovalQueue().queue,
      auditSink: log as unknown as AuditSink,
      defaultApprovalTimeoutSeconds: 30,
      pinnedProducerKeyB64url: publicKeyB64url,
      fortressId,
      now: () => capturedAtUnixMs + 1000,
    });
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: token, template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: new Date(capturedAtUnixMs).toISOString(),
    };
    notification.producer = signedMacOSProducerFor(notification, privateKey, {
      capturedAtUnixMs,
    });

    await consumer.handleFlowDecisionRecorded(notification);

    const matching = await buildCastleWallPosture({
      auditLog: log,
      originMachine: fortressId,
      platform: "linux",
      now: capturedAtUnixMs + 1000,
      pinnedProducerKeyB64url: publicKeyB64url,
      protectionClaimSubject: subjectForUid(fortressId, agentUid),
    });
    expect(matching.arm_state).toBe("armed");

    const foreign = await buildCastleWallPosture({
      auditLog: log,
      originMachine: fortressId,
      platform: "linux",
      now: capturedAtUnixMs + 1000,
      pinnedProducerKeyB64url: publicKeyB64url,
      protectionClaimSubject: subjectForUid(fortressId, agentUid + 1),
    });
    expect(foreign.arm_state).toBe("unknown");
    expect(foreign.evidence_basis).toBe("subject_unbound_evidence");
  });

  it("binds producer-signed subject attribution to the signed body when the unsigned envelope agent is swapped", async () => {
    const fortressId = "fortress-test";
    const signedUid = 65;
    const swappedEnvelopeUid = 503;
    const signedToken = auditTokenForRuid(signedUid);
    const swappedToken = auditTokenForRuid(swappedEnvelopeUid);
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKeyB64url = toBase64url(ed25519.getPublicKey(privateKey));
    const capturedAtUnixMs = Date.now();
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE], "sigA"),
      approvalQueue: makeApprovalQueue().queue,
      auditSink: log as unknown as AuditSink,
      defaultApprovalTimeoutSeconds: 30,
      pinnedProducerKeyB64url: publicKeyB64url,
      fortressId,
      now: () => capturedAtUnixMs + 1000,
    });
    const signedNotification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: signedToken, template: "system" },
      matched_rule_id: "rule-anthropic",
      recorded_at: new Date(capturedAtUnixMs).toISOString(),
    };
    const producer = signedMacOSProducerFor(signedNotification, privateKey, {
      capturedAtUnixMs,
    });
    const swappedNotification: FlowDecisionRecordedNotification = {
      ...signedNotification,
      agent: { id: swappedToken, template: "coding-assistant" },
      producer,
    };

    await consumer.handleFlowDecisionRecorded(swappedNotification);
    await log.flush();

    const entries = (await log.query({ layer: "l1", limit: 20 })).entries;
    const persisted = entries.find((e) => e.operation === "egress_allowed");
    expect(persisted?.identity_id).toBe(subjectForUid(fortressId, signedUid));
    expect(persisted?.identity_id).not.toBe(
      subjectForUid(fortressId, swappedEnvelopeUid),
    );
    expect(persisted?.details?.agent_id).toBe(signedToken);

    const swappedPosture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: fortressId,
      platform: "linux",
      now: capturedAtUnixMs + 1000,
      pinnedProducerKeyB64url: publicKeyB64url,
      protectionClaimSubject: subjectForUid(fortressId, swappedEnvelopeUid),
    });
    expect(swappedPosture.arm_state).toBe("unknown");
    expect(swappedPosture.evidence_basis).toBe("subject_unbound_evidence");

    const signedPosture = await buildCastleWallPosture({
      auditLog: log,
      originMachine: fortressId,
      platform: "linux",
      now: capturedAtUnixMs + 1000,
      pinnedProducerKeyB64url: publicKeyB64url,
      protectionClaimSubject: subjectForUid(fortressId, signedUid),
    });
    expect(signedPosture.arm_state).toBe("armed");
    expect(signedPosture.producer_authenticity).toBe("producer_signed");
  });

  it("rejects an unsigned macOS verdict when an audit-producer key is pinned", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const { consumer, auditSinkBundle } = buildConsumer({
      pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(privateKey)),
    });
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00.000Z",
    };

    await consumer.handleFlowDecisionRecorded(notification);

    expect(
      auditSinkBundle.entries.some((entry) => entry.operation === "egress_allowed"),
    ).toBe(false);
    expect(consumer.getStats().decisionsRecorded).toBe(0);
    expect(consumer.getStats().decisionsRejected).toBe(1);
  });

  it("rejects a producer-signed macOS verdict when the unsigned prior hash is tampered", async () => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const capturedAtUnixMs = 1_760_000_000_000;
    const { consumer, auditSinkBundle } = buildConsumer({
      pinnedProducerKeyB64url: toBase64url(ed25519.getPublicKey(privateKey)),
      now: () => capturedAtUnixMs + 1000,
    });
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00.000Z",
    };
    notification.producer = signedMacOSProducerFor(notification, privateKey, {
      capturedAtUnixMs,
      priorSha256Hex: "0".repeat(64),
    });
    notification.producer = {
      ...notification.producer,
      prior_sha256_hex: "f".repeat(64),
    };

    await consumer.handleFlowDecisionRecorded(notification);

    expect(
      auditSinkBundle.entries.some((entry) => entry.operation === "egress_allowed"),
    ).toBe(false);
    expect(consumer.getStats().decisionsRecorded).toBe(0);
    expect(consumer.getStats().decisionsRejected).toBe(1);
  });

  it("translates drop with null matched_rule_id to egress_blocked audit event", async () => {
    const { consumer, auditSinkBundle } = buildConsumer();
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "drop",
      destination: {
        host: null,
        ip: "203.0.113.4",
        port: 8080,
        protocol: "tcp",
        hostname_source: null,
        opaque: true,
      },
      agent: { id: auditTokenForRuid(509), template: "ops-runner" },
      matched_rule_id: null,
      recorded_at: "2026-05-11T12:01:00Z",
    };
    await consumer.handleFlowDecisionRecorded(notification);

    expect(auditSinkBundle.entries).toHaveLength(1);
    const entry = auditSinkBundle.entries[0];
    expect(entry?.operation).toBe("egress_blocked");
    expect(entry?.details?.rule_id).toBeNull();
    expect(consumer.getStats().decisionsRecorded).toBe(1);
    expect(consumer.getStats().decisionsRejected).toBe(0);
  });

  it("translates absent matched_rule_id to audit event with null rule_id", async () => {
    const { consumer, auditSinkBundle } = buildConsumer();
    const notification: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.anthropic.com",
        ip: "104.18.32.10",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
      recorded_at: "2026-05-11T12:00:00Z",
    };
    await consumer.handleFlowDecisionRecorded(notification);

    expect(auditSinkBundle.entries).toHaveLength(1);
    const entry = auditSinkBundle.entries[0];
    expect(entry?.operation).toBe("egress_allowed");
    expect(entry?.details?.rule_id).toBeNull();
    expect(consumer.getStats().decisionsRecorded).toBe(1);
    expect(consumer.getStats().decisionsRejected).toBe(0);
  });

  it("rejects malformed flow_decision_recorded with a rejected audit entry", async () => {
    const { consumer, auditSinkBundle } = buildConsumer();
    const malformed = {
      type: "flow_decision_recorded",
      decision: "INVALID",
      destination: {
        host: "x",
        ip: "1.2.3.4",
        port: 443,
        protocol: "tcp",
        hostname_source: null,
        opaque: false,
      },
      agent: { id: auditTokenForRuid(509), template: "ops-runner" },
      matched_rule_id: null,
      recorded_at: "2026-05-11T12:01:00Z",
    } as unknown as FlowDecisionRecordedNotification;
    await consumer.handleFlowDecisionRecorded(malformed);

    expect(auditSinkBundle.entries).toHaveLength(1);
    const entry = auditSinkBundle.entries[0];
    expect(entry?.operation).toBe("flow_decision_rejected");
    expect(entry?.result).toBe("failure");
    expect(entry?.details?.reason).toMatch(/decision/);
    expect(consumer.getStats().decisionsRejected).toBe(1);
    expect(consumer.getStats().decisionsRecorded).toBe(0);
  });

  it("validateFlowDecisionRecorded reports specific shape problems", () => {
    const valid: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "allow",
      destination: {
        host: "api.example.com",
        ip: "1.2.3.4",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: auditTokenForRuid(501), template: "research-assistant" },
      matched_rule_id: "rule-1",
      recorded_at: "2026-05-11T12:00:00Z",
    };
    expect(validateFlowDecisionRecorded(valid)).toBeNull();
    expect(validateFlowDecisionRecorded({ ...valid, matched_rule_id: null })).toBeNull();
    const withoutMatchedRuleId: FlowDecisionRecordedNotification = {
      type: "flow_decision_recorded",
      decision: "drop",
      destination: valid.destination,
      agent: valid.agent,
      recorded_at: valid.recorded_at,
    };
    expect(validateFlowDecisionRecorded(withoutMatchedRuleId)).toBeNull();
    expect(
      validateFlowDecisionRecorded({ ...valid, decision: "x" as never })
    ).toMatch(/decision/);
    expect(
      validateFlowDecisionRecorded({ ...valid, recorded_at: "" })
    ).toMatch(/recorded_at/);
    expect(
      validateFlowDecisionRecorded({
        ...valid,
        agent: { id: "", template: "research-assistant" },
      })
    ).toMatch(/agent/);
    expect(
      validateFlowDecisionRecorded({
        ...valid,
        agent: {
          id: "fortress-malformed-drive/uid-503",
          template: "research-assistant",
        },
      })
    ).toMatch(/audit_token_t/);
    expect(protectionSubjectForUid("fortress-test", 0)).toBeNull();
    expect(
      validateFlowDecisionRecorded({
        ...valid,
        agent: {
          id: auditTokenForRuid(0),
          template: "research-assistant",
        },
      })
    ).toMatch(/audit_token_t/);
    expect(
      validateFlowDecisionRecorded({
        ...valid,
        matched_rule_id: 42 as never,
      })
    ).toMatch(/matched_rule_id/);
  });
});

describe("MacOSFlowEventConsumer : emission-liveness feed (Slice M)", () => {
  interface RecordedNote {
    decisions: string[];
    emissions: number;
    rejections: string[];
  }
  function makeNotes(): { notes: EmissionLivenessNotes; recorded: RecordedNote } {
    const recorded: RecordedNote = { decisions: [], emissions: 0, rejections: [] };
    const notes: EmissionLivenessNotes = {
      noteDecision(source) {
        recorded.decisions.push(source);
      },
      noteEmission() {
        recorded.emissions += 1;
      },
      noteRejection(reason) {
        recorded.rejections.push(reason);
      },
    };
    return { notes, recorded };
  }

  const goodNotification: FlowDecisionRecordedNotification = {
    type: "flow_decision_recorded",
    decision: "allow",
    destination: {
      host: "api.anthropic.com",
      ip: "104.18.32.10",
      port: 443,
      protocol: "tcp",
      hostname_source: "sni",
      opaque: false,
    },
    agent: { id: auditTokenForRuid(503), template: "coding-assistant" },
    matched_rule_id: "rule-anthropic",
    recorded_at: "2026-05-11T12:00:00Z",
  };

  it("notes a decision AND an emission on the channel-authenticated success path", async () => {
    const { notes, recorded } = makeNotes();
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE], "sigA"),
      approvalQueue: makeApprovalQueue().queue,
      auditSink: makeAuditSink().sink,
      defaultApprovalTimeoutSeconds: 30,
      emissionLiveness: notes,
    });
    await consumer.handleFlowDecisionRecorded(goodNotification);
    expect(recorded.decisions).toEqual(["flow_decision_recorded"]);
    expect(recorded.emissions).toBe(1);
    expect(recorded.rejections).toEqual([]);
  });

  it("notes a decision AND a rejection (never an emission) on a malformed notification", async () => {
    const { notes, recorded } = makeNotes();
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE], "sigA"),
      approvalQueue: makeApprovalQueue().queue,
      auditSink: makeAuditSink().sink,
      defaultApprovalTimeoutSeconds: 30,
      emissionLiveness: notes,
    });
    const malformed = {
      ...goodNotification,
      decision: "INVALID",
    } as unknown as FlowDecisionRecordedNotification;
    await consumer.handleFlowDecisionRecorded(malformed);
    expect(recorded.decisions).toEqual(["flow_decision_recorded"]);
    expect(recorded.emissions).toBe(0);
    expect(recorded.rejections).toHaveLength(1);
    expect(recorded.rejections[0]).toMatch(/^validation:/);
  });

  it("notes a rejection (not an emission) when the channel-path persist throws", async () => {
    const { notes, recorded } = makeNotes();
    const throwingSink: AuditSink = {
      append() {
        throw new Error("disk full");
      },
      async flush() {},
    };
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE], "sigA"),
      approvalQueue: makeApprovalQueue().queue,
      auditSink: throwingSink,
      defaultApprovalTimeoutSeconds: 30,
      emissionLiveness: notes,
    });
    await expect(
      consumer.handleFlowDecisionRecorded(goodNotification),
    ).rejects.toThrow(/disk full/);
    expect(recorded.decisions).toEqual(["flow_decision_recorded"]);
    expect(recorded.emissions).toBe(0);
    expect(recorded.rejections).toHaveLength(1);
    expect(recorded.rejections[0]).toMatch(/^persist_error:/);
  });

  it("works without an emission-liveness feed wired (optional dependency)", async () => {
    const consumer = new MacOSFlowEventConsumer({
      manifestProvider: makeManifestProvider([SAMPLE_RULE], "sigA"),
      approvalQueue: makeApprovalQueue().queue,
      auditSink: makeAuditSink().sink,
      defaultApprovalTimeoutSeconds: 30,
    });
    await expect(
      consumer.handleFlowDecisionRecorded(goodNotification),
    ).resolves.toBeUndefined();
    expect(consumer.getStats().decisionsRecorded).toBe(1);
  });
});

describe("MacOSFlowEventConsumer : extension diagnostics", () => {
  it("records provider_unbound diagnostics from audit_emit", async () => {
    const { consumer, auditSinkBundle } = buildConsumer();
    const notification: AuditEmitNotification = {
      type: "audit_emit",
      event: {
        schema_version: 1,
        layer: "l1",
        timestamp: "2026-06-11T00:00:00.000Z",
        fortress_id: "fortress-test",
        event_type: "provider_unbound",
        agent: null,
        destination: null,
        decision: null,
        rule_id: null,
        details: {
          source: "macos_extension",
          trigger: "verdict",
          manifest_received: false,
          arm_lease_received: false,
        },
      },
    };

    await consumer.handleAuditEmit(notification);

    expect(auditSinkBundle.entries).toHaveLength(1);
    expect(auditSinkBundle.entries[0]).toMatchObject({
      layer: "l1",
      operation: "provider_unbound",
      identityId: "fortress-test",
      result: "failure",
    });
    expect(auditSinkBundle.entries[0]?.details).toMatchObject({
      source: "macos_extension",
      trigger: "verdict",
      manifest_received: false,
      arm_lease_received: false,
      timestamp: "2026-06-11T00:00:00.000Z",
    });
    expect(consumer.getStats().extensionDiagnosticsRecorded).toBe(1);
    expect(consumer.getStats().extensionDiagnosticsRejected).toBe(0);
  });

  it("rejects non-provider extension audit events", async () => {
    const { consumer, auditSinkBundle } = buildConsumer();
    const notification: AuditEmitNotification = {
      type: "audit_emit",
      event: {
        schema_version: 1,
        layer: "l1",
        timestamp: "2026-06-11T00:00:00.000Z",
        fortress_id: "fortress-test",
        event_type: "egress_allowed",
        agent: null,
        destination: null,
        decision: null,
        rule_id: null,
        details: {},
      },
    };

    await consumer.handleAuditEmit(notification);

    expect(auditSinkBundle.entries).toHaveLength(1);
    expect(auditSinkBundle.entries[0]?.operation).toBe("extension_diagnostic_rejected");
    expect(auditSinkBundle.entries[0]?.result).toBe("failure");
    expect(consumer.getStats().extensionDiagnosticsRecorded).toBe(0);
    expect(consumer.getStats().extensionDiagnosticsRejected).toBe(1);
  });
});

describe("MacOSFlowEventConsumer : flow_pending_approval", () => {
  it("enqueues a pending approval into the approval queue", async () => {
    const { consumer, queueBundle } = buildConsumer({ defaultApprovalTimeoutSeconds: 45 });
    const notification: FlowPendingApprovalNotification = {
      type: "flow_pending_approval",
      request_id: "req-1",
      destination: {
        host: "novel.example.com",
        ip: "192.0.2.5",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: "agent-3", template: "research-assistant" },
      surface: "egress",
      expires_in_seconds: 25,
    };
    await consumer.handleFlowPendingApproval(notification);

    expect(queueBundle.enqueued).toHaveLength(1);
    expect(queueBundle.enqueued[0]).toEqual({
      requestId: "req-1",
      expiresInSeconds: 25,
      agentId: "agent-3",
      destinationHost: "novel.example.com",
    });
    expect(consumer.getStats().pendingApprovalsEnqueued).toBe(1);
  });

  it("clamps non-positive expires_in_seconds to the default", async () => {
    const { consumer, queueBundle } = buildConsumer({ defaultApprovalTimeoutSeconds: 30 });
    const notification: FlowPendingApprovalNotification = {
      type: "flow_pending_approval",
      request_id: "req-2",
      destination: {
        host: null,
        ip: "192.0.2.6",
        port: 443,
        protocol: "tcp",
        hostname_source: null,
        opaque: true,
      },
      agent: { id: "agent-4", template: "ops-runner" },
      surface: "egress",
      expires_in_seconds: 0,
    };
    await consumer.handleFlowPendingApproval(notification);

    expect(queueBundle.enqueued[0]?.expiresInSeconds).toBe(30);
  });

  it("rejects malformed flow_pending_approval with a rejected audit entry", async () => {
    const { consumer, auditSinkBundle, queueBundle } = buildConsumer();
    const malformed = {
      type: "flow_pending_approval",
      request_id: "",
      destination: {
        host: "novel.example.com",
        ip: "192.0.2.5",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: "agent-3", template: "research-assistant" },
      surface: "egress",
      expires_in_seconds: 30,
    } as unknown as FlowPendingApprovalNotification;
    await consumer.handleFlowPendingApproval(malformed);

    expect(queueBundle.enqueued).toHaveLength(0);
    expect(auditSinkBundle.entries).toHaveLength(1);
    expect(auditSinkBundle.entries[0]?.operation).toBe("flow_pending_approval_rejected");
    expect(consumer.getStats().pendingApprovalsRejected).toBe(1);
    expect(consumer.getStats().pendingApprovalsEnqueued).toBe(0);
  });

  it("validateFlowPendingApproval reports specific shape problems", () => {
    const valid: FlowPendingApprovalNotification = {
      type: "flow_pending_approval",
      request_id: "req-1",
      destination: {
        host: "novel.example.com",
        ip: "192.0.2.5",
        port: 443,
        protocol: "tcp",
        hostname_source: "sni",
        opaque: false,
      },
      agent: { id: "agent-3", template: "research-assistant" },
      surface: "egress",
      expires_in_seconds: 25,
    };
    expect(validateFlowPendingApproval(valid)).toBeNull();
    expect(
      validateFlowPendingApproval({ ...valid, surface: "ingress" as never })
    ).toMatch(/surface/);
    expect(
      validateFlowPendingApproval({ ...valid, request_id: "" })
    ).toMatch(/request_id/);
    expect(
      validateFlowPendingApproval({ ...valid, expires_in_seconds: Number.NaN })
    ).toMatch(/expires_in_seconds/);
  });
});
