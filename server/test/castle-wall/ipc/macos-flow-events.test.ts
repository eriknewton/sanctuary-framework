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

import type {
  FlowDecisionRecordedNotification,
  FlowPendingApprovalNotification,
  ManifestSubscribeRequest,
  ManifestUpdatedNotification,
} from "../../../src/castle-wall/ipc/messages.js";
import {
  MacOSFlowEventConsumer,
  validateFlowDecisionRecorded,
  validateFlowPendingApproval,
  type AuditSink,
  type MacOSApprovalQueue,
  type MacOSManifestProvider,
  type MacOSSubscriber,
} from "../../../src/castle-wall/runtime/index.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { SignedManifest } from "../../../src/castle-wall/allowlist/manifest.js";

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
  });
  return { consumer, auditSinkBundle, queueBundle, manifestProvider };
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
      agent: { id: "agent-7", template: "coding-assistant" },
      matched_rule_id: "rule-anthropic",
      recorded_at: "2026-05-11T12:00:00Z",
    };
    await consumer.handleFlowDecisionRecorded(notification);

    expect(auditSinkBundle.entries).toHaveLength(1);
    const entry = auditSinkBundle.entries[0];
    expect(entry?.layer).toBe("l1");
    expect(entry?.operation).toBe("egress_allowed");
    expect(entry?.identityId).toBe("agent-7");
    expect(entry?.result).toBe("success");
    // Property #11: rule_id is ALWAYS redacted from audit entries to prevent
    // agents from mapping the essentials list by probing.
    expect(entry?.details?.rule_id).toBeNull();
    expect(entry?.details?.source).toBe("macos_extension");
    expect(consumer.getStats().decisionsRecorded).toBe(1);
    expect(consumer.getStats().decisionsRejected).toBe(0);
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
      agent: { id: "agent-9", template: "ops-runner" },
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
      agent: { id: "agent-7", template: "coding-assistant" },
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
      agent: { id: "agent-9", template: "ops-runner" },
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
      agent: { id: "agent-1", template: "research-assistant" },
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
        matched_rule_id: 42 as never,
      })
    ).toMatch(/matched_rule_id/);
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
