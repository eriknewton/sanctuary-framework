/**
 * macOS flow event consumer.
 *
 * The macOS NEFilterDataProvider subclass running inside the system
 * extension bundle emits three new IPC notifications added in Castle Wall
 * macOS Phase 1 Alpha-2: `manifest_subscribe`, `flow_decision_recorded`,
 * and `flow_pending_approval`. This module wires those notifications into
 * the existing audit log + approval queue surfaces on the runtime side so
 * Phase 1 ships a working end-to-end IPC contract for the macOS surface.
 *
 * Out of scope here: the loaded-extension integration (Alpha-3 scope) and
 * the install + notarization flow (Alpha-4 scope). This module is the
 * server-side handler shape that runtime + tests consume; a future PR
 * wires the live IPC dispatcher to call into these handlers.
 *
 * Scope rationale:
 *   - Manifest subscribe registers a subscriber; the runtime emits an
 *     immediate `manifest_updated` snapshot so the extension boots with
 *     authoritative rules and never has to read the manifest off disk.
 *   - Flow decisions translate into existing `egress_allowed` /
 *     `egress_blocked` audit events so the audit consumer treats macOS
 *     events identically to Linux daemon events on the persistence side.
 *   - Pending approvals enter the existing approval queue surface; the
 *     operator-decision response lands back on the extension via the
 *     existing `decision_response` envelope keyed by request_id.
 */

import type { AllowlistRule } from "../allowlist/schema.js";
import type { SignedManifest } from "../allowlist/manifest.js";
import {
  CASTLE_WALL_AUDIT_LAYER,
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
} from "../constants.js";
import { buildAuditEvent } from "../audit/builder.js";
import type {
  AuditEmitNotification,
  AuditProducerSignatureNotification,
  FlowDecisionRecordedNotification,
  FlowPendingApprovalNotification,
  IpcAgentAttribution,
  IpcDestination,
  ManifestSubscribeRequest,
  ManifestUpdatedNotification,
} from "../ipc/messages.js";
import {
  AuditChainError,
  AuditConsumer,
  type AuditSink,
  type CriticalEventEnvelope,
} from "./audit-consumer.js";

/** The runtime's view of a registered macOS subscriber. */
export interface MacOSSubscriber {
  /** Stable identifier for the subscriber connection. */
  subscriberId: string;
  /** Send a manifest snapshot to this subscriber. Implementation routes the bytes over IPC. */
  emitManifestUpdate(notification: ManifestUpdatedNotification): Promise<void>;
}

/** The shape the manifest provider exposes to the consumer. */
export interface MacOSManifestProvider {
  /**
   * Snapshot of the current allowlist rules plus the signed manifest
   * envelope. The runtime calls this on subscribe and on every change.
   * Phase 1 ships a full snapshot each time; a delta variant is reserved
   * for v1.x.
   */
  currentSnapshot(): {
    signed_manifest: SignedManifest;
    rules: AllowlistRule[];
  };
}

/** The shape the approval queue exposes to the consumer. */
export interface MacOSApprovalQueue {
  /**
   * Enqueue a pending approval surfaced from the macOS extension. The
   * existing approval pipeline coalesces, rate-limits, and surfaces to the
   * dashboard; the operator's decision returns via the existing IPC path.
   */
  enqueue(input: {
    requestId: string;
    destination: IpcDestination;
    agent: IpcAgentAttribution;
    expiresInSeconds: number;
  }): Promise<void>;
}

/** Diagnostic counters for observability. */
export interface MacOSFlowEventStats {
  subscribers: number;
  manifestSnapshotsEmitted: number;
  decisionsRecorded: number;
  decisionsRejected: number;
  extensionDiagnosticsRecorded: number;
  extensionDiagnosticsRejected: number;
  pendingApprovalsEnqueued: number;
  pendingApprovalsRejected: number;
}

/** Constructor input. */
export interface MacOSFlowEventConsumerInput {
  manifestProvider: MacOSManifestProvider;
  approvalQueue: MacOSApprovalQueue;
  auditSink: AuditSink;
  /**
   * Default approval timeout in seconds, used when the extension reports
   * `expires_in_seconds <= 0`. Mirrors the existing
   * `CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS` knob; passed in so tests
   * can override.
   */
  defaultApprovalTimeoutSeconds: number;
  /**
   * Optional macOS audit-producer public key. When present, flow verdicts MUST
   * carry the extension-side producer tuple and pass the same fail-closed
   * re-verification gate Linux uses. When absent, macOS stays on the honest
   * channel-authenticated floor.
   */
  pinnedProducerKeyB64url?: string | null;
  now?: () => number;
}

/**
 * Stateful consumer the runtime wires to its IPC dispatcher. Public methods
 * map 1:1 to the new IPC message types; tests drive them directly without
 * standing up a real IPC transport.
 */
export class MacOSFlowEventConsumer {
  private readonly subscribers = new Map<string, MacOSSubscriber>();
  private readonly manifestProvider: MacOSManifestProvider;
  private readonly approvalQueue: MacOSApprovalQueue;
  private readonly auditSink: AuditSink;
  private readonly defaultApprovalTimeoutSeconds: number;
  private readonly producerAuditConsumer: AuditConsumer | null;
  private stats: MacOSFlowEventStats = {
    subscribers: 0,
    manifestSnapshotsEmitted: 0,
    decisionsRecorded: 0,
    decisionsRejected: 0,
    extensionDiagnosticsRecorded: 0,
    extensionDiagnosticsRejected: 0,
    pendingApprovalsEnqueued: 0,
    pendingApprovalsRejected: 0,
  };

  constructor(input: MacOSFlowEventConsumerInput) {
    this.manifestProvider = input.manifestProvider;
    this.approvalQueue = input.approvalQueue;
    this.auditSink = input.auditSink;
    this.defaultApprovalTimeoutSeconds = input.defaultApprovalTimeoutSeconds;
    this.producerAuditConsumer =
      typeof input.pinnedProducerKeyB64url === "string" &&
      input.pinnedProducerKeyB64url.length > 0
        ? new AuditConsumer(input.auditSink, undefined, {
            pinnedProducerKeyB64url: input.pinnedProducerKeyB64url,
            ...(input.now ? { now: input.now } : {}),
          })
        : null;
  }

  /** Add a subscriber. The runtime calls this when an IPC connection finishes the handshake. */
  registerSubscriber(subscriber: MacOSSubscriber): void {
    this.subscribers.set(subscriber.subscriberId, subscriber);
    this.stats.subscribers = this.subscribers.size;
  }

  /** Remove a subscriber. Idempotent. */
  unregisterSubscriber(subscriberId: string): void {
    this.subscribers.delete(subscriberId);
    this.stats.subscribers = this.subscribers.size;
  }

  /**
   * Handle a `manifest_subscribe` request. Emits an immediate snapshot to
   * the requesting subscriber so the extension boots with authoritative
   * rules. Throws when the subscriber has not been registered (the runtime
   * must register the connection before dispatching its messages).
   */
  async handleManifestSubscribe(
    request: ManifestSubscribeRequest,
    subscriberId: string
  ): Promise<ManifestUpdatedNotification> {
    const subscriber = this.subscribers.get(subscriberId);
    if (!subscriber) {
      throw new Error(
        `manifest_subscribe from unregistered subscriber: ${subscriberId}`
      );
    }
    if (request.type !== "manifest_subscribe") {
      throw new Error(`unexpected message type: ${String(request.type)}`);
    }
    const snapshot = this.manifestProvider.currentSnapshot();
    const notification: ManifestUpdatedNotification = {
      type: "manifest_updated",
      manifest: snapshot.signed_manifest.manifest,
      signature: snapshot.signed_manifest.signature,
      rules: snapshot.rules,
    };
    await subscriber.emitManifestUpdate(notification);
    this.stats.manifestSnapshotsEmitted += 1;
    return notification;
  }

  /**
   * Push a `manifest_updated` notification to every registered subscriber.
   * The runtime calls this when the manifest publisher rotates the
   * allowlist. Phase 1 fans out the same snapshot to every subscriber.
   */
  async broadcastManifestUpdate(): Promise<number> {
    const snapshot = this.manifestProvider.currentSnapshot();
    const notification: ManifestUpdatedNotification = {
      type: "manifest_updated",
      manifest: snapshot.signed_manifest.manifest,
      signature: snapshot.signed_manifest.signature,
      rules: snapshot.rules,
    };
    let emitted = 0;
    for (const subscriber of this.subscribers.values()) {
      await subscriber.emitManifestUpdate(notification);
      emitted += 1;
      this.stats.manifestSnapshotsEmitted += 1;
    }
    return emitted;
  }

  /**
   * Handle a `flow_decision_recorded` notification. Translates into an
   * `egress_allowed` or `egress_blocked` audit event so the existing
   * persistence path applies. Validates required fields; rejects malformed
   * payloads with an audit-rejected entry.
   */
  async handleFlowDecisionRecorded(
    notification: FlowDecisionRecordedNotification
  ): Promise<void> {
    const reason = validateFlowDecisionRecorded(notification);
    if (reason !== null) {
      this.stats.decisionsRejected += 1;
      await this.auditSink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "flow_decision_rejected",
        notification.agent?.id ?? "unknown",
        { reason },
        "failure"
      );
      await this.auditSink.flush();
      return;
    }
    const eventType =
      notification.decision === "allow" ? "egress_allowed" : "egress_blocked";
    if (this.producerAuditConsumer !== null) {
      try {
        await this.producerAuditConsumer.ingestCritical(
          buildProducerSignedEnvelope(notification, eventType)
        );
        this.stats.decisionsRecorded += 1;
      } catch (err) {
        this.stats.decisionsRejected += 1;
        if (err instanceof AuditChainError) return;
        throw err;
      }
      return;
    }
    // OPERATOR ATTRIBUTION (#381): the matched rule id is written into the
    // stored audit entry so the operator -- who owns the policy -- can attribute
    // each flow to the specific rule that decided it (a specific allow/deny rule
    // id, `operator-baseline-uid` / `essentials-<name>` for baseline-allow
    // fast paths, or null for a baseline default-deny that matched no rule). It
    // is null only when the sysext reported no matched rule.
    //
    // SECURITY (property #11, no-policy-inference): `rule_id` is an operator-only
    // key. The agent-facing read surfaces use an ALLOWLIST (agent-audit-redaction.ts),
    // not a denylist: `monitor_audit_log` and the SIEM formatters emit only the
    // fixed safe view (timestamp/operation/result/has_details) and never pass
    // `details` through, and the cooperative-surface pull/search tools never
    // return raw details (search is matched only against the safe-key allowlist).
    // So an agent that can query audit entries cannot learn which rules matched
    // and map the essentials list by probing — and a NEW operator-attribution
    // detail key added here stays private by default (no denylist to forget to
    // update). The operator reads the unredacted entry via the Castle Wall CLI /
    // dashboard.
    await this.auditSink.append(
      CASTLE_WALL_AUDIT_LAYER,
      eventType,
      notification.agent.id,
      {
        agent: notification.agent,
        destination: notification.destination,
        decision: notification.decision,
        rule_id: notification.matched_rule_id ?? null,
        recorded_at: notification.recorded_at,
        source: "macos_extension",
        // Provenance marker stamped LAST: this entry is genuine Castle Wall
        // enforcement evidence, so the honest posture readers (posture.ts G4,
        // the ARMED banner, the dashboard shield) count it as armed. Without
        // this, a genuinely-enforcing macOS wall reads amber/"not confirmed"
        // (the 2026-06-17 under-claim). Stamped last + from constructed fields
        // only (no untrusted spread), so an inbound forged cw_source cannot win.
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
      "success"
    );
    await this.auditSink.flush();
    this.stats.decisionsRecorded += 1;
  }

  /**
   * Handle a `flow_pending_approval` notification. Enqueues into the
   * approval queue. Validates required fields; rejects malformed payloads
   * with an audit-rejected entry. Clamps non-positive `expires_in_seconds`
   * to the configured default so the operator surface always has a
   * deterministic deadline.
   */
  async handleFlowPendingApproval(
    notification: FlowPendingApprovalNotification
  ): Promise<void> {
    const reason = validateFlowPendingApproval(notification);
    if (reason !== null) {
      this.stats.pendingApprovalsRejected += 1;
      await this.auditSink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "flow_pending_approval_rejected",
        notification.agent?.id ?? "unknown",
        { reason },
        "failure"
      );
      await this.auditSink.flush();
      return;
    }
    const expires =
      notification.expires_in_seconds > 0
        ? notification.expires_in_seconds
        : this.defaultApprovalTimeoutSeconds;
    await this.approvalQueue.enqueue({
      requestId: notification.request_id,
      destination: notification.destination,
      agent: notification.agent,
      expiresInSeconds: expires,
    });
    this.stats.pendingApprovalsEnqueued += 1;
  }

  /**
   * Handle extension-origin diagnostic audit events. This path is for provider
   * state, not flow verdicts, so it appends directly to the macOS audit sink
   * instead of requiring WAL chain fields from the extension.
   */
  async handleAuditEmit(notification: AuditEmitNotification): Promise<void> {
    const event = notification.event;
    if (
      notification.type !== "audit_emit" ||
      event.layer !== CASTLE_WALL_AUDIT_LAYER ||
      event.event_type !== "provider_unbound" ||
      typeof event.fortress_id !== "string" ||
      event.fortress_id.length === 0
    ) {
      this.stats.extensionDiagnosticsRejected += 1;
      await this.auditSink.append(
        CASTLE_WALL_AUDIT_LAYER,
        "extension_diagnostic_rejected",
        event?.fortress_id ?? "unknown",
        {
          reason: "invalid_extension_diagnostic",
          event_type: event?.event_type,
        },
        "failure"
      );
      await this.auditSink.flush();
      return;
    }
    await this.auditSink.append(
      CASTLE_WALL_AUDIT_LAYER,
      event.event_type,
      event.fortress_id,
      {
        ...event.details,
        timestamp: event.timestamp,
      },
      "failure"
    );
    await this.auditSink.flush();
    this.stats.extensionDiagnosticsRecorded += 1;
  }

  getStats(): MacOSFlowEventStats {
    return { ...this.stats };
  }
}

function buildProducerSignedEnvelope(
  notification: FlowDecisionRecordedNotification,
  eventType: "egress_allowed" | "egress_blocked"
): CriticalEventEnvelope {
  const producer = normalizeProducerSignature(notification.producer);
  const destination = {
    host: notification.destination.host,
    ip: notification.destination.ip,
    port: notification.destination.port,
    protocol: notification.destination.protocol,
  };
  const event = buildAuditEvent({
    timestamp: notification.recorded_at,
    fortress_id: notification.agent.id,
    event_type: eventType,
    agent: notification.agent,
    destination,
    decision: null,
    rule_id: notification.matched_rule_id ?? null,
    details: producer
      ? {
          seq: producer.seq,
          prior_sha256_hex: producer.prior_sha256_hex,
        }
      : {},
  });
  return {
    event,
    ack: async () => {},
    ...(producer
      ? {
          producer: {
            eventCanonicalJson: producer.event_canonical_json,
            capturedAtUnixMs: producer.captured_at_unix_ms,
            seq: producer.seq,
            signatureB64url: producer.signature_b64url,
            keyId: producer.key_id,
          },
        }
      : {}),
  };
}

function normalizeProducerSignature(
  producer: FlowDecisionRecordedNotification["producer"]
): AuditProducerSignatureNotification | null {
  if (producer === null || producer === undefined) return null;
  if (
    typeof producer.event_canonical_json !== "string" ||
    typeof producer.captured_at_unix_ms !== "number" ||
    typeof producer.seq !== "number" ||
    !(
      typeof producer.prior_sha256_hex === "string" ||
      producer.prior_sha256_hex === null
    ) ||
    typeof producer.signature_b64url !== "string" ||
    typeof producer.key_id !== "string"
  ) {
    return null;
  }
  return producer;
}

/**
 * Validate a `flow_decision_recorded` notification. Returns `null` when
 * valid; returns a short reason string otherwise.
 */
export function validateFlowDecisionRecorded(
  notification: FlowDecisionRecordedNotification
): string | null {
  if (notification.type !== "flow_decision_recorded") {
    return `unexpected message type: ${String(notification.type)}`;
  }
  if (notification.decision !== "allow" && notification.decision !== "drop") {
    return `decision must be allow or drop (got ${String(notification.decision)})`;
  }
  if (!notification.agent || typeof notification.agent.id !== "string" || notification.agent.id.length === 0) {
    return "missing agent.id";
  }
  if (!notification.destination || typeof notification.destination.ip !== "string") {
    return "missing destination.ip";
  }
  if (typeof notification.recorded_at !== "string" || notification.recorded_at.length === 0) {
    return "missing recorded_at";
  }
  const matchedRuleId = notification.matched_rule_id;
  if (matchedRuleId !== undefined && matchedRuleId !== null && typeof matchedRuleId !== "string") {
    return "matched_rule_id must be string or null";
  }
  return null;
}

/**
 * Validate a `flow_pending_approval` notification. Returns `null` when
 * valid; returns a short reason string otherwise.
 */
export function validateFlowPendingApproval(
  notification: FlowPendingApprovalNotification
): string | null {
  if (notification.type !== "flow_pending_approval") {
    return `unexpected message type: ${String(notification.type)}`;
  }
  if (typeof notification.request_id !== "string" || notification.request_id.length === 0) {
    return "missing request_id";
  }
  if (notification.surface !== "egress") {
    return `surface must be egress (got ${String(notification.surface)})`;
  }
  if (!notification.agent || typeof notification.agent.id !== "string" || notification.agent.id.length === 0) {
    return "missing agent.id";
  }
  if (!notification.destination || typeof notification.destination.ip !== "string") {
    return "missing destination.ip";
  }
  if (typeof notification.expires_in_seconds !== "number" || !Number.isFinite(notification.expires_in_seconds)) {
    return "expires_in_seconds must be finite";
  }
  return null;
}
