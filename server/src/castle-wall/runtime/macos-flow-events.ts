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
import {
  EMISSION_STALL_LOG_PREFIX,
  type EmissionLivenessNotes,
} from "../audit/emission-liveness.js";
import type {
  AuditEmitNotification,
  AuditProducerSignatureNotification,
  EnforcementAvailabilityReportNotification,
  EnforcementAvailabilitySnapshot,
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
  type ChainAnchorSource,
  type CriticalEventEnvelope,
} from "./audit-consumer.js";
import { protectionSubjectFromMacOSAuditToken } from "../subject-binding.js";
import {
  EnforcementAvailabilityStore,
  verifyEnforcementAvailabilityReport,
  verifyFlowDecisionEnforcementCarriage,
  type ResolvedEnforcementAvailability,
  type EnforcementAvailabilityStream,
  type EnforcementAvailabilityVerification,
} from "./enforcement-availability.js";

const DUPLICATE_REPLAY_ROLLUP_COUNT = 100;
const DUPLICATE_REPLAY_ROLLUP_INTERVAL_MS = 60_000;

interface DuplicateReplayRollup {
  pendingCount: number;
  firstPendingAtMs: number | null;
  lastPendingAtMs: number | null;
  distinctSeqs: Set<number>;
  minSeq: number | null;
  maxSeq: number | null;
  minFloor: number | null;
  maxFloor: number | null;
}

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
  enforcementAvailabilityReportsRecorded: number;
  enforcementAvailabilityReportsRejected: number;
  pendingApprovalsEnqueued: number;
  pendingApprovalsRejected: number;
}

/** Constructor input. */
export interface MacOSFlowEventConsumerInput {
  manifestProvider: MacOSManifestProvider;
  approvalQueue: MacOSApprovalQueue;
  auditSink: AuditSink;
  /**
   * Stable fortress id whose wall is producing these events. Required for the
   * macOS subject binding that turns the per-process audit_token_t into the
   * canonical `fortress/uid` claim subject. Tests that omit it fall back to the
   * signed manifest fortress id.
   */
  fortressId?: string;
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
  /**
   * Reader for the flow consumer's own last persisted chain position (wire it
   * with `buildChainAnchorSourceFromAuditLog` over the same audit log
   * `auditSink` appends to). With a pinned producer key, the producer-signed
   * flow chain restores its anchor from LOCAL persisted history before the
   * first flow decision — including the one-time old-basis migration. Omitting
   * it keeps the legacy null-anchor bootstrap.
   */
  chainAnchorSource?: ChainAnchorSource;
  now?: () => number;
  /**
   * Optional decided-vs-emitted divergence feed (Slice M emission-liveness
   * watchdog). Every `flow_decision_recorded` arrival is noted as a decision;
   * only a successful enforcement persist is noted as an emission; every
   * reject/persist-failure path is noted as a rejection. The daemon owns the
   * watchdog's tick timer and loud outputs; this consumer only feeds it.
   */
  emissionLiveness?: EmissionLivenessNotes;
  /**
   * Optional lease-delivery watchdog feed. Called only after an extension
   * availability report or flow-carried availability snapshot has passed the
   * producer-signature and replay gates and updated the store.
   */
  onVerifiedAvailabilityReport?: (
    connectionId: string,
    snapshot: EnforcementAvailabilitySnapshot,
  ) => void;
  /**
   * Optional companion to `onVerifiedAvailabilityReport`: called when a
   * subscriber connection unregisters, so per-connection watchdog state keyed
   * on the subscriber id is cleared with the connection and cannot leak onto
   * a later connection that reuses the id (gate-found on PR #1086: a
   * contradiction count of 2 survived a clean disconnect and fired after one
   * report on a same-id reconnect).
   */
  onSubscriberUnregistered?: (connectionId: string) => void;
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
  private readonly fortressId: string;
  private readonly defaultApprovalTimeoutSeconds: number;
  private readonly producerAuditConsumer: AuditConsumer | null;
  private readonly pinnedProducerKeyB64url: string | null;
  private readonly now: () => number;
  private readonly enforcementAvailability: EnforcementAvailabilityStore;
  private readonly emissionLiveness: EmissionLivenessNotes | null;
  private readonly onSubscriberUnregistered: (connectionId: string) => void;
  private readonly duplicateReplayRollups = new Map<string, DuplicateReplayRollup>();
  private stats: MacOSFlowEventStats = {
    subscribers: 0,
    manifestSnapshotsEmitted: 0,
    decisionsRecorded: 0,
    decisionsRejected: 0,
    extensionDiagnosticsRecorded: 0,
    extensionDiagnosticsRejected: 0,
    enforcementAvailabilityReportsRecorded: 0,
    enforcementAvailabilityReportsRejected: 0,
    pendingApprovalsEnqueued: 0,
    pendingApprovalsRejected: 0,
  };

  constructor(input: MacOSFlowEventConsumerInput) {
    this.manifestProvider = input.manifestProvider;
    this.approvalQueue = input.approvalQueue;
    this.auditSink = input.auditSink;
    this.fortressId = resolveMacOSFlowFortressId(input);
    this.defaultApprovalTimeoutSeconds = input.defaultApprovalTimeoutSeconds;
    this.emissionLiveness = input.emissionLiveness ?? null;
    this.pinnedProducerKeyB64url =
      typeof input.pinnedProducerKeyB64url === "string" &&
      input.pinnedProducerKeyB64url.length > 0
        ? input.pinnedProducerKeyB64url
        : null;
    this.now = input.now ?? Date.now;
    this.enforcementAvailability = new EnforcementAvailabilityStore({
      now: this.now,
      onVerifiedReport: input.onVerifiedAvailabilityReport,
    });
    this.onSubscriberUnregistered =
      input.onSubscriberUnregistered ?? (() => undefined);
    this.producerAuditConsumer =
      this.pinnedProducerKeyB64url !== null
        ? new AuditConsumer(input.auditSink, undefined, {
            pinnedProducerKeyB64url: this.pinnedProducerKeyB64url,
            now: this.now,
            // The extension signs flow decisions AND availability reports into
            // ONE shared seq/prior chain, but only flow decisions arrive here
            // — subset continuity (signature + strict seq monotonicity), never
            // complete-chain prior-hash contiguity, which is unsatisfiable for
            // this consumer by construction.
            chainContinuity: "producer_subset",
            ...(input.chainAnchorSource !== undefined
              ? { chainAnchorSource: input.chainAnchorSource }
              : {}),
          })
        : null;
  }

  /** Add a subscriber. The runtime calls this when an IPC connection finishes the handshake. */
  registerSubscriber(subscriber: MacOSSubscriber): void {
    this.subscribers.set(subscriber.subscriberId, subscriber);
    this.enforcementAvailability.registerConnection(subscriber.subscriberId);
    this.stats.subscribers = this.subscribers.size;
  }

  /** Remove a subscriber. Idempotent. */
  unregisterSubscriber(subscriberId: string): void {
    this.subscribers.delete(subscriberId);
    this.enforcementAvailability.unregisterConnection(subscriberId);
    this.clearDuplicateReplayRollups(subscriberId);
    this.stats.subscribers = this.subscribers.size;
    try {
      this.onSubscriberUnregistered(subscriberId);
    } catch {
      // Watchdog/telemetry consumers must never corrupt unregister cleanup.
    }
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
    notification: FlowDecisionRecordedNotification,
    subscriberId?: string,
  ): Promise<void> {
    if (subscriberId !== undefined) {
      this.recordFlowCarriedAvailability(notification, subscriberId);
    }
    // Slice M emission-liveness: an ARRIVING flow_decision_recorded is
    // evidence the wall reports having decided a flow, independent of whether
    // it persists below. Noted FIRST so every downstream reject path counts
    // as decided-but-not-emitted divergence, never as silence.
    this.emissionLiveness?.noteDecision("flow_decision_recorded");
    const reason = validateFlowDecisionRecorded(notification, this.fortressId);
    if (reason !== null) {
      this.stats.decisionsRejected += 1;
      this.emissionLiveness?.noteRejection(`validation:${reason}`);
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
          buildProducerSignedEnvelope(notification, eventType, this.fortressId)
        );
        this.stats.decisionsRecorded += 1;
        this.emissionLiveness?.noteEmission();
      } catch (err) {
        this.stats.decisionsRejected += 1;
        if (err instanceof AuditChainError) {
          // The consumer has already durably recorded the rejection entry
          // before throwing (audit_event_rejected / producer_signature_rejected
          // / wal_chain_verification_failed), but this catch used to be
          // stderr-silent. Root-cause pass 2026-07-17: a rejection BURST here
          // is a decided-but-not-emitted divergence and must be loud, so it
          // feeds the watchdog and leaves one greppable stderr line.
          this.emissionLiveness?.noteRejection(
            `audit_chain:${err.message}`
          );
          // SAFETY: the AuditChainError swallow used to be stderr-silent; a
          // rejection burst is a decided-but-not-emitted divergence and must
          // leave one greppable operator line (the rejection entry itself is
          // already durably recorded by the consumer before the throw).
          console.error(
            `${EMISSION_STALL_LOG_PREFIX} flow_decision_recorded rejected by the audit chain gate (recorded as a rejection entry, NOT persisted as evidence): ${err.message}`
          );
          return;
        }
        this.emissionLiveness?.noteRejection(
          `persist_error:${err instanceof Error ? err.message : String(err)}`
        );
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
    try {
      const subject = macOSFlowProtectionSubject(
        this.fortressId,
        notification.agent.id,
      );
      await this.auditSink.append(
        CASTLE_WALL_AUDIT_LAYER,
        eventType,
        subject,
        {
          agent: notification.agent,
          agent_id: notification.agent.id,
          agent_template: notification.agent.template,
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
    } catch (err) {
      // A failed channel-path persist re-throws to the listener (which logs
      // to daemon stderr); the watchdog counts it so a persist-failure BURST
      // shows up as decided-but-not-emitted divergence, not just log lines.
      this.emissionLiveness?.noteRejection(
        `persist_error:${err instanceof Error ? err.message : String(err)}`
      );
      throw err;
    }
    this.stats.decisionsRecorded += 1;
    this.emissionLiveness?.noteEmission();
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
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
      "failure"
    );
    await this.auditSink.flush();
    this.stats.extensionDiagnosticsRecorded += 1;
  }

  getStats(): MacOSFlowEventStats {
    return { ...this.stats };
  }

  handleEnforcementAvailabilityReport(
    notification: EnforcementAvailabilityReportNotification,
    subscriberId: string,
  ): void {
    const verified = verifyEnforcementAvailabilityReport({
      notification,
      pinnedProducerKeyB64url: this.pinnedProducerKeyB64url,
      fortressId: this.fortressId,
    });
    this.recordVerifiedAvailability(subscriberId, verified, "dedicated_report");
  }

  resolveEnforcementAvailability(nowMs = this.now()): ResolvedEnforcementAvailability {
    return this.enforcementAvailability.resolve(nowMs);
  }

  private recordFlowCarriedAvailability(
    notification: FlowDecisionRecordedNotification,
    subscriberId: string,
  ): void {
    const verified = verifyFlowDecisionEnforcementCarriage({
      notification,
      pinnedProducerKeyB64url: this.pinnedProducerKeyB64url,
    });
    this.recordVerifiedAvailability(subscriberId, verified, "flow_carried");
  }

  /**
   * Replay protection is a per-stream monotonic floor. The extension signs
   * dedicated availability reports and flow-carried availability from ONE
   * producer counter, but the two paths deliver asynchronously, so a
   * dedicated report signed at seq N legitimately arrives after a
   * flow-carried event signed at seq N+k (F-AVAIL-SEQ-FLAP: a single shared
   * floor misread that interleaving as replay and flapped the armed surface to
   * undetermined). Within-stream reordering is rare but real: a Mini2 24h
   * drill observed 23 delta-1/delta-2 rejections in about 26h. A seq at or
   * below that stream's floor is still rejected because a stale report must
   * never overwrite fresher verified state; exact duplicates are rolled up in
   * the operator log, while lower-seq reorders remain individually visible.
   * Cross-stream re-delivery is rejected earlier by the verifiers' signed
   * `operation` binding. Never-green-on-absence is untouched: acceptance still
   * requires a verified, signed, fortress-bound report inside the
   * consumer-observed freshness window.
   */
  private recordVerifiedAvailability(
    subscriberId: string,
    verified: EnforcementAvailabilityVerification,
    stream: EnforcementAvailabilityStream,
  ): void {
    if (!verified.ok) {
      this.enforcementAvailability.recordInvalidReport(subscriberId, verified.reason);
      this.stats.enforcementAvailabilityReportsRejected += 1;
      return;
    }
    const lastSeq = this.enforcementAvailability.lastProducerSeq(
      subscriberId,
      stream,
    );
    if (lastSeq !== null && verified.seq <= lastSeq) {
      this.logRejectedAvailabilityReplay(
        subscriberId,
        stream,
        verified.seq,
        lastSeq,
      );
      this.enforcementAvailability.recordInvalidReport(
        subscriberId,
        "producer_sequence_replay",
      );
      this.stats.enforcementAvailabilityReportsRejected += 1;
      return;
    }
    this.enforcementAvailability.recordValidReport(
      subscriberId,
      verified.enforcement,
      this.now(),
      verified.seq,
      stream,
    );
    this.stats.enforcementAvailabilityReportsRecorded += 1;
  }

  private logRejectedAvailabilityReplay(
    subscriberId: string,
    stream: EnforcementAvailabilityStream,
    rejectedSeq: number,
    floor: number,
  ): void {
    const delta = floor - rejectedSeq;
    if (delta === 0) {
      this.recordDuplicateReplay(subscriberId, stream, rejectedSeq, floor);
      return;
    }
    // SAFETY: stderr is the daemon operator log; lower-seq same-stream
    // availability rejections are rare hardware-observed reorders, and each
    // one must stay individually greppable apart from duplicate redelivery.
    console.error(
      `[castle-wall] enforcement availability replay reorder rejected stream=${stream} rejected_seq=${rejectedSeq} floor=${floor} delta=${delta}`,
    );
  }

  private recordDuplicateReplay(
    subscriberId: string,
    stream: EnforcementAvailabilityStream,
    rejectedSeq: number,
    floor: number,
  ): void {
    const key = duplicateReplayRollupKey(subscriberId, stream);
    let rollup = this.duplicateReplayRollups.get(key);
    if (!rollup) {
      rollup = {
        pendingCount: 0,
        firstPendingAtMs: null,
        lastPendingAtMs: null,
        distinctSeqs: new Set<number>(),
        minSeq: null,
        maxSeq: null,
        minFloor: null,
        maxFloor: null,
      };
      this.duplicateReplayRollups.set(key, rollup);
    }

    const nowMs = this.now();
    if (duplicateReplayWindowExpired(rollup, nowMs)) {
      emitDuplicateReplayRollup(stream, rollup);
      resetDuplicateReplayRollup(rollup);
    }

    if (rollup.pendingCount === 0) {
      rollup.firstPendingAtMs = nowMs;
    }
    rollup.lastPendingAtMs = nowMs;
    rollup.pendingCount += 1;
    rollup.distinctSeqs.add(rejectedSeq);
    rollup.minSeq =
      rollup.minSeq === null ? rejectedSeq : Math.min(rollup.minSeq, rejectedSeq);
    rollup.maxSeq =
      rollup.maxSeq === null ? rejectedSeq : Math.max(rollup.maxSeq, rejectedSeq);
    rollup.minFloor =
      rollup.minFloor === null ? floor : Math.min(rollup.minFloor, floor);
    rollup.maxFloor =
      rollup.maxFloor === null ? floor : Math.max(rollup.maxFloor, floor);

    if (rollup.pendingCount >= DUPLICATE_REPLAY_ROLLUP_COUNT) {
      emitDuplicateReplayRollup(stream, rollup);
      resetDuplicateReplayRollup(rollup);
    }
  }

  private clearDuplicateReplayRollups(subscriberId: string): void {
    for (const key of this.duplicateReplayRollups.keys()) {
      if (key.startsWith(`${subscriberId}\0`)) {
        this.duplicateReplayRollups.delete(key);
      }
    }
  }
}

function duplicateReplayRollupKey(
  subscriberId: string,
  stream: EnforcementAvailabilityStream,
): string {
  return `${subscriberId}\0${stream}`;
}

function emitDuplicateReplayRollup(
  stream: EnforcementAvailabilityStream,
  rollup: DuplicateReplayRollup,
): void {
  const firstPendingAtMs = rollup.firstPendingAtMs;
  const lastPendingAtMs = rollup.lastPendingAtMs;
  const minSeq = rollup.minSeq;
  const maxSeq = rollup.maxSeq;
  const minFloor = rollup.minFloor;
  const maxFloor = rollup.maxFloor;
  if (
    rollup.pendingCount <= 0 ||
    firstPendingAtMs === null ||
    lastPendingAtMs === null ||
    minSeq === null ||
    maxSeq === null ||
    minFloor === null ||
    maxFloor === null ||
    rollup.distinctSeqs.size <= 0
  ) {
    return;
  }
  const windowMs = Math.max(0, lastPendingAtMs - firstPendingAtMs);
  // SAFETY: stderr is the daemon operator log; distinct-seq duplicate
  // redeliveries can be sustained and noisy, so they are emitted as bounded
  // windows that preserve total count, distinct seq count, ranges, and stream.
  console.error(
    `[castle-wall] enforcement availability duplicate replays suppressed stream=${stream} count=${rollup.pendingCount} distinct_seqs=${rollup.distinctSeqs.size} seq_range=[${minSeq},${maxSeq}] floor_range=[${minFloor},${maxFloor}] window_ms=${windowMs}`,
  );
}

function resetDuplicateReplayRollup(rollup: DuplicateReplayRollup): void {
  rollup.pendingCount = 0;
  rollup.firstPendingAtMs = null;
  rollup.lastPendingAtMs = null;
  rollup.distinctSeqs.clear();
  rollup.minSeq = null;
  rollup.maxSeq = null;
  rollup.minFloor = null;
  rollup.maxFloor = null;
}

function duplicateReplayWindowExpired(
  rollup: DuplicateReplayRollup,
  nowMs: number,
): boolean {
  return (
    rollup.pendingCount > 0 &&
    rollup.firstPendingAtMs !== null &&
    nowMs - rollup.firstPendingAtMs >= DUPLICATE_REPLAY_ROLLUP_INTERVAL_MS
  );
}

function buildProducerSignedEnvelope(
  notification: FlowDecisionRecordedNotification,
  eventType: "egress_allowed" | "egress_blocked",
  fortressId: string,
): CriticalEventEnvelope {
  const producer = normalizeProducerSignature(notification.producer);
  const event = buildAuditEvent({
    timestamp: notification.recorded_at,
    fortress_id: fortressId,
    event_type: eventType,
    agent: notification.agent,
    destination: notification.destination,
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
    producerSubjectBinding: {
      kind: "macos_audit_token",
      fortressId,
    },
  };
}

function macOSFlowProtectionSubject(fortressId: string, agentId: string): string {
  const subject = protectionSubjectFromMacOSAuditToken(fortressId, agentId);
  if (subject === null) {
    throw new Error("agent.id must be a non-root macOS audit_token_t hex");
  }
  return subject;
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
  notification: FlowDecisionRecordedNotification,
  fortressId = "validation",
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
  if (protectionSubjectFromMacOSAuditToken(fortressId, notification.agent.id) === null) {
    return "agent.id must be a non-root macOS audit_token_t hex";
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

function resolveMacOSFlowFortressId(input: MacOSFlowEventConsumerInput): string {
  if (typeof input.fortressId === "string" && input.fortressId.length > 0) {
    return input.fortressId;
  }
  try {
    const manifestFortressId =
      input.manifestProvider.currentSnapshot().signed_manifest?.manifest
        ?.fortress_id;
    if (
      typeof manifestFortressId === "string" &&
      manifestFortressId.length > 0
    ) {
      return manifestFortressId;
    }
  } catch {
    // The provider is still allowed to fail when a manifest is actually read;
    // construction itself must not hard-crash for tests/CLI readers that never
    // subscribe to the manifest.
  }
  return "unknown";
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
