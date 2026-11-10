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

import type { CanarySlotPort } from "../liveness/recorder.js";
import { randomUUID } from "node:crypto";
import { FlowAdmission, FlowCoalescer, FLOW_COALESCE_SUMMARY_OPERATION, flowCoalescingMetadata } from "./macos-flow-coalescing.js";
import type { FlowClassification } from "./macos-flow-coalescing.js";
import type { AllowlistRule } from "../allowlist/schema.js";
import { withAuditWriteSettlement } from "../../operational/audit-log.js";
import type { SignedManifest } from "../allowlist/manifest.js";
import {
  CASTLE_WALL_AUDIT_LAYER,
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_SIGNED_ROW_BINDING_IGNORED_DETAIL_KEYS,
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
  parseSignedBody,
  signedDetailsFromBody,
  type AuditSink,
  type ChainAnchorSource,
  type CriticalEventEnvelope,
} from "./audit-consumer.js";
import {
  isLegacyMacOSAuditTokenHex,
  protectionSubjectFromMacOSAuditToken,
  ruidFromMacOSAuditTokenHex,
} from "../subject-binding.js";
import { verifyProducerSignature } from "./producer-signature.js";
import {
  countNonAgentRootFlow,
  createNonAgentRootFlowCounters,
  NON_AGENT_FLOW_SUMMARY_OPERATION,
  type NonAgentRootFlowCounters,
} from "./macos-non-agent-flows.js";
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

export type MacOSIngressDropReason =
  | "audit_backpressure"
  | "approval_capacity"
  | "approval_expired"
  | "approval_shutdown"
  | "approval_id_too_large"
  | "audit_persist_failed"
  | "flow_shutdown";

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
   * Return false when admission is refused; void preserves legacy queues.
   */
  enqueue(input: {
    requestId: string;
    destination: IpcDestination;
    agent: IpcAgentAttribution;
    expiresInSeconds: number;
  }): Promise<void | boolean>;
}

/** Diagnostic counters for observability. */
export interface MacOSFlowEventStats {
  subscribers: number;
  manifestSnapshotsEmitted: number;
  decisionsRecorded: number;
  decisionsCoalesced: number;
  coalescedSummariesWritten: number;
  received: number;
  waiting_or_in_flight: number;
  primary_confirmed: number;
  coalesced: number;
  rejection_confirmed: number;
  duplicate_settled: number;
  delivery_unconfirmed_or_discarded: number;
  counters_lower_bound: boolean;
  /** Informational root observations counted without a per-flow append. */
  nonAgentRootFlowsCounted: number;
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
  /** Trusted runtime opt-in for live delivery; existing callers keep primary persistence. */
  coalesceLiveFlows?: boolean;
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
   * watchdog). Arrivals outside root counting are noted as decisions;
   * only a successful enforcement persist is noted as an emission; every
   * reject/persist-failure path is noted as a rejection. The daemon owns the
   * watchdog's tick timer and loud outputs; this consumer only feeds it.
   */
  emissionLiveness?: EmissionLivenessNotes;
  /**
   * Optional canary drop-recording slot from the full daemon's liveness
   * recorder, passed unchanged into the producer audit consumer. Must match
   * the `canarySlot` option in server/src/castle-wall/runtime/audit-consumer.ts.
   */
  canarySlot?: CanarySlotPort;
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
  // Fixed reason vocabulary: discarded packets never become a second queue.
  private readonly ingressDrops: Record<MacOSIngressDropReason, number> = {
    audit_backpressure: 0,
    approval_capacity: 0,
    approval_expired: 0,
    approval_shutdown: 0,
    approval_id_too_large: 0,
    audit_persist_failed: 0,
    flow_shutdown: 0,
  };
  private readonly instanceId = randomUUID();
  private readonly flowAdmission = new FlowAdmission();
  private readonly coalescer: FlowCoalescer;
  private readonly coalesceLiveFlows: boolean;
  private summaryWrite: Promise<void> | null = null;
  private stopBudgetLapsed = false;
  private ingressDropWrite: Promise<void> | null = null;
  private ingressFirst: number | null = null;
  private ingressLast: number | null = null;
  private ingressBatchSeq = 0;
  private lossStatusFailures = 0;
  private ingressReservation: { details: Record<string, unknown>; counts: Record<MacOSIngressDropReason, number>; appended: boolean } | null = null;
  private readonly nonAgentRootFlows = createNonAgentRootFlowCounters();
  private nonAgentSummaryWrite: Promise<void> | null = null;
  private nonAgentSummarySeq = 0;
  private nonAgentPersistedTotal = 0;
  private readonly nonAgentCountingStartedAt: string;
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
    decisionsCoalesced: 0,
    coalescedSummariesWritten: 0,
    received: 0,
    waiting_or_in_flight: 0,
    primary_confirmed: 0,
    coalesced: 0,
    rejection_confirmed: 0,
    duplicate_settled: 0,
    delivery_unconfirmed_or_discarded: 0,
    counters_lower_bound: false,
    nonAgentRootFlowsCounted: 0,
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
    this.coalescer = new FlowCoalescer(this.instanceId, this.now);
    this.coalesceLiveFlows = input.coalesceLiveFlows ?? false;
    this.nonAgentCountingStartedAt = new Date(this.now()).toISOString();
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
            ...(this.coalesceLiveFlows ? { liveFlowCoalescer: this.coalescer } : {}),
            ...(input.canarySlot !== undefined ? { canarySlot: input.canarySlot } : {}),
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
   * Handle a `flow_decision_recorded` notification. Counts validated root
   * observations for informational summaries; persists agent flows through
   * the existing `egress_allowed` / `egress_blocked` audit path. Invalid
   * frames and root frames that fail pinned verification remain loud rejections.
   */
  async handleFlowDecisionRecorded(
    notification: FlowDecisionRecordedNotification,
    subscriberId?: string,
  ): Promise<void> {
    // Agent deliveries partition into waiting, primary, coalesced, rejection, duplicate and unconfirmed outcomes.
    // Root observations retain their separate informational accounting in macos-non-agent-flows.ts.
    const accounting = { terminal: false, root: false };
    this.countFlow("received"); this.countFlow("waiting_or_in_flight");
    const finish = (kind: "primary_confirmed" | "coalesced" | "rejection_confirmed" | "duplicate_settled" | "delivery_unconfirmed_or_discarded") => {
      if (accounting.terminal) return;
      accounting.terminal = true;
      this.stats.waiting_or_in_flight--;
      this.countFlow(kind);
    };
    const shutdown = () => { finish("delivery_unconfirmed_or_discarded"); this.noteIngressDrop("flow_shutdown"); };
    const run = async () => {
      try { await this.handleAdmittedFlow(notification, subscriberId, finish, accounting); }
      catch (error) {
        if (!accounting.terminal) { finish("delivery_unconfirmed_or_discarded"); this.noteIngressDrop("audit_persist_failed"); }
        throw error;
      }
    };
    if (this.coalesceLiveFlows) return this.flowAdmission.enter(() => withAuditWriteSettlement(run), shutdown);
    return run();
  }

  private async handleAdmittedFlow(
    notification: FlowDecisionRecordedNotification,
    subscriberId: string | undefined,
    finish: (kind: "primary_confirmed" | "coalesced" | "rejection_confirmed" | "duplicate_settled" | "delivery_unconfirmed_or_discarded") => void,
    accounting: { terminal: boolean; root: boolean },
  ): Promise<void> {
    if (subscriberId !== undefined) {
      this.recordFlowCarriedAvailability(notification, subscriberId);
    }
    const validation = validateFlowDecisionRecordedTyped(notification, this.fortressId);
    if (validation.code === "root") {
      const envelope = buildProducerSignedEnvelope(
        notification,
        notification.decision === "allow" ? "egress_allowed" : "egress_blocked",
        this.fortressId,
      );
      // Verified binds the pinned signer, signed subject token with root RUID,
      // decision, operation and seq to this counted flow. Freshness is not checked:
      // counts are informational and no reader treats them as evidence. Duplicates
      // are possible; no consumer chain state moves.
      let signedDecision: "allow" | "drop" | null = null;
      if (this.pinnedProducerKeyB64url !== null &&
        envelope.producer !== undefined &&
        verifyProducerSignature(envelope.producer, this.pinnedProducerKeyB64url).ok) {
        // Must match parseSignedBody and signedDetailsFromBody in audit-consumer.ts:
        // both consumers use the shared signed-body shape before trusting its fields.
        const parsed = parseSignedBody(envelope.producer.eventCanonicalJson);
        if (parsed.kind === "ok") {
          const details = signedDetailsFromBody(parsed.body);
          if (details.agent_id === notification.agent.id &&
            ruidFromMacOSAuditTokenHex(details.agent_id) === 0 &&
            (details.decision === "allow" || details.decision === "drop") &&
            details.decision === notification.decision &&
            // Must match AuditProducerSigning.swift's decision operation mapping.
            parsed.operation === (details.decision === "allow" ? "egress_approved" : "egress_blocked") &&
            details.seq === envelope.producer.seq) {
            signedDecision = details.decision;
          }
        }
      }
      const verified = signedDecision !== null;
      // Only otherwise-valid root flows may bypass rejection and emission notes;
      // a failed pinned binding retains the existing loud rejection path.
      // Continuing paths: no pin -> unverified count; verified pin -> verified count.
      // Refusal path: failed pin -> existing rejection. Other frames keep their
      // existing validation rejection or agent evidence path below.
      if (this.pinnedProducerKeyB64url === null || verified) {
        countNonAgentRootFlow(this.nonAgentRootFlows, signedDecision ?? notification.decision, verified);
        this.stats.nonAgentRootFlowsCounted += 1;
        // The existing root summary owns these observations, outside the agent-delivery partition.
        accounting.root = true; accounting.terminal = true;
        this.stats.received--; this.stats.waiting_or_in_flight--;
        return;
      }
    }
    const reason = validation.reason;
    if (reason !== null) {
      this.emissionLiveness?.noteDecision("flow_decision_recorded");
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
      finish("rejection_confirmed");
      return;
    }
    const eventType =
      notification.decision === "allow" ? "egress_allowed" : "egress_blocked";
    if (this.producerAuditConsumer !== null) {
      try {
        await this.producerAuditConsumer.ingestCritical(
          buildProducerSignedEnvelope(notification, eventType, this.fortressId),
          {
            classify: (kind) => {
              if (kind === "coalesced") {
                this.countFlow("decisionsCoalesced");
                finish("coalesced");
              } else if (kind === "shutdown") {
                finish("delivery_unconfirmed_or_discarded"); this.noteIngressDrop("flow_shutdown");
              } else {
                // Continuing heads and bounded windows are required for two-decision detection; a held head has no two-window guarantee.
                this.emissionLiveness?.noteDecision("flow_decision_recorded");
              }
            },
            confirmed: (kind) => {
              if (kind === "primary") {
                finish("primary_confirmed"); this.stats.decisionsRecorded += 1; this.emissionLiveness?.noteEmission();
              } else finish(kind === "duplicate" ? "duplicate_settled" : "rejection_confirmed");
            },
          },
        );
      } catch (err) {
        this.stats.decisionsRejected += 1;
        if (err instanceof AuditChainError) {
          if (!accounting.terminal) { finish("delivery_unconfirmed_or_discarded"); this.noteIngressDrop("audit_persist_failed"); }
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
        // A delivery owns one terminal outcome even when its persistence diagnostic also fails.
        if (!accounting.terminal) { finish("delivery_unconfirmed_or_discarded"); this.noteIngressDrop("audit_persist_failed"); }
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
    let classification: FlowClassification | undefined;
    try {
      const subject = macOSFlowProtectionSubject(
        this.fortressId,
        notification.agent.id,
      );
      classification = this.coalesceLiveFlows ? this.coalescer.classify(flowCoalescingMetadata(subject, {
        dest_ip: notification.destination.ip, dest_port: notification.destination.port,
        dest_protocol: notification.destination.protocol, dest_host: notification.destination.host,
        decision: notification.decision,
      })) : undefined;
      if (classification?.kind === "coalesced") {
        this.countFlow("decisionsCoalesced"); finish("coalesced"); return;
      }
      this.emissionLiveness?.noteDecision("flow_decision_recorded");
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
      classification?.settled(true);
      finish("primary_confirmed");
    } catch (err) {
      // A failed primary closes only its logical window, preserving older pending summary evidence.
      if (classification?.kind === "head") classification.settled(false);
      if (!accounting.terminal) { finish("delivery_unconfirmed_or_discarded"); this.noteIngressDrop("audit_persist_failed"); }
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
    const admitted = await this.approvalQueue.enqueue({
      requestId: notification.request_id,
      destination: notification.destination,
      agent: notification.agent,
      expiresInSeconds: expires,
    });
    if (admitted === false) this.stats.pendingApprovalsRejected += 1;
    else this.stats.pendingApprovalsEnqueued += 1;
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
        // The extension's `details` are UNTRUSTED wire input, and this entry
        // is stamped with the consumer provenance marker below. Strip every
        // consumer-added carrier key first: those keys are the vocabulary
        // read-side consumers use to identify chain-participating, signature-
        // bearing entries (chain seq/prior, producer signature material,
        // evidence + chain basis). Without this, a diagnostic frame could
        // plant a fabricated chain position that the startup anchor restore
        // would later read back as its own history. Mirrors the same
        // strip-then-stamp rule the unsigned branch of `buildDetailsForEvent`
        // enforces in audit-consumer.ts.
        ...stripConsumerCarrierDetailKeys(event.details),
        timestamp: event.timestamp,
        [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
      "failure"
    );
    await this.auditSink.flush();
    this.stats.extensionDiagnosticsRecorded += 1;
  }

  getStats(): MacOSFlowEventStats {
    const coalescing = this.coalescer.snapshot();
    return { ...this.stats, coalescedSummariesWritten: coalescing.coalescedSummariesWritten,
      counters_lower_bound: this.stats.counters_lower_bound || coalescing.counters_lower_bound };
  }

  /** Return cumulative informational counts without exposing mutable consumer state. */
  getNonAgentFlowCounters(): NonAgentRootFlowCounters {
    return { ...this.nonAgentRootFlows };
  }

  /** Whether any counted flow remains outside the last successfully persisted summary. */
  hasUnpersistedNonAgentFlows(): boolean {
    return this.nonAgentRootFlows.root_verified_total +
      this.nonAgentRootFlows.root_unverified_total !== this.nonAgentPersistedTotal;
  }

  /** Persist cumulative observations at the daemon's existing heartbeat cadence. */
  async flushNonAgentFlowSummary(): Promise<void> {
    if (this.stopBudgetLapsed) return;
    // The one slot stays occupied through actual storage settlement, so slow
    // writes cannot accumulate retained summaries across heartbeat ticks.
    if (this.nonAgentSummaryWrite !== null) {
      this.nonAgentRootFlows.summaries_skipped_in_flight += 1;
      // A skipped tick returns at once rather than adopting the in-flight write, so
      // retained reactions never grow with ticks; drainNonAgentFlowSummary awaits the slot.
      return;
    }
    if (!this.hasUnpersistedNonAgentFlows()) return Promise.resolve();
    const snapshot = { ...this.nonAgentRootFlows };
    const summarySeq = ++this.nonAgentSummarySeq;
    const windowEnd = new Date(this.now()).toISOString();
    // Must match flushIngressDrops in macos-flow-events.ts: withAuditWriteSettlement
    // retains the single slot even when the audit append's lock deadline rejects.
    const write = withAuditWriteSettlement(() => Promise.resolve().then(async () => {
      await this.auditSink.append(
        CASTLE_WALL_AUDIT_LAYER,
        NON_AGENT_FLOW_SUMMARY_OPERATION,
        this.fortressId,
        {
          ...snapshot,
          summary_seq: summarySeq,
          counting_started_at: this.nonAgentCountingStartedAt,
          window_end: windowEnd,
        },
        "success",
      );
      this.nonAgentPersistedTotal = snapshot.root_verified_total + snapshot.root_unverified_total;
      this.nonAgentRootFlows.summaries_written += 1;
    })).catch(() => {
      this.nonAgentRootFlows.summaries_failed += 1;
    }).finally(() => {
      // A failed append never schedules work; the next tick carries cumulative totals.
      this.nonAgentSummaryWrite = null;
    });
    this.nonAgentSummaryWrite = write;
    return write;
  }

  /** Wait for the occupied slot, then start at most one final cumulative write. */
  async drainNonAgentFlowSummary(continuing = () => true): Promise<void> {
    if (this.nonAgentSummaryWrite !== null) await this.nonAgentSummaryWrite;
    if (continuing()) await this.flushNonAgentFlowSummary();
  }

  private countFlow(key: "decisionsCoalesced" | "received" | "waiting_or_in_flight" | "primary_confirmed" | "coalesced" | "rejection_confirmed" | "duplicate_settled" | "delivery_unconfirmed_or_discarded"): void {
    if (this.stats[key] === Number.MAX_SAFE_INTEGER) this.stats.counters_lower_bound = true;
    else this.stats[key]++;
  }

  /** Close routed waiters before teardown; active writes retain their listener charges. */
  closeFlowAdmission(): void { this.flowAdmission.close(); this.producerAuditConsumer?.closeFlowAdmission(); }
  /** Join admitted work under the daemon's stop deadline. */
  async drainFlowAdmission(): Promise<void> { await this.flowAdmission.drain(); await this.producerAuditConsumer?.drainFlowAdmission(); }
  /** Fence new evidence writes after the stop result has latched; existing reservations remain owned. */
  lapseStopBudget(): void { this.stopBudgetLapsed = true; }
  /** Read queued and active work without changing admission ownership. */
  getFlowAdmissionSnapshot() { return this.flowAdmission.snapshot(); }
  /** Read current signed-flow floor for ordered-admission diagnostics. */
  getFlowChainState() { return this.producerAuditConsumer?.getWalChainState() ?? null; }
  /** Read all coalesced ownership, including an immutable reservation held in storage. */
  getCoalescingSnapshot() { return this.publicCoalescingSnapshot(this.coalescer.snapshot()); }

  private publicCoalescingSnapshot(snapshot: ReturnType<FlowCoalescer["snapshot"]>) {
    const { keys, pending_keys, coalesced_total, keys_overflowed, coalesced_evidence_pending, coalesced_evidence_confirmed, summary_write_failures } = snapshot;
    return { keys, pending_keys, coalesced_total, keys_overflowed, coalesced_evidence_pending, coalesced_evidence_confirmed, summary_write_failures };
  }

  /** Capture pending ownership once for heartbeat and sink-independent stop reporting. */
  getPendingEvidenceSnapshot() {
    const coalesced = this.coalescer.snapshot();
    return { ingress_loss_pending: this.ingressLossSnapshot(coalesced), coalesced_pending: this.publicCoalescingSnapshot(coalesced),
      coalesced_counters_lower_bound: coalesced.counters_lower_bound,
      admission: this.getFlowAdmissionSnapshot(), non_agent: this.getNonAgentFlowCounters(), non_agent_pending: this.hasUnpersistedNonAgentFlows() };
  }

  /** Close windows on the existing heartbeat; a busy slot never attaches another waiter. */
  flushCoalescedFlowSummaries(): Promise<void> {
    if (this.stopBudgetLapsed) return Promise.resolve();
    this.coalescer.closeWindows();
    if (this.summaryWrite !== null) return Promise.resolve();
    // Reserve closed windows before yielding so reopened keys keep their new counts in a separate window.
    const reservations = [...this.coalescer.reservations()];
    const write = withAuditWriteSettlement(() => Promise.resolve().then(async () => {
      for (const reservation of reservations) {
        if (this.stopBudgetLapsed) return;
        try {
          if (!reservation.appended) {
            await this.auditSink.append(CASTLE_WALL_AUDIT_LAYER, FLOW_COALESCE_SUMMARY_OPERATION, this.fortressId, { ...reservation.record }, "success");
            reservation.markAppended();
          }
          if (this.stopBudgetLapsed) return;
          await this.auditSink.flush();
          reservation.confirm();
        } catch {
          this.coalescer.noteWriteFailure();
          break;
        }
      }
    })).finally(() => { this.summaryWrite = null; });
    this.summaryWrite = write;
    const snapshot = this.coalescer.snapshot();
    if (snapshot.keys_overflowed > 0) {
      // SAFETY: bounded operator diagnostics use scalar counters only.
      console.error(`[castle-wall] flow summary flush keys_overflowed=${snapshot.keys_overflowed}`);
    }
    return write;
  }
  /** Await the occupied slot and at most one final pass; failed reservations stay owned. */
  async drainCoalescedFlowSummaries(continuing = () => true): Promise<void> { await this.summaryWrite; if (continuing()) await this.flushCoalescedFlowSummaries(); }

  /** Record terminal loss without retaining payloads; retries preserve the reservation's identity. */
  noteFlowIngressDrop(): void {
    // Flow telemetry refused by the listener belongs to the flow partition; approval traffic does not.
    this.countFlow("received"); this.countFlow("delivery_unconfirmed_or_discarded");
    this.noteIngressDrop("audit_backpressure");
  }

  /** Record one reason in the shared loss ledger without retaining its payload. */
  noteIngressDrop(reason: MacOSIngressDropReason, count = 1): void {
    if (!Number.isSafeInteger(count) || count < 1) return;
    if (this.ingressDrops[reason] === 0) {
      // SAFETY: existing operator diagnostic remains independent of the audit sink.
      console.error(`[castle-wall] ingress discarded reason=${reason}; counts pending audit`);
    }
    const now = this.now();
    this.ingressFirst ??= now; this.ingressLast = now;
    if (count > Number.MAX_SAFE_INTEGER - this.ingressDrops[reason]) this.stats.counters_lower_bound = true;
    this.ingressDrops[reason] = Math.min(Number.MAX_SAFE_INTEGER, this.ingressDrops[reason] + count);
    void this.flushIngressDrops();
  }

  /** Snapshot live and reserved counts together; ownership transfers do not change pending totals. */
  getIngressLossSnapshot() { return this.ingressLossSnapshot(this.coalescer.snapshot()); }

  private ingressLossSnapshot(coalesced: ReturnType<FlowCoalescer["snapshot"]>) {
    const counts = { ...this.ingressDrops };
    let lowerBound = this.stats.counters_lower_bound;
    for (const reason of Object.keys(counts) as MacOSIngressDropReason[]) {
      const reserved = this.ingressReservation?.counts[reason] ?? 0;
      if (reserved > Number.MAX_SAFE_INTEGER - counts[reason]) lowerBound = true;
      counts[reason] = Math.min(Number.MAX_SAFE_INTEGER, counts[reason] + reserved);
    }
    return { counts, counters_lower_bound: lowerBound, summary_write_failures: coalesced.summary_write_failures,
      coalesced_evidence_pending: coalesced.coalesced_evidence_pending };
  }

  /** Reserve pending counts before yielding; attempted batches retain their own identity and content. */
  private reserveIngressDrops(): void {
    if (this.ingressReservation) return;
    const snapshot = this.coalescer.snapshot();
    if (!Object.values(this.ingressDrops).some(count => count > 0) && snapshot.summary_write_failures === this.lossStatusFailures) return;
    if (this.ingressBatchSeq === Number.MAX_SAFE_INTEGER) { this.stats.counters_lower_bound = true; return; }
    const counts = { ...this.ingressDrops };
    const first = this.ingressFirst, last = this.ingressLast;
    // Reserve before yielding: later arrivals cannot mutate an attempted identifier or disappear with its confirmation.
    this.ingressReservation = { counts, appended: false, details: {
      counts, consumer_instance_id: this.instanceId, batch_seq: ++this.ingressBatchSeq,
      first_dropped_at: first === null ? null : new Date(first).toISOString(),
      last_dropped_at: last === null ? null : new Date(last).toISOString(),
      window_ms: first === null || last === null ? 0 : Math.max(0, last - first),
      summary_write_failures: snapshot.summary_write_failures,
      coalesced_evidence_pending: snapshot.coalesced_evidence_pending,
    } };
    for (const reason of Object.keys(counts) as MacOSIngressDropReason[]) this.ingressDrops[reason] = 0;
    this.ingressFirst = null; this.ingressLast = null;
  }

  /** Persist loss through the shared sink; a successful retry also drains one pending batch. */
  flushIngressDrops(): Promise<void> {
    if (this.stopBudgetLapsed) return Promise.resolve();
    if (this.ingressDropWrite) return this.ingressDropWrite;
    const retrying = this.ingressReservation !== null;
    this.reserveIngressDrops();
    if (!this.ingressReservation) return Promise.resolve();
    // Two passes are one immutable retry and one newly reserved pending batch, never a retry loop.
    const passes = retrying ? 2 : 1;
    const write = withAuditWriteSettlement(() => Promise.resolve().then(async () => {
      for (let pass = 0; pass < passes && !this.stopBudgetLapsed; pass++) {
        this.reserveIngressDrops();
        const reservation = this.ingressReservation;
        if (!reservation) return;
        if (!reservation.appended) {
          // Must match CASTLE_WALL_AUDIT_OPERATIONS in cli/castle-wall.ts.
          await this.auditSink.append(CASTLE_WALL_AUDIT_LAYER, "castle_wall_ingress_discarded", this.fortressId, reservation.details, "failure");
          reservation.appended = true;
        }
        if (this.stopBudgetLapsed) return;
        await this.auditSink.flush();
        this.lossStatusFailures = reservation.details.summary_write_failures as number;
        this.ingressReservation = null;
      }
    })).catch(() => {
      // A failed store must not spin: retain the immutable reservation and leave the pending batch for a later flush.
    }).finally(() => { this.ingressDropWrite = null; });
    this.ingressDropWrite = write;
    return write;
  }

  /** Join the occupied slot then attempt one final loss batch without scheduling a retry loop. */
  async drainIngressDrops(continuing = () => true): Promise<void> { await this.ingressDropWrite; if (continuing()) await this.flushIngressDrops(); }

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
    producerDelivery: "live",
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

/**
 * Remove every consumer-added carrier key from an UNTRUSTED wire `details`
 * blob before it is persisted under the consumer provenance marker. Must stay
 * in sync with `CASTLE_WALL_SIGNED_ROW_BINDING_IGNORED_DETAIL_KEYS` in
 * `castle-wall/constants.ts` — that list is the authoritative inventory of
 * keys the consumer itself writes (chain seq/prior, producer signature
 * material, evidence + chain basis, provenance), and read-side consumers treat
 * them as consumer-authored facts.
 */
function stripConsumerCarrierDetailKeys(
  details: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  if (details === null || details === undefined) return {};
  const out: Record<string, unknown> = { ...details };
  for (const key of CASTLE_WALL_SIGNED_ROW_BINDING_IGNORED_DETAIL_KEYS) {
    delete out[key];
  }
  return out;
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
  return validateFlowDecisionRecordedTyped(notification, fortressId).reason;
}

/** Closed classification retaining the legacy validator's reason and precedence. */
export type FlowDecisionRecordedValidation =
  | { code: "agent"; reason: null }
  | { code: "root" | "invalid"; reason: string };

/** Classify root only after every other recorded-decision field has passed validation. */
export function validateFlowDecisionRecordedTyped(
  notification: FlowDecisionRecordedNotification,
  fortressId = "validation",
): FlowDecisionRecordedValidation {
  if (notification.type !== "flow_decision_recorded") {
    return { code: "invalid", reason: `unexpected message type: ${String(notification.type)}` };
  }
  if (notification.decision !== "allow" && notification.decision !== "drop") {
    return { code: "invalid", reason: `decision must be allow or drop (got ${String(notification.decision)})` };
  }
  if (!notification.agent || typeof notification.agent.id !== "string" || notification.agent.id.length === 0) {
    return { code: "invalid", reason: "missing agent.id" };
  }
  // RUID names the flow's principal; effective root from a setuid binary never
  // converts an agent's traffic into informational root accounting.
  const root = isLegacyMacOSAuditTokenHex(notification.agent.id) &&
    ruidFromMacOSAuditTokenHex(notification.agent.id) === 0;
  const subjectReason = protectionSubjectFromMacOSAuditToken(fortressId, notification.agent.id) === null
    ? "agent.id must be a non-root macOS audit_token_t hex"
    : null;
  if (subjectReason !== null && !root) return { code: "invalid", reason: subjectReason };
  // Preserve the old subject-error precedence even when a root frame has
  // another invalid field; only the closed code can authorize root counting.
  if (!notification.destination || typeof notification.destination.ip !== "string") {
    return { code: "invalid", reason: subjectReason ?? "missing destination.ip" };
  }
  if (typeof notification.recorded_at !== "string" || notification.recorded_at.length === 0) {
    return { code: "invalid", reason: subjectReason ?? "missing recorded_at" };
  }
  const matchedRuleId = notification.matched_rule_id;
  if (matchedRuleId !== undefined && matchedRuleId !== null && typeof matchedRuleId !== "string") {
    return { code: "invalid", reason: subjectReason ?? "matched_rule_id must be string or null" };
  }
  return root
    ? { code: "root", reason: "agent.id must be a non-root macOS audit_token_t hex" }
    : { code: "agent", reason: null };
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
