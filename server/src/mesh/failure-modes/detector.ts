/**
 * FailureModeDetector — orchestrator for the five §8 failure modes plus the
 * §9 recovery cascade integration.
 *
 * Responsibilities:
 *   - Wire MeshNode hooks (onAuditBatchRejected, onEnvelopeRejected,
 *     onHeartbeatReceived, onPolicyUpdate, onLocatorUpdate) and NodeRoster
 *     hooks (onPresenceChange, onDropout) into the right detection module.
 *   - Periodically tick `roster.checkDropouts()` for offline detection.
 *   - Periodically tick canonical-audit-loss check.
 *   - Emit `sentinel_alert` usage events for every detection.
 *   - Maintain `MeshHealthSnapshot` for the dashboard SSE bridge.
 *   - Provide operator-decision APIs for: rollback (accept/revoke),
 *     split-brain conflict resolution, canonical-audit promotion.
 *   - DMswitch propagation receipt: surface alert + flag guardian-revocation
 *     unlock state.
 *
 * Spec §8 (failure modes), §9 (recovery), Architecture Walk Key 13 (recovery
 * cascade), Key 8 (incident-response ladder).
 *
 * The detector is non-Concordia, non-Verascore, intra-fortress only. It does
 * NOT touch §10 extension reservations.
 */

import { randomBytes } from "../../core/random.js";
import {
  MeshChainDiscontinuityError,
  MeshRollbackDetectedError,
} from "../errors.js";
import { MeshNode } from "../lifecycle/mesh-node.js";
import type { NodePresenceState } from "../lifecycle/constants.js";
import type {
  AuditBatch,
  LocatorUpdatePayload,
  PolicyUpdatePayload,
  SignedEvent,
} from "../types.js";
import {
  DEFAULT_DETECTOR_TICK_INTERVAL_MS,
  FAILURE_MODE,
  FAILURE_MODE_CANONICAL_AUDIT_LOSS_GRACE_MS,
  type FailureMode,
} from "./constants.js";
import {
  emitGateApproved,
  emitGateDenied,
  emitPolicyPinned,
  emitSentinelAlert,
  type AlertEmitContext,
  type EmittedAlert,
} from "./alerts.js";
import type {
  FailureModeAlert,
  MeshHealthNodeRow,
  MeshHealthSnapshot,
  SplitBrainConflict,
} from "./types.js";

export interface FailureModeDetectorOptions {
  /** Operator-designated canonical audit node id. */
  canonical_audit_node_id: string;
  /** Grace window after canonical audit unreachable before operator prompt. */
  canonical_audit_loss_grace_ms?: number;
  /** Tick interval for periodic checks. Default 1s. */
  tick_interval_ms?: number;
  /**
   * Optional: callback invoked for every alert emitted, in addition to
   * sentinel_alert / gate_* / policy_pinned usage-event emission. The
   * dashboard SSE bridge subscribes here to push to clients.
   */
  on_alert?: (alert: FailureModeAlert) => void;
  /**
   * Optional: callback invoked for every Mesh Health snapshot update. The
   * dashboard SSE bridge re-renders on each call.
   */
  on_health_snapshot?: (snapshot: MeshHealthSnapshot) => void;
}

interface CompromisedSignalState {
  last_monotonic_seq: number;
  attestation_failures: number;
  audit_chain_discontinuities: number;
  rollback_detected: boolean;
}

export class FailureModeDetector {
  private readonly node: MeshNode;
  private readonly emit: AlertEmitContext;
  private readonly opts: Required<FailureModeDetectorOptions>;
  private readonly alerts = new Map<string, FailureModeAlert>();
  private readonly compromised = new Map<string, CompromisedSignalState>();
  private readonly splitBrainConflicts = new Map<string, SplitBrainConflict>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private canonicalAuditLastSeenAt: number;
  private canonicalAuditLossEmittedFor: number | null = null;
  private dmswitchUnlockedFor = false;
  /**
   * Map (emitter_node) → most-recent received locator update so split-brain
   * detection can compare versions on policy-conflict signals. Updated on
   * onLocatorUpdate('conflict').
   */
  private locatorByAgent = new Map<
    string,
    SignedEvent<LocatorUpdatePayload>[]
  >();

  constructor(node: MeshNode, deps: {
    emit_context: AlertEmitContext;
  }, opts: FailureModeDetectorOptions) {
    this.node = node;
    this.emit = deps.emit_context;
    this.opts = {
      canonical_audit_node_id: opts.canonical_audit_node_id,
      canonical_audit_loss_grace_ms:
        opts.canonical_audit_loss_grace_ms ??
        FAILURE_MODE_CANONICAL_AUDIT_LOSS_GRACE_MS,
      tick_interval_ms:
        opts.tick_interval_ms ?? DEFAULT_DETECTOR_TICK_INTERVAL_MS,
      on_alert: opts.on_alert ?? (() => {}),
      on_health_snapshot: opts.on_health_snapshot ?? (() => {}),
    };
    this.canonicalAuditLastSeenAt = Date.now();
    this.wireHooks();
  }

  // ─────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────

  /** Begin periodic ticks for offline + canonical-audit-loss detection. */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(
      () => this.tick(Date.now()),
      this.opts.tick_interval_ms
    );
    // Some Node test runtimes hang on intervals; unref where supported.
    if (typeof (this.timer as unknown as { unref?: () => void }).unref ===
      "function"
    ) {
      (this.timer as unknown as { unref: () => void }).unref();
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Manual tick — exposed so tests can advance state without waiting for the
   * timer. Production code can also use this from a higher-resolution clock.
   */
  tick(nowMs: number): void {
    // 1. Offline detection — promotes nodes to `unreachable` and emits dropouts.
    this.node.getRoster().checkDropouts(nowMs);
    // 2. Canonical-audit-loss check.
    this.checkCanonicalAuditLoss(nowMs);
    // 3. Push fresh snapshot.
    this.opts.on_health_snapshot(this.snapshot(nowMs));
  }

  // ─────────────────────────────────────────────────────────────────────
  // Hook wiring
  // ─────────────────────────────────────────────────────────────────────

  private wireHooks(): void {
    // §8.1 offline → presence transition to `unreachable`.
    this.node.getRoster().onDropout((e) => {
      const alert = this.makeAlert({
        mode: FAILURE_MODE.OFFLINE,
        target: e.node_id,
        message: `Node ${e.node_id} missed ${this.missedThreshold()} consecutive heartbeats and is now unreachable. Agents canonically hosted on this node have been paused.`,
        detail: {
          last_seen_at: e.last_seen_at,
          reason: e.reason,
        },
      });
      this.publishAlert(alert);
      this.emitSentinel(alert);
    });

    // Track presence transitions for the dashboard health rollup.
    this.node.getRoster().onPresenceChange((nodeId, next, prev) => {
      // When canonical audit comes back online, clear our staleness tracker.
      if (
        nodeId === this.opts.canonical_audit_node_id &&
        next === "active" &&
        prev !== "active"
      ) {
        this.canonicalAuditLastSeenAt = Date.now();
        this.canonicalAuditLossEmittedFor = null;
      }
    });

    // Receipt-of-heartbeat → compromised aggregator (monotonic_seq canary).
    this.node.onHeartbeatReceived = (info) => {
      const state = this.getOrInitCompromised(info.emitter_node);
      // monotonic_seq must strictly advance from the same emitter. Equal or
      // less is rollback / replay; surface as compromised signal.
      if (
        state.last_monotonic_seq > 0 &&
        info.monotonic_seq <= state.last_monotonic_seq
      ) {
        const alert = this.makeAlert({
          mode: FAILURE_MODE.COMPROMISED,
          target: info.emitter_node,
          message: `Heartbeat from ${info.emitter_node} carries a non-monotonic envelope sequence (got ${info.monotonic_seq}, last seen ${state.last_monotonic_seq}). This may indicate a rollback, replay attack, or compromised node.`,
          detail: {
            signal: "non_monotonic_seq",
            seq_observed: info.monotonic_seq,
            seq_last_seen: state.last_monotonic_seq,
          },
        });
        this.publishAlert(alert);
        this.emitSentinel(alert);
        state.rollback_detected = true;
      } else if (info.monotonic_seq > state.last_monotonic_seq) {
        state.last_monotonic_seq = info.monotonic_seq;
      }
      // Track that canonical audit has been heard from recently.
      if (info.emitter_node === this.opts.canonical_audit_node_id) {
        this.canonicalAuditLastSeenAt = Date.now();
        this.canonicalAuditLossEmittedFor = null;
      }
    };

    // §8.3 rollback / chain discontinuity — surfaces from canonical-audit
    // batch ingestion path (caught + observable via onAuditBatchRejected).
    this.node.onAuditBatchRejected = (info) => {
      const target = info.emitter_node ?? "<unknown>";
      const isRollback = info.error instanceof MeshRollbackDetectedError;
      const isChainDiscontinuity =
        info.error instanceof MeshChainDiscontinuityError;
      if (isRollback || isChainDiscontinuity) {
        const alert = this.makeAlert({
          mode: FAILURE_MODE.ROLLBACK,
          target,
          message: `Node ${target} has rolled back to a prior state (${info.error.name}). This may indicate compromise, restored backup, or replay attack. Choose: accept_restored_backup or revoke_compromised.`,
          detail: {
            error_name: info.error.name,
            error_message: info.error.message,
            decision_options: ["accept_restored_backup", "revoke_compromised"],
          },
        });
        this.publishAlert(alert);
        this.emitSentinel(alert);
        const state = this.getOrInitCompromised(target);
        state.audit_chain_discontinuities += 1;
        state.rollback_detected = true;
      } else {
        // Other audit-batch failures (HKDF chain proof mismatch, signature
        // failure) are compromise signals — surface as compromised, not
        // rollback.
        const alert = this.makeAlert({
          mode: FAILURE_MODE.COMPROMISED,
          target,
          message: `Audit-batch verification failed from ${target}: ${info.error.message}. This may indicate a stolen signing key without master-derived chain key.`,
          detail: {
            signal: "audit_batch_verification_failure",
            error_name: info.error.name,
            error_message: info.error.message,
          },
        });
        this.publishAlert(alert);
        this.emitSentinel(alert);
      }
    };

    // Envelope rejections — `key_attestation` failure / signature mismatch
    // surfaces here when a peer's signed event fails verification.
    this.node.onEnvelopeRejected = (info) => {
      const target = info.emitter_node ?? "<unknown>";
      const state = this.getOrInitCompromised(target);
      state.attestation_failures += 1;
      const alert = this.makeAlert({
        mode: FAILURE_MODE.COMPROMISED,
        target,
        message: `Envelope verification failed for event_type=${info.event_type} from ${target}: ${info.error.message}.`,
        detail: {
          signal: "envelope_verification_failure",
          event_type: info.event_type,
          error_name: info.error.name,
        },
      });
      this.publishAlert(alert);
      this.emitSentinel(alert);
    };

    // §8.4 split-brain — locator-conflict signal.
    this.node.onLocatorUpdate = (evt, result) => {
      const list = this.locatorByAgent.get(evt.payload.agent_id) ?? [];
      list.push(evt);
      this.locatorByAgent.set(evt.payload.agent_id, list);
      if (result === "conflict") {
        this.detectLocatorSplitBrain(evt.payload.agent_id);
      }
    };

    // Policy-conflict signal: same agent, same parent_version, two distinct
    // policy_versions arriving from different principals during partition heal.
    // PolicyBundleStore.upsert emits 'older' or 'applied' but doesn't have a
    // dedicated 'conflict' branch; we detect here by tracking observed
    // (agent_id, parent_version) tuples across `applied` updates.
    const observedPolicy = new Map<string, Set<number>>();
    this.node.onPolicyUpdate = (evt, _result) => {
      const key = `${evt.payload.agent_id}:p${evt.payload.parent_version ?? 0}`;
      const seen = observedPolicy.get(key) ?? new Set();
      seen.add(evt.payload.policy_version);
      observedPolicy.set(key, seen);
      if (seen.size > 1) {
        this.detectPolicySplitBrain(evt.payload.agent_id, [...seen]);
      }
    };

    // Lifecycle events — receipt of `dmswitch_triggered` unlocks
    // guardian-revocation path and emits sentinel alert.
    this.node.onLifecycleEvent = (evt, _kind) => {
      if (evt.event_type === "dmswitch_triggered") {
        this.dmswitchUnlockedFor = true;
        const alert = this.makeAlert({
          mode: FAILURE_MODE.COMPROMISED,
          // dmswitch is mode-adjacent (operator-presence) but not strictly a
          // failure mode; we tag it as compromised mode for UI grouping at
          // v1.0. v1.x may add a dedicated mode.
          target: "operator_presence",
          message: `DMswitch fired — operator absence threshold exceeded. Guardian-revocation path is unlocked. Guardians may now coordinate.`,
          detail: {
            signal: "dmswitch_triggered",
            event_id: evt.event_id,
          },
        });
        this.publishAlert(alert);
        emitSentinelAlert(this.emit, {
          failure_mode: "dmswitch",
          target: "operator_presence",
          detail: {
            event_id: evt.event_id,
          },
        });
      }
      if (evt.event_type === "master_rotation") {
        // The master_rotation acceptance flow runs separately
        // (failure-mode detector exposes `acceptMasterRotationLocally`); the
        // event itself just records the operator-visible audit trail.
      }
    };
  }

  private missedThreshold(): number {
    // Roster default — same constant the roster uses internally.
    // We reach into the roster's effective threshold via a safe accessor
    // (default if absent).
    return 3;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Detection helpers
  // ─────────────────────────────────────────────────────────────────────

  private getOrInitCompromised(nodeId: string): CompromisedSignalState {
    let state = this.compromised.get(nodeId);
    if (!state) {
      state = {
        last_monotonic_seq: 0,
        attestation_failures: 0,
        audit_chain_discontinuities: 0,
        rollback_detected: false,
      };
      this.compromised.set(nodeId, state);
    }
    return state;
  }

  private detectLocatorSplitBrain(agentId: string): void {
    const candidates = (this.locatorByAgent.get(agentId) ?? []).map((evt) => ({
      event_id: evt.event_id,
      version: evt.payload.locator_version,
      canonical_node: evt.payload.canonical_node,
      signed_at: evt.payload.last_migration_at,
    }));
    const conflict: SplitBrainConflict = {
      conflict_id: generateId(),
      agent_id: agentId,
      candidates,
      detected_at: Date.now(),
    };
    this.splitBrainConflicts.set(conflict.conflict_id, conflict);
    const alert = this.makeAlert({
      mode: FAILURE_MODE.SPLIT_BRAIN,
      target: agentId,
      message: `While a portion of the mesh was disconnected, two locator versions for Agent ${agentId} were issued. Compare and choose which to keep.`,
      detail: {
        kind: "locator_conflict",
        conflict_id: conflict.conflict_id,
        candidates,
      },
    });
    this.publishAlert(alert);
    this.emitSentinel(alert);
  }

  private detectPolicySplitBrain(agentId: string, versions: number[]): void {
    const conflict: SplitBrainConflict = {
      conflict_id: generateId(),
      agent_id: agentId,
      candidates: versions.map((v) => ({
        event_id: `policy:${agentId}:v${v}`,
        version: v,
        canonical_node: "",
        signed_at: "",
      })),
      detected_at: Date.now(),
    };
    this.splitBrainConflicts.set(conflict.conflict_id, conflict);
    const alert = this.makeAlert({
      mode: FAILURE_MODE.SPLIT_BRAIN,
      target: agentId,
      message: `Two distinct policy versions issued for Agent ${agentId} from the same parent_version. Choose which to keep.`,
      detail: {
        kind: "policy_conflict",
        conflict_id: conflict.conflict_id,
        versions,
      },
    });
    this.publishAlert(alert);
    this.emitSentinel(alert);
  }

  private checkCanonicalAuditLoss(nowMs: number): void {
    const since = nowMs - this.canonicalAuditLastSeenAt;
    if (since < this.opts.canonical_audit_loss_grace_ms) {
      return;
    }
    // Only fire once per grace-window crossing.
    if (this.canonicalAuditLossEmittedFor === this.canonicalAuditLastSeenAt) {
      return;
    }
    this.canonicalAuditLossEmittedFor = this.canonicalAuditLastSeenAt;
    const alert = this.makeAlert({
      mode: FAILURE_MODE.CANONICAL_AUDIT_LOSS,
      target: this.opts.canonical_audit_node_id,
      message: `Your canonical audit node ${this.opts.canonical_audit_node_id} has been unreachable for over ${Math.floor(this.opts.canonical_audit_loss_grace_ms / (60 * 60 * 1000))}h. New audit data is buffering on every node. Designate a new canonical node from your replicas.`,
      detail: {
        last_seen_at: this.canonicalAuditLastSeenAt,
        grace_ms: this.opts.canonical_audit_loss_grace_ms,
        decision_options: ["promote_replica"],
      },
    });
    this.publishAlert(alert);
    this.emitSentinel(alert);
  }

  // ─────────────────────────────────────────────────────────────────────
  // Operator-decision API
  // ─────────────────────────────────────────────────────────────────────

  /**
   * Operator-resolution for a flagged rollback alert.
   *   - "accept_restored_backup" → record gate_approved, leave node active.
   *   - "revoke_compromised" → record gate_denied, caller MUST also call
   *     `MeshNode.revokePeer` to actually revoke (kept separate so the
   *     detector does not own revocation authority).
   *
   * Returns the emitted alert envelope so callers can audit.
   */
  resolveRollback(params: {
    alert_id: string;
    decision: "accept_restored_backup" | "revoke_compromised";
    note?: string;
  }): EmittedAlert {
    const alert = this.alerts.get(params.alert_id);
    if (!alert) throw new Error(`unknown alert_id ${params.alert_id}`);
    if (alert.mode !== FAILURE_MODE.ROLLBACK) {
      throw new Error(
        `alert ${params.alert_id} is mode=${alert.mode}, not rollback`
      );
    }
    alert.resolution = {
      state: "resolved",
      decision: params.decision,
      decided_at: Date.now(),
      note: params.note,
    };
    if (params.decision === "accept_restored_backup") {
      const emitted = emitGateApproved(this.emit, {
        failure_mode: FAILURE_MODE.ROLLBACK,
        target: alert.target_node,
        decision: params.decision,
        detail: { alert_id: alert.alert_id, note: params.note },
      });
      this.opts.on_health_snapshot(this.snapshot(Date.now()));
      return emitted;
    } else {
      const emitted = emitGateDenied(this.emit, {
        failure_mode: FAILURE_MODE.ROLLBACK,
        target: alert.target_node,
        decision: params.decision,
        detail: { alert_id: alert.alert_id, note: params.note },
      });
      this.opts.on_health_snapshot(this.snapshot(Date.now()));
      return emitted;
    }
  }

  /**
   * Operator-resolution for a split-brain conflict — picks one branch as
   * canonical and emits policy_pinned. Caller MUST persist the choice
   * separately (locator/policy upsert path).
   */
  resolveSplitBrainConflict(params: {
    conflict_id: string;
    chosen_event_id: string;
    note?: string;
  }): EmittedAlert {
    const conflict = this.splitBrainConflicts.get(params.conflict_id);
    if (!conflict) {
      throw new Error(`unknown conflict_id ${params.conflict_id}`);
    }
    const chosen = conflict.candidates.find(
      (c) => c.event_id === params.chosen_event_id
    );
    if (!chosen) {
      throw new Error(
        `chosen_event_id ${params.chosen_event_id} not in conflict ${params.conflict_id}`
      );
    }
    // Mark every alert about this agent as resolved.
    for (const a of this.alerts.values()) {
      if (
        a.mode === FAILURE_MODE.SPLIT_BRAIN &&
        a.target_node === conflict.agent_id &&
        a.resolution.state === "open"
      ) {
        a.resolution = {
          state: "resolved",
          decision: `pin:${params.chosen_event_id}`,
          decided_at: Date.now(),
          note: params.note,
        };
      }
    }
    const emitted = emitPolicyPinned(this.emit, {
      subject: conflict.agent_id,
      pinned_to: chosen.event_id,
      detail: {
        conflict_id: params.conflict_id,
        rejected_candidates: conflict.candidates
          .filter((c) => c.event_id !== params.chosen_event_id)
          .map((c) => ({ event_id: c.event_id, superseded_by: chosen.event_id })),
        note: params.note,
      },
    });
    this.splitBrainConflicts.delete(params.conflict_id);
    this.opts.on_health_snapshot(this.snapshot(Date.now()));
    return emitted;
  }

  /**
   * Operator-promotes a replica to canonical audit on canonical-audit-loss.
   * Emits policy_pinned + clears the canonical-audit-loss alert. Caller MUST
   * separately invoke `MeshNode.designateCanonicalAudit` to broadcast.
   */
  promoteCanonicalAudit(params: {
    new_canonical_node_id: string;
    note?: string;
  }): EmittedAlert {
    for (const a of this.alerts.values()) {
      if (
        a.mode === FAILURE_MODE.CANONICAL_AUDIT_LOSS &&
        a.resolution.state === "open"
      ) {
        a.resolution = {
          state: "resolved",
          decision: `promote:${params.new_canonical_node_id}`,
          decided_at: Date.now(),
          note: params.note,
        };
      }
    }
    const emitted = emitPolicyPinned(this.emit, {
      subject: "canonical_audit_node",
      pinned_to: params.new_canonical_node_id,
      detail: {
        previous_canonical: this.opts.canonical_audit_node_id,
        note: params.note,
      },
    });
    // Re-target our staleness tracker at the new canonical.
    this.opts.canonical_audit_node_id = params.new_canonical_node_id;
    this.canonicalAuditLastSeenAt = Date.now();
    this.canonicalAuditLossEmittedFor = null;
    this.opts.on_health_snapshot(this.snapshot(Date.now()));
    return emitted;
  }

  /**
   * Operator-acknowledged master rotation acceptance — emits gate_approved
   * tagged `master_rotation`. The cascade itself runs through
   * `MeshNode.installMasterRotation`; this is the operator-visible audit
   * trail of the acceptance.
   */
  acknowledgeMasterRotation(params: {
    new_master_pubkey: string;
    rotated_at: string;
    note?: string;
  }): EmittedAlert {
    return emitGateApproved(this.emit, {
      failure_mode: "master_rotation",
      target: params.new_master_pubkey,
      decision: "accept_master_rotation",
      detail: {
        rotated_at: params.rotated_at,
        note: params.note,
      },
    });
  }

  // ─────────────────────────────────────────────────────────────────────
  // Snapshot / introspection
  // ─────────────────────────────────────────────────────────────────────

  snapshot(nowMs: number = Date.now()): MeshHealthSnapshot {
    const rosterEntries = this.node.getRoster().listAll();
    const openAlerts = [...this.alerts.values()].filter(
      (a) => a.resolution.state === "open"
    );
    const openAlertsByNode = new Map<string, FailureMode[]>();
    for (const a of openAlerts) {
      const arr = openAlertsByNode.get(a.target_node) ?? [];
      arr.push(a.mode);
      openAlertsByNode.set(a.target_node, arr);
    }
    const rows: MeshHealthNodeRow[] = rosterEntries.map((e) => {
      const flags = openAlertsByNode.get(e.certificate.node_id) ?? [];
      return {
        node_id: e.certificate.node_id,
        presence: e.presence,
        flags,
        rollup: this.computeRollup(e.presence, flags),
        last_heartbeat_at: e.last_heartbeat_at || null,
        last_audit_seq: e.last_audit_seq,
      };
    });
    return {
      generated_at: nowMs,
      fortress_id: this.emit.fortress_id,
      observer_node: this.emit.emitter_node,
      nodes: rows,
      open_alerts: openAlerts,
      canonical_audit_node: this.opts.canonical_audit_node_id,
      canonical_audit_loss:
        this.canonicalAuditLossEmittedFor !== null,
    };
  }

  /** Read-only access to the open alerts list. */
  listAlerts(): FailureModeAlert[] {
    return [...this.alerts.values()];
  }

  /** Read-only access to the open split-brain conflicts. */
  listSplitBrainConflicts(): SplitBrainConflict[] {
    return [...this.splitBrainConflicts.values()];
  }

  /** Read-only — has the dmswitch fired (and unlocked guardian-revocation)? */
  isDmswitchUnlocked(): boolean {
    return this.dmswitchUnlockedFor;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Internals
  // ─────────────────────────────────────────────────────────────────────

  private makeAlert(params: {
    mode: FailureMode;
    target: string;
    message: string;
    detail: Record<string, unknown>;
  }): FailureModeAlert {
    return {
      alert_id: generateId(),
      mode: params.mode,
      target_node: params.target,
      detected_at: Date.now(),
      message: params.message,
      detail: params.detail,
      resolution: { state: "open" },
    };
  }

  private publishAlert(alert: FailureModeAlert): void {
    this.alerts.set(alert.alert_id, alert);
    this.opts.on_alert(alert);
  }

  private emitSentinel(alert: FailureModeAlert): EmittedAlert {
    return emitSentinelAlert(this.emit, {
      failure_mode: alert.mode,
      target: alert.target_node,
      detail: {
        alert_id: alert.alert_id,
        message: alert.message,
        ...alert.detail,
      },
    });
  }

  private computeRollup(
    presence: NodePresenceState,
    flags: FailureMode[]
  ): MeshHealthNodeRow["rollup"] {
    if (presence === "left") return "left";
    if (presence === "expired") return "expired";
    if (presence === "revoked") return "compromised";
    if (presence === "unreachable") return "unreachable";
    if (flags.includes(FAILURE_MODE.COMPROMISED)) return "compromised";
    if (flags.length > 0) return "degraded";
    return "ok";
  }
}

function generateId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

// Avoid unused-import errors for typed-only references.
void (null as unknown as AuditBatch);
void (null as unknown as PolicyUpdatePayload);
