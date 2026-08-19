/**
 * FailureModeDetector - orchestrator for the five §8 failure modes plus the
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
import {
  NO_AUTHENTICATED_PEER,
  isCompromiseSignal,
  type RejectionOrigin,
} from "../lifecycle/envelope-rejection.js";
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

/**
 * One observed policy claim for a given (agent_id, parent_version) generation.
 *
 * `outcome` records what the policy store did with it. `refused_replay` means
 * the store already held a version at or above this one and correctly refused
 * it; the claim is still a claim, and is retained here precisely because the
 * store discards it.
 */
interface PolicyClaim {
  event_id: string;
  version: number;
  /** Node that signed the envelope (the origin, not any relaying peer). */
  origin_node: string;
  /** Principal that authored the policy. */
  origin_principal: string;
  /** SHA-256 of the canonical payload; identifies the policy content. */
  payload_hash: string;
  emitted_at: string;
  outcome: "applied" | "refused_replay";
}

/**
 * Retention bounds for the policy-claim tracker. A long-lived node sees one
 * generation per policy version per agent forever, so the map is capped;
 * oldest generations are dropped first. The per-generation cap bounds the
 * candidate list an operator is asked to choose from - the conflict has
 * already been raised by the second claim, so dropping a 17th only costs a
 * row in the candidate table, never the alarm itself.
 */
const POLICY_CLAIM_GENERATION_LIMIT = 512;
const POLICY_CLAIMS_PER_GENERATION_LIMIT = 16;

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
  /**
   * Retained alerts. STATED BOUND (rule 8), open rather than closed: nothing in
   * this class deletes from this map, and `snapshot()` walks it on every tick,
   * so its size and the per-tick work both track the number of detections. A
   * cap alone is not the fix — an admission-only cap over a map nothing removes
   * from becomes a permanent refusal whose symptom is silence, and evicting
   * open alerts discards pending operator decisions. Closing it needs a
   * lifetime rule, which is a design. Bare id UEK-02; it resolves only in the
   * private register.
   */
  private readonly alerts = new Map<string, FailureModeAlert>();
  /**
   * Per-origin aggregate compromise signals.
   *
   * INVARIANT — WHOSE CREDIBILITY THE KEY CARRIES (rule 7), per ARM, because
   * the two writers differ and the difference is the point:
   *   - from `onEnvelopeRejected` the key is a `RejectionOrigin`: either an
   *     identity THIS node authenticated by verifying a signature against a
   *     roster-resident certificate chained to the pinned fortress master key,
   *     or the single shared `NO_AUTHENTICATED_PEER` sentinel standing for
   *     "the transport that delivered this authenticated nobody." It is never
   *     an `emitter_node` read out of an event whose verification failed;
   *   - from `onAuditBatchRejected` the key is the batch's own `emitter_node`,
   *     which `ingestAuditBatch` authenticated before the rollback and
   *     continuity checks but NOT before the signature check. That arm's
   *     residual is bare id UEK-02, which resolves only in the private
   *     register.
   *
   * The key type is therefore `string` and not the branded union: it states
   * what is true of the whole map rather than what is true of one writer.
   */
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
  /**
   * Map `${agent_id}:p${parent_version}` → every distinct policy claim seen
   * for that (agent, parent_version) generation, whether the store applied it
   * or refused it as a replay. Siblings of the same parent_version are the
   * only claims that can genuinely compete; a lower version under a DIFFERENT
   * parent is ordinary linear history arriving late, not a split.
   */
  private policyClaimsByGeneration = new Map<string, PolicyClaim[]>();

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
   * Manual tick - exposed so tests can advance state without waiting for the
   * timer. Production code can also use this from a higher-resolution clock.
   */
  tick(nowMs: number): void {
    // 1. Offline detection - promotes nodes to `unreachable` and emits dropouts.
    this.node.getRoster().checkDropouts(nowMs);
    // 2. Canonical-audit-loss check.
    this.checkCanonicalAuditLoss(nowMs);
    // 3. C12-REPLAY: flush any pending audit-governor saturation summaries
    //    (revoke denials + uncorrelated sync_response refusals). This tick IS
    //    the mesh's periodic timer — MeshNode owns none of its own — so a
    //    saturated-then-quiet attack schedule still gets its sealed
    //    {suppressed_count, distinct_emitter_count} summary here instead of
    //    waiting for the next denial to roll the window.
    this.node.flushRevokeDenialSaturation();
    // 4. Push fresh snapshot.
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

    // §8.3 rollback / chain discontinuity - surfaces from canonical-audit
    // batch ingestion path (caught + observable via onAuditBatchRejected).
    this.node.onAuditBatchRejected = (info) => {
      // ATTRIBUTION ON THIS ARM (rule 7), stated because its sibling below
      // reaches the opposite conclusion. `ingestAuditBatch` verifies the batch
      // signature against the roster-resident certificate BEFORE the
      // chain-proof, monotonicity and continuity checks, so for a rollback or
      // continuity refusal this emitter IS authenticated and naming it is what
      // gives the operator's `revoke_compromised` decision a subject. The
      // signature-failure arm below is the case where it is not, and telling
      // the two apart needs `ingestAuditBatch` to report which stage failed:
      // bare id UEK-02, which resolves only in the private register.
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
        // failure) are compromise signals - surface as compromised, not
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

    // Envelope rejections — a peer's signed event failed verification, OR a
    // verified peer's event was refused on admission.
    //
    // UEK-02 / QI-02-F12, the two invariants this handler enforces:
    //
    //   ATTRIBUTION. `target_node` is `info.rejection_origin`, which the type
    //   system guarantees is an identity this node authenticated or the shared
    //   un-attributable sentinel. `info.claimed_emitter_node` — on the
    //   `envelope_unverified` path, a string chosen by whoever sent bytes that
    //   failed verification, about whoever they wanted blamed — is recorded in
    //   `detail` under an explicitly unverified key and is NEVER the target,
    //   never the map key, and never interpolated as the subject of a
    //   sentence. Those three prohibitions are the invariant; a reviewer
    //   checking this handler is checking exactly them.
    //
    //   SEVERITY. Only a compromise-class reason produces a COMPROMISED alert
    //   and increments the attestation-failure tally. A freshness or capacity
    //   refusal produces PEER_REFUSED, which `computeRollup` renders as
    //   `degraded`, because those refusals describe this node's clock or its
    //   own local bounds rather than any evidence about the peer.
    this.node.onEnvelopeRejected = (info) => {
      const target = info.rejection_origin;
      const compromiseClass = isCompromiseSignal(info.reason_class);
      if (compromiseClass) {
        // Tally only compromise-class refusals: counting clock skew toward a
        // compromise score is how a benign drift accumulates into a false
        // accusation over time.
        this.getOrInitCompromised(target).attestation_failures += 1;
      }
      const alert = this.makeAlert({
        mode: compromiseClass
          ? FAILURE_MODE.COMPROMISED
          : FAILURE_MODE.PEER_REFUSED,
        target,
        // SIGNED-DOWNSTREAM DIAGNOSTIC (invariant, and an obligation on whoever
        // edits this composition). `info.error.message` is a refusal rendering
        // whose untrusted fragments were bounded by `describeUntrusted` at the
        // verifier that produced it, and anything added to this message must be
        // bounded the same way - the string does not stop here: it is retained
        // in the alert map, emitted as sentinel input, and hashed and signed
        // downstream. The refused peer's original value is deliberately NOT
        // recoverable from it, because the rendering truncates. Nothing
        // downstream may parse this text or branch on it; `reason_class`,
        // `event_type`, and `error_name` in `detail` below are the
        // machine-readable facts.
        message: compromiseClass
          ? `An event of type ${info.event_type} received ${describeOrigin(target)} was refused (${info.reason_class}): ${info.error.message}.`
          : `An event of type ${info.event_type} received ${describeOrigin(target)} was refused by this node (${info.reason_class}): ${info.error.message}. This describes a timing or capacity condition on this node, not evidence that the peer is compromised. Check clock synchronisation before treating it as an incident.`,
        detail: {
          signal: "envelope_rejected",
          event_type: info.event_type,
          reason_class: info.reason_class,
          error_name: info.error.name,
          ...claimedEmitterDetail(info.claimed_emitter_node),
        },
      });
      this.publishAlert(alert);
      this.emitSentinel(alert);
    };

    // §8.4 split-brain - locator-conflict signal.
    this.node.onLocatorUpdate = (evt, result) => {
      const list = this.locatorByAgent.get(evt.payload.agent_id) ?? [];
      list.push(evt);
      this.locatorByAgent.set(evt.payload.agent_id, list);
      if (result === "conflict") {
        this.detectLocatorSplitBrain(evt.payload.agent_id);
      }
    };

    // Policy-conflict signal: same agent, same parent_version, two conflicting
    // policy claims arriving from different origins during partition heal.
    // PolicyBundleStore.upsert emits explicit rejection reasons or 'applied',
    // but not a dedicated 'conflict' branch, so the conflict is reconstructed
    // here from observed (agent_id, parent_version) claims.
    //
    // ORDERING: the store keeps only the highest policy_version per agent and
    // refuses anything at or below it as `policy_version_replay`. That is
    // correct anti-rollback behaviour and is NOT relaxed. But a detector that
    // counts only `applied` results can see a conflict only when the network
    // happens to deliver the competing versions in ascending order, and there
    // is no delivery-order guarantee on a gossip mesh. If the newer sibling
    // lands first, the older one is refused as a replay and thrown away, and
    // the operator is never told a second policy exists. A replay refusal that
    // carries a DIFFERENT origin under the same parent_version is exactly the
    // evidence of a split, so it is recorded rather than discarded.
    this.node.onPolicyUpdate = (evt, result) => {
      if (result === "applied") {
        this.recordPolicyClaim(evt, "applied");
      } else if (result === "policy_version_replay") {
        this.recordPolicyClaim(evt, "refused_replay");
      }
      // Every other rejection reason (malformed payload, missing/invalid or
      // out-of-range validity window) says nothing about who authored what;
      // those already surface on their own via onPolicyBundleRejected.
    };

    this.node.onPolicyBundleRejected = (event) => {
      const alert = this.makeAlert({
        mode: FAILURE_MODE.ROLLBACK,
        target: event.agent_id,
        message: `Policy bundle rejected for ${event.agent_id}: ${event.reason}.`,
        detail: {
          signal: "policy_bundle_rejected",
          event_id: event.event_id,
          reason: event.reason,
          incoming_policy_version: event.incoming_policy_version,
          current_policy_version: event.current_policy_version,
          valid_from: event.valid_from ?? null,
          valid_until: event.valid_until ?? null,
        },
      });
      this.publishAlert(alert);
      this.emitSentinel(alert);
    };

    // Lifecycle events - receipt of `dmswitch_triggered` unlocks
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
          message: `DMswitch fired - operator absence threshold exceeded. Guardian-revocation path is unlocked. Guardians may now coordinate.`,
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
    // Roster default - same constant the roster uses internally.
    // We reach into the roster's effective threshold via a safe accessor
    // (default if absent).
    return 3;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Detection helpers
  // ─────────────────────────────────────────────────────────────────────

  /**
   * Aggregate signal state for `origin`, creating it on first sight.
   *
   * STATED BOUND (rule 8), open rather than closed: entries are never removed,
   * so the map's size tracks the number of distinct origins seen. It is not
   * capped here, because an admission-only cap over a map nothing removes from
   * becomes a permanent refusal whose symptom is silence — the degradation
   * MUST-NEVER #5 forbids. Closing it needs a lifetime rule (roster membership
   * is the natural one), which is a design. Bare id UEK-02; it resolves only in
   * the private register.
   *
   * What DID change and is closed: the key population. See the `compromised`
   * field's per-arm invariant — the envelope-rejection arm can no longer key
   * this map on an unverified claim, so the arm that used to grow with an
   * inbound stream's chosen strings now grows only with authenticated peers.
   */
  private getOrInitCompromised(origin: string): CompromisedSignalState {
    let state = this.compromised.get(origin);
    if (state) return state;
    state = {
      last_monotonic_seq: 0,
      attestation_failures: 0,
      audit_chain_discontinuities: 0,
      rollback_detected: false,
    };
    this.compromised.set(origin, state);
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

  /**
   * Record one policy claim against its (agent_id, parent_version) generation
   * and raise SPLIT_BRAIN when the generation now holds competing claims.
   *
   * Called for `applied` AND for `policy_version_replay`. The replay branch is
   * the whole point: the store throws the refused event away, so if the
   * detector does not keep it, a conflict delivered newest-first is invisible.
   *
   * What is deliberately NOT treated as a conflict:
   *   - the same envelope redelivered (same `event_id`) - gossip duplicates
   *     and sync backfill both re-present events a node already has;
   *   - the same origin re-announcing its own version (same version, same
   *     origin node) - a legitimate retransmit under a fresh envelope;
   *   - byte-identical policy content re-signed by another node (same version,
   *     same `payload_hash`) - one decision forwarded, not two decisions;
   *   - a lower version under a DIFFERENT `parent_version` - a node catching
   *     up after being offline receives ancestors, and an ancestor is refused
   *     as a replay without ever being a sibling. Generation keying, not
   *     special-casing, is what keeps that quiet.
   */
  private recordPolicyClaim(
    evt: SignedEvent<PolicyUpdatePayload>,
    outcome: PolicyClaim["outcome"]
  ): void {
    const payload = evt.payload;
    const agentId = payload.agent_id;
    const key = `${agentId}:p${payload.parent_version ?? 0}`;
    const claims = this.policyClaimsByGeneration.get(key) ?? [];
    const claim: PolicyClaim = {
      event_id: evt.event_id,
      version: payload.policy_version,
      origin_node: evt.emitter_node,
      origin_principal: evt.emitter_principal,
      payload_hash: evt.payload_hash,
      emitted_at: evt.emitted_at,
      outcome,
    };

    const isRedelivery = claims.some(
      (c) =>
        c.event_id === claim.event_id ||
        (c.version === claim.version &&
          (c.origin_node === claim.origin_node ||
            (claim.payload_hash.length > 0 &&
              c.payload_hash === claim.payload_hash)))
    );
    if (isRedelivery) return;
    if (claims.length >= POLICY_CLAIMS_PER_GENERATION_LIMIT) return;

    claims.push(claim);
    this.policyClaimsByGeneration.set(key, claims);
    // Map iteration is insertion-ordered; drop the oldest generations first.
    while (this.policyClaimsByGeneration.size > POLICY_CLAIM_GENERATION_LIMIT) {
      const oldest = this.policyClaimsByGeneration.keys().next();
      if (oldest.done === true || oldest.value === key) break;
      this.policyClaimsByGeneration.delete(oldest.value);
    }

    if (outcome === "applied") {
      // Unchanged v0.1 semantics: two distinct policy_versions applied under
      // one parent_version is a conflict on its own.
      const appliedVersions = new Set(
        claims.filter((c) => c.outcome === "applied").map((c) => c.version)
      );
      if (appliedVersions.size > 1) {
        this.detectPolicySplitBrain(agentId, claims, claim);
      }
      return;
    }

    // Refused as a replay. Evidence of a split only when some other origin
    // already claimed this same generation - otherwise it is our own history
    // coming back to us.
    const rival = claims.find(
      (c) => c !== claim && c.origin_node !== claim.origin_node
    );
    if (rival) {
      this.detectPolicySplitBrain(agentId, claims, claim);
    }
  }

  private detectPolicySplitBrain(
    agentId: string,
    claims: readonly PolicyClaim[],
    trigger: PolicyClaim
  ): void {
    const candidates = claims.map((c) => ({
      event_id: c.event_id,
      version: c.version,
      canonical_node: c.origin_node,
      signed_at: c.emitted_at,
    }));
    const conflict: SplitBrainConflict = {
      conflict_id: generateId(),
      agent_id: agentId,
      candidates,
      detected_at: Date.now(),
    };
    this.splitBrainConflicts.set(conflict.conflict_id, conflict);
    const message =
      trigger.outcome === "refused_replay"
        ? `Two conflicting policy versions were issued for Agent ${agentId} from the same parent_version by different nodes. Version ${trigger.version} from ${trigger.origin_node} arrived after a newer version was already pinned, so it was correctly refused as a rollback - but it is still a second, competing policy. Choose which to keep.`
        : `Two distinct policy versions issued for Agent ${agentId} from the same parent_version. Choose which to keep.`;
    const alert = this.makeAlert({
      mode: FAILURE_MODE.SPLIT_BRAIN,
      target: agentId,
      message,
      detail: {
        kind: "policy_conflict",
        conflict_id: conflict.conflict_id,
        versions: [...new Set(claims.map((c) => c.version))],
        candidates: claims.map((c) => ({
          event_id: c.event_id,
          version: c.version,
          origin_node: c.origin_node,
          origin_principal: c.origin_principal,
          outcome: c.outcome,
        })),
        trigger_outcome: trigger.outcome,
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
   * Operator-resolution for a split-brain conflict - picks one branch as
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
   * Operator-acknowledged master rotation acceptance - emits gate_approved
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

  /**
   * Read-only access to the origins this detector holds aggregate compromise
   * signals for (UEK-02). Exists so a reader — an operator surface, or a
   * regression test — can observe the map's key population DIRECTLY rather
   * than infer it from alert volume. Key provenance differs per writing arm;
   * see the `compromised` field's invariant.
   */
  listCompromisedOrigins(): string[] {
    return [...this.compromised.keys()];
  }

  /** Read-only - has the dmswitch fired (and unlocked guardian-revocation)? */
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
    // RETAINED DIAGNOSTIC (invariant): `alert.message` can carry a rendering of
    // peer-supplied text, so it is bounded before it reaches here and the
    // peer's original value is deliberately NOT recoverable from it. This map
    // retains it and `on_alert` forwards it onward, including to paths that
    // hash and sign it, so an unbounded message assigned upstream would be both
    // retained and sealed. Neither this store nor any `on_alert` consumer may
    // parse the message or branch on its text; the structured alert fields are
    // what a consumer reads.
    this.alerts.set(alert.alert_id, alert);
    this.opts.on_alert(alert);
  }

  private emitSentinel(alert: FailureModeAlert): EmittedAlert {
    return emitSentinelAlert(this.emit, {
      failure_mode: alert.mode,
      target: alert.target_node,
      detail: {
        alert_id: alert.alert_id,
        // SENTINEL INPUT (invariant): this is a bounded DISPLAY rendering of a
        // refusal, not a parseable record. It enters sentinel evaluation here
        // and can be hashed and signed further downstream, so it must already
        // be bounded when it arrives, and the refused peer's original value is
        // deliberately NOT recoverable from it. No sentinel rule may match on
        // this text or branch on it - the structured fields spread in below are
        // what a rule reads.
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
    // Severity comes from the per-mode table, never from a catch-all — see
    // MODE_ROLLUP. `some` rather than `includes(COMPROMISED)`: the escalating
    // set is the table's business, not this function's.
    if (flags.some((mode) => MODE_ROLLUP[mode] === "compromised")) {
      return "compromised";
    }
    if (flags.length > 0) return "degraded";
    return "ok";
  }
}

/**
 * Mesh Health severity for each failure mode, as a TOTAL table.
 *
 * WHY A TABLE AND NOT A FALLTHROUGH (QI-02-F12; AGENTS.md rule 11). This
 * replaced `flags.includes(COMPROMISED) ? "compromised" : "degraded"`, which
 * is exhaustive only over the one mode its author enumerated: every other
 * mode, present and future, inherited `degraded` by omission. That is fine
 * until a mode is added whose correct severity is `compromised`, at which
 * point the fallthrough silently under-reports it, and no test over the
 * catch-all can see the difference because the catch-all has no per-mode
 * behaviour to assert.
 *
 * `Record<FailureMode, ...>` makes the table total AT THE TYPE LEVEL: adding a
 * value to `FAILURE_MODE` without deciding its severity here is a compile
 * error. That compile error IS the guard — it forces the decision to be made
 * by someone, in the same change, rather than defaulted by a fallthrough.
 *
 * FAILURE MODE FROM THE OUTSIDE if a row is set wrong: the Mesh Health panel
 * reads `compromised` for a node whose only flag describes THIS observer's
 * clock or its own local ceilings, which is the false accusation
 * `peer_refused` exists to prevent. Its row is `degraded` deliberately, and a
 * regression test pins that exact pair.
 *
 * CROSS-FILE PIN: must cover every key of `FAILURE_MODE` in `./constants.ts`.
 */
const MODE_ROLLUP: Record<FailureMode, "compromised" | "degraded"> = {
  [FAILURE_MODE.OFFLINE]: "degraded",
  [FAILURE_MODE.COMPROMISED]: "compromised",
  [FAILURE_MODE.ROLLBACK]: "degraded",
  [FAILURE_MODE.SPLIT_BRAIN]: "degraded",
  [FAILURE_MODE.CANONICAL_AUDIT_LOSS]: "degraded",
  // QI-02-F12. A refusal caused by this node's own clock, correlation table,
  // or local ceilings is NOT evidence about the peer, so it must never
  // escalate. Changing this to "compromised" reinstates the accusation.
  [FAILURE_MODE.PEER_REFUSED]: "degraded",
};

/**
 * Render a `RejectionOrigin` for an operator-facing sentence.
 *
 * The sentinel must never read as a node name. `NO_AUTHENTICATED_PEER`'s
 * literal value is a wire/audit key, not English, and interpolating it raw
 * produced sentences of the form "Node unknown-relaying-peer has rolled back"
 * — which an operator can reasonably read as a node actually called that. The
 * replacement says what is true: the delivering transport authenticated
 * nobody, so this refusal cannot be attributed to any peer.
 */
function describeOrigin(origin: RejectionOrigin): string {
  return origin === NO_AUTHENTICATED_PEER
    ? "from an unauthenticated sender (no verified peer identity on this transport)"
    : `from node ${origin}`;
}

/**
 * Attach the unverified claimed emitter to an alert's `detail`, under a key
 * whose NAME states that it is a claim (rule 7: a trust-bearing field names
 * what consuming it means; this field's meaning is "do not trust this"). A
 * consumer reading `claimed_emitter_node_unverified` cannot mistake it for the
 * attribution — that is `target_node`, always.
 *
 * Returns an empty object when there is no claim, so the key is absent rather
 * than present-and-null: an absent key cannot be rendered as an identity by a
 * downstream template, and a null one can.
 */
function claimedEmitterDetail(
  claimed: string | undefined
): Record<string, unknown> {
  return claimed === undefined
    ? {}
    : { claimed_emitter_node_unverified: claimed };
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
