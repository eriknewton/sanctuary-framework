/**
 * Sanctuary v1.3 WP-V1.3-1 Sentinel Dispatcher.
 *
 * Drives the sentinel evaluation tick. On each tick:
 *  1. For every subscribed sentinel, call `evaluate()`.
 *  2. Each returned finding routes to:
 *     - the sentinel finding store (encrypted persistence)
 *     - the audit log (`sentinel_finding_emitted`)
 *     - in-process subscribers (dashboard SSE wires through this)
 *  3. Per-sentinel exceptions log `sentinel_evaluation_failed` and the
 *     dispatcher continues with the next sentinel.
 *
 * The dispatcher is one-per-fortress. The fortress id is stamped on
 * every finding before persistence + emission so multi-fortress
 * isolation holds at the cryptographic + structural layers both.
 *
 * Castle-walking discipline: the dispatcher introduces no outbound
 * surface. It reads from the audit log, writes to the encrypted
 * findings store + audit log, and emits to in-process subscribers.
 */

import { randomUUID } from "node:crypto";

import type { AuditLog } from "../operational/audit-log.js";
import type { Sentinel } from "./sentinel.js";
import type { SentinelRegistry } from "./sentinel-registry.js";
import type { SentinelFindingStore } from "./sentinel-finding-store.js";
import {
  SENTINEL_AUDIT_OPS,
  type SentinelContext,
  type SentinelFinding,
} from "./types.js";

export type SentinelDispatcherUnsubscribe = () => void;

/**
 * Event emitted to in-process subscribers when a finding is produced.
 * The dashboard SSE pipeline subscribes here.
 */
export interface SentinelDispatcherEmit {
  type: "finding";
  finding: SentinelFinding;
}

/**
 * Event emitted on per-sentinel evaluation failure. Distinct from
 * `finding` so subscribers can render diagnostics separately.
 */
export interface SentinelDispatcherFailureEmit {
  type: "evaluation_failed";
  sentinel_id: string;
  error_message: string;
  observed_at: string;
}

export type SentinelDispatcherAnyEmit =
  | SentinelDispatcherEmit
  | SentinelDispatcherFailureEmit;

export interface SentinelDispatcherDeps {
  registry: SentinelRegistry;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  /** Stable fortress id stamped on every finding. */
  fortressId: string;
  /** Operator identity id for audit attribution. */
  identityId: string;
  /** Wall-clock provider for deterministic tests. */
  now?: () => Date;
  /** Tick interval, ms. Default 60s. Set to 0 to disable auto-tick. */
  tickIntervalMs?: number;
}

const DEFAULT_TICK_INTERVAL_MS = 60_000;

export class SentinelDispatcher {
  private readonly registry: SentinelRegistry;
  private readonly findingStore: SentinelFindingStore;
  private readonly auditLog: AuditLog;
  private readonly fortressId: string;
  private readonly identityId: string;
  private readonly now: () => Date;
  private readonly tickIntervalMs: number;
  private readonly listeners = new Set<
    (event: SentinelDispatcherAnyEmit) => void
  >();
  private tickTimer: NodeJS.Timeout | null = null;
  private tickInFlight = false;

  constructor(deps: SentinelDispatcherDeps) {
    this.registry = deps.registry;
    this.findingStore = deps.findingStore;
    this.auditLog = deps.auditLog;
    this.fortressId = deps.fortressId;
    this.identityId = deps.identityId;
    this.now = deps.now ?? (() => new Date());
    this.tickIntervalMs = deps.tickIntervalMs ?? DEFAULT_TICK_INTERVAL_MS;
  }

  /** Read-only view of the registry. Convenience for route handlers. */
  getRegistry(): SentinelRegistry {
    return this.registry;
  }

  /** Read-only view of the finding store. Convenience for route handlers. */
  getFindingStore(): SentinelFindingStore {
    return this.findingStore;
  }

  /**
   * Subscribe an in-process listener. Returns an unsubscribe fn.
   */
  onEvent(
    listener: (event: SentinelDispatcherAnyEmit) => void,
  ): SentinelDispatcherUnsubscribe {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Subscribe a sentinel to this fortress + emit the
   * `sentinel_subscribed` audit event. Wraps `registry.subscribe()` so
   * the audit emission lives at the dispatcher boundary (the
   * fortress-aware site).
   */
  async subscribeSentinel(
    sentinelId: string,
    contextOverrides?: Partial<SentinelContext>,
  ): Promise<Sentinel> {
    const context: SentinelContext = {
      fortressId: this.fortressId,
      auditLog: this.auditLog,
      now: this.now,
      // Phi-5 meta-sentinel reads the per-fortress finding store to
      // detect patterns across other sentinels' findings. First-order
      // sentinels ignore the field; the dispatcher always attaches it
      // because the store is already in scope here.
      findingStore: this.findingStore,
      ...(contextOverrides ?? {}),
    };
    const sentinel = await this.registry.subscribe(sentinelId, context);
    void this.auditLog.append(
      "l2",
      SENTINEL_AUDIT_OPS.SUBSCRIBED,
      this.identityId,
      { sentinel_id: sentinelId, fortress_id: this.fortressId },
    );
    return sentinel;
  }

  /**
   * Unsubscribe + emit `sentinel_unsubscribed`. Returns true when an
   * active subscription was torn down. Audit fires only on successful
   * removal.
   */
  async unsubscribeSentinel(sentinelId: string): Promise<boolean> {
    const removed = await this.registry.unsubscribe(sentinelId);
    if (removed) {
      void this.auditLog.append(
        "l2",
        SENTINEL_AUDIT_OPS.UNSUBSCRIBED,
        this.identityId,
        { sentinel_id: sentinelId, fortress_id: this.fortressId },
      );
    }
    return removed;
  }

  /**
   * Run one evaluation pass over every subscribed sentinel. Used by
   * the auto-tick AND by tests that want a synchronous evaluation
   * gate. Returns the findings produced this tick (already persisted
   * + audit-logged + emitted).
   */
  async tick(): Promise<SentinelFinding[]> {
    if (this.tickInFlight) return [];
    this.tickInFlight = true;
    try {
      const subscribed = this.registry.snapshotSubscribed();
      const findings: SentinelFinding[] = [];
      for (const { sentinelId, sentinel } of subscribed) {
        try {
          const tickFindings = await sentinel.evaluate();
          for (const finding of tickFindings) {
            const stamped = await this.routeFinding(sentinelId, finding);
            findings.push(stamped);
          }
        } catch (err) {
          const errorMessage = err instanceof Error ? err.message : String(err);
          const observedAt = this.now().toISOString();
          void this.auditLog.append(
            "l2",
            SENTINEL_AUDIT_OPS.EVALUATION_FAILED,
            this.identityId,
            {
              sentinel_id: sentinelId,
              fortress_id: this.fortressId,
              error_message: errorMessage,
            },
            "failure",
          );
          this.emit({
            type: "evaluation_failed",
            sentinel_id: sentinelId,
            error_message: errorMessage,
            observed_at: observedAt,
          });
        }
      }
      return findings;
    } finally {
      this.tickInFlight = false;
    }
  }

  /**
   * Start the auto-tick loop. No-op when tickIntervalMs is 0 or when
   * already started. Tests typically leave auto-tick off and call
   * `tick()` directly.
   */
  start(): void {
    if (this.tickTimer !== null) return;
    if (this.tickIntervalMs <= 0) return;
    this.tickTimer = setInterval(() => {
      void this.tick();
    }, this.tickIntervalMs);
    if (typeof this.tickTimer.unref === "function") {
      this.tickTimer.unref();
    }
  }

  /** Stop the auto-tick loop. Idempotent. */
  stop(): void {
    if (this.tickTimer === null) return;
    clearInterval(this.tickTimer);
    this.tickTimer = null;
  }

  /**
   * Tear down every subscription + stop the tick loop. Called on
   * fortress shutdown.
   */
  async dispose(): Promise<void> {
    this.stop();
    await this.registry.unsubscribeAll();
    this.listeners.clear();
  }

  private async routeFinding(
    sentinelId: string,
    raw: SentinelFinding,
  ): Promise<SentinelFinding> {
    const stamped: SentinelFinding = {
      ...raw,
      finding_id: raw.finding_id || randomUUID(),
      sentinel_id: sentinelId,
      fortress_id: this.fortressId,
      observed_at: raw.observed_at || this.now().toISOString(),
    };
    await this.findingStore.saveFinding(stamped);
    // LD6 BP-DEADLINE-03 (V2-5 sentinel exception): AWAITED appendCritical
    // immediately AFTER the locked saveFinding, NOT folded into
    // saveFinding's own admission section -- a saturated saveFinding can
    // already emit an evict-INTENT appendCritical (up to
    // ON_EVICT_AUDIT_TIMEOUT_MS = 40s, its withTimeout bound) inside its
    // lock; adding this bare 35s-worst-case audit write there would need
    // up to 40s + 35s = 75s against the shared 50s admission-deadline
    // budget (see sentinel-finding-store.ts's STORE_ADMISSION_DEADLINE_MS
    // derivation; the 75s figure must match the asymmetry notes on
    // BRIDGE_STORE_ADMISSION_DEADLINE_MS in bridge/tools.ts and
    // REPUTATION_STORE_ADMISSION_DEADLINE_MS in reputation-store.ts).
    //
    // HONEST BOUND (fix-round correction -- the prior comment here claimed
    // "finding_id already gives this store I2/I3 (overwrite-in-place on a
    // retry)"; that was FALSE for every shipped sentinel): every sentinel in
    // src/sentinel/sentinels/*.ts emits `finding_id: ""`, so the stamp above
    // (`raw.finding_id || randomUUID()`) mints a FRESH random id on every
    // single finding, every tick -- there is no caller-supplied or
    // content-derived key for a later tick to land back on. A crash between
    // saveFinding settling and this append settling leaves a
    // durably-persisted-but-PERMANENTLY-unaudited orphan record: the NEXT
    // tick's finding (even one describing the same underlying condition,
    // e.g. egress-volume-watcher re-detecting the same server's ongoing
    // anomaly) gets its OWN new random id and its OWN new audit attempt --
    // it does not overwrite or reconcile the orphan the way a bridge_commit/
    // bridge_attest/reputation_record retry does (V2-2's self-healing
    // in-lock audits, which DO have a caller-supplied identifying tuple to
    // derive a stable id from).
    //
    // This is an ACCEPTED, weaker residual, not a bug to silently paper
    // over: sentinels are timer-driven autonomous detectors, not
    // caller-retried operations, and most sentinels' rolling-window findings
    // (current_count, evidence_audit_ids, observed_at) genuinely differ tick
    // to tick even when the underlying condition persists -- there is no
    // sentinel-agnostic "condition key" this dispatcher could derive a
    // stable id from without sentinel-specific semantics it does not have,
    // and collapsing distinct ticks' evidence onto one overwritten key would
    // silently lose that evidence.
    //
    // HONEST BOUND, part 2 (LD6 gate fix-round F3 -- batch isolation): the
    // append is still AWAITED (never fire-and-forget: the outcome must be
    // KNOWN before this method reports), but its failure no longer
    // propagates out of routeFinding. The finding was already durably
    // persisted by saveFinding above, so suppressing the ANOMALY over an
    // audit-backend failure inverts the priority: pre-fix, the rejection
    // escaped into tick()'s per-sentinel catch, which (a) never emitted the
    // finding to subscribers (the dashboard saw `evaluation_failed` carrying
    // the audit error INSTEAD of the anomaly) and (b) aborted every
    // remaining finding in that sentinel's batch -- none persisted, none
    // audited, none emitted. Now the finding is emitted to subscribers
    // regardless of audit-append outcome, and an audit failure surfaces as
    // its OWN `evaluation_failed` diagnostic event alongside the finding
    // (no `void append` back into the sink that just failed -- that
    // "surfacing" would be a write into the very backend whose failure it
    // reports). The durable-write-then-awaited-audit ORDERING is unchanged;
    // the crash-window no-self-heal residual above is unchanged.
    let auditAppendError: unknown = null;
    try {
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: SENTINEL_AUDIT_OPS.FINDING_EMITTED,
        identity_id: this.identityId,
        result: "success",
        details: {
          sentinel_id: sentinelId,
          finding_id: stamped.finding_id,
          severity: stamped.severity,
          ...(stamped.agent_id !== undefined ? { agent_id: stamped.agent_id } : {}),
          evidence_audit_ids: stamped.evidence_audit_ids,
          fortress_id: this.fortressId,
        },
      });
    } catch (err) {
      auditAppendError = err;
    }
    // The finding is durable (saveFinding settled above); subscribers get it
    // whether or not its audit landed -- the anomaly outranks its paper trail.
    this.emit({ type: "finding", finding: stamped });
    if (auditAppendError !== null) {
      const errorMessage =
        auditAppendError instanceof Error
          ? auditAppendError.message
          : String(auditAppendError);
      this.emit({
        type: "evaluation_failed",
        sentinel_id: sentinelId,
        error_message:
          `finding audit append failed (finding ${stamped.finding_id} is ` +
          `durably persisted but its FINDING_EMITTED audit entry is not): ` +
          errorMessage,
        observed_at: this.now().toISOString(),
      });
    }
    return stamped;
  }

  private emit(event: SentinelDispatcherAnyEmit): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener exceptions never fail the dispatcher tick.
      }
    }
  }
}
