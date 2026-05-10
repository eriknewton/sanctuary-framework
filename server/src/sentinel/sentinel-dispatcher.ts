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

import type { AuditLog } from "../l2-operational/audit-log.js";
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
    this.auditLog.append(
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
      this.auditLog.append(
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
          this.auditLog.append(
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
    this.auditLog.append(
      "l2",
      SENTINEL_AUDIT_OPS.FINDING_EMITTED,
      this.identityId,
      {
        sentinel_id: sentinelId,
        finding_id: stamped.finding_id,
        severity: stamped.severity,
        ...(stamped.agent_id !== undefined ? { agent_id: stamped.agent_id } : {}),
        evidence_audit_ids: stamped.evidence_audit_ids,
        fortress_id: this.fortressId,
      },
    );
    this.emit({ type: "finding", finding: stamped });
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
