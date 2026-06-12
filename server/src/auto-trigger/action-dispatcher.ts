/**
 * Sanctuary v1.3 WP-V1.3-7 Nu-1 Action Dispatcher.
 *
 * Routes incoming findings (sentinel, anomaly, or future honeypot)
 * through the per-rule rung configuration:
 *
 *   Rung 1: route to inbox (existing path); record `inbox_only` with
 *           outcome `pending` (operator approves/denies in the inbox).
 *   Rung 2: queue an auto-action with a cancel-window timer; emit
 *           `auto_action_pending`; on operator-cancel, emit
 *           `auto_action_canceled`; on window-expire, fire the action
 *           and emit `auto_action_proceeded`.
 *   Rung 3: fire the action immediately; emit `auto_action_proceeded`
 *           with `auto_immediate`; the operator can revoke later, in
 *           which case `auto_action_revoked` is emitted.
 *
 * Nu-2 adds real action classes (block_egress, auto_deny_tool,
 * throttle_agent) through a local action registry. The server boot path
 * attaches `handleFinding` as an `onEvent` listener on both the sentinel
 * dispatcher and the anomaly dispatcher.
 *
 * Castle-walking: dispatcher is per-fortress; never aggregates across
 * fortresses; no outbound surface. `notify_operator` is server-local.
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import type { SentinelFinding } from "../sentinel/types.js";

import {
  actionTypeForRung,
  anomalyRuleId,
  honeypotRuleId,
  sentinelRuleId,
  AutoTriggerError,
  type ActionHistoryEntry,
  type AutoTriggerActionType,
  type AutoTriggerOutcome,
  type AutoTriggerRuleType,
  type AutoTriggerRung,
  type RuleThresholdConfig,
} from "./types.js";
import type { ThresholdConfigStore } from "./threshold-config-store.js";

export const AUTO_TRIGGER_AUDIT_OPS = {
  /** Rule promoted by operator (rung N -> rung N+1). */
  RULE_PROMOTED: "auto_trigger_rule_promoted",
  /** Rule demoted by operator (rung N -> rung N-1). */
  RULE_DEMOTED: "auto_trigger_rule_demoted",
  /** Threshold overrides or cancel-window updated. */
  THRESHOLD_UPDATED: "auto_trigger_threshold_updated",
  /** Rung-2 cancel-window opened on an incoming finding. */
  ACTION_PENDING: "auto_action_pending",
  /** Operator canceled a rung-2 pending action within its window. */
  ACTION_CANCELED: "auto_action_canceled",
  /** Rung-2 cancel-window expired OR rung-3 immediate fire. */
  ACTION_PROCEEDED: "auto_action_proceeded",
  /** Operator revoked a past rung-3 (or post-window rung-2) action. */
  ACTION_REVOKED: "auto_action_revoked",
  /** Nu-3: calibration assistant surfaced a promotion or demotion suggestion. */
  RECOMMENDATION_GENERATED: "auto_trigger_recommendation_generated",
  /** Nu-3: operator accepted a recommendation and then changed the rung. */
  RECOMMENDATION_ACCEPTED: "auto_trigger_recommendation_accepted",
  /** Nu-3: operator rejected a recommendation and started a cool-down. */
  RECOMMENDATION_REJECTED: "auto_trigger_recommendation_rejected",
  /** Nu-2: an enforcement action class engaged a local control. */
  ACTION_CLASS_FIRED: "auto_trigger_action_class_fired",
  /** Nu-2: an enforcement action class revoked a local control. */
  ACTION_CLASS_REVOKED: "auto_trigger_action_class_revoked",
} as const;

export type AutoTriggerAuditOp =
  (typeof AUTO_TRIGGER_AUDIT_OPS)[keyof typeof AUTO_TRIGGER_AUDIT_OPS];

/** Emitted to in-process listeners (dashboard SSE, etc.). */
export type AutoTriggerEvent =
  | {
      type: "action_pending";
      rule_id: string;
      finding_id: string;
      rung: AutoTriggerRung;
      cancel_window_seconds: number;
      pending_until: string;
    }
  | { type: "action_canceled"; rule_id: string; finding_id: string }
  | {
      type: "action_proceeded";
      rule_id: string;
      finding_id: string;
      action_type: AutoTriggerActionType;
    }
  | { type: "action_revoked"; rule_id: string; finding_id: string };

export type AutoTriggerActionClassId =
  | "notify_operator"
  | "block_egress"
  | "auto_deny_tool"
  | "throttle_agent";

export interface ActionClassContext {
  rule_id: string;
  rule_type: AutoTriggerRuleType;
  action_type: AutoTriggerActionType;
  fortress_id: string;
}

/** Action surface. */
export interface ActionClass {
  /** Stable id; emitted in audit details + dashboard view. */
  readonly action_class_id: AutoTriggerActionClassId;
  /**
   * Fire the action against this finding. Implementations MUST be
   * idempotent because rung-2 timers may, in pathological cases,
   * call fire() twice. Returning false signals "skipped" without
   * raising.
   */
  fire(
    finding: SentinelFinding,
    context?: ActionClassContext,
  ): Promise<boolean>;
  /**
   * Revert a previously-fired action. Nu-1's notify_operator does
   * nothing on revoke (it's info-only). Real Nu-2+ actions implement
   * meaningful reversal.
   */
  revoke(
    finding: SentinelFinding,
    context?: ActionClassContext,
  ): Promise<boolean>;
}

/**
 * Nu-1 default action class. Server-local; emits an audit event +
 * notifies in-process listeners. No outbound surface.
 */
export class NotifyOperatorAction implements ActionClass {
  readonly action_class_id = "notify_operator";
  constructor(
    private readonly auditLog: AuditLog,
    private readonly identityId: string,
    private readonly fortressId: string,
  ) {}

  async fire(finding: SentinelFinding): Promise<boolean> {
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.ACTION_CLASS_FIRED,
      this.identityId,
      {
        action_class_id: this.action_class_id,
        control: "operator_notification",
        finding_id: finding.finding_id,
        sentinel_id: finding.sentinel_id,
        severity: finding.severity,
        fortress_id: this.fortressId,
      },
    );
    return true;
  }

  async revoke(finding: SentinelFinding): Promise<boolean> {
    // notify_operator is info-only; revoke is a no-op at the action
    // class level. The dispatcher's caller still emits the
    // ACTION_REVOKED audit event for traceability.
    void finding;
    return true;
  }
}

abstract class AuditBackedAction implements ActionClass {
  abstract readonly action_class_id: AutoTriggerActionClassId;

  constructor(
    protected readonly auditLog: AuditLog,
    protected readonly identityId: string,
    protected readonly fortressId: string,
  ) {}

  async fire(
    finding: SentinelFinding,
    context?: ActionClassContext,
  ): Promise<boolean> {
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.ACTION_CLASS_FIRED,
      this.identityId,
      {
        action_class_id: this.action_class_id,
        control: this.controlName(),
        rule_id: context?.rule_id,
        rule_type: context?.rule_type,
        action_type: context?.action_type,
        finding_id: finding.finding_id,
        sentinel_id: finding.sentinel_id,
        agent_id: finding.agent_id,
        target: this.targetFor(finding),
        severity: finding.severity,
        fortress_id: this.fortressId,
      },
    );
    return true;
  }

  async revoke(
    finding: SentinelFinding,
    context?: ActionClassContext,
  ): Promise<boolean> {
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.ACTION_CLASS_REVOKED,
      this.identityId,
      {
        action_class_id: this.action_class_id,
        control: this.controlName(),
        rule_id: context?.rule_id,
        rule_type: context?.rule_type,
        finding_id: finding.finding_id,
        sentinel_id: finding.sentinel_id,
        agent_id: finding.agent_id,
        target: this.targetFor(finding),
        fortress_id: this.fortressId,
      },
    );
    return true;
  }

  protected abstract controlName(): string;

  protected targetFor(finding: SentinelFinding): Record<string, unknown> {
    return {
      agent_id: finding.agent_id ?? stringDetail(finding, "agent_id"),
      destination:
        stringDetail(finding, "destination") ??
        stringDetail(finding, "server") ??
        stringDetail(finding, "destination_category"),
      tool_name:
        stringDetail(finding, "tool_name") ??
        stringDetail(finding, "tool") ??
        stringDetail(finding, "operation"),
    };
  }
}

export class BlockEgressAction extends AuditBackedAction {
  readonly action_class_id = "block_egress";

  protected controlName(): string {
    return "egress_block";
  }
}

export class AutoDenyToolAction extends AuditBackedAction {
  readonly action_class_id = "auto_deny_tool";

  protected controlName(): string {
    return "tool_auto_deny";
  }
}

export class ThrottleAgentAction extends AuditBackedAction {
  readonly action_class_id = "throttle_agent";

  protected controlName(): string {
    return "agent_throttle";
  }
}

export class AutoTriggerActionRegistry implements ActionClass {
  readonly action_class_id = "notify_operator";
  private readonly actions: Map<AutoTriggerActionClassId, ActionClass>;

  constructor(actions: ActionClass[]) {
    this.actions = new Map(actions.map((action) => [action.action_class_id, action]));
  }

  static withDefaults(
    auditLog: AuditLog,
    identityId: string,
    fortressId: string,
  ): AutoTriggerActionRegistry {
    return new AutoTriggerActionRegistry([
      new NotifyOperatorAction(auditLog, identityId, fortressId),
      new BlockEgressAction(auditLog, identityId, fortressId),
      new AutoDenyToolAction(auditLog, identityId, fortressId),
      new ThrottleAgentAction(auditLog, identityId, fortressId),
    ]);
  }

  async fire(
    finding: SentinelFinding,
    context?: ActionClassContext,
  ): Promise<boolean> {
    return this.resolve(finding, context).fire(finding, context);
  }

  async revoke(
    finding: SentinelFinding,
    context?: ActionClassContext,
  ): Promise<boolean> {
    return this.resolve(finding, context).revoke(finding, context);
  }

  resolve(
    finding: SentinelFinding,
    context?: ActionClassContext,
  ): ActionClass {
    const explicit = stringDetail(finding, "auto_trigger_action_class");
    if (isActionClassId(explicit)) {
      return this.actions.get(explicit) ?? this.fallback();
    }
    const sentinelId = finding.sentinel_id.toLowerCase();
    if (
      sentinelId.includes("egress") ||
      stringDetail(finding, "destination") ||
      stringDetail(finding, "server") ||
      stringDetail(finding, "destination_category")
    ) {
      return this.actions.get("block_egress") ?? this.fallback();
    }
    if (
      sentinelId.includes("tool") ||
      stringDetail(finding, "tool_name") ||
      stringDetail(finding, "tool")
    ) {
      return this.actions.get("auto_deny_tool") ?? this.fallback();
    }
    if (context?.rule_type === "anomaly") {
      return this.actions.get("throttle_agent") ?? this.fallback();
    }
    return this.fallback();
  }

  private fallback(): ActionClass {
    const action = this.actions.get("notify_operator") ?? this.actions.values().next().value;
    if (!action) {
      throw new Error("AutoTriggerActionRegistry requires at least one action");
    }
    return action;
  }
}

export interface ActionDispatcherDeps {
  store: ThresholdConfigStore;
  action: ActionClass;
  auditLog: AuditLog;
  fortressId: string;
  identityId: string;
  now?: () => Date;
  /**
   * Schedule a callback after `delayMs`. Tests inject a fake
   * scheduler so cancel-window timers advance deterministically.
   * Default: setTimeout (production); the dispatcher passes the
   * timer through `unref` when supported so a pending timer doesn't
   * keep the process alive. The callback may return a Promise; the
   * production scheduler ignores it (setTimeout-style), but a test
   * scheduler can await it to flush async work synchronously.
   */
  schedule?: (
    fn: () => void | Promise<void>,
    delayMs: number,
  ) => () => void;
}

interface PendingAction {
  rule_id: string;
  rule_type: AutoTriggerRuleType;
  finding: SentinelFinding;
  pending_since: number;
  cancel_window_ms: number;
  cancel: () => void;
}

/**
 * Per-fortress action dispatcher. One instance per fortress; never
 * aggregates across fortresses.
 */
export class ActionDispatcher {
  private readonly store: ThresholdConfigStore;
  private readonly action: ActionClass;
  private readonly auditLog: AuditLog;
  private readonly fortressId: string;
  private readonly identityId: string;
  private readonly now: () => Date;
  private readonly schedule: (
    fn: () => void | Promise<void>,
    delayMs: number,
  ) => () => void;
  private readonly pending = new Map<string, PendingAction>();
  private readonly listeners = new Set<(event: AutoTriggerEvent) => void>();

  constructor(deps: ActionDispatcherDeps) {
    this.store = deps.store;
    this.action = deps.action;
    this.auditLog = deps.auditLog;
    this.fortressId = deps.fortressId;
    this.identityId = deps.identityId;
    this.now = deps.now ?? (() => new Date());
    this.schedule =
      deps.schedule ??
      ((fn, delayMs) => {
        const t = setTimeout(fn, delayMs);
        if (typeof t.unref === "function") t.unref();
        return () => clearTimeout(t);
      });
  }

  /** Subscribe to in-process events. Returns an unsubscribe fn. */
  onEvent(
    listener: (event: AutoTriggerEvent) => void,
  ): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(event: AutoTriggerEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener exceptions never fail the dispatcher.
      }
    }
  }

  /**
   * Entry point for incoming findings. The caller (Nu-2 boot wiring
   * or a test rig) derives the rule_type and rule_id from the
   * finding's sentinel_id + classifier_id (for anomaly) before
   * calling this. Returns the action-type that was chosen.
   */
  async handleFinding(
    finding: SentinelFinding,
    ruleType: AutoTriggerRuleType,
    overrideRuleId?: string,
  ): Promise<AutoTriggerActionType> {
    const ruleId = overrideRuleId ?? deriveRuleId(finding, ruleType);
    const config = await this.store.getOrInit(ruleId, ruleType);
    const actionType = actionTypeForRung(config.current_rung);
    const historyEntry: ActionHistoryEntry = {
      observed_at: this.now().toISOString(),
      rung_at_action: config.current_rung,
      action_type: actionType,
      outcome: actionType === "inbox_only" ? "pending" : "pending",
      finding_id: finding.finding_id,
      severity: finding.severity,
    };
    await this.store.recordAction(ruleId, ruleType, historyEntry);
    if (config.current_rung === 1) {
      // No dispatcher-side action; the inbox already has the finding.
      // History entry stays `pending` until the operator approves or
      // denies via the inbox. (Nu-2 callbacks may close the loop.)
      return actionType;
    }
    if (config.current_rung === 2) {
      this.schedulePending(config, finding, ruleType);
      return actionType;
    }
    // Rung 3: fire immediately.
    await this.fireAndRecord(finding, ruleId, ruleType, actionType);
    return actionType;
  }

  /**
   * Rung-2 helper. Emit the pending audit event, schedule the
   * cancel-window timer, and store the cancel handle keyed by
   * finding_id. The expiry callback fires the action and records
   * `auto_proceeded`.
   */
  private schedulePending(
    config: RuleThresholdConfig,
    finding: SentinelFinding,
    ruleType: AutoTriggerRuleType,
  ): void {
    const windowMs = Math.max(1, config.cancel_window_seconds) * 1000;
    const pendingUntil = new Date(this.now().getTime() + windowMs);
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.ACTION_PENDING,
      this.identityId,
      {
        rule_id: config.rule_id,
        finding_id: finding.finding_id,
        sentinel_id: finding.sentinel_id,
        severity: finding.severity,
        cancel_window_seconds: config.cancel_window_seconds,
        pending_until: pendingUntil.toISOString(),
        fortress_id: this.fortressId,
      },
    );
    const cancelHandle = this.schedule(
      () =>
        this.expirePending(
          finding.finding_id,
          finding,
          config.rule_id,
          ruleType,
        ),
      windowMs,
    );
    this.pending.set(finding.finding_id, {
      rule_id: config.rule_id,
      rule_type: ruleType,
      finding,
      pending_since: this.now().getTime(),
      cancel_window_ms: windowMs,
      cancel: cancelHandle,
    });
    this.emit({
      type: "action_pending",
      rule_id: config.rule_id,
      finding_id: finding.finding_id,
      rung: 2,
      cancel_window_seconds: config.cancel_window_seconds,
      pending_until: pendingUntil.toISOString(),
    });
  }

  /**
   * Cancel-window expiry callback. Fires the action + records
   * `auto_proceeded`. No-op if the operator already canceled (the
   * pending entry was removed).
   */
  private async expirePending(
    findingId: string,
    finding: SentinelFinding,
    ruleId: string,
    ruleType: AutoTriggerRuleType,
  ): Promise<void> {
    const pending = this.pending.get(findingId);
    if (!pending) return;
    this.pending.delete(findingId);
    await this.fireAndRecord(finding, ruleId, ruleType, "auto_with_cancel");
  }

  /**
   * Common path for fire+record. Used by rung-3 immediate fires AND
   * by rung-2 cancel-window expiry. Emits `action_proceeded` audit
   * + listener event; updates the matching history entry's outcome.
   */
  private async fireAndRecord(
    finding: SentinelFinding,
    ruleId: string,
    ruleType: AutoTriggerRuleType,
    actionType: AutoTriggerActionType,
  ): Promise<void> {
    await this.action.fire(finding, {
      rule_id: ruleId,
      rule_type: ruleType,
      action_type: actionType,
      fortress_id: this.fortressId,
    });
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.ACTION_PROCEEDED,
      this.identityId,
      {
        rule_id: ruleId,
        finding_id: finding.finding_id,
        sentinel_id: finding.sentinel_id,
        severity: finding.severity,
        action_type: actionType,
        fortress_id: this.fortressId,
      },
    );
    await this.store.updateActionOutcome(
      ruleId,
      ruleType,
      finding.finding_id,
      "auto_proceeded",
    );
    this.emit({
      type: "action_proceeded",
      rule_id: ruleId,
      finding_id: finding.finding_id,
      action_type: actionType,
    });
  }

  /**
   * Operator cancels a pending rung-2 action within its window. Emits
   * `auto_action_canceled`; the action is NOT fired. Returns true on
   * success, false when the pending entry is absent (e.g. window
   * already expired or finding_id never queued).
   */
  async cancelPending(findingId: string): Promise<boolean> {
    const pending = this.pending.get(findingId);
    if (!pending) return false;
    pending.cancel();
    this.pending.delete(findingId);
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.ACTION_CANCELED,
      this.identityId,
      {
        rule_id: pending.rule_id,
        finding_id: findingId,
        fortress_id: this.fortressId,
      },
    );
    await this.store.updateActionOutcome(
      pending.rule_id,
      pending.rule_type,
      findingId,
      "operator_canceled",
    );
    this.emit({
      type: "action_canceled",
      rule_id: pending.rule_id,
      finding_id: findingId,
    });
    return true;
  }

  /**
   * Operator revokes a past rung-3 (or post-window rung-2) action.
   * Looks up the history entry (which must exist), calls
   * action.revoke, emits ACTION_REVOKED, and updates the outcome.
   * Throws AutoTriggerError if the finding_id has no recorded history.
   */
  async revokeAction(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
    findingId: string,
  ): Promise<void> {
    const config = await this.store.get(ruleId);
    if (!config) {
      throw new AutoTriggerError(
        `rule ${ruleId} not found`,
        "rule_not_found",
      );
    }
    const entry = config.history.find((h) => h.finding_id === findingId);
    if (!entry) {
      throw new AutoTriggerError(
        `finding ${findingId} not in rule ${ruleId} history`,
        "pending_not_found",
      );
    }
    // Reconstruct a minimal SentinelFinding shape from the history
    // entry for the action class's revoke contract. Nu-1's
    // notify_operator ignores the finding payload, so this is safe;
    // future action classes that need richer finding data can fetch
    // it from the SentinelFindingStore when wired in Nu-2.
    const stub: SentinelFinding = {
      finding_id: findingId,
      sentinel_id: ruleId,
      severity: entry.severity,
      summary: "",
      details: {},
      observed_at: entry.observed_at,
      evidence_audit_ids: [],
      fortress_id: this.fortressId,
    };
    await this.action.revoke(stub, {
      rule_id: ruleId,
      rule_type: ruleType,
      action_type: entry.action_type,
      fortress_id: this.fortressId,
    });
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.ACTION_REVOKED,
      this.identityId,
      {
        rule_id: ruleId,
        finding_id: findingId,
        fortress_id: this.fortressId,
      },
    );
    await this.store.updateActionOutcome(
      ruleId,
      ruleType,
      findingId,
      "operator_revoked",
    );
    this.emit({
      type: "action_revoked",
      rule_id: ruleId,
      finding_id: findingId,
    });
  }

  /** Promote a rule + emit audit. */
  async promoteRule(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
  ): Promise<RuleThresholdConfig> {
    const before = await this.store.getOrInit(ruleId, ruleType);
    const after = await this.store.promote(ruleId, ruleType);
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.RULE_PROMOTED,
      this.identityId,
      {
        rule_id: ruleId,
        from_rung: before.current_rung,
        to_rung: after.current_rung,
        fortress_id: this.fortressId,
      },
    );
    return after;
  }

  /** Demote a rule + emit audit. */
  async demoteRule(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
  ): Promise<RuleThresholdConfig> {
    const before = await this.store.getOrInit(ruleId, ruleType);
    const after = await this.store.demote(ruleId, ruleType);
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.RULE_DEMOTED,
      this.identityId,
      {
        rule_id: ruleId,
        from_rung: before.current_rung,
        to_rung: after.current_rung,
        fortress_id: this.fortressId,
      },
    );
    return after;
  }

  /** Update threshold overrides + cancel-window; emit audit. */
  async updateThresholds(
    ruleId: string,
    ruleType: AutoTriggerRuleType,
    patch: {
      threshold_overrides?: RuleThresholdConfig["threshold_overrides"];
      cancel_window_seconds?: number;
    },
  ): Promise<RuleThresholdConfig> {
    const after = await this.store.updateConfig(ruleId, ruleType, patch);
    void this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.THRESHOLD_UPDATED,
      this.identityId,
      {
        rule_id: ruleId,
        ...(patch.threshold_overrides !== undefined
          ? { threshold_overrides: patch.threshold_overrides }
          : {}),
        ...(patch.cancel_window_seconds !== undefined
          ? { cancel_window_seconds: patch.cancel_window_seconds }
          : {}),
        fortress_id: this.fortressId,
      },
    );
    return after;
  }

  /** List pending rung-2 actions (for the dashboard "pending" panel). */
  listPending(): Array<{
    rule_id: string;
    finding_id: string;
    pending_until: string;
    cancel_window_seconds: number;
  }> {
    const out: ReturnType<ActionDispatcher["listPending"]> = [];
    for (const [finding_id, pending] of this.pending.entries()) {
      out.push({
        rule_id: pending.rule_id,
        finding_id,
        pending_until: new Date(
          pending.pending_since + pending.cancel_window_ms,
        ).toISOString(),
        cancel_window_seconds: pending.cancel_window_ms / 1000,
      });
    }
    return out;
  }

  /**
   * Tear down all pending timers + listeners. Idempotent. Useful in
   * tests + shutdown paths.
   */
  dispose(): void {
    for (const pending of this.pending.values()) {
      try {
        pending.cancel();
      } catch {
        // ignore
      }
    }
    this.pending.clear();
    this.listeners.clear();
  }
}

/**
 * Derive the canonical rule_id from a finding + ruleType. For
 * anomaly findings the classifier_id is expected in details (Chi-1
 * stamps it there). Sentinel findings use the sentinel_id directly.
 * The dispatcher (and Nu-2 boot wiring) can override with an
 * explicit rule_id if needed.
 */
export function deriveRuleId(
  finding: SentinelFinding,
  ruleType: AutoTriggerRuleType,
): string {
  if (ruleType === "anomaly") {
    const detectorId =
      typeof finding.details["detector_id"] === "string"
        ? (finding.details["detector_id"] as string)
        : finding.sentinel_id;
    const classifierId =
      typeof finding.details["classifier_id"] === "string"
        ? (finding.details["classifier_id"] as string)
        : "rolling-baseline";
    return anomalyRuleId(detectorId, classifierId);
  }
  if (ruleType === "honeypot") {
    return honeypotRuleId(finding.sentinel_id);
  }
  return sentinelRuleId(finding.sentinel_id);
}

function stringDetail(
  finding: SentinelFinding,
  key: string,
): string | undefined {
  const value = finding.details[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function isActionClassId(value: unknown): value is AutoTriggerActionClassId {
  return (
    value === "notify_operator" ||
    value === "block_egress" ||
    value === "auto_deny_tool" ||
    value === "throttle_agent"
  );
}

// Re-export the outcome enum for consumers (route handlers, tests).
export type { AutoTriggerOutcome };
