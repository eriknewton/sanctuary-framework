/**
 * Nu-3 Auto-Trigger calibration suggester.
 *
 * Scheduled evaluator over active rule configs. It surfaces recommendations
 * and emits audit events, but it never changes a rung unless the operator
 * calls acceptRecommendation().
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import { AUTO_TRIGGER_AUDIT_OPS, type ActionDispatcher } from "./action-dispatcher.js";
import type { ThresholdConfigStore } from "./threshold-config-store.js";
import type {
  AutoTriggerRuleType,
  RuleThresholdConfig,
} from "./types.js";
import {
  DEFAULT_DEMOTION_CANCEL_COUNT,
  DEFAULT_PROMOTION_FIRE_COUNT,
  DEFAULT_PROMOTION_WINDOW_DAYS,
  evaluatePromotion,
  type PromotionRecommendation,
} from "./promotion-criteria.js";

export const DEFAULT_RECOMMENDATION_TICK_MS = 60_000;
export const DEFAULT_RECOMMENDATION_COOLDOWN_HOURS = 24;

export interface RecommendationView extends PromotionRecommendation {
  rule_type: AutoTriggerRuleType;
  fortress_id: string;
  suppressed_until?: string;
}

export interface CalibrationSuggesterDeps {
  store: ThresholdConfigStore;
  dispatcher: ActionDispatcher;
  auditLog: AuditLog;
  fortressId: string;
  identityId: string;
  now?: () => Date;
  tickIntervalMs?: number;
  schedule?: (fn: () => void | Promise<void>, delayMs: number) => () => void;
}

export class CalibrationSuggester {
  private readonly store: ThresholdConfigStore;
  private readonly dispatcher: ActionDispatcher;
  private readonly auditLog: AuditLog;
  private readonly fortressId: string;
  private readonly identityId: string;
  private readonly now: () => Date;
  private readonly tickIntervalMs: number;
  private readonly schedule: (fn: () => void | Promise<void>, delayMs: number) => () => void;
  private cancelTimer: (() => void) | null = null;
  private tickInFlight = false;

  constructor(deps: CalibrationSuggesterDeps) {
    this.store = deps.store;
    this.dispatcher = deps.dispatcher;
    this.auditLog = deps.auditLog;
    this.fortressId = deps.fortressId;
    this.identityId = deps.identityId;
    this.now = deps.now ?? (() => new Date());
    this.tickIntervalMs = deps.tickIntervalMs ?? DEFAULT_RECOMMENDATION_TICK_MS;
    this.schedule =
      deps.schedule ??
      ((fn, delayMs) => {
        const t = setInterval(fn, delayMs);
        if (typeof t.unref === "function") t.unref();
        return () => clearInterval(t);
      });
  }

  start(): void {
    if (this.cancelTimer !== null) return;
    if (this.tickIntervalMs <= 0) return;
    this.cancelTimer = this.schedule(async () => {
      await this.tick();
    }, this.tickIntervalMs);
  }

  stop(): void {
    if (!this.cancelTimer) return;
    this.cancelTimer();
    this.cancelTimer = null;
  }

  async tick(): Promise<RecommendationView[]> {
    if (this.tickInFlight) return [];
    this.tickInFlight = true;
    try {
      const recommendations = await this.listRecommendations({
        includeSuppressed: false,
        includeNoChange: false,
      });
      for (const rec of recommendations) {
        this.auditLog.append(
          "l2",
          AUTO_TRIGGER_AUDIT_OPS.RECOMMENDATION_GENERATED,
          this.identityId,
          {
            rule_id: rec.rule_id,
            rule_type: rec.rule_type,
            current_rung: rec.current_rung,
            recommended_rung: rec.recommended_rung,
            confidence: rec.confidence,
            history_summary: rec.history_summary,
            fortress_id: this.fortressId,
          },
        );
      }
      return recommendations;
    } finally {
      this.tickInFlight = false;
    }
  }

  async listRecommendations(opts?: {
    includeSuppressed?: boolean;
    includeNoChange?: boolean;
  }): Promise<RecommendationView[]> {
    const ids = await this.store.listRuleIds();
    const out: RecommendationView[] = [];
    for (const id of ids) {
      const config = await this.store.get(id);
      if (!config) continue;
      const view = this.evaluateConfig(config);
      const suppressed = isSuppressed(config, this.now());
      if (!opts?.includeSuppressed && suppressed) continue;
      if (!opts?.includeNoChange && view.recommended_rung === view.current_rung) continue;
      out.push(view);
    }
    return out.sort((a, b) => a.rule_id.localeCompare(b.rule_id));
  }

  async getRecommendation(
    ruleId: string,
    opts?: { includeSuppressed?: boolean; includeNoChange?: boolean },
  ): Promise<RecommendationView | null> {
    const config = await this.store.get(ruleId);
    if (!config) return null;
    const view = this.evaluateConfig(config);
    const suppressed = isSuppressed(config, this.now());
    if (!opts?.includeSuppressed && suppressed) return null;
    if (!opts?.includeNoChange && view.recommended_rung === view.current_rung) {
      return null;
    }
    return view;
  }

  async acceptRecommendation(ruleId: string): Promise<{
    recommendation: RecommendationView;
    rule: RuleThresholdConfig;
  }> {
    const rec = await this.getRecommendation(ruleId, {
      includeSuppressed: false,
      includeNoChange: false,
    });
    if (!rec) throw new Error(`no active recommendation for ${ruleId}`);
    const rule =
      rec.recommended_rung > rec.current_rung
        ? await this.dispatcher.promoteRule(ruleId, rec.rule_type)
        : await this.dispatcher.demoteRule(ruleId, rec.rule_type);
    await this.store.suppressRecommendation(ruleId, rec.rule_type, null);
    this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.RECOMMENDATION_ACCEPTED,
      this.identityId,
      {
        rule_id: ruleId,
        rule_type: rec.rule_type,
        from_rung: rec.current_rung,
        to_rung: rec.recommended_rung,
        confidence: rec.confidence,
        fortress_id: this.fortressId,
      },
    );
    return { recommendation: rec, rule };
  }

  async rejectRecommendation(
    ruleId: string,
    cooldownHours = DEFAULT_RECOMMENDATION_COOLDOWN_HOURS,
  ): Promise<{ suppressed_until: string }> {
    const config = await this.store.get(ruleId);
    if (!config) throw new Error(`rule not found: ${ruleId}`);
    const until = new Date(
      this.now().getTime() + Math.max(1, cooldownHours) * 3_600_000,
    ).toISOString();
    await this.store.suppressRecommendation(ruleId, config.rule_type, until);
    this.auditLog.append(
      "l2",
      AUTO_TRIGGER_AUDIT_OPS.RECOMMENDATION_REJECTED,
      this.identityId,
      {
        rule_id: ruleId,
        rule_type: config.rule_type,
        suppressed_until: until,
        fortress_id: this.fortressId,
      },
    );
    return { suppressed_until: until };
  }

  private evaluateConfig(config: RuleThresholdConfig): RecommendationView {
    const minFires =
      config.threshold_overrides.promotion_fire_count ??
      DEFAULT_PROMOTION_FIRE_COUNT;
    const windowDays =
      config.threshold_overrides.promotion_window_days ??
      DEFAULT_PROMOTION_WINDOW_DAYS;
    const demotionCancelCount =
      config.threshold_overrides.demotion_cancel_count ??
      DEFAULT_DEMOTION_CANCEL_COUNT;
    const rec = evaluatePromotion(config.rule_id, config.history, windowDays, {
      currentRung: config.current_rung,
      minFires,
      demotionCancelCount,
      now: this.now,
    });
    return {
      ...rec,
      rule_type: config.rule_type,
      fortress_id: config.fortress_id,
      ...(config.recommendation_suppressed_until
        ? { suppressed_until: config.recommendation_suppressed_until }
        : {}),
    };
  }
}

function isSuppressed(config: RuleThresholdConfig, now: Date): boolean {
  if (!config.recommendation_suppressed_until) return false;
  const t = Date.parse(config.recommendation_suppressed_until);
  return Number.isFinite(t) && t > now.getTime();
}
