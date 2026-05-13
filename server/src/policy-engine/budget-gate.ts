/**
 * Sanctuary Policy Engine - Budget gate + tracker (WP-MVP-6).
 *
 * Per-agent spend budgets with daily (rolling 24h) and monthly (rolling 30d)
 * windows. Budget consumption is tracked against usage events from the
 * WP-MVP-4 UsageEventEmitter.
 *
 * Threshold behavior:
 *   - Soft warn at threshold (default 80%): emits `budget_consumed` event.
 *     Agent continues operating.
 *   - Hard stop at 100%: emits `budget_exceeded` event. Commitment-boundary
 *     gate refuses new commitments with `budget_exhausted` reason.
 *
 * Cross-agent priority arbitration and shared-pool grammar are v1.x.
 * v1.0 ships per-agent budgets only.
 *
 * No network, no LLM at gate time.
 */

import {
  DEFAULT_SOFT_WARN_THRESHOLD,
  EGRESS_BUDGET_RETENTION_REASON_CODES,
  ROLLING_DAILY_WINDOW_MS,
  ROLLING_MONTHLY_WINDOW_MS,
} from "./constants.js";
import type { BudgetLimit, BudgetPolicy, CompiledPolicy } from "./types.js";

/** A single spend record in the rolling window. */
export interface SpendRecord {
  /** Amount consumed. */
  amount: number;
  /** ISO8601 UTC timestamp. */
  recorded_at: string;
}

/** Budget state for one agent. */
export interface AgentBudgetState {
  agent_id: string;
  /** Append-only spend records. The tracker prunes records outside the window. */
  records: SpendRecord[];
}

/** Result of a budget check. */
export interface BudgetCheckResult {
  /** Whether the agent may proceed. */
  allowed: boolean;
  /** Which window triggered (if any). */
  triggered_window?: "daily" | "monthly";
  /** Threshold level: "within_limits" | "soft_warn" | "hard_stop". */
  level: "within_limits" | "soft_warn" | "hard_stop";
  /** Reason code for gate receipt. */
  reason_code: string;
  /** Human-readable explanation. */
  explanation: string;
  /** Current consumption for daily window. */
  daily_consumed?: number;
  /** Current consumption for monthly window. */
  monthly_consumed?: number;
}

export type BudgetThresholdCallback = (event: {
  agent_id: string;
  threshold_name: "soft_warn" | "hard_stop";
  current_value: number;
  limit: number;
  window: "daily" | "monthly";
  observed_at: string;
}) => void;

/**
 * In-memory budget tracker. Production wires a persistent store; this
 * in-memory implementation is sufficient for v1.0 per-agent tracking.
 */
export class BudgetTracker {
  private agents = new Map<string, AgentBudgetState>();

  constructor(private readonly opts: {
    onThresholdCross?: BudgetThresholdCallback;
    now?: () => Date;
  } = {}) {}

  /** Get or create budget state for an agent. */
  private getState(agent_id: string): AgentBudgetState {
    let state = this.agents.get(agent_id);
    if (!state) {
      state = { agent_id, records: [] };
      this.agents.set(agent_id, state);
    }
    return state;
  }

  /**
   * Record a spend event. Called when a usage event with cost is emitted.
   */
  recordSpend(agent_id: string, amount: number, recorded_at?: string): void {
    const state = this.getState(agent_id);
    state.records.push({
      amount,
      recorded_at: recorded_at ?? new Date().toISOString(),
    });
  }

  /**
   * Compute the total spend within a rolling window ending at `now`.
   */
  private sumWindow(
    records: SpendRecord[],
    windowMs: number,
    now: number
  ): number {
    const cutoff = now - windowMs;
    let total = 0;
    for (const r of records) {
      if (new Date(r.recorded_at).getTime() >= cutoff) {
        total += r.amount;
      }
    }
    return total;
  }

  /**
   * Prune records older than the largest window to bound memory.
   */
  pruneOldRecords(agent_id: string, now?: number): void {
    const state = this.agents.get(agent_id);
    if (!state) return;
    const cutoff = (now ?? Date.now()) - ROLLING_MONTHLY_WINDOW_MS;
    state.records = state.records.filter(
      (r) => new Date(r.recorded_at).getTime() >= cutoff
    );
  }

  /**
   * Check an agent's current budget status against the pinned policy.
   *
   * Returns a BudgetCheckResult indicating whether the agent may proceed
   * and the current consumption levels.
   */
  checkBudget(
    agent_id: string,
    budgetPolicy: BudgetPolicy | undefined,
    now?: number
  ): BudgetCheckResult {
    if (!budgetPolicy) {
      return {
        allowed: true,
        level: "within_limits",
        reason_code: EGRESS_BUDGET_RETENTION_REASON_CODES.BUDGET_NO_POLICY,
        explanation: `no budget policy for ${agent_id}; no enforcement`,
      };
    }

    const nowMs = now ?? Date.now();
    const state = this.getState(agent_id);

    // Check daily window.
    const dailyResult = budgetPolicy.daily
      ? this.checkLimit(
          state.records,
          budgetPolicy.daily,
          ROLLING_DAILY_WINDOW_MS,
          nowMs,
          "daily"
        )
      : undefined;

    // Check monthly window.
    const monthlyResult = budgetPolicy.monthly
      ? this.checkLimit(
          state.records,
          budgetPolicy.monthly,
          ROLLING_MONTHLY_WINDOW_MS,
          nowMs,
          "monthly"
        )
      : undefined;

    // Hard stop takes precedence.
    if (dailyResult?.level === "hard_stop") {
      this.emitThreshold(agent_id, dailyResult, budgetPolicy.daily!.amount, "daily");
      return dailyResult;
    }
    if (monthlyResult?.level === "hard_stop") {
      this.emitThreshold(agent_id, monthlyResult, budgetPolicy.monthly!.amount, "monthly");
      return monthlyResult;
    }

    // Soft warn.
    if (dailyResult?.level === "soft_warn") {
      this.emitThreshold(agent_id, dailyResult, budgetPolicy.daily!.amount, "daily");
      return dailyResult;
    }
    if (monthlyResult?.level === "soft_warn") {
      this.emitThreshold(agent_id, monthlyResult, budgetPolicy.monthly!.amount, "monthly");
      return monthlyResult;
    }

    // Within limits.
    return {
      allowed: true,
      level: "within_limits",
      reason_code: EGRESS_BUDGET_RETENTION_REASON_CODES.BUDGET_WITHIN_LIMITS,
      explanation: `${agent_id} within budget limits`,
      daily_consumed: dailyResult?.daily_consumed,
      monthly_consumed: monthlyResult?.monthly_consumed,
    };
  }

  private checkLimit(
    records: SpendRecord[],
    limit: BudgetLimit,
    windowMs: number,
    nowMs: number,
    windowName: "daily" | "monthly"
  ): BudgetCheckResult {
    const consumed = this.sumWindow(records, windowMs, nowMs);
    const threshold = limit.soft_warn_threshold ?? DEFAULT_SOFT_WARN_THRESHOLD;

    if (consumed >= limit.amount) {
      return {
        allowed: false,
        triggered_window: windowName,
        level: "hard_stop",
        reason_code: EGRESS_BUDGET_RETENTION_REASON_CODES.BUDGET_HARD_STOP,
        explanation: `${windowName} budget exhausted: ${consumed.toFixed(2)} / ${limit.amount} ${limit.unit}`,
        ...(windowName === "daily"
          ? { daily_consumed: consumed }
          : { monthly_consumed: consumed }),
      };
    }

    if (consumed >= limit.amount * threshold) {
      return {
        allowed: true,
        triggered_window: windowName,
        level: "soft_warn",
        reason_code: EGRESS_BUDGET_RETENTION_REASON_CODES.BUDGET_SOFT_WARN,
        explanation: `${windowName} budget at ${((consumed / limit.amount) * 100).toFixed(0)}%: ${consumed.toFixed(2)} / ${limit.amount} ${limit.unit}`,
        ...(windowName === "daily"
          ? { daily_consumed: consumed }
          : { monthly_consumed: consumed }),
      };
    }

    return {
      allowed: true,
      triggered_window: windowName,
      level: "within_limits",
      reason_code: EGRESS_BUDGET_RETENTION_REASON_CODES.BUDGET_WITHIN_LIMITS,
      explanation: `${windowName} budget within limits: ${consumed.toFixed(2)} / ${limit.amount} ${limit.unit}`,
      ...(windowName === "daily"
        ? { daily_consumed: consumed }
        : { monthly_consumed: consumed }),
    };
  }

  /** Reset all budget state. Used in tests. */
  reset(): void {
    this.agents.clear();
  }

  /** Get raw state for an agent. Used in tests. */
  getAgentState(agent_id: string): AgentBudgetState | undefined {
    return this.agents.get(agent_id);
  }

  private emitThreshold(
    agent_id: string,
    result: BudgetCheckResult,
    limit: number,
    window: "daily" | "monthly",
  ): void {
    const consumed =
      window === "daily" ? result.daily_consumed : result.monthly_consumed;
    if (consumed === undefined) return;
    this.opts.onThresholdCross?.({
      agent_id,
      threshold_name: result.level === "hard_stop" ? "hard_stop" : "soft_warn",
      current_value: consumed,
      limit,
      window,
      observed_at: (this.opts.now?.() ?? new Date()).toISOString(),
    });
  }
}

/**
 * Check whether a commitment is allowed given the current budget state.
 *
 * This is the integration point with the commitment-boundary gate. When
 * budget is exhausted (hard_stop), new commitments MUST be refused.
 */
export function isBudgetExhausted(
  tracker: BudgetTracker,
  agent_id: string,
  policy: CompiledPolicy | null
): { exhausted: boolean; result: BudgetCheckResult } {
  const result = tracker.checkBudget(
    agent_id,
    policy?.budgets ?? undefined
  );
  return {
    exhausted: result.level === "hard_stop",
    result,
  };
}
