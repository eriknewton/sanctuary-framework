/**
 * QLA performance budget module.
 *
 * Enforces p99 latency budgets for each query-anonymity tier operation.
 * Throws if a measured duration exceeds the budget for the named
 * operation. Budgets are intentionally tight: the QLA pipeline must
 * not add perceptible latency to the LLM call round-trip.
 */

/** Budget in milliseconds per operation (p99 target). */
export const BUDGET_MS: Record<string, number> = {
  tier_a_header_strip: 5,
  tier_b_pii_rewrite_local: 100,
  tier_b_pii_rewrite_provider_call: 500,
  tier_b_smart_rewriter_classification: 50,
};

export class PerformanceBudgetExceeded extends Error {
  constructor(
    public readonly operationName: string,
    public readonly durationMs: number,
    public readonly budgetMs: number,
  ) {
    super(
      `QLA performance budget exceeded: ${operationName} took ${durationMs.toFixed(2)}ms (budget: ${budgetMs}ms)`,
    );
    this.name = "PerformanceBudgetExceeded";
  }
}

/**
 * Assert that the measured duration is within the budget for the named
 * operation. Throws `PerformanceBudgetExceeded` if not.
 *
 * Throws `Error` if the operation name is not in the budget table.
 */
export function assertWithinBudget(
  operationName: string,
  durationMs: number,
): void {
  const budget = BUDGET_MS[operationName];
  if (budget === undefined) {
    throw new Error(
      `Unknown QLA operation: "${operationName}". Known operations: ${Object.keys(BUDGET_MS).join(", ")}`,
    );
  }
  if (durationMs > budget) {
    throw new PerformanceBudgetExceeded(operationName, durationMs, budget);
  }
}
