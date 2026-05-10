/**
 * Sanctuary v1.3 WP-V1.3-1 Sentinel base class.
 *
 * Subclass to add a new sentinel. The dispatcher schedules `evaluate()`
 * on a tick. `subscribe()` is called once when an operator opts in;
 * `unsubscribe()` is called once when they opt out (or the fortress is
 * disposed). Sentinels MUST treat the SentinelContext as read-only.
 */

import type { SentinelContext, SentinelFinding } from "./types.js";

/**
 * Concrete sentinels implement these three methods and stamp a
 * sentinel_id. Implementations must:
 *  - Be pure with respect to the SentinelContext (no writable
 *    storage, no external network).
 *  - Return findings synchronously deterministically given the same
 *    context state.
 *  - Tolerate empty audit logs (return []).
 */
export abstract class Sentinel {
  /**
   * Stable identifier. Used as the dictionary key in the registry, the
   * URL path component, and the audit-log details payload's
   * `sentinel_id` field. Convention: lowercase, dash-separated, prefix
   * with the sentinel category (e.g. `egress-volume`,
   * `credential-usage`).
   */
  abstract readonly sentinelId: string;

  /**
   * Human-readable description shown in the operator dashboard's
   * "available sentinels" list. Should answer "what does this watch?"
   * in one sentence.
   */
  abstract readonly description: string;

  /**
   * Bind the sentinel to a fortress context. Called once on
   * subscribe. Default implementation stores the context on `this`;
   * sentinels that need additional setup (e.g. priming a baseline
   * cache) override.
   */
  async subscribe(context: SentinelContext): Promise<void> {
    this.context = context;
  }

  /**
   * Tear down. Default implementation clears the context; subclasses
   * that hold timers or external handles override.
   */
  async unsubscribe(): Promise<void> {
    this.context = undefined;
  }

  /**
   * Compute findings against the current audit-log + agent-state
   * snapshot. Returns an empty array when nothing notable is observed.
   * Throwing is allowed; the dispatcher catches and emits a
   * `sentinel_evaluation_failed` audit event.
   */
  abstract evaluate(): Promise<SentinelFinding[]>;

  protected context: SentinelContext | undefined;

  /** Internal helper: assert subscribed before evaluation. */
  protected requireContext(): SentinelContext {
    if (!this.context) {
      throw new Error(
        `sentinel ${this.sentinelId}: evaluate() called before subscribe()`,
      );
    }
    return this.context;
  }
}
